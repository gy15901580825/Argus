"""Disposable Docker sandbox that runs Claude Code with an untrusted skill, decoys and a logging proxy."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import shutil
import socket
import string
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator

from orchestrator.redteam.skillscan.decoys import Decoy, render_decoy_file

DOCKER_DIR = Path(__file__).parent / "docker"
AGENT_HOME = "/home/agent"
PROXY_ALIAS = "proxy"
LABEL = "sk.run"
DNS_ENV = "ARGUS_SKILLSCAN_DNS"
BUILD_NETWORK_ENV = "ARGUS_SKILLSCAN_BUILD_NETWORK"
_BUILD_FILES = {
    "agent": ("agent.Dockerfile", "agent_entry.sh"),
    "proxy": ("proxy.Dockerfile", "proxy_addon.py", "proxy_entry.sh"),
}
_PROXY_CA = "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"
_KEY_FIFO = "/run/upstream-key"
_AGENT_CA = "/usr/local/share/ca-certificates/internal-root-ca.crt"
_SYSTEM_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
_PROXY_LOG = "/var/log/proxy/requests.jsonl"
# Host-to-proxy control: root writes the task id here over `docker exec`; the addon answers in the ack file.
# The agent reaches the proxy only over HTTP on 8080, and the addon serves nothing from this dir.
_PROXY_CONTROL = "/var/log/proxy/control"
_PROXY_ACK = "/var/log/proxy/control-ack"
_SWITCH_TIMEOUT_S = 5
# Spend control, enforced by the proxy per task: the models allowed besides --model, and a limit on Messages
# calls. Claude Code 2.1.311 names several Haiku ids for its background calls, so run_task pins them to this one.
BACKGROUND_MODELS = ("claude-haiku-4-5-20251001",)
MAX_REQUESTS = 200
# (model id prefix, input, output) in USD per million tokens: proxy_addon._PRICES without the cache-read rate,
# which a reservation never uses (a test keeps the two equal). The CLI takes only these for --model, because the
# proxy charges an unknown model at the top rate.
_RATES = (
    ("claude-fable-5-1", 10.0, 50.0), ("claude-mythos-5-1", 10.0, 50.0), ("claude-fable-5", 10.0, 50.0),
    ("claude-mythos-5", 10.0, 50.0), ("claude-opus-5-5", 4.0, 20.0), ("claude-opus-5", 5.0, 25.0),
    ("claude-opus-4-8", 5.0, 25.0), ("claude-opus-4-7", 5.0, 25.0), ("claude-opus-4-6", 5.0, 25.0),
    ("claude-opus-4-5", 5.0, 25.0), ("claude-opus-4", 15.0, 75.0), ("claude-3-opus", 15.0, 75.0),
    ("claude-sonnet-5", 2.0, 10.0), ("claude-sonnet-4", 3.0, 15.0), ("claude-3-7-sonnet", 3.0, 15.0),
    ("claude-3-5-sonnet", 3.0, 15.0), ("claude-haiku-5-5", 0.1, 0.5), ("claude-haiku-4-5", 1.0, 5.0),
    ("claude-3-5-haiku", 0.8, 4.0), ("claude-3-haiku", 0.25, 1.25),
)
# proxy_addon._LONG_PROMPT and INPUT_PAD_TOKENS.
_LONG_PROMPT = (("claude-sonnet-4", 200_000, 2.0, 1.5), ("claude-haiku-5-5", 100_000, 5.0, 5.0))
_INPUT_PAD_TOKENS = 2000
PRICED_MODEL_PREFIXES = tuple(p for p, _, _ in _RATES)
# Claude Code 2.1.311's calls on a benign skill were 47-98 KB; the default cap holds two 150 KB calls, and a cap
# below one 100 KB call would refuse Claude Code's first call.
_LARGE_CALL_BYTES = 150_000
_MIN_CALL_BYTES = 100_000
_CAP_FLOOR_USD = 1.00
_CAP_STEP_USD = 0.25
# proxy_addon.SETTLED_ABOVE: the error on a cost row whose real charge passed the call's reservation.
_SETTLED_ABOVE = "settled above its reservation"


def is_priced_model(model: str) -> bool:
    return any(model.startswith(p) for p in PRICED_MODEL_PREFIXES)


def call_reserve_usd(model: str, body_bytes: int, max_tokens: int) -> float:
    """What the proxy reserves for a Claude Code call of body_bytes (proxy_addon.reserve_usd, no images,
    5-minute cache writes); a test keeps the two equal."""
    _, inp, out = max((r for r in _RATES if model.startswith(r[0])), key=lambda r: len(r[0]))
    est = body_bytes + _INPUT_PAD_TOKENS
    for prefix, threshold, in_x, out_x in _LONG_PROMPT:
        if model.startswith(prefix) and est > threshold:
            inp, out = inp * in_x, out * out_x
    return (est * inp * 1.25 + max_tokens * out) / 1_000_000


def default_cap_usd(model: str) -> float:
    """The per-task cap for model: room for two large Claude Code calls, at least $1.00, rounded up to $0.25."""
    two = 2 * call_reserve_usd(model, _LARGE_CALL_BYTES, CLAUDE_CODE_MAX_OUTPUT_TOKENS)
    return max(_CAP_FLOOR_USD, math.ceil(two / _CAP_STEP_USD - 1e-9) * _CAP_STEP_USD)


def min_cap_usd(model: str) -> float:
    """The smallest per-task cap that admits one Claude Code call of 100 KB, rounded up to the cent."""
    return math.ceil(call_reserve_usd(model, _MIN_CALL_BYTES, CLAUDE_CODE_MAX_OUTPUT_TOKENS) * 100 - 1e-9) / 100

# The proxy reserves each call's max_tokens of output against the task's cap. Claude Code 2.1.311 asks for 32000
# on Sonnet (about $0.48 reserved), so it is pinned lower; its live calls used at most about 1,500. The agent
# image also pins it in /etc/claude-code/managed-settings.json, which wins over ~/.claude/settings.json.
CLAUDE_CODE_MAX_OUTPUT_TOKENS = 8192
# The scan budget bounds a task's backlog to about 20 s of scanning.
_DRAIN_TIMEOUT_S = 30
_FILE_LOG = "/var/log/fsmon/files.jsonl"
_READY = "/var/log/fsmon/ready"
_STAMP = "/usr/local/lib/fsmon/stamp.py"
_MONITORS = 7
_MONITOR_NAMES = ("files", "decoydirs", "trees", "home", "project", "homeread", "projectread")
# inotifywait's words for running out of watches or instances.
_LIMIT_PATTERNS = ("upper limit on inotify", "No space left on device", "Too many open files")
# The MCP check's root read of ~/.claude.json happens between tasks. Before the next task starts, wait until
# the monitor has stamped it (homeread sees every open by path), plus a guard for the inode watches.
_OWN_READ_WAIT_S = 2.0
_OWN_READ_GUARD_S = 0.2
# rules.py uses no file event of ~/.claude.json (Claude Code rewrites it on every run), so a lost or late
# watch on it costs no evidence. Such notes go to TaskRun.debug_notes, never to monitor_errors.
_CLAUDE_JSON = AGENT_HOME + "/.claude.json"
NO_EVIDENCE_LOST = "the rules use no file events of it, so no evidence was lost"
# Logs are read in chunks of this many bytes, under one deadline per task.
_READ_CAP = 128 * 1024 * 1024
_READ_DEADLINE_S = 60
# inotify rows for the same path and event closer than this are one access seen by two watches.
_DUP_WINDOW_S = 0.1
_RESOLVE_ERRORS = ("Temporary failure resolving", "EAI_AGAIN", "Could not resolve")
# Hosts each image build fetches from (apt sources incl. security, and npm); the proxy fetches nothing.
_BUILD_HOSTS = {"agent": ("deb.debian.org", "registry.npmjs.org"), "proxy": ()}
_ORPHAN_AGE_S = 3600
_BUILD_TIMEOUT_S = 900
_INSPECT_TIMEOUT_S = 30
# Without it, the internal network's bridge holds a host address the agent can connect to (e.g. host sshd).
# IPv6 is off on that network, and its gateway isolated too in case a daemon default turns IPv6 on.
_INTERNAL_NET_OPTS = ("--internal", "--ipv6=false", "-o", "com.docker.network.bridge.gateway_mode_ipv4=isolated",
                      "-o", "com.docker.network.bridge.gateway_mode_ipv6=isolated")
_MIN_DOCKER = 28
_SKILL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Run as root inside the agent: hash every persistence location, so a task's changes show up
# even if the agent renamed a watched directory out from under inotify.
_SNAPSHOT_CODE = r"""
import hashlib, json, os, stat, sys, time
H = "/home/agent"
CAP = 8 * 1024 * 1024
MAX_ENTRIES = 20000
deadline = time.monotonic() + 30
# ~/.claude itself: its inode changes if the agent swaps in a whole new one.
files = [H + "/.bashrc", H + "/.profile", H + "/.bash_profile", H + "/.claude", H + "/.claude/settings.json",
         H + "/.claude/settings.local.json", H + "/.claude/CLAUDE.md", H + "/project/.mcp.json"]
decoys = sys.argv[1:]
trees = [H + "/.claude/hooks", H + "/.claude/skills", H + "/.claude/commands", H + "/.claude/agents",
         H + "/.claude/plugins", H + "/project/.claude", H + "/Library/LaunchAgents", "/etc/cron.d"]
out, errors = {}, []

def large(st):
    # The agent can reset mtime but not ctime or the inode number.
    return "large:%d:%d:%d" % (st.st_ino, st.st_size, st.st_ctime_ns)

def add(p):
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return False
    except OSError:
        out[p] = "unreadable"
        return False
    if stat.S_ISLNK(st.st_mode):
        out[p] = "link:" + os.readlink(p)
    elif stat.S_ISDIR(st.st_mode):
        # The inode shows a dir replaced by an identical copy (e.g. the skill swapped back and forth).
        out[p] = "dir:%d" % st.st_ino
        return True
    elif not stat.S_ISREG(st.st_mode):
        out[p] = "special:%o" % stat.S_IFMT(st.st_mode)
    elif st.st_size > CAP:
        out[p] = large(st)
    else:
        try:
            fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            out[p] = "unreadable"
            return False
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode):
                out[p] = "special:%o" % stat.S_IFMT(fst.st_mode)
            elif fst.st_size > CAP:
                out[p] = large(fst)
            else:
                h, left = hashlib.sha256(), CAP + 1
                while left > 0 and (chunk := os.read(fd, min(65536, left))):
                    h.update(chunk)
                    left -= len(chunk)
                out[p] = h.hexdigest() if left > 0 else large(os.fstat(fd))
        finally:
            os.close(fd)
    return False

for p in files:
    add(p)
for p in decoys:
    # lstat only: opening a decoy as root would show up in the file log as a read.
    try:
        st = os.lstat(p)
        out[p] = "stat:%o:%d:%d:%d" % (stat.S_IFMT(st.st_mode), st.st_ino, st.st_size, st.st_ctime_ns)
    except FileNotFoundError:
        pass
    except OSError:
        out[p] = "unreadable"
stack = list(trees)
while stack:
    if len(out) >= MAX_ENTRIES or time.monotonic() > deadline:
        errors.append("The persistence snapshot stopped early after %d entries; some changes may be missed." % len(out))
        break
    p = stack.pop()
    if add(p):
        try:
            with os.scandir(p) as it:
                stack.extend(e.path for e in it)
        except OSError:
            out[p] = "unreadable"
print(json.dumps({"entries": out, "errors": errors}))
"""


# Run as root: hash the MCP server entries in ~/.claude.json (Claude Code starts these servers), and the
# per-project approvals of ~/project/.mcp.json servers. The file is agent-owned: no symlinks, regular files
# only, size-capped. Empty entries and false flags count as none (Claude Code writes those defaults).
_MCP_CODE = r"""
import hashlib, json, os, stat
P = "/home/agent/.claude.json"
CAP = 8 * 1024 * 1024
try:
    fd = os.open(P, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
except FileNotFoundError:
    print(json.dumps({"hash": "missing"})); raise SystemExit
except OSError as e:
    print(json.dumps({"error": "cannot open: %s" % type(e).__name__})); raise SystemExit
try:
    st = os.fstat(fd)
    data = os.read(fd, CAP + 1) if stat.S_ISREG(st.st_mode) else None
finally:
    os.close(fd)
if data is None or len(data) > CAP:
    print(json.dumps({"error": "not a regular file, or larger than 8 MiB"})); raise SystemExit
try:
    doc = json.loads(data)
except ValueError:
    print(json.dumps({"error": "not valid JSON"})); raise SystemExit
if not isinstance(doc, dict):
    print(json.dumps({"error": "not a JSON object"})); raise SystemExit
KEYS = ("mcpServers", "enabledMcpjsonServers", "enableAllProjectMcpServers")
def pick(d):
    return {k: d[k] for k in KEYS if d.get(k)}
found = {}
if pick(doc):
    found["top"] = pick(doc)
projects = doc.get("projects")
if isinstance(projects, dict):
    for k, v in projects.items():
        if isinstance(v, dict) and pick(v):
            found["projects/" + k] = pick(v)
print(json.dumps({"hash": hashlib.sha256(json.dumps(found, sort_keys=True).encode()).hexdigest()}))
"""
MCP_PATH = AGENT_HOME + "/.claude.json#mcpServers"


class SandboxError(RuntimeError):
    def __init__(self, message: str, code: str):
        super().__init__(message)
        self.code = code


@dataclass
class TaskRun:
    prompt: str
    transcript: list[dict]
    proxy_log: list[dict]
    file_log: list[dict]
    exit_code: int
    timed_out: bool
    # Plain-English notes on monitoring that failed during the task; empty means every monitor reported.
    monitor_errors: list[str] = field(default_factory=list)
    # The proxy's count for this task: spent_usd, reserved_usd, requests, denied_budget, denied_model; None if unknown.
    spend: dict | None = None
    # True when the proxy refused API calls because the task reached its spend cap or call limit. Not a
    # monitoring failure: rules.py reports it as skill_spend_cap_reached.
    budget_exhausted: bool = False
    # Notes that cost no evidence (Claude Code's own ~/.claude.json housekeeping); kept for debugging, not shown.
    debug_notes: list[str] = field(default_factory=list)


def _docker(*args: str, check: bool = True, timeout: float | None = 120,
            input: str | None = None, text: bool = True) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(["docker", *args], capture_output=True, text=text, timeout=timeout, input=input)
    except subprocess.TimeoutExpired:
        raise SandboxError(f"docker {args[0]} timed out after {timeout} seconds.", code="run") from None
    if check and r.returncode != 0:
        detail = (r.stderr or r.stdout or "").strip().splitlines()[-1:] or ["no output"]
        raise SandboxError(f"docker {args[0]} failed: {detail[0]}", code="run")
    return r


def check_docker() -> None:
    if shutil.which("docker") is None:
        raise SandboxError(
            "Docker is not installed. Install it from https://docs.docker.com/get-docker/ and try again.",
            code="docker_missing",
        )
    down = SandboxError(
        "Docker is installed but not running. Start Docker (Docker Desktop, or "
        "`sudo systemctl start docker`) and try again.",
        code="docker_down",
    )
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        raise down from None
    if r.returncode != 0:
        raise down


def image_tag(kind: str, docker_dir: Path = DOCKER_DIR) -> str:
    h = hashlib.sha256()
    for name in _BUILD_FILES[kind]:
        h.update(name.encode() + b"\0" + (docker_dir / name).read_bytes() + b"\0")
    return f"argus-skillscan-{kind}:{h.hexdigest()[:12]}"


def _host_pins(hosts: tuple[str, ...]) -> list[str] | None:
    """--add-host args for hosts, looked up with this machine's resolver; None if any lookup fails."""
    args = []
    for host in hosts:
        try:
            addr = socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        except (OSError, IndexError):
            return None
        args += ["--add-host", f"{host}:{addr}"]
    return args


def _image_exists(tag: str) -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", tag], capture_output=True, text=True,
                           timeout=_INSPECT_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise SandboxError(f"docker image inspect timed out after {_INSPECT_TIMEOUT_S} seconds; check that Docker "
                           f"is responding.", code="build") from None
    return r.returncode == 0


def ensure_images(echo: Callable[[str], None]) -> tuple[str, str]:
    tags = {kind: image_tag(kind) for kind in _BUILD_FILES}
    missing = [k for k, t in tags.items() if not _image_exists(t)]
    if missing:
        echo("Building the scan-skill sandbox images. This takes a minute or two and needs network access.")
    # Opt-in for hosts whose Docker daemon DNS is broken: build with the host's network and resolver.
    network = ["--network", "host"] if os.environ.get(BUILD_NETWORK_ENV, "").strip() == "host" else []

    def build(extra: list[str]) -> tuple[int, str]:
        try:
            r = subprocess.run(
                ["docker", "build", *network, *extra, "-f", str(DOCKER_DIR / f"{kind}.Dockerfile"), "-t",
                 tags[kind], str(DOCKER_DIR)],
                capture_output=True, text=True, timeout=_BUILD_TIMEOUT_S,
            )
        except subprocess.TimeoutExpired:
            raise SandboxError(f"Building the {kind} sandbox image took longer than {_BUILD_TIMEOUT_S} seconds. "
                               f"Check this machine's network access and try again.", code="build") from None
        return r.returncode, (r.stderr or "") + (r.stdout or "")

    for kind in missing:
        rc, output = build([])
        resolve_failed = rc != 0 and any(e in output for e in _RESOLVE_ERRORS)
        retried = False
        # Docker's own DNS failed: retry once with the build's hosts looked up by this machine.
        if resolve_failed and _BUILD_HOSTS[kind] and (pins := _host_pins(_BUILD_HOSTS[kind])) is not None:
            rc, output = build(pins)
            retried = True
            resolve_failed = rc != 0 and any(e in output for e in _RESOLVE_ERRORS)
        if resolve_failed:
            even = ", even with addresses looked up on this machine" if retried else ""
            raise SandboxError(
                f"Building the {kind} sandbox image failed because Docker could not look up host names{even}. "
                f'Set "dns" in /etc/docker/daemon.json to a DNS server that works on this network and restart '
                f"Docker. If daemon.json sets no \"dns\", setting {BUILD_NETWORK_ENV}=host to build on this "
                f"machine's network may also work.", code="build")
        if rc != 0:
            tail = " ".join(output.strip().splitlines()[-3:])
            raise SandboxError(f"Building the {kind} sandbox image failed: {tail}", code="build")
    return tags["agent"], tags["proxy"]


def make_dummy_key() -> str:
    # Shaped like a real key and fresh per run, so a skill cannot spot the sandbox by its value.
    alphabet = string.ascii_letters + string.digits + "-_"
    return "sk-ant-api03-" + "".join(secrets.choice(alphabet) for _ in range(93)) + "AA"


def _agent_env(decoys: list[Decoy], dummy_key: str) -> dict[str, str]:
    proxy = f"http://{PROXY_ALIAS}:8080"
    env = {
        "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy,
        "NODE_EXTRA_CA_CERTS": _AGENT_CA,
        "SSL_CERT_FILE": _SYSTEM_BUNDLE,
        "REQUESTS_CA_BUNDLE": _SYSTEM_BUNDLE,
        "ANTHROPIC_API_KEY": dummy_key,
        # Claude Code's own telemetry would otherwise show up as non-Anthropic egress.
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "DISABLE_AUTOUPDATER": "1",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    }
    for d in decoys:
        if d.kind == "env":
            env[d.path] = render_decoy_file(d)
    return env


def _root_exec(container: str, *cmd: str, timeout: float = 120, text: bool = True) -> subprocess.CompletedProcess:
    # Root commands run from / with absolute binaries, so nothing the agent writes is on their path.
    return _docker("exec", "-w", "/", container, *cmd, check=False, timeout=timeout, text=text)


def _wait_until(container: str, cmd: list[str], what: str, timeout_s: float = 60, fix: str = "",
                attempt_s: float = 15) -> None:
    deadline = time.monotonic() + timeout_s
    while (left := deadline - time.monotonic()) > 0:
        try:
            if _root_exec(container, *cmd, timeout=max(0.5, min(attempt_s, left))).returncode == 0:
                return
        except SandboxError:
            pass
        time.sleep(0.25)
    if fix:
        raise SandboxError(fix, code="run")
    logs = _docker("logs", "--tail", "5", container, check=False)
    tail = " ".join((logs.stdout + logs.stderr).strip().splitlines()[-3:])
    raise SandboxError(f"The sandbox {what} did not start in time. {tail}".strip(), code="run")


def _running(container: str, timeout: float) -> bool | None:
    try:
        r = _docker("inspect", "-f", "{{.State.Running}}", container, check=False, timeout=max(0.5, timeout))
    except SandboxError:
        return None
    return r.stdout.strip() == "true" if r.returncode == 0 else False


def _read_chunk(container: str, path: str, pos: int, deadline: float, tmp: str, local: str | None,
                what: str, errors: list[str]) -> tuple[bytes | None, str | None, bool]:
    """Up to _READ_CAP bytes of the log from pos, the local copy if one was made, and whether time ran out.

    Falls back to docker cp, which works on a stopped container, but not when a running one was only slow.
    """
    if local is None:
        try:
            r = _root_exec(container, "/usr/bin/dd", f"if={path}", "bs=1M", "iflag=skip_bytes,count_bytes",
                           f"skip={pos}", f"count={_READ_CAP}", "status=none",
                           timeout=max(1.0, min(120, deadline - time.monotonic())), text=False)
        except SandboxError:  # only a timeout: _root_exec does not check the exit code
            r = None
        if r is not None and r.returncode == 0:
            return r.stdout, None, False
        if r is None and _running(container, min(10, deadline - time.monotonic())) is not False:
            return None, None, True
        if (left := deadline - time.monotonic()) <= 0:
            return None, None, True
        try:
            _docker("cp", f"{container}:{path}", f"{tmp}/log", timeout=max(1.0, min(120, left)))
        except SandboxError:
            errors.append(f"Could not read the {what}.")
            return None, None, False
        errors.append(f"Could not read the {what} from the running sandbox (its container may have crashed); "
                      f"it was recovered with docker cp.")
        local = f"{tmp}/log"
    try:
        with open(local, "rb") as f:
            f.seek(pos)
            return f.read(_READ_CAP), local, False
    except OSError:
        errors.append(f"Could not read the {what}.")
        return None, None, False


def _read_jsonl(container: str, path: str, start: float, end: float, what: str, errors: list[str],
                offset: int = 0, resync: bool = False, later: list[dict] | None = None) -> tuple[list[dict], int, bool]:
    """Rows in [start, end] after offset, the offset to resume from, and whether the read reached the end.

    Rows stamped after end are added to later (they are past the offset, so the next read will not see them).

    With resync, offset may fall inside a line, so the bytes up to the first newline are skipped.
    """
    deadline = time.monotonic() + _READ_DEADLINE_S
    out, bad, carry, pos, done = [], 0, b"", offset, True
    with tempfile.TemporaryDirectory(prefix="skillscan-log-") as tmp:
        local = None
        while True:
            out_of_time = deadline - time.monotonic() <= 0
            if not out_of_time:
                chunk, local, out_of_time = _read_chunk(container, path, pos, deadline, tmp, local, what, errors)
            if out_of_time:
                errors.append(f"Reading the {what} took longer than {_READ_DEADLINE_S} seconds, so the rest of "
                              f"this task's rows were not read.")
                done = False
                break
            if chunk is None:
                break
            pos += len(chunk)
            data = carry + chunk
            if resync:
                nl = data.find(b"\n")
                resync = nl < 0
                data = b"" if resync else data[nl + 1:]
            # Hold back a partial last line for the next read, unless it alone is longer than a chunk.
            used = data.rfind(b"\n") + 1
            carry = data[used:]
            if len(carry) >= _READ_CAP:
                bad, carry = bad + 1, b""
            for line in data[:used].splitlines():
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    bad += 1
                    continue
                ts = rec.get("ts") if isinstance(rec, dict) else None
                if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts) or ts <= 0:
                    bad += 1
                elif start <= ts <= end:
                    out.append(rec)
                elif ts > end and later is not None:
                    later.append(rec)
            if len(chunk) < _READ_CAP:
                break
    if bad:
        errors.append(f"{bad} line(s) in the {what} could not be parsed or had no usable timestamp; "
                      f"they may belong to this task.")
    return out, pos - len(carry), done


def _collapse_duplicates(rows: list[dict]) -> list[dict]:
    """Keep the earliest of rows with the same path and event within _DUP_WINDOW_S (a file watch and a dir watch)."""
    kept, last = [], {}
    for r in sorted(rows, key=lambda r: r.get("ts", 0)):
        key = (r.get("path"), r.get("event"))
        if key in last and r.get("ts", 0) - last[key] <= _DUP_WINDOW_S:
            continue
        last[key] = r.get("ts", 0)
        kept.append(r)
    return kept


def _parse_stream(stdout: str) -> list[dict]:
    events = []
    for line in stdout.splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict):
            events.append(ev)
    return events


def merge_proxy_rows(rows: list[dict]) -> list[dict]:
    """One row per request: a refused request's arrival row, overlaid in place by its scan row (same rid)."""
    out, at = [], {}
    for r in rows:
        rid = r.get("rid")
        if isinstance(rid, str) and rid in at:
            out[at[rid]] = {**out[at[rid]], **r}
            continue
        if isinstance(rid, str):
            at[rid] = len(out)
        out.append(r)
    return out


def snapshot_diff(before: dict[str, str], after: dict[str, str], ts: float) -> list[dict]:
    rows = []
    for path in sorted(set(before) | set(after)):
        if path not in before:
            rows.append({"ts": ts, "path": path, "event": "CREATE"})
        elif before[path] != after.get(path):
            rows.append({"ts": ts, "path": path, "event": "MODIFY"})
    return rows


class Sandbox:
    def __init__(self, suffix: str, agent_name: str, proxy_name: str, real_key: str,
                 decoy_files: tuple[str, ...] = ()):
        self.suffix = suffix
        self.agent_name = agent_name
        self.proxy_name = proxy_name
        self._real_key = real_key
        self._decoy_files = decoy_files
        # Each log is read from where the previous task stopped, not from the start.
        self._offsets = {_PROXY_LOG: 0, _FILE_LOG: 0}
        # Logs whose last read ran out of time; the next task skips to its own rows.
        self._behind: set[str] = set()
        # Last good hash of the MCP servers in ~/.claude.json; read only outside task windows (it is a decoy).
        self._mcp: str | None = None
        self._control_seq = 0
        # Limits the next control message sends with a new task: models, cap_usd, max_requests.
        self._limits: dict = {}
        # Lines in the monitors' stderr that said inotify ran out of watches, already reported.
        self._limit_hits = 0
        # Each task also gets the rows stamped after the previous task's end, so none fall between windows:
        # rows already read past that end, and the MCP check's span to leave out (its own read).
        self._last_end: float | None = None
        self._later: dict[str, list[dict]] = {_PROXY_LOG: [], _FILE_LOG: []}
        self._own_read: tuple[float, float] | None = None

    def _mcp_hash(self) -> tuple[str | None, str | None]:
        """(hash, None), or (None, why it could not be read)."""
        try:
            r = _root_exec(self.agent_name, "/usr/bin/python3", "-I", "-c", _MCP_CODE, timeout=30)
            out = json.loads(r.stdout) if r.returncode == 0 else {"error": "check failed"}
        except (SandboxError, ValueError):
            out = {"error": "check failed"}
        if not isinstance(out, dict) or not isinstance(out.get("hash"), str):
            return None, str(out.get("error") if isinstance(out, dict) else "check failed")
        return out["hash"], None

    def _check_mcp(self, ts: float, file_log: list[dict], errors: list[str]) -> None:
        t0 = time.time()
        h, why = self._mcp_hash()
        # Wait only when the check opened the file; a missing file or a refused open leaves no row to wait for.
        if (h is not None and h != "missing") or (why is not None and not why.startswith(("cannot open", "check"))):
            self._await_own_read(t0)
            self._own_read = (t0, time.time())
        if h is None:
            errors.append(f"Could not read the MCP servers in ~/.claude.json ({why}); a change to them would be "
                          f"missed.")
            return
        if self._mcp is not None and h != self._mcp:
            file_log.append({"ts": ts, "path": MCP_PATH, "event": "MODIFY"})
        self._mcp = h

    def _await_own_read(self, t0: float) -> None:
        """Wait until the file monitor has stamped the MCP check's read, so it can never fall in a task window."""
        deadline = time.monotonic() + _OWN_READ_WAIT_S
        while time.monotonic() < deadline:
            try:
                tail = _root_exec(self.agent_name, "/usr/bin/tail", "-c", "65536", _FILE_LOG, timeout=5).stdout
            except SandboxError:
                tail = ""
            for line in reversed(tail.splitlines()):
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("path") == f"{AGENT_HOME}/.claude.json" and \
                        rec.get("event") == "OPEN" and isinstance(rec.get("ts"), (int, float)) and rec["ts"] >= t0:
                    time.sleep(_OWN_READ_GUARD_S)
                    return
            time.sleep(0.05)

    def _proxy_control(self, task: str, drain: bool, timeout_s: float) -> dict | None:
        """Tell the proxy the current task and its limits (and, with drain, to finish its queued scans).

        Returns the proxy's ack, with its spend counts for the task, or None if it did not ack in time."""
        self._control_seq += 1
        seq = self._control_seq
        msg = json.dumps({"task": task, "seq": seq, "drain": drain, **self._limits})
        try:
            r = _docker("exec", "-i", "-u", "root", "-w", "/", self.proxy_name, "/bin/sh", "-c",
                        f"cat > {_PROXY_CONTROL}.tmp && mv -f {_PROXY_CONTROL}.tmp {_PROXY_CONTROL}",
                        input=msg, check=False, timeout=10)
        except SandboxError:
            return None
        if r.returncode != 0:
            return None
        deadline = time.monotonic() + timeout_s
        while (left := deadline - time.monotonic()) > 0:
            try:
                out = _root_exec(self.proxy_name, "/bin/cat", _PROXY_ACK, timeout=max(0.5, min(5, left))).stdout
                ack = json.loads(out) if out.strip() else None
            except (SandboxError, ValueError):
                ack = None
            if isinstance(ack, dict) and ack.get("task") == task and ack.get("seq") == seq:
                return ack
            time.sleep(0.05)
        return None

    def _watch_limit_hit(self) -> bool:
        """True when the monitors' stderr has new lines saying inotify ran out of watches or instances."""
        args = [a for pat in _LIMIT_PATTERNS for a in ("-e", pat)]
        try:
            r = _root_exec(self.agent_name, "/usr/bin/grep", "-c", "-s", "-F", *args,
                           *(f"/var/log/fsmon/{n}.err" for n in _MONITOR_NAMES), timeout=30)
        except SandboxError:
            return False
        hits = sum(int(line.rsplit(":", 1)[-1]) for line in r.stdout.splitlines()
                   if line.rsplit(":", 1)[-1].strip().isdigit())
        new, self._limit_hits = hits > self._limit_hits, max(hits, self._limit_hits)
        return new

    def _skip_to_end(self, container: str, path: str, what: str, errors: list[str]) -> bool:
        """Move a log that fell behind to its current size; True when the next read must resync to a line."""
        if path not in self._behind:
            return False
        try:
            r = _root_exec(container, "/usr/bin/stat", "-c", "%s", path, timeout=30)
            size = int(r.stdout.strip()) if r.returncode == 0 else None
        except (SandboxError, ValueError):
            size = None
        if size is None:
            errors.append(f"Could not find where this task starts in the {what}; older rows are read first.")
            return False
        self._behind.discard(path)
        if self._offsets[path] >= size - 1:
            return False
        self._offsets[path] = size - 1
        return True

    def _snapshot(self) -> tuple[dict[str, str], list[str]]:
        # -I: isolated mode, so a module the agent drops anywhere cannot be imported by this root process.
        r = _root_exec(self.agent_name, "/usr/bin/python3", "-I", "-c", _SNAPSHOT_CODE, *self._decoy_files,
                       timeout=60)
        try:
            snap = json.loads(r.stdout) if r.returncode == 0 else None
        except json.JSONDecodeError:
            snap = None
        if not isinstance(snap, dict) or not isinstance(snap.get("entries"), dict):
            raise SandboxError("The persistence snapshot failed.", code="run")
        return snap["entries"], list(snap.get("errors") or [])

    def _monitors_alive(self) -> str | None:
        try:
            # Root-owned only: the agent can name its own processes anything.
            pgrep = ("/usr/bin/pgrep", "-c", "-U", "0")
            watchers = _root_exec(self.agent_name, *pgrep, "-x", "inotifywait").stdout.strip()
            # Re-watches of replaced decoys read their path from stdin; each one's death is its own WATCH_LOST row.
            rewatches = _root_exec(self.agent_name, *pgrep, "-f", "--", "--fromfile -$").stdout.strip()
            filters = _root_exec(self.agent_name, *pgrep, "-f", _STAMP).stdout.strip()
        except SandboxError:
            return "Could not check that the file monitor was running; it timed out."
        base = int(watchers) - int(rewatches) if watchers.isdigit() and rewatches.isdigit() else None
        if base != _MONITORS or filters != str(_MONITORS):
            return (f"The file monitor was not fully running at the end of this task "
                    f"({base if base is not None else '?'} of {_MONITORS} watchers, "
                    f"{filters or 0} of {_MONITORS} filters).")
        return None

    def run_task(self, prompt: str, *, model: str, budget_usd: float, timeout_s: int = 300) -> TaskRun:
        errors: list[str] = []
        before = None
        try:
            before, snap_errors = self._snapshot()
            errors += snap_errors
        except SandboxError:
            errors.append("The persistence snapshot before this task failed, so changes to persistence "
                          "files are known only from the live file monitor.")
        resync = {path: self._skip_to_end(c, path, what, errors)
                  for c, path, what in ((self.proxy_name, _PROXY_LOG, "network log"),
                                        (self.agent_name, _FILE_LOG, "file access log"))}
        task_id = secrets.token_hex(8)
        # A new task id resets the proxy's scan-time budget and spend, so each task gets its own.
        self._limits = {"models": sorted({model, *BACKGROUND_MODELS}), "cap_usd": budget_usd,
                        "max_requests": MAX_REQUESTS}
        if self._proxy_control(task_id, False, _SWITCH_TIMEOUT_S) is None:
            errors.append("The network monitor did not confirm the start of this task, so its time limit for "
                          "checking request bodies may not have been reset and it may refuse Claude Code's own "
                          "API calls; more requests than usual may have scan_complete false.")
        start = time.time()
        # `timeout` runs inside the container; killing the host-side `docker exec` would not stop claude.
        cmd = ["docker", "exec", "-u", "agent", "-w", f"{AGENT_HOME}/project", "-e", f"HOME={AGENT_HOME}",
               "-e", f"ANTHROPIC_SMALL_FAST_MODEL={BACKGROUND_MODELS[0]}",
               "-e", f"ANTHROPIC_DEFAULT_HAIKU_MODEL={BACKGROUND_MODELS[0]}",
               "-e", f"CLAUDE_CODE_MAX_OUTPUT_TOKENS={CLAUDE_CODE_MAX_OUTPUT_TOKENS}",
               self.agent_name, "timeout", "-k", "10", str(timeout_s),
               "claude", "-p", "--dangerously-skip-permissions",
               "--output-format", "stream-json", "--verbose",
               "--disallowedTools", "WebSearch",
               "--model", model, "--max-budget-usd", str(budget_usd),
               "--", prompt]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL,
                               timeout=timeout_s + 60)
            stdout, exit_code = r.stdout, r.returncode
            timed_out = exit_code == 124 or (exit_code == 137 and time.time() - start >= timeout_s)
        except subprocess.TimeoutExpired as e:
            try:
                _root_exec(self.agent_name, "/usr/bin/pkill", "-KILL", "-u", "agent", "-x", "claude")
            except SandboxError:
                errors.append("Could not stop Claude Code after the task timed out.")
            out = e.stdout or ""
            stdout = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
            exit_code, timed_out = 124, True
        time.sleep(0.5)  # let the file monitor flush the last events
        # Refused requests are logged on arrival and again once their body is checked; wait for the checks.
        ack = self._proxy_control(task_id, True, _DRAIN_TIMEOUT_S)
        if ack is None:
            errors.append(f"The network monitor was still checking refused requests {_DRAIN_TIMEOUT_S} seconds "
                          f"after the task ended; those requests are listed, but with scan_complete false and "
                          f"possibly without the decoy markers they carried.")
        spend = {k: ack[k] for k in ("spent_usd", "reserved_usd", "requests", "denied_budget", "denied_model")
                 if isinstance(ack.get(k), (int, float)) and not isinstance(ack.get(k), bool)} if ack else {}
        end = time.time()
        logs = {}
        for c, path, what in ((self.proxy_name, _PROXY_LOG, "network log"),
                              (self.agent_name, _FILE_LOG, "file access log")):
            # From just after the previous task's end, unless this read skipped ahead to this task.
            lo = start if self._last_end is None or resync[path] else math.nextafter(self._last_end, math.inf)
            later: list[dict] = []
            read, self._offsets[path], done = _read_jsonl(
                c, path, lo, end, what, errors, self._offsets[path], resync[path], later)
            carried = self._later[path]
            logs[path] = [r for r in carried if lo <= r["ts"] <= end] + read
            self._later[path] = [r for r in carried if r["ts"] > end] + later
            if not done:
                self._behind.add(path)
        self._last_end = end
        own = self._own_read
        proxy_log = merge_proxy_rows(logs[_PROXY_LOG])
        # The cap holds only while every call settles within its reservation; a broken bound must not be silent.
        over = [r for r in proxy_log if r.get("error") == _SETTLED_ABOVE]
        if over:
            errors.append(f"Spend accounting bound broken: {len(over)} API call(s) cost more than the proxy "
                          f"reserved for them (first: {over[0].get('model')}, reserved "
                          f"${over[0].get('reserve_usd')}, charged ${over[0].get('cost_usd')}), so this task "
                          f"may have spent more than its cap.")
        rows = [r for r in logs[_FILE_LOG] if not (own and own[0] <= r["ts"] <= own[1] and r.get("path") == _CLAUDE_JSON
                                                    and r.get("event") in ("OPEN", "ACCESS"))]
        if any(r.get("event") == "Q_OVERFLOW" for r in rows):
            errors.append("The file monitor's event queue overflowed during this task; some file events were lost.")
        debug: list[str] = []
        for lost in sorted({r.get("path") for r in rows if r.get("event") == "WATCH_LOST"}):
            note = f"The file monitor's watch on {lost}, started after it was replaced, could not start or stopped; "
            (debug if lost == _CLAUDE_JSON else errors).append(
                note + (f"{NO_EVIDENCE_LOST}." if lost == _CLAUDE_JSON else "later reads of it may be missed."))
        if any(r.get("event") == "WATCH_LIMIT" for r in rows) or self._watch_limit_hit():
            errors.append("The file monitor ran out of inotify watches or instances (fs.inotify.max_user_watches "
                          "or max_user_instances on the Docker host); file events after that may be missed.")
        for gap in sorted({r.get("path") for r in rows if r.get("event") == "WATCH_GAP"}):
            note = f"{gap} was replaced, and the file monitor started watching the new copy only after it existed; "
            (debug if gap == _CLAUDE_JSON else errors).append(
                note + (f"{NO_EVIDENCE_LOST}." if gap == _CLAUDE_JSON else "a read in that moment would be missed."))
        file_log = _collapse_duplicates([r for r in rows
                                         if r.get("event") not in ("Q_OVERFLOW", "WATCH_LOST", "WATCH_GAP",
                                                                   "WATCH_LIMIT")])
        if (dead := self._monitors_alive()) is not None:
            errors.append(dead)
        try:
            after, snap_errors = self._snapshot()
            errors += snap_errors
            if before is not None:
                file_log += snapshot_diff(before, after, end)
        except SandboxError:
            errors.append("The persistence snapshot after this task failed, so changes to persistence "
                          "files are known only from the live file monitor.")
        if self._mcp is None:
            errors.append("The MCP servers in ~/.claude.json had no baseline before this task, so a change to "
                          "them would be missed.")
        self._check_mcp(end, file_log, errors)
        run = {"transcript": _parse_stream(stdout), "proxy_log": proxy_log, "file_log": file_log,
               "monitor_errors": errors, "debug_notes": debug}
        # The agent never holds the real key; this guards against an upstream echo of it.
        if self._real_key:
            run = json.loads(json.dumps(run).replace(self._real_key, "[REDACTED]"))
        return TaskRun(prompt=prompt, exit_code=exit_code, timed_out=timed_out, spend=spend or None,
                       budget_exhausted=bool(spend.get("denied_budget")), **run)


def _sweep_orphans() -> None:
    now = time.time()
    for kind, rm in ((["ps", "-a"], ["rm", "-f"]), (["network", "ls"], ["network", "rm"])):
        try:
            r = _docker(*kind, "--filter", f"label={LABEL}",
                        "--format", '{{.ID}} {{.Label "sk.created"}}', check=False, timeout=30)
        except SandboxError:
            continue
        old = [line.split()[0] for line in r.stdout.splitlines()
               if len(line.split()) == 2 and line.split()[1].isdigit()
               and now - int(line.split()[1]) > _ORPHAN_AGE_S]
        if old:
            try:
                _docker(*rm, *old, check=False, timeout=60)
            except SandboxError:
                pass


def _check_docker_version() -> None:
    """Refuse a Docker Engine too old to give the internal network no host-side gateway address."""
    r = _docker("version", "--format", "{{.Server.Version}}", check=False, timeout=30)
    m = re.match(r"\s*(\d+)\.", r.stdout or "") if r.returncode == 0 else None
    if m is None:
        detail = " ".join((r.stderr or r.stdout or "").split())[:200] or "no output"
        raise SandboxError(
            f"Could not read the Docker Engine version (docker version said: {detail}). scan-skill needs Docker "
            f"Engine {_MIN_DOCKER} or newer to keep the sandbox away from services on this machine. Check that "
            f"Docker is running and try again.", code="docker_version")
    if int(m.group(1)) < _MIN_DOCKER:
        raise SandboxError(
            f"scan-skill needs Docker Engine {_MIN_DOCKER} or newer (found {r.stdout.strip()}). Older versions "
            f"cannot keep the sandbox from connecting to services on this machine through its network gateway. "
            f"Upgrade Docker and try again.", code="docker_old")


def _cleanup(*steps: Callable[[], object]) -> None:
    # Each step runs even if an earlier one fails or hangs.
    for step in steps:
        try:
            step()
        except Exception:  # noqa: BLE001 - teardown must not mask the original error
            pass


@contextmanager
def sandbox(skill_dir: Path, skill_name: str, decoys: list[Decoy], api_key: str) -> Iterator[Sandbox]:
    if not _SKILL_NAME_RE.match(skill_name):
        raise ValueError(f"invalid skill name: {skill_name!r}")
    _sweep_orphans()
    suffix = secrets.token_hex(4)
    # Neutral names: the agent can see them through reverse DNS on the internal network.
    net_int, net_ext = f"net-{suffix}", f"out-{suffix}"
    proxy_name, agent_name = f"gw-{suffix}", f"ws-{suffix}"
    labels = ["--label", f"{LABEL}={suffix}", "--label", f"sk.created={int(time.time())}"]
    dummy_key = make_dummy_key()
    while dummy_key == api_key:
        dummy_key = make_dummy_key()
    tmp = Path(tempfile.mkdtemp(prefix="skillscan-"))
    try:
        _check_docker_version()
        _docker("network", "create", *_INTERNAL_NET_OPTS, *labels, net_int)
        _docker("network", "create", *labels, net_ext)
        dns = [a for s in os.environ.get(DNS_ENV, "").split(",") if s.strip() for a in ("--dns", s.strip())]
        _docker("run", "-d", "--name", proxy_name, *labels, "--network", net_int,
                "--network-alias", PROXY_ALIAS, "--memory", "512m", "--pids-limit", "256",
                *dns, image_tag("proxy"))
        _docker("network", "connect", net_ext, proxy_name)
        # The key, then the decoy markers, go over stdin into a FIFO: never in the container config or on disk.
        _wait_until(proxy_name, ["/usr/bin/test", "-p", _KEY_FIFO], "proxy")
        _docker("exec", "-i", "-w", "/", proxy_name, "/bin/sh", "-c", f"cat > {_KEY_FIFO}",
                input=api_key + "\n" + " ".join(d.marker for d in decoys) + "\n", timeout=30)
        _wait_until(proxy_name, ["/usr/local/bin/python3", "-I", "-c",
                                 "import socket; socket.create_connection(('127.0.0.1', 8080), 1)"], "proxy")
        _wait_until(proxy_name, ["/usr/local/bin/python3", "-I", "-c",
                                 "import socket; socket.getaddrinfo('api.anthropic.com', 443)"],
                    "proxy", timeout_s=10, attempt_s=3,
                    fix=f"The sandbox proxy cannot resolve api.anthropic.com. Set {DNS_ENV} to a DNS server "
                        f"that works on this network (for example {DNS_ENV}=1.1.1.1) and try again.")
        _docker("cp", f"{proxy_name}:{_PROXY_CA}", str(tmp / "ca.crt"))

        staged = tmp / "decoys"
        for d in decoys:
            if d.kind == "env":
                continue
            p = staged / d.path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(render_decoy_file(d))
            p.chmod(0o600)

        env_args = [a for k, v in _agent_env(decoys, dummy_key).items() for a in ("-e", f"{k}={v}")]
        # --dns 127.0.0.1 leaves the embedded DNS able to find the proxy but unable to forward lookups out.
        _docker("create", "--name", agent_name, "--hostname", "devbox", *labels, "--init",
                "--network", net_int, "--dns", "127.0.0.1",
                "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER",
                "--security-opt", "no-new-privileges", "--pids-limit", "512", "--memory", "2g",
                *env_args, image_tag("agent"))
        _docker("cp", str(tmp / "ca.crt"), f"{agent_name}:{_AGENT_CA}")
        if staged.exists():
            _docker("cp", f"{staged}/.", f"{agent_name}:/opt/stage/decoys")
        _docker("cp", f"{Path(skill_dir)}/.", f"{agent_name}:{AGENT_HOME}/.claude/skills/{skill_name}")
        _docker("start", agent_name)
        _wait_until(agent_name, ["/usr/bin/test", "-f", _READY], "agent")
        decoy_files = tuple(f"{AGENT_HOME}/{d.path}" for d in decoys if d.kind != "env")
        sb = Sandbox(suffix, agent_name, proxy_name, api_key, decoy_files)
        # Baseline before any task, so this root read of a decoy falls outside every task's window.
        sb._check_mcp(time.time(), [], [])
        yield sb
    except SandboxError as e:
        msg = str(e).replace(api_key, "[REDACTED]") if api_key else str(e)
        raise SandboxError(msg, code=e.code) from None
    finally:
        _cleanup(
            lambda: _docker("rm", "-f", agent_name, proxy_name, check=False, timeout=60),
            lambda: _docker("network", "rm", net_int, net_ext, check=False, timeout=60),
            lambda: shutil.rmtree(tmp, ignore_errors=True),
        )
