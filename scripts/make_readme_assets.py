"""Regenerate the README quickstart assets from a fresh `argus-probe quickstart` run.

    python scripts/make_readme_assets.py

Writes docs/assets/quickstart-demo.svg (terminal animation) and
docs/assets/quickstart-report.png (report screenshot, finding details hidden).

Needs `argus-probe` with the `web` extra (`pip install -e '.[web]'` and
`playwright install chromium`) and svg-term (`npm install -g svg-term-cli`).
The run is offline on 127.0.0.1; API-key variables are removed from its
environment so none can show up in the recording.
"""
from __future__ import annotations

import fcntl
import json
import math
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
COLS = 90
SVG_WIDTH = 800
KEY_VARS = ("ANTHROPIC_API_KEY", "AZURE_API_KEY", "AZURE_OPENAI_API_KEY", "OPENAI_API_KEY")
COMMAND = "argus-probe quickstart"

# Collapse every finding to its one-line heading, as in the README screenshot.
REPORT_CSS = """
.finding { margin: 0; padding: 0.5em 0.8em; border-radius: 0; }
.finding + .finding { border-top: none; }
.finding > :not(h3) { display: none !important; }
.finding h3 { margin: 0; font-size: 15px; font-weight: normal; }
"""


def record(workdir: Path) -> tuple[list[tuple[float, str]], int]:
    """Run the quickstart under a pty; return timed output chunks and the exit code."""
    env = {k: v for k, v in os.environ.items() if k not in KEY_VARS}
    env.update(TERM="xterm-256color", COLUMNS=str(COLS), NO_COLOR="1")
    exe = shutil.which("argus-probe", path=str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", ""))
    if not exe:
        sys.exit("argus-probe not found on PATH")
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, COLS, 0, 0))
    proc = subprocess.Popen([exe, "quickstart"], cwd=workdir, env=env,
                            stdin=slave, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    start, chunks = time.monotonic(), []
    while True:
        ready, _, _ = select.select([master], [], [], 0.1)
        if ready:
            try:
                data = os.read(master, 4096)
            except OSError:
                break
            if not data:
                break
            chunks.append((time.monotonic() - start, data.decode("utf-8", "replace")))
        elif proc.poll() is not None:
            break
    os.close(master)
    return chunks, proc.wait()


def write_cast(chunks: list[tuple[float, str]], path: Path) -> int:
    """Write an asciicast v2 file: banner, typed command, then the real output. Returns rows."""
    events, t = [], 0.0
    events.append((t, "Argus by Veyon Solutions\r\n\r\n$ "))
    t += 0.6
    for ch in COMMAND:
        events.append((t, ch))
        t += 0.06
    events.append((t, "\r\n"))
    t += 0.3
    for at, text in chunks:
        events.append((t + at, text))
    events.append((events[-1][0] + 4.0, ""))  # hold the last frame

    text = "".join(c for _, c in chunks)
    lines = text.replace("\r\n", "\n").rstrip("\n").split("\n")
    rows = 3 + sum(max(1, math.ceil(len(line) / COLS)) for line in lines) + 1
    with path.open("w") as fh:
        fh.write(json.dumps({"version": 2, "width": COLS, "height": rows}) + "\n")
        for at, data in events:
            fh.write(json.dumps([round(at, 3), "o", data]) + "\n")
    return rows


def make_svg(cast: Path, rows: int, out: Path) -> None:
    subprocess.run(["svg-term", "--in", str(cast), "--out", str(out), "--window",
                    "--width", str(COLS), "--height", str(rows)], check=True)
    svg = out.read_text()
    m = re.match(r'<svg [^>]*?width="([\d.]+)" height="([\d.]+)"', svg)
    w, h = float(m.group(1)), float(m.group(2))
    head = (f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
            f'width="{SVG_WIDTH}" height="{round(h * SVG_WIDTH / w, 2)}" viewBox="0 0 {w:g} {h:g}">'
            "<title>Argus by Veyon Solutions quickstart demo</title>"
            f"<desc>A real argus-probe {version('argus-probe')} quickstart run against the bundled "
            "local demo, without an API key.</desc>")
    out.write_text(head + svg[svg.index(">") + 1:])


def make_png(report: Path, out: Path) -> None:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 760})
        page.goto(report.as_uri())
        page.add_style_tag(content=REPORT_CSS)
        bottom = page.evaluate(
            "Math.ceil([...document.querySelectorAll('.finding')].pop().getBoundingClientRect().bottom)")
        page.set_viewport_size({"width": 1280, "height": bottom + 12})
        page.screenshot(path=str(out))
        browser.close()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="argus-demo-") as tmp:
        workdir = Path(tmp)
        chunks, code = record(workdir)
        if code != 0:
            sys.exit("".join(c for _, c in chunks) + f"\nquickstart exited {code}")
        rows = write_cast(chunks, workdir / "quickstart.cast")
        make_svg(workdir / "quickstart.cast", rows, ASSETS / "quickstart-demo.svg")
        make_png(workdir / "argus-quickstart.html", ASSETS / "quickstart-report.png")
    for name in ("quickstart-demo.svg", "quickstart-report.png"):
        print(f"{name}: {(ASSETS / name).stat().st_size} bytes")


if __name__ == "__main__":
    main()
