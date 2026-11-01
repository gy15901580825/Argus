"""Shared base for agents that act inside a simulated environment.

`TestbedAgentTarget` opens a per-probe session on a testbed, renders the
environment's URL placeholder into the prompt, and collects what the agent did
there. Add a new environment by adding an entry to `ENVIRONMENTS`.
"""

from __future__ import annotations

import inspect
import json
import logging
import sys
from dataclasses import dataclass, field, replace
from typing import Any, ClassVar

import httpx

from argus.targets._base import ProbeNotApplicable, Target, Turn

logger = logging.getLogger(__name__)


class TestbedAgentTarget(Target):
    url_key: ClassVar[str]
    staging_noun: ClassVar[str]
    teardown_label: ClassVar[str]
    controlled: ClassVar[bool] = False
    extra_placeholders: ClassVar[tuple[str, ...]] = ()

    def _httpx(self):
        # Tests patch `httpx` on the concrete adapter's module (mcp_agent,
        # payment_agent); look it up there so those patches keep applying.
        return getattr(sys.modules[type(self).__module__], "httpx", httpx)

    def __init__(self, spec: Any) -> None:
        from argus.targets import build_target

        self.spec = spec
        self._inner = build_target(dict(spec.inner))
        self._session: dict | None = None
        self._lease_id: str | None = None
        # The script the *next* session opens with. begin_probe() replaces it
        # per probe; the spec-level script is only the run default.
        self._script: dict[str, Any] = dict(spec.script)

    @property
    def supports_history(self) -> bool:  # type: ignore[override]
        return bool(getattr(self._inner, "supports_history", False))

    async def _control(
        self, method: str, path: str, json: dict | None = None
    ) -> httpx.Response:
        headers = (
            {"Authorization": ("Bearer " + self.spec.control_token).rstrip()}
            if self.controlled
            else {}
        )
        async with self._httpx().AsyncClient(timeout=self.spec.timeout_s) as client:
            kwargs = {"headers": headers} if headers else {}
            if json is not None:
                kwargs["json"] = json
            resp = await getattr(client, method.lower())(
                f"{self.spec.testbed_url.rstrip('/')}{path}", **kwargs
            )
            if getattr(resp, "status_code", None) in (401, 503) and self.controlled:
                raise ValueError(
                    f'{self.teardown_label} refused the control token; for a remote testbed set "control_token": "${{ARGUS_TESTBED_TOKEN}}" (status '
                    + str(resp.status_code)
                    + ")"
                )
            resp.raise_for_status()
            return resp

    @property
    def supports_phases(self) -> bool:
        return self.controlled

    async def _acquire_lease(self) -> None:
        if self._lease_id is not None:
            return
        try:
            self._lease_id = (await self._control("post", "/lease")).json()["lease_id"]
        except httpx.HTTPStatusError as exc:
            detail = exc.response.json().get("detail", {})
            if exc.response.status_code == 409 and detail.get("code") == "lease_held":
                raise ValueError(
                    f"MCP testbed fixed endpoint is in use by another run (lease held, expires in {detail['expires_in']:.1f}s)"
                ) from exc
            raise

    async def _activate(self) -> None:
        for attempt in range(2):
            await self._acquire_lease()
            try:
                activated = (
                    await self._control(
                        "post",
                        f"/lease/{self._lease_id}/activate",
                        json={"session_id": self._session["session_id"]},
                    )
                ).json()
            except httpx.HTTPStatusError as exc:
                detail = exc.response.json().get("detail", {})
                if (
                    exc.response.status_code == 422
                    and detail.get("code") == "dynamic_only"
                ):
                    raise ProbeNotApplicable(
                        f"scenario {self._script.get('world') or self._script['scenario']} only runs in mcp_mode dynamic (it changes the tool list mid-session or serves a second MCP server)"
                    ) from exc
                if (
                    exc.response.status_code == 409
                    and detail.get("code") == "lease_mismatch"
                ):
                    self._lease_id = None
                    if attempt == 0:
                        continue
                    raise ValueError(
                        "MCP testbed refused fixed endpoint lease after reacquisition"
                    ) from exc
                raise
            self._session["mcp_url"] = activated["mcp_url"]
            return

    def _session_settings(self) -> dict:
        settings = dict(self._script)
        for name, key in (
            ("agent_credentials", "principals"),
            ("capabilities", "capabilities"),
        ):
            value = getattr(self.spec, name, None)
            if value:
                settings[key] = list(value) if name == "capabilities" else dict(value)
        return settings

    async def _deliver_session_ingress(self) -> None:
        ingress = self._session.get("ingress")
        if ingress:
            from argus.targets.a2a_agent import deliver_ingress

            async def log(row):
                await self._control(
                    "post",
                    f"/sessions/{self._session['session_id']}/ingress-log",
                    json=row,
                )

            await deliver_ingress(self.spec, ingress["deliveries"], log)

    async def _open_session(self) -> dict:
        if self._session is None:
            self._session = (
                await self._control("post", "/sessions", json=self._session_settings())
            ).json()
        return self._session

    async def _close_session(self) -> None:
        """Discard the current session at the testbed.

        A teardown that fails is a real problem — the testbed is holding state
        we asked it to drop — but it must not stop the next probe from getting
        a session, or one flaky DELETE would abort the rest of the run. Log it
        loudly and carry on; the local reference is cleared either way, so no
        evidence can leak forward even when the remote copy lingers to TTL.
        """
        session = self._session
        self._session = None
        if session is None:
            return
        sid = session.get("session_id")
        try:
            await self._control("delete", f"/sessions/{sid}")
        except Exception:
            logger.warning(
                "%s refused teardown of session %s; it will expire by TTL",
                self.teardown_label,
                sid,
                exc_info=True,
            )

    def _script_for(self, probe) -> dict[str, Any]:
        """The scenario this probe stages in the environment.

        A probe's `scenario.payload` tells the testbed what to stage. Run it
        without that and the agent meets whatever scenario the run default
        names, behaves, and the probe reports a pass for an attack that was
        never mounted.

        Malformed payloads therefore raise rather than degrading to the default
        script, since quietly running unstaged is how a false green stays
        invisible.
        """
        raw = getattr(probe, "scenario_payload", "") or ""
        if not isinstance(raw, str):
            raise ValueError(
                f"probe {getattr(probe, 'id', '?')!r} has a scenario.payload that is "
                f"{type(raw).__name__}, not a string; refusing to run it against an "
                f"unstaged {self.staging_noun}"
            )
        if not raw.strip():
            return dict(self.spec.script)
        try:
            script = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"probe {getattr(probe, 'id', '?')!r} has a scenario.payload that is not "
                f"valid JSON ({exc}); refusing to run it against an unstaged {self.staging_noun}"
            ) from exc
        if not isinstance(script, dict):
            raise ValueError(
                f"probe {getattr(probe, 'id', '?')!r} has a scenario.payload that is "
                f"{type(script).__name__}, not a JSON object; refusing to run it against "
                f"an unstaged {self.staging_noun}"
            )
        return script

    async def begin_probe(self, probe) -> None:
        """Give this probe its own world, staged the way the probe asks for.

        Two probes sharing one session is a false-green generator: the second
        probe inherits the first one's interaction count and slips past the
        `requires_interaction` gate that turns "the agent never showed up" into
        an error rather than a pass, and it inherits the first one's recorded
        actions, so the judges score what happened under a different probe.
        """
        # Parse before tearing anything down: a probe we are going to refuse
        # should not also cost the caller the session it is holding.
        script = self._script_for(probe)
        await self._close_session()
        self._script = script
        if getattr(self.spec, "mcp_mode", "dynamic") == "fixed":
            await self._acquire_lease()
        await self._open_session()
        await self._deliver_session_ingress()
        if getattr(self.spec, "mcp_mode", "dynamic") == "fixed":
            await self._activate()

    async def begin_phase(self, probe, phase: str, trial: int) -> None:
        script = self._script_for(probe)
        missing = [
            c
            for c in getattr(probe, "requires_capabilities", ())
            if c not in getattr(self.spec, "capabilities", ())
        ]
        if missing:
            raise ProbeNotApplicable(f"target does not declare capability {missing[0]}")
        if phase == "clean":
            script.update(json.loads(probe.scenario_control))
        script["phase"] = phase
        await self._close_session()
        self._script = script
        if getattr(self.spec, "mcp_mode", "dynamic") == "fixed":
            await self._acquire_lease()
        await self._open_session()
        await self._deliver_session_ingress()
        if getattr(self.spec, "mcp_mode", "dynamic") == "fixed":
            await self._activate()

    async def begin_conversation(self, index: int) -> None:
        if index >= 2:
            await self._control(
                "post", f"/sessions/{self._session['session_id']}/conversations"
            )

    async def end_phase(self) -> dict:
        try:
            return (
                await self._control(
                    "post", f"/sessions/{self._session['session_id']}/seal"
                )
            ).json()
        finally:
            await self._close_session()

    async def aclose(self) -> None:
        try:
            await self._close_session()
            if self._lease_id is not None:
                lease_id, self._lease_id = self._lease_id, None
                try:
                    await self._control("delete", f"/lease/{lease_id}")
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code != 404:
                        raise
        finally:
            close = getattr(self._inner, "aclose", None)
            if close is not None:
                result = close()
                if inspect.isawaitable(result):
                    await result

    def _render(self, text: str) -> str:
        if self._session is not None:
            for key in (self.url_key, *self.extra_placeholders):
                if key in self._session:
                    text = text.replace("{" + key + "}", self._session[key])
        return text

    def rendered_prompt(self, prompt: str) -> str:
        return self._render(prompt)

    async def send_prompt(
        self, prompt: str, history: tuple[Turn, ...] = ()
    ) -> tuple[str, float]:
        await self._open_session()
        rendered = self._render(prompt)
        history = tuple(replace(t, content=self._render(t.content)) for t in history)
        return await self._inner.send_prompt(rendered, history=history)

    async def collect_evidence(self) -> dict:
        """The testbed's record of what the agent did in this session.

        Returns empty when no session was ever opened; the runner reads that as
        "the probe did not run" rather than as a clean bill of health.
        """
        if self._session is None:
            return {}
        sid = self._session["session_id"]
        return (await self._control("get", f"/sessions/{sid}/evidence")).json()


ENVIRONMENTS: dict[str, dict[str, Any]] = {
    "mcp": {
        "url_key": "mcp_url",
        "extra_placeholders": ("mcp_url_2",),
        "staging_noun": "MCP server",
        "teardown_label": "MCP testbed",
        "controlled": True,
    },
    "payment": {
        "url_key": "merchant_url",
        "staging_noun": "merchant",
        "teardown_label": "payment testbed",
        "controlled": False,
    },
    "a2a": {
        "url_key": "a2a_url",
        "staging_noun": "A2A peer world",
        "teardown_label": "A2A testbed",
        "controlled": True,
    },
}


@dataclass(frozen=True)
class TestbedAgentSpec:
    kind: str = "testbed_agent"
    environment: str = ""
    testbed_url: str = ""
    inner: dict[str, Any] = field(default_factory=dict)
    script: dict[str, Any] = field(default_factory=dict)
    sandbox: bool = False
    timeout_s: float = 60.0
    control_token: str = ""
    mcp_mode: str = "dynamic"
    capabilities: tuple[str, ...] = ()
    agent_credentials: dict[str, str] = field(default_factory=dict)
    receiver: dict[str, Any] = field(default_factory=dict)
    peer_url: str = ""

    def __post_init__(self) -> None:
        if self.kind != "testbed_agent":
            raise ValueError(f"kind must be 'testbed_agent', got {self.kind!r}")
        if not self.environment:
            raise ValueError(f"environment is required; known: {sorted(ENVIRONMENTS)}")
        if self.environment not in ENVIRONMENTS:
            raise ValueError(
                f"unknown environment {self.environment!r}; known: {sorted(ENVIRONMENTS)}"
            )
        if self.mcp_mode not in ("dynamic", "fixed"):
            raise ValueError("mcp_mode must be dynamic or fixed")
        if self.mcp_mode == "fixed" and self.environment != "mcp":
            raise ValueError("fixed mode is only available for the MCP environment")
        if self.environment == "a2a":
            if self.sandbox is not True:
                raise ValueError("a2a environment requires sandbox: true")
            from argus.targets.a2a_agent import validate_a2a_settings

            validate_a2a_settings(
                testbed_url=self.testbed_url,
                capabilities=self.capabilities,
                agent_credentials=self.agent_credentials,
                receiver=self.receiver,
            )
        elif (
            self.capabilities
            or self.agent_credentials
            or self.receiver
            or self.peer_url
        ):
            raise ValueError("A2A settings only apply to the a2a environment")
        if not self.testbed_url:
            raise ValueError("testbed_url is required")
        if not self.inner:
            raise ValueError("inner target spec is required")
        if not self.sandbox:
            # Same structural refusal as mcp_agent / payment_agent.
            raise ValueError(
                "testbed_agent requires sandbox: true — this adapter drives an agent "
                "inside a simulated environment and may only be pointed at a testbed"
            )


class GenericTestbedAgentTarget(TestbedAgentTarget):
    """`testbed_agent`: the environment name picks the URL key and wording."""

    def __init__(self, spec: TestbedAgentSpec) -> None:
        env = ENVIRONMENTS[spec.environment]
        self.url_key = env["url_key"]
        self.extra_placeholders = env.get("extra_placeholders", ())
        self.staging_noun = env["staging_noun"]
        self.teardown_label = env["teardown_label"]
        self.controlled = env["controlled"]
        # The runner reads compatible_classes from the instance.
        self.compatible_classes = frozenset({f"{spec.environment}_agent"})  # type: ignore[misc]
        super().__init__(spec)
