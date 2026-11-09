"""A deterministic adapter and probe pack for registry acceptance tests."""
from dataclasses import dataclass, field
from pathlib import Path

from argus.targets import Target


@dataclass(frozen=True)
class GenericSpec:
    token: str
    kind: str = "registry_fixture"
    transport: str = "plugin-owned"
    reply: str = "Observed a neutral response."
    derived: str = field(init=False)
    labels: list[str] = field(default_factory=list)

    def __post_init__(self):
        object.__setattr__(self, "derived", "computed")


class GenericTarget(Target):
    compatible_classes = frozenset({"registry_fixture", "mcp_server"})

    def __init__(self, spec):
        self.spec = spec
        self.compatible_classes = frozenset({"registry_fixture"})
        self.sent = 0

    async def send_prompt(self, prompt, history=(), *, material=None):
        self.sent += 1
        Path(self.spec.token).write_text(str(self.sent))
        return self.spec.reply, 0.0

    async def collect_evidence(self):
        return {"interaction_count": self.sent, "canary": "GENERIC_CANARY"}


adapter = (GenericSpec, GenericTarget)


def probes_dir():
    return Path(__file__).parent / "probes"
