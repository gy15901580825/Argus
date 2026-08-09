"""One-shot generator: extract attack prompts from garak Probe classes
into our YAML schema.

Setup (dev machine only — garak is NOT in runtime requirements.txt because
its transitive deps cause pip resolution-too-deep against google-adk):
    pip install -r requirements-tools.txt

Usage:
    python scripts/wrap_garak_probes.py --output orchestrator/redteam/probes/garak

Run from orchestrator/ working dir.

Note: the committed YAMLs under orchestrator/redteam/probes/garak/ are the
durable source-of-truth. Re-running this script overwrites them. Only
regenerate intentionally (e.g., on a garak version bump) and review the diff
— prompt ordering and probe counts can shift between garak versions.

First run on a fresh machine may download large datasets (HuggingFace Hub,
NLTK corpora) into the user cache; allow ~5min and a working network
connection.
"""

from __future__ import annotations

import argparse
import importlib
import inspect
from pathlib import Path

import yaml


# (garak module, our category, owasp_llm code, atlas id) — manually curated.
# Updated for garak 0.15: leakage→leakreplay, xss→ansiescape; added 9 more
# 0.15-era modules to reach the plan's >= 30 probe target.
GARAK_TARGETS = [
    ("garak.probes.promptinject", "prompt-injection", "LLM01", "AML.T0051.000"),
    ("garak.probes.dan", "jailbreak", "LLM01", "AML.T0051.001"),
    ("garak.probes.goodside", "prompt-injection", "LLM01", "AML.T0051.000"),
    ("garak.probes.latentinjection", "indirect-prompt-injection", "LLM01", "AML.T0051.001"),
    ("garak.probes.leakreplay", "data-exfil", "LLM06", "AML.T0024"),
    ("garak.probes.glitch", "input-handling", "LLM05", "AML.T0050"),
    ("garak.probes.realtoxicityprompts", "harmful-content", "LLM02", "AML.T0040"),
    ("garak.probes.ansiescape", "output-handling", "LLM02", "AML.T0019"),
    ("garak.probes.continuation", "harmful-content", "LLM02", "AML.T0040"),
    ("garak.probes.encoding", "input-handling", "LLM05", "AML.T0050"),
    ("garak.probes.donotanswer", "harmful-content", "LLM02", "AML.T0040"),
    ("garak.probes.malwaregen", "harmful-content", "LLM02", "AML.T0040"),
    ("garak.probes.misleading", "harmful-content", "LLM02", "AML.T0040"),
    ("garak.probes.snowball", "data-exfil", "LLM06", "AML.T0024"),
    ("garak.probes.sysprompt_extraction", "data-exfil", "LLM06", "AML.T0024"),
    ("garak.probes.divergence", "data-exfil", "LLM06", "AML.T0024"),
    ("garak.probes.grandma", "jailbreak", "LLM01", "AML.T0051.001"),
    ("garak.probes.packagehallucination", "harmful-content", "LLM02", "AML.T0040"),
]


def severity_for(category: str) -> str:
    return {
        "prompt-injection": "medium",
        "jailbreak": "medium",
        "indirect-prompt-injection": "high",
        "data-exfil": "high",
        "input-handling": "low",
        "harmful-content": "medium",
        "output-handling": "medium",
    }.get(category, "low")


def rubric_for(category: str) -> str:
    return {
        "prompt-injection": "rubrics/prompt_injection.md",
        "indirect-prompt-injection": "rubrics/prompt_injection.md",
        "jailbreak": "rubrics/jailbreak.md",
        "data-exfil": "rubrics/data_exfil.md",
        "harmful-content": "rubrics/jailbreak.md",
    }.get(category, "rubrics/default.md")


def extract_prompts_from_probe_class(probe_cls) -> list[str]:
    """Extract prompts from a garak Probe class.

    Older garak (<0.15) exposed `prompts` as a class attribute. 0.15+
    populates it dynamically inside the constructor — fall back to instantiating
    the class when the class-level attribute is empty/missing.
    """
    prompts = getattr(probe_cls, "prompts", None)
    if not isinstance(prompts, list) or not prompts:
        try:
            inst = probe_cls()
        except Exception:
            return []
        prompts = getattr(inst, "prompts", None)
    if not isinstance(prompts, list):
        return []
    return [p for p in prompts if isinstance(p, str) and 0 < len(p) < 4000]


def wrap_module(module_name: str, category: str, owasp: str, atlas: str, output_dir: Path) -> int:
    mod = importlib.import_module(module_name)
    written = 0
    for name, cls in inspect.getmembers(mod, inspect.isclass):
        if cls.__module__ != module_name:
            continue
        prompts = extract_prompts_from_probe_class(cls)
        if not prompts:
            continue
        # Cap at 5 prompts per probe to keep judge cost bounded
        prompts = prompts[:5]
        probe_id = f"garak_{module_name.rsplit('.', 1)[-1]}_{name.lower()}"
        doc = {
            "id": probe_id,
            "name": f"garak {name} ({category})",
            "target_class": ["http-chat"],
            "attack_class": [category],
            "severity": severity_for(category),
            "prompts": prompts,
            "mappings": {
                "atlas": [atlas],
                "owasp_llm": [owasp],
                "nist_ai_rmf": ["MAP-2.3", "MEASURE-2.6"],
                "eu_ai_act": ["Article 15(3)"],
            },
            "judge": {
                "model": "claude-haiku-4-5-20251001",
                "rubric_path": rubric_for(category),
            },
            "_attribution": f"Wrapped from {module_name}.{name} (garak, Apache-2.0, NVIDIA)",
        }
        out_path = output_dir / f"{probe_id}.yaml"
        out_path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True))
        written += 1
    return written


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    args = p.parse_args()
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    total = 0
    for module_name, category, owasp, atlas in GARAK_TARGETS:
        try:
            n = wrap_module(module_name, category, owasp, atlas, out)
            print(f"{module_name}: {n} probes")
            total += n
        except (ImportError, AttributeError) as e:
            print(f"  SKIP {module_name}: {e}")
    print(f"Total: {total} probes written to {out}")


if __name__ == "__main__":
    main()
