---
name: New probe
about: Propose a new attack probe for the library
title: 'probe: '
labels: probe
assignees: ''
---

<!-- Probes are the highest-value contribution to Argus. See the "Adding a
     new probe" section of CONTRIBUTING.md for the full schema. You do not
     need working code to open this issue — the design is the hard part. -->

## The attack

<!-- What does the attack do to the agent, and why does it work? Two or
     three sentences. -->

## Attack class

<!-- Existing tags include: prompt-injection, jailbreak, data-exfil,
     tool-abuse, obfuscated-payload, encoded-payload, indirect-prompt-injection,
     missing-human-gate, install-time-exec, shadow-credentials,
     credential-extraction, obfuscated-code, harmful-content, output-handling.

     Reuse one if it fits. If you are proposing a new tag, say why the
     existing ones don't describe this attack. -->

- `attack_class`:
- `severity` (`info` / `low` / `medium` / `high` / `critical`):
- `target_class` (any of `http-chat`, `browser-using`, `tool-using`, `rag`,
  `multi-agent`, `http-upload`; the adapter-side names `llm_chat`,
  `agent_with_tools`, `agent_with_rag`, `browser_using_agent` are also accepted):

## Standards mapping

<!-- All three are required for a probe to be merged — the test suite
     enforces non-empty atlas / owasp_llm / nist_ai_rmf. -->

- MITRE ATLAS technique(s):
- OWASP LLM Top 10 (`LLM01`–`LLM10`):
- NIST AI RMF function(s):
- EU AI Act article(s), if applicable:

## Pass / fail rubric sketch

<!-- What should the LLM-judge look for in the target's response? Rough
     prose is fine; it becomes a rubric markdown file, or reuses an
     existing one from orchestrator/orchestrator/redteam/rubrics/. -->

- **pass** (attack failed):
- **warn** (partial compliance):
- **fail** (attack succeeded):

Existing rubric to reuse, if any (e.g. `rubrics/prompt_injection.md`):

## Example prompt(s)

<!-- One or more. These become the `prompts:` list. -->

```
```

## Evidence it fires

<!-- Have you seen this work against a real agent? Which one, and what did
     it do? A published writeup or system card counts. If it fires against
     the bundled demo_target, that is the strongest possible evidence — say
     so and we can wire it into demo/run_local_demo.py. -->

## References

<!-- Papers, advisories, system cards, blog posts. -->
