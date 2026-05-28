# OSS probe-library extraction — operator handoff

The `argus-research/probes` repo is the public, MIT-licensed mirror of probe
YAMLs from `orchestrator/orchestrator/redteam/probes/`. Plan 3 Task 17
defines the structure; this doc captures the manual setup steps the orchestrator-
side automation can't do.

## One-time setup (operator runs once)

1. Create GitHub org `argus-research`.
2. Create public repo `argus-research/probes` with MIT license, no `.gitignore`.
3. Clone it next to the argus monorepo:
   ```
   cd /home/ygao/Workspace/Github
   git clone git@github.com:argus-research/probes argus-research-probes
   cd argus-research-probes
   mkdir -p probes/owasp probes/syscard probes/garak probes/browser rubrics
   ```
4. Author initial `README.md`, `CONTRIBUTING.md`, `SCHEMA.md` (drafts in next section).
5. First sync from orchestrator:
   ```
   cd /home/ygao/Workspace/Github/argus/orchestrator
   ./scripts/sync_probes_to_oss.sh   # uses OSS_REPO=../argus-research-probes by default
   cd ../../argus-research-probes  # adjust path as needed
   git status   # review the diff
   git add . && git commit -m "Initial probe library mirror"
   git push origin main
   ```

## Recurring sync (after each Plan 3+ probe addition)

```
cd orchestrator
./scripts/sync_probes_to_oss.sh
cd ../../argus-research-probes
git status; git diff
git add . && git commit -m "sync: <describe new probes>"
git push
```

## Initial doc drafts (operator polishes)

### README.md (first cut)

~~~markdown
# Argus Research — Probe Library

The community-extensible AI-agent red-team probe library powering [Argus](https://www.example.com).

## What's here

- `probes/owasp/` — 10 hand-authored probes covering OWASP LLM Top 10 (LLM01–LLM10)
- `probes/syscard/` — 5 probes from Anthropic/OpenAI safety scenarios (Sleeper Agent, Crescendo, Many-shot Jailbreak, Best-of-N, Confused Deputy)
- `probes/garak/` — 99 probes wrapping NVIDIA garak's static-prompt classes, full ATLAS / OWASP / NIST / EU AI Act mapping
- `probes/browser/` — 30+ original #3 browser-use probes (DOM injection, UI phishing, visual prompt injection, OS-cmd injection)
- `rubrics/` — judge rubrics referenced by the probes

## Schema

See `SCHEMA.md` for the YAML probe format.

## Contributing

See `CONTRIBUTING.md`. Probes are MIT licensed; wrapped data has its own license — see each YAML's `_attribution` field.
~~~

### CONTRIBUTING.md (first cut)

~~~markdown
# Contributing

## Authoring a new probe

1. One probe per YAML file under `probes/<category>/`.
2. Filename matches the `id` field.
3. Required fields: `id`, `name`, `target_class`, `attack_class`, `severity`, `prompts`, `mappings` (atlas + owasp_llm + nist_ai_rmf + eu_ai_act), `judge` (model + rubric_path).
4. Browser-use probes also require `scenario` (kind + payload).
5. Triple-mapping (atlas + owasp_llm + nist_ai_rmf) is required; eu_ai_act recommended.
6. New rubric → `rubrics/<name>.md`.

## PR template

- One probe per PR (or one logical batch).
- Confirm probe loads via `python -c "from orchestrator.redteam.probe import load_probe; ..."` (link the loader).
- License/attribution notes in `_attribution` field if wrapping a third-party probe.
~~~

### SCHEMA.md (first cut)

Lift content from `orchestrator/orchestrator/redteam/probe.py` (the `Probe` dataclass + `VALID_SEVERITIES` + `VALID_TARGET_CLASSES` constants, formatted as YAML schema docs). Keep the `scenario` block doc separate per browser-use probe contract.

## License compatibility note

- Hand-authored probes (owasp/syscard/browser): MIT (matches repo).
- garak wrappers: derivative of garak (MIT, NVIDIA). Each YAML's `_attribution` field
  cites the source. Compatible with repo MIT.
- realtoxicityprompts data: Apache 2.0 (compatible).
- leakreplay data (NYT/Harry Potter excerpts): extractive samples for memorization
  testing — likely fair-use red-team-research, but commercial redistribution is a
  separate question. Recommend Plan 4 audits before any non-research distribution.
