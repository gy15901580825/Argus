## What changed

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- The effect on a user of Argus. -->

## Checklist

- [ ] Tests pass (`python3 -m pytest tests/ -q` from the repo root)
- [ ] Import boundaries hold (`lint-imports` from the repo root)
- [ ] New probes include `mappings` (atlas + owasp_llm + nist_ai_rmf) and a
      `judge.rubric_path` that points at a rubric file that exists
- [ ] Commit messages follow Conventional Commits (`feat(scope): ...`)
- [ ] No credentials, real hostnames, or internal infrastructure details in
      the diff
