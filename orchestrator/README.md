# argus-orchestrator

The red-team engine of [Argus](https://github.com/gy15901580825/Argus), black-box red-team testing for AI agents. `argus-probe run --local` runs this package in-process. It contains:

- the probe library: 205 probe YAML files mapped to OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF and the EU AI Act
- target adapters for `openai_compat`, `anthropic_native`, `custom_http`, `grpc`, `browser_use`, `payment_agent`, `mcp_agent`, `testbed_agent` and `http_upload` agents
- the judge, which scores each probe response against a rubric with an LLM

Most users want the CLI rather than this package:

```bash
pipx install "argus-probe[local]"
```

The import package is `orchestrator.redteam`. The FastAPI service in the repo's `orchestrator/` directory is not part of this wheel.

## Judge configuration

The judge reads these environment variables:

- `ANTHROPIC_API_KEY`: used by the default provider (Anthropic).
- `OPENAI_API_KEY`: used automatically when it is the only key set.
- `REDTEAM_MODEL_PROVIDER=litellm`: runs the judge on a local or other model. Set `REDTEAM_FAST_MODEL` (for example `ollama/qwen2.5:32b`) and, for a non-default host, `REDTEAM_LLM_API_BASE`. Small models miss many jailbreaks, so a clean report from one is weak evidence. Local models other than Ollama (vLLM or LM Studio via `openai/...` with `REDTEAM_LLM_API_BASE`) are billed at the most expensive known rate, so pass `--per-run-cap`.
- `REDTEAM_MODEL_PROVIDER=azure`: runs the judge on Azure OpenAI through litellm instead. Set `AZURE_API_KEY`, `AZURE_API_BASE` and `AZURE_API_VERSION`. The default deployment name is `gpt-5.4-mini`.
- `REDTEAM_FAST_MODEL`, `REDTEAM_STRONG_MODEL`: optional model overrides for the two judge roles.

Azure's default content filter blocks judge calls because the judge reads attack text, so use a custom filter policy with jailbreak detection turned off for that deployment. If `OPENAI_API_KEY` is paired with `REDTEAM_LLM_API_BASE` pointing at Azure, set `REDTEAM_FAST_MODEL` and `REDTEAM_STRONG_MODEL` to your deployment names, because the default strong model `gpt-5.6-terra` is usually not deployed.

License: Apache-2.0. Source and docs: https://github.com/gy15901580825/Argus
