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

- `ANTHROPIC_API_KEY`: required with the default provider (Anthropic).
- `REDTEAM_MODEL_PROVIDER=azure`: runs the judge on Azure OpenAI through litellm instead. Set `AZURE_API_KEY`, `AZURE_API_BASE` and `AZURE_API_VERSION`. The default deployment name is `gpt-5.4-mini`.
- `REDTEAM_FAST_MODEL`, `REDTEAM_STRONG_MODEL`: optional model overrides for the two judge roles.

License: Apache-2.0. Source and docs: https://github.com/gy15901580825/Argus
