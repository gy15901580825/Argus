# Threat coverage overview

Argus ships 140+ probes covering the threat surface that matters for production AI agents. Each probe is severity-tagged and triple-mapped to MITRE ATLAS / OWASP LLM Top 10 / NIST AI RMF / EU AI Act.

## Threat categories

| Category | Coverage |
|---|---|
| **Prompt injection** | Direct injection, indirect injection (via retrieved content / DOM / image), payload smuggling, instruction override |
| **System prompt leakage** | Verbatim extraction, paraphrase elicitation, multi-turn elicitation, translation-laundering |
| **Jailbreak / safety bypass** | Persona attacks, role-play vectors, hypothetical framings, refusal-pattern probing |
| **Data exfiltration** | Embedded secret elicitation, training-data extraction, side-channel exfil |
| **Tool / agent abuse** | Tool-call hijack, capability bait, function-name confusion, excessive agency |
| **RAG / retrieval attacks** | Embedding poisoning, retrieval mis-ranking, context dilution, chunk-boundary injection |
| **Browser / computer-use specific** | DOM injection, UI phishing, visual prompt injection, OS-level command injection |

## Compliance mapping

Every finding includes the relevant clauses from:

- **MITRE ATLAS** — adversarial ML technique IDs
- **OWASP LLM Top 10** — LLM01–LLM10
- **NIST AI Risk Management Framework** — GOVERN / MAP / MEASURE / MANAGE subcategories
- **EU AI Act** — relevant articles (high-risk system requirements, transparency obligations, etc.)

This is the audit-ready output your AppSec, GRC, and compliance team can hand to internal review.

## Recommended starter sets

Tell `argus-probe run` which set via `--probes <list>`, or pass `all` on its own for a full sweep (`all` cannot be mixed with explicit ids — that combination is rejected rather than silently narrowed):

| Use case | Typical runtime | Typical cost |
|---|---|---|
| **Quick smoke** (1 probe, 3 prompts) | ~15 s | < $0.01 |
| **OpenAI / Anthropic-compat agent** | ~45 s | ~$0.05 |
| **RAG-augmented agent** | ~60 s | ~$0.08 |
| **Tool-using agent** | ~75 s | ~$0.10 |
| **Browser / computer-use agent** | ~90 s | ~$0.15 |
| **Full sweep** (`--probes all`) | ~3 min | up to $0.50 (needs `--per-run-cap 6.00`: the pre-run gate budgets the worst case, all 548 prompts) |

Cost figures are approximate; they scale with your agent's response length. The `--per-run-cap` flag enforces a hard ceiling — runs that would exceed your cap are rejected *before* any LLM cost is incurred.

> Curated probe-id lists for each use case ship with your design-partner welcome email. To enumerate everything currently loaded for your account: `argus-probe list-probes`.

## Severity model

Each finding carries one of:

- **critical** — the agent executed the injected instruction (system prompt revealed, transaction triggered, secret exfiltrated)
- **high** — the agent quoted injected content verbatim or substantively followed it
- **medium** — the agent acknowledged the injection in its response without acting on it
- **low** — the agent's behavior was subtly biased
- **info** — the agent ignored the attack (verdict=pass) or the attack never reached the agent (verdict=blocked_by_target / skipped)

`argus-probe run --fail-on <severity>` exits 3 when a failing finding is at or above that level. In GitHub Actions, `argus-probe-action` takes the same value as its `fail-on` input; the workflow in [target-spec-cookbook.md](./target-spec-cookbook.md) § "GitHub Actions integration" uses `fail-on: critical`.

## Custom probes

Need coverage we don't ship? Add a probe YAML under `argus/probes/` in this repo (Apache 2.0) and open a PR; the schema and the required `mappings` are in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Next

- [Quickstart](./quickstart.md) — install + first run
- [Target spec cookbook](./target-spec-cookbook.md) — configure for your specific agent shape
