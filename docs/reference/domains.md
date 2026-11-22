# Deployment domains

A target's optional `domain` selects generic probes plus probes written for
that deployment domain. The registered ids are defined in `argus/domains.py`:

| Id | Title | Agents covered |
| --- | --- | --- |
| healthcare | Healthcare | Clinical services, pharmacy and health insurance; no bundled probes. |
| financial-services | Financial services | Banking, payments, lending, wealth and general insurance. |
| retail-ecommerce | Retail and ecommerce | Shopping, orders, refunds and quotes. |
| travel-hospitality | Travel and hospitality | Airlines, hotels and bookings. |
| telecom | Telecom | Carrier support. |
| hr-employment | HR and employment | Recruiting, HR self-service and payroll. |
| legal | Legal | Legal research and law-firm assistance. |
| public-sector | Public sector | Citizen services and benefits. |
| software-it-ops | Software and IT operations | Coding, DevOps and IT helpdesk work. |
| workplace-productivity | Workplace productivity | Email, calendars, documents and workplace chat. |

Declare one domain at the top level of any builtin or plugin target spec:

```json
{
  "kind": "custom_http",
  "request_url": "http://127.0.0.1:8000/chat",
  "request_body_template": "{\"prompt\": \"{{ prompt }}\"}",
  "response_jsonpath": "$.reply",
  "domain": "financial-services"
}
```

The built target exposes `target.domain`. Omit `domain` or use `null` for a
generic run. Putting it inside `inner` is an error: declare it on the outer
target. Unknown ids fail validation, including `validate-target`, with the
valid ids listed. Test a target spanning two domains in two runs.

Selection follows these rules:

1. Without a target domain, `all`, named probe ids and existing suites select
   exactly the same probes as before. Tags alone never remove a probe.
2. With domain D, `all` keeps generic probes and probes tagged D, subject to
   the existing target class, history and browser trap-mode compatibility rules.
   Probes tagged only with other domains are left out.
3. Opt-in probes still require named ids. A declared domain or domain suite
   does not opt into document injection probes.
4. Named probe ids run when compatible, whatever their domain tags. Existing
   standards and attack-class suites keep their membership for every target domain.
5. The API derives a `domain:<id>` suite for each domain with eligible probes.
   These suites contain only tagged probes; generic probes are not added. Opt-in
   probes and MCP scan/trap probes are excluded, and empty suites are omitted.
   The bundled library has `domain:financial-services` with 23 payment probes;
   its HR and legal document probes are opt-in, so those domain suites are absent.
   Suites are selected through the API, like existing suites.
6. `argus-probe list-probes --domain D` lists probes tagged D, including opt-in
   probes. `list-probes --target target.json` lists the default selection for
   that spec, including its domain. Domain and target filters use the local
   library and cannot be combined with `--api-url`.

Probe YAML may declare several registered domains:

```yaml
domains: [financial-services, retail-ecommerce]
```

An absent or empty list means generic. Unknown ids and repeated ids fail
loading, naming the probe. A tagged probe must have deterministic assertions
and `needs_judge == False`: no assertions, `judge_when_assertions_pass: true`
or `judge_when_assertions_warn: true` makes loading fail. A `judge` block may
still supply evidence or explanations; the verdict cannot depend on it.
The four judge-only payment credential probes remain generic.

Probe packs installed through the `argus.probe_packs` entry point may tag
their probes with any registered domain. They follow the same load rules;
as with other invalid pack probes, a rejected probe causes its pack to be
skipped with a warning naming the probe.

Probes reach their facts at three integration levels, derived from their
behavior rather than a declared field:

- `none`: the facts travel in the attack, such as a document or prompt canary,
  or the probe compares a constrained response with a fact file. These probes
  have no `scenario` and no seeded canary.
- `seed`: the operator plants canaries in a test account or knowledge base.
  This integration level is not implemented in this phase.
- `tool`: Argus serves mock tools for a probe with a `scenario`, such as the
  payment and MCP worlds. These targets require `sandbox: true` today.

A chat-only target gets only the probes that carry their facts in the attack
(the `none` level), including a chat-only production target. Declaring a domain
does not give it access to the mock tool worlds. Most deterministic checks
of domain actions need `seed` or `tool` integration. No fact-file probes ship
yet. A future `none`-level probe that compares an answer with a fact will record
that fact's jurisdiction, source URL and as-of date. Keyword
matches alone are weak signals and cannot establish a deterministic advice verdict.
