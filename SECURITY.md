# Security policy

This file covers two separate things. Do not confuse them:

1. **Reporting a vulnerability *in Argus itself*** — a flaw in this code that
   puts an Argus operator at risk. Private disclosure, details below.
2. **The ethical-use boundary** — Argus is an offensive security tool. What
   you are and are not permitted to point it at.

---

## 1. Reporting a vulnerability in Argus

Report privately to **contact@veyon.solutions**. Do not open a public GitHub
issue for a security-sensitive report.

Please include:

- A description of the issue
- Steps to reproduce
- Affected component (`orchestrator`, `api_service`, `client_agent`, `cli`,
  `frontend`) and the commit you tested
- Your assessment of impact

We aim to acknowledge reports within 2 business days and to ship a fix or
mitigation within 30 days, depending on severity.

### In scope

- Code in this repository across all sub-projects
- Credential handling: target API keys, judge API keys, and any secret
  referenced by a target spec are read from the operator's environment and
  used only to reach the operator's own target. If you can show them landing
  somewhere else — logs, findings, reports, transcripts, an outbound request
  to a third party — that is a vulnerability, report it here
- Anything that lets a *target under test* influence the Argus process:
  target responses are attacker-controlled data, and a target response that
  achieves code execution, path traversal, template injection, or judge
  hijacking on the Argus side is a vulnerability

### Out of scope

- **Findings Argus reports about your own agent.** Those are the tool's
  intended output, not vulnerabilities in Argus. If your agent leaks its
  system prompt under `owasp_07_system_prompt_leakage`, the bug is in your
  agent.
- **Probe content and judge verdicts.** A probe that is too weak, too strong,
  or mis-mapped, or a judge verdict you disagree with, is a normal issue or
  PR — open one, they are welcome.
- Vulnerabilities in third-party targets you scanned. Report those to the
  target's owner under their disclosure policy.
- Vulnerabilities in NVIDIA garak itself. Report those to
  https://github.com/NVIDIA/garak.

### Supported versions

Argus is pre-1.0. Security fixes land on the default branch. There is no
backport channel for older commits.

---

## 2. Ethical use

**Argus attacks the system you point it at.** It sends prompt injections,
jailbreaks, data-exfiltration attempts, and — with the `browser_use` adapter —
drives a real browser through a target's UI. The iterative attacks (TAP, PAIR,
GCG) generate novel attack prompts adaptively, so the exact traffic sent is
not fully predictable in advance.

Only run Argus against systems you own or have explicit, documented
authorization to test.

Before running a scan:

- Confirm you have written authorization covering the specific endpoint,
  the time window, and automated adversarial testing. A bug-bounty program's
  scope rules count only if they actually cover LLM/agent testing — many
  explicitly do not.
- Prefer a staging environment. Probes are designed to induce unsafe
  behavior; against a production agent with real tool access that can mean
  real side effects (writes, purchases, emails, API calls) performed by the
  agent on your behalf.
- Understand where the data goes. Probe prompts go to your target. Target
  responses go to the judge model, which is a third-party LLM API. Do not
  scan a target whose responses may contain data you are not permitted to
  send to that provider.
- Respect the target's rate limits and your own budget. Argus has a daily
  and per-run cost cap with predictive abort for the judge; it does not cap
  what your target charges you.

Do not use Argus to attack third-party services, to test systems without
authorization, or to develop attacks intended for deployment against systems
you do not own. Unauthorized testing is illegal in most jurisdictions
regardless of intent.

If a probe in this repository demonstrates a real, unfixed vulnerability in
a third-party product or an open-source LLM stack, email
**contact@veyon.solutions** rather than opening a public issue, so the
affected vendor can be notified first.
