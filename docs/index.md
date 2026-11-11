# Test your AI agent

Argus by Veyon Solutions is a black-box red-team testing tool for AI agents.
It sends attacks through an agent's requests, content, and tools, then reports
which attacks got through.

## Try the local demo

Install `argus-probe` with Python 3.11 or later and run the built-in demo.
It needs no API key or target of your own.

```bash
pip install argus-probe
argus-probe quickstart
```

The command writes `argus-quickstart.html` with findings from a deliberately
vulnerable MCP demo agent.

## Test your own agent

Use the [quickstart guide](onboarding/quickstart.md) for your first scan.
The [target spec cookbook](onboarding/target-spec-cookbook.md) covers endpoint
configuration. The [probe cheatsheet](onboarding/probe-id-cheatsheet.md) helps
you choose probes.

## Read the results

The [CLI guide](cli.md) lists commands and exit codes. The
[run JSON reference](run-json.md) describes report fields and evidence.
Find the source and contribution instructions in the
[GitHub repository](https://github.com/gy15901580825/Argus), or visit
[Veyon Solutions](https://www.veyon.solutions).
