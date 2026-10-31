# A2A peer testbed

A deterministic A2A 1.0 HTTP+JSON fixture for outgoing agent handling and observed cascades. It provides invoice peers, an invoice ledger, business approvals, a passive action sink and a Planner, Reviewer, Executor demo. The testbed never calls an external service; only the demo sends HTTP requests, restricted to the configured peer and its own listener origin.

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/ -q
TESTBED_CONTROL_TOKEN=<your-controller-token> python -m testbed.serve
```

The default peer port is 8080. The controller binds to `127.0.0.1:8081` and refuses every request without its configured bearer token. `TESTBED_CONTROL_HOST` accepts loopback hosts only; `0.0.0.0` is rejected. Set `PORT`, `TESTBED_CONTROL_PORT`, `TESTBED_PUBLIC_URL` and `TESTBED_PLAINTEXT_URL` when needed. The public and control applications have separate route sets. The default Docker command runs `python -m testbed.serve`; do not publish the control port.

The demo image uses the same files with a different command:

```bash
export TESTBED_ORIGIN=http://127.0.0.1:8080
export A2A_AGENT_CREDENTIALS='{"planner":"Bearer <planner-token>","reviewer":"Bearer <reviewer-token>","executor":"Bearer <executor-token>"}'
export A2A_DRIVER_CREDENTIAL='Bearer <receiver-token>'
export DEMO_WEAKNESSES=safe
uvicorn demo_agent.app:app --host 0.0.0.0 --port 8095
```

Missing configuration leaves the demo unconfigured with 503 responses. Invalid explicit environment configuration stops startup with a redacted error. `safe` is the default policy; `naive` enables the seven documented demo weaknesses. Use this demo with this fixture only.

For Azure Container Apps, a shared pod or host must provide a private controller reachable on the Argus runner's loopback through a private channel. Expose only the peer listener through HTTPS and set `TESTBED_PUBLIC_URL` to that peer address. Use one instance per concurrent run. Set the control token before upgrade; an unset token fails closed. An optional separate `TESTBED_PLAINTEXT_URL` is used only for the explicitly declared production TLS subcase.

Each phase is limited to 64 messages, 32 action requests, 12 rounds, 3 delegation levels, 4 concurrent requests and 30 seconds; payloads are limited to 64 KiB. Seal waits for in-flight work, snapshots evidence and rejects late mutation. Telemetry can still be recorded after an exhausted business budget so a known violation is not lost. Client-chosen message IDs do not prove current-world membership: actions need a fresh public business identifier. A parent-only action is incomplete evidence. Stop old traffic before reusing static endpoints, or use separate instances.

Credentials and bare auth tokens are scrubbed from business text and fields in live and sealed controller evidence. Known public structural labels, including actor roles, schema/version and decision enums, remain unchanged even if a token equals one of those public labels. No arbitrary message or business string is restored.

The nine probes cover outgoing ASI07 risks and four ASI08 cascades with observed edges between distinct verified target identities. A single agent's loop or retry is not a cascade. Missing target capabilities cause skipped probes; declared capabilities without normal proof cause errors. Fixture actions record request, acceptance and application separately and do not perform real payment effects. Agent Card signatures, PKI, mTLS and a customer's production multi-agent architecture are outside this demonstration.
