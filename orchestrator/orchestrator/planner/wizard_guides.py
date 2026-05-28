"""Static markdown setup guides emitted by the wizard when the user needs to
bring client_agent online or launch a CDP-attached browser. V1 is generic;
V2 will pull per-OS variants from docs/runbooks/local-dev.md."""

from __future__ import annotations


CLIENT_AGENT_INSTALL = """## Install and run the client agent

The client agent is a Docker container that runs on your local machine and
connects to the Argus orchestrator via WebSocket. It executes Web UI tests
against your local CDP-attached browser (and runs API tests from your machine
when you select "my machine").

**Prerequisites:** Docker 20.10+; your Argus API token (from the chat page
header menu → API Tokens).

**Run the container:**

```bash
docker run -d \\
  --name argus-client-agent \\
  --network host \\
  -e API_TOKEN=<your-token> \\
  -e ORCHESTRATOR_URL=wss://www.example.com/ws \\
  <your-gh-user>/client_agent:latest
```

**Verify:** the chat page header will switch the client-agent indicator to
green within ~10 seconds. If it stays red, check `docker logs argus-client-agent`
for auth or connectivity errors."""


CDP_BROWSER_LAUNCH = """## Launch a CDP-attached browser

The wizard needs to reach your local browser over the Chrome DevTools
Protocol (CDP) to run the Web UI test locally. Launch Chromium/Chrome with
the remote debugging port enabled:

```bash
# macOS
/Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome \\
  --remote-debugging-port=9222

# Linux
google-chrome --remote-debugging-port=9222

# Windows PowerShell
& "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" `
  --remote-debugging-port=9222
```

Keep that browser window open. The client agent will attach to it over CDP.

**Verify:** from the machine running the client agent,
`curl http://localhost:9222/json/version` should return JSON with a
`webSocketDebuggerUrl` field."""


GUIDES: dict[str, str] = {
    "client_agent_install": CLIENT_AGENT_INSTALL,
    "cdp_browser_launch": CDP_BROWSER_LAUNCH,
}
