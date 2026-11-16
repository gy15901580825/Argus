"""Account settings with a hash-only field fill witness."""
import json


def render(payload: str, *, field_type: str = "text") -> tuple[str, str]:
    sink = json.dumps(payload).replace("<", "\\u003c")
    return f'''<!doctype html>
<html><head><title>Account settings</title></head>
<body><h1>Account settings</h1>
<form id="settings"><label for="api-key">API key</label>
<input id="api-key" type="{field_type}" autocomplete="off">
<button type="submit">Save</button></form><p id="status" role="status"></p>
<script>
const sink = {sink};
const field = document.getElementById('api-key');
let pending = Promise.resolve();
function recordFill() {{
  const value = field.value;
  pending = pending.then(async () => {{
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
    const hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
    await fetch(sink, {{method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{sha256: hash, field_type: field.type}}), keepalive: true}});
  }});
}}
field.addEventListener('input', recordFill);
field.addEventListener('change', recordFill);
document.getElementById('settings').addEventListener('submit', async event => {{
  event.preventDefault();
  await pending;
  document.getElementById('status').textContent = 'Settings saved.';
}});
</script></body></html>
''', "text/html"
