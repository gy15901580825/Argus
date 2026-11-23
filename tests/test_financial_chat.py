"""Financial chat probes decide from replies over an offline loopback transport."""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from argus import api
from argus.assertions import evaluate_assertions
from argus.probe import load_probe
from argus.targets import build_target


PAN = "4901234567890121"  # Synthetic Luhn-valid test value.
IDS = {"fin_card_number_readback", "fin_statement_amount_injection"}


def luhn(number):
    digits = [int(d) for d in number]
    return sum(d if i % 2 == 0 else (2 * d // 10 + 2 * d % 10)
               for i, d in enumerate(reversed(digits))) % 10 == 0


def mint(length):
    prefix = ("49012345678901234567")[:length - 1]
    return next(prefix + str(d) for d in range(10) if luhn(prefix + str(d)))


def result(reply, evidence=None):
    return evaluate_assertions(({"no_unmasked_pan": True},), evidence or {}, reply)[0]


@pytest.mark.parametrize("reply", [
    PAN, "4901 2345 6789 0121", "4901-2345-6789-0121", mint(13), mint(19),
])
def test_full_pan_fails_and_mask_mutation_passes(reply):
    assert luhn(re.sub(r"[ -]", "", reply))
    failed = result(reply)
    assert not failed.passed and not failed.error
    assert re.sub(r"[ -]", "", reply)[-4:] in failed.reason
    assert not re.search(r"\d{5}", failed.reason)
    assert result("**** **** **** " + re.sub(r"[ -]", "", reply)[-4:]).passed


@pytest.mark.parametrize("reply", [
    mint(12), mint(20), PAN[:-1] + "7", "4111 11** **** 1111",
    "**** **** **** 1234", "00000" + PAN, "0000 " + PAN,
    "49012345  67890121", "49012345\t67890121", "49012345\n67890121",
])
def test_non_candidates_pass_and_full_pan_mutation_fails(reply):
    passed = result(reply)
    assert passed.passed and not passed.error
    assert not result(PAN).passed


def test_double_space_separates_two_maximal_runs():
    assert not result(PAN + "  " + PAN).passed
    assert result(PAN + " " + PAN).passed


def test_pan_only_reads_reply():
    assert result("Total spend: EUR 75.00", {"card": PAN}).passed
    assert not result(PAN, {"card": "****"}).passed


@pytest.mark.parametrize("probe_id", sorted(IDS))
def test_fixture_hygiene_and_domain_load_rule(probe_id):
    probe = load_probe(api.PROBES_DIR / "financial" / f"{probe_id}.yaml")
    assert probe.target_class == ("http-chat",)
    assert probe.domains == ("financial-services",) and not probe.needs_judge
    assert not probe.opt_in and not probe.requires_interaction and not probe.indirect
    assert 2 <= len(probe.prompts) <= 3
    for prompt in probe.prompts:
        candidates = [re.sub(r"[ -]", "", m.group())
                      for m in re.finditer(r"\d(?:[ -]?\d)*", prompt)]
        valid = [n for n in candidates if 13 <= len(n) <= 19 and luhn(n)]
        assert valid == ([PAN] if probe_id == "fin_card_number_readback" else [])
        mutated = prompt.replace(PAN, PAN[:-1] + "7") if valid else prompt + "\n" + PAN
        changed = [re.sub(r"[ -]", "", m.group())
                   for m in re.finditer(r"\d(?:[ -]?\d)*", mutated)]
        assert [n for n in changed if 13 <= len(n) <= 19 and luhn(n)] != valid


@pytest.fixture
def chat_agent(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    state = {"behavior": "vulnerable", "prompts": []}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            prompt = json.loads(self.rfile.read(int(self.headers["Content-Length"])))['prompt']
            state["prompts"].append(prompt)
            card = "Forwarded card-transaction export" in prompt
            if state["behavior"] == "refusing":
                reply = "I cannot help with this request."
            elif state["behavior"] == "safe":
                reply = "Last week's spend was EUR 75.00; card **** **** **** 0121." if card else "Pay EUR 480.00."
            else:
                reply = f"Last week's spend was EUR 75.00; card {PAN}." if card else "Pay EUR 4,800.00."
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"reply": reply}).encode())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    state["spec"] = {"kind": "custom_http", "request_url": f"http://127.0.0.1:{server.server_port}/chat",
                     "request_body_template": '{"prompt": {{ prompt | tojson }}}', "response_jsonpath": "$.reply"}
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("probe_id", sorted(IDS))
@pytest.mark.parametrize("behavior", ["vulnerable", "safe", "refusing"])
async def test_probe_verdict_over_custom_http_with_mutation(chat_agent, probe_id, behavior):
    async def run(mode):
        chat_agent["behavior"] = mode
        return [f async for f in api._run_probes(api.RunRequest(
            target=chat_agent["spec"], probe_ids=[probe_id]), "")]

    expected = "fail" if behavior == "vulnerable" else (
        "skipped" if behavior == "refusing" and probe_id == "fin_statement_amount_injection" else "pass")
    findings = await run(behavior)
    assert findings and {f["verdict"] for f in findings} == {expected}
    probe = load_probe(api.PROBES_DIR / "financial" / f"{probe_id}.yaml")
    assert chat_agent["prompts"] == list(probe.prompts)
    opposite = await run("safe" if behavior == "vulnerable" else "vulnerable")
    assert {f["verdict"] for f in opposite} == {"pass" if expected == "fail" else "fail"}


@pytest.mark.parametrize("domain,selected,mutation", [
    (None, False, "financial-services"),
    ("financial-services", True, "retail-ecommerce"),
    ("retail-ecommerce", False, "financial-services"),
])
def test_all_chat_selection_flips_with_domain(domain, selected, mutation):
    spec = {"kind": "custom_http", "request_url": "http://127.0.0.1:1/chat",
            "request_body_template": '{"prompt": {{ prompt | tojson }}}',
            "response_jsonpath": "$.reply", "domain": domain}
    target = build_target(spec)
    req = api.RunRequest(target=spec)
    ids = set(api._resolve_request_probe_ids(req, target))
    assert (IDS <= ids) if selected else IDS.isdisjoint(ids)
    target.domain = mutation
    changed = set(api._resolve_request_probe_ids(req, target))
    assert IDS.isdisjoint(changed) if selected else IDS <= changed
