"""Deployment domains narrow defaults while preserving explicit selections."""

import json
from dataclasses import FrozenInstanceError, dataclass, replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import yaml
from click.testing import CliRunner

import argus.api as api
import argus.probe as probe_module
import argus.targets as targets_module
from argus.cli.__main__ import main
from argus.domains import DOMAINS
from argus.probe import load_probe, load_probe_library
from argus.suites import SUITE_ATTACK_CLASSES, SUITE_MAPPING_FIELDS, derive_suites
from argus.targets import _BUILDERS, build_target
from argus.targets._base import Target


CHAT = {"kind": "openai_compat", "endpoint_url": "http://127.0.0.1:1/chat", "model": "test-model"}
WORLD = {"testbed_url": "http://127.0.0.1:1", "sandbox": True, "inner": CHAT}
TARGET_SPECS = {
    "custom_http": {"kind": "custom_http", "request_url": "http://127.0.0.1:1/chat",
                    "request_body_template": '{"prompt": "{{ prompt }}"}', "response_jsonpath": "$.reply"},
    "python": {"kind": "python", "entry": "fictitious_fixture:reply"},
    "payment_agent": {"kind": "payment_agent", **WORLD},
    "mcp_agent": {"kind": "mcp_agent", **WORLD},
    "testbed_agent": {"kind": "testbed_agent", "environment": "payment", **WORLD},
    "browser_use": {"kind": "browser_use", "agent_url": "http://127.0.0.1:1/chat", "scenario_kind": "dom_injection"},
    "web_chat": {"kind": "web_chat", "url": "http://127.0.0.1:1/chat", "input_selector": "input", "response_selector": "output"},
    "openai_compat": CHAT,
    "anthropic_native": {"kind": "anthropic_native", "api_key": "test-value", "model": "test-model"},
    "grpc": {"kind": "grpc", "endpoint": "127.0.0.1:1", "service_method": "fixture.Chat/Send"},
    "http_upload": {"kind": "http_upload", "upload_url": "http://127.0.0.1:1/upload", "render_url_jsonpath": "$.url"},
    "a2a_server": {"kind": "a2a_server", "url": "http://127.0.0.1:1/a2a"},
    "mcp_server": {"kind": "mcp_server", "url": "http://127.0.0.1:1/mcp"},
    "vllm_server": {"kind": "vllm_server", "url": "http://127.0.0.1:1"},
    "a2a_agent": {"kind": "a2a_agent", **WORLD},
    "mcp_gateway": {"kind": "mcp_gateway", "sandbox": True,
                    "gateway": {"url": "http://127.0.0.1:1/mcp"},
                    "fixtures": {"control_url": "http://127.0.0.1:1", "control_token": "test-value", "install_file": "fictitious-install.json"}},
}
PAYMENT_IDS = {
    "pay_approval_forged", "pay_approval_threshold_split", "pay_cart_steering_product_text",
    "pay_inject_authority_framing", "pay_inject_failed_payment_lure", "pay_inject_json_field",
    "pay_inject_markdown_comment", "pay_inject_non_english", "pay_wallet_approve_max",
    "pay_wallet_limit_raise_multi_turn", "pay_wallet_preapprove_year", "pay_x402_asset_confusion",
    "pay_x402_decimal_shift", "pay_x402_injected_followup_charge", "pay_x402_micro_drain",
    "pay_x402_no_budget_stated", "pay_x402_payee_switch_in_content", "pay_x402_payto_swap",
    "pay_x402_quote_tampering", "pay_x402_retry_double_charge", "pay_x402_retry_total_cap",
    "pay_x402_subtle_overcharge", "pay_x402_zero_address_payee",
}
GENERIC_PAYMENT_IDS = {
    "pay_wallet_key_exfil", "pay_wallet_key_exfil_compliance",
    "pay_wallet_key_exfil_encoded", "pay_wallet_key_exfil_partial",
}
CHAT_FIN_IDS = {"fin_card_number_readback", "fin_statement_amount_injection"}
MCP_FIN_IDS = {"fin_card_tool_full_pan", "fin_cross_customer_account"}
FIN_IDS = CHAT_FIN_IDS | MCP_FIN_IDS


def test_registry_is_closed_and_frozen():
    assert len(DOMAINS) == 10
    domain = DOMAINS["financial-services"]
    assert domain.id == "financial-services" and domain.title and domain.description
    with pytest.raises(FrozenInstanceError):
        domain.title = "Changed"
    with pytest.raises(TypeError):
        DOMAINS["unregistered"] = domain


@pytest.mark.parametrize("kind", TARGET_SPECS)
def test_no_domain_preserves_full_library_selection(monkeypatch, kind):
    assert set(TARGET_SPECS) == set(_BUILDERS)
    if kind == "web_chat":
        pytest.importorskip("playwright.async_api")
    target = build_target(TARGET_SPECS[kind], trusted_code=True)
    assert target.domain is None
    probes = load_probe_library(api.PROBES_DIR)
    assert len(probes) == 333
    monkeypatch.setattr(api, "load_probe_library", lambda _: probes)
    original = [api.compatible_probe_ids(target, include_opt_in=False), api.compatible_probe_ids(target)]
    domain_only = {p.id for p in probes if p.domain_only}
    assert domain_only == FIN_IDS
    assert all(domain_only.isdisjoint(ids) for ids in original)
    old_suites = {k: v for k, v in derive_suites(probes).items() if not k.startswith("domain:")}
    for suite in old_suites:
        req = api.RunRequest(target=TARGET_SPECS[kind], suite=suite)
        selected = api._resolve_request_probe_ids(req, target)
        assert selected == [pid for pid in old_suites[suite] if pid not in domain_only]
        assert domain_only.isdisjoint(selected)
    cleared = [replace(p, domains=(), domain_only=False) for p in probes]
    monkeypatch.setattr(api, "load_probe_library", lambda _: cleared)
    baseline = [api.compatible_probe_ids(target, include_opt_in=False), api.compatible_probe_ids(target)]
    assert original == [[pid for pid in ids if pid not in domain_only] for ids in baseline]
    for suite, ids in old_suites.items():
        assert api._resolve_request_probe_ids(api.RunRequest(target=TARGET_SPECS[kind], suite=suite), target) == ids
    assert derive_suites(cleared) == old_suites


def test_domain_targeting_flips_with_domain_and_tags(monkeypatch):
    target = build_target({**TARGET_SPECS["payment_agent"], "domain": "financial-services"})
    assert set(api.compatible_probe_ids(target, include_opt_in=False)) == PAYMENT_IDS | GENERIC_PAYMENT_IDS
    target.domain = "retail-ecommerce"
    assert set(api.compatible_probe_ids(target, include_opt_in=False)) == GENERIC_PAYMENT_IDS
    probes = load_probe_library(api.PROBES_DIR)
    monkeypatch.setattr(api, "load_probe_library", lambda _: [replace(p, domains=()) for p in probes])
    assert set(api.compatible_probe_ids(target, include_opt_in=False)) == PAYMENT_IDS | GENERIC_PAYMENT_IDS


def test_domain_suites_and_existing_suites_keep_their_members(monkeypatch):
    probes = load_probe_library(api.PROBES_DIR)
    suites = derive_suites(probes)
    monkeypatch.setattr(api, "load_probe_library", lambda _: probes)
    assert len(suites["domain:financial-services"]) == 27
    assert suites["domain:financial-services"] == sorted(PAYMENT_IDS | {
        "fin_card_number_readback", "fin_statement_amount_injection",
        "fin_card_tool_full_pan", "fin_cross_customer_account",
    })
    assert "domain:hr-employment" not in suites
    assert "domain:legal" not in suites
    assert set(suites) == set(SUITE_MAPPING_FIELDS) | set(SUITE_ATTACK_CLASSES) | {"domain:financial-services"}
    target = build_target({**TARGET_SPECS["payment_agent"], "domain": "retail-ecommerce"})
    for suite, ids in suites.items():
        expected = ids if suite.startswith("domain:") else [pid for pid in ids if pid not in PAYMENT_IDS | FIN_IDS]
        assert api._resolve_request_probe_ids(api.RunRequest(target=TARGET_SPECS["payment_agent"], suite=suite), target) == expected
        assert api._resolve_suite(suite) == ids
    changed = [replace(p, opt_in=False) if p.domains in (("legal",), ("hr-employment",)) else p for p in probes]
    changed_suites = derive_suites(changed)
    assert len(changed_suites["domain:legal"]) == len(changed_suites["domain:hr-employment"]) == 3
    tagged = next(p for p in probes if p.id in PAYMENT_IDS)
    assert derive_suites([replace(tagged, domains=("telecom",))])["domain:telecom"] == [tagged.id]
    for target_class in ("mcp_scan", "mcp_trap"):
        assert derive_suites([replace(tagged, target_class=(target_class,))]) == {}
    assert derive_suites([replace(tagged, opt_in=True)]) == {}


def test_opt_in_stays_opt_in_with_domain():
    spec = {**TARGET_SPECS["custom_http"], "domain": "financial-services"}
    target = build_target(spec)
    default = api.compatible_probe_ids(target, include_opt_in=False)
    inclusive = api.compatible_probe_ids(target)
    invoice = {p.id for p in load_probe_library(api.PROBES_DIR) if p.id.startswith("doc_injection_invoice_payee_swap_")}
    assert len(invoice) == 3
    assert invoice <= set(inclusive) and invoice.isdisjoint(default)


@pytest.mark.parametrize("kind,financial", [("custom_http", CHAT_FIN_IDS), ("mcp_agent", MCP_FIN_IDS)])
@pytest.mark.parametrize("suite", ["owasp-llm-top10", None])
@pytest.mark.parametrize("domain", [None, "financial-services", "healthcare"])
def test_financial_selection_flips_with_target_domain(kind, financial, suite, domain):
    spec = {**TARGET_SPECS[kind], "domain": domain}
    target = build_target(spec)
    req = api.RunRequest(target=spec, suite=suite)
    selected = set(api._resolve_request_probe_ids(req, target))
    if domain == "financial-services":
        assert financial <= selected
    else:
        assert FIN_IDS.isdisjoint(selected)
    target.domain = None if domain == "financial-services" else "financial-services"
    flipped = set(api._resolve_request_probe_ids(req, target))
    assert financial.isdisjoint(flipped) if domain == "financial-services" else financial <= flipped


@pytest.mark.parametrize("suite", ["owasp-llm-top10", "payments", None])
@pytest.mark.parametrize("domain", [None, "retail-ecommerce"])
def test_payment_selection_flips_with_target_domain(suite, domain):
    spec = {**TARGET_SPECS["payment_agent"], "domain": domain}
    target = build_target(spec)
    req = api.RunRequest(target=spec, suite=suite)
    selected = set(api._resolve_request_probe_ids(req, target))
    assert PAYMENT_IDS <= selected if domain is None else PAYMENT_IDS.isdisjoint(selected)
    target.domain = "retail-ecommerce" if domain is None else None
    flipped = set(api._resolve_request_probe_ids(req, target))
    assert PAYMENT_IDS.isdisjoint(flipped) if domain is None else PAYMENT_IDS <= flipped


def test_suite_domain_filter_empty_is_422_and_flips(monkeypatch):
    financial = next(p for p in load_probe_library(api.PROBES_DIR) if p.id in CHAT_FIN_IDS)
    monkeypatch.setattr(api, "load_probe_library", lambda _: [financial])
    spec = TARGET_SPECS["custom_http"]
    target = build_target(spec)
    req = api.RunRequest(target=spec, suite="owasp-llm-top10")
    with pytest.raises(api.HTTPException) as exc:
        api._resolve_request_probe_ids(req, target)
    assert exc.value.status_code == 422 and "domain None" in exc.value.detail
    target.domain = "telecom"
    with pytest.raises(api.HTTPException, match="telecom") as exc:
        api._resolve_request_probe_ids(req, target)
    assert exc.value.status_code == 422
    target.domain = "financial-services"
    assert api._resolve_request_probe_ids(req, target) == [financial.id]
    assert api._resolve_request_probe_ids(req) == [financial.id]
    target.domain = None
    assert api._resolve_request_probe_ids(req.model_copy(update={"suite": "domain:financial-services"}), target) == [financial.id]
    with pytest.raises(api.HTTPException) as exc:
        api._resolve_request_probe_ids(req.model_copy(update={"suite": None}), target)
    assert exc.value.status_code == 422 and "domain None" in exc.value.detail


async def test_explicit_domain_only_probe_runs_without_domain_in_api_and_local(monkeypatch):
    from argus import local

    spec = TARGET_SPECS["custom_http"]
    target = build_target(spec)
    target.send_prompt = AsyncMock(return_value=("Card **** **** **** 0121.", 0.0))
    target.aclose = AsyncMock()
    monkeypatch.setattr(api, "build_target", lambda *_, **__: target)
    monkeypatch.setattr(local, "build_target", lambda *_, **__: target)
    req = api.RunRequest(target=spec, probe_ids=["fin_card_number_readback"])
    assert "fin_card_number_readback" not in api._resolve_request_probe_ids(req.model_copy(update={"probe_ids": []}), target)
    assert api._resolve_request_probe_ids(req, target) == req.probe_ids
    prompts = load_probe(api.PROBES_DIR / "financial/fin_card_number_readback.yaml").prompts
    for run in (api._run_probes(req, ""), local.run_local(spec, req.probe_ids, env={})):
        findings = [f async for f in run if f.get("probe_id")]
        assert len(findings) == len(prompts)
        assert {f["probe_id"] for f in findings} == {"fin_card_number_readback"}
        assert {f["verdict"] for f in findings} == {"pass"}
    assert target.send_prompt.await_count == 2 * len(prompts)


@pytest.mark.parametrize("domain", ["retail-ecommerce", "financial-services"])
async def test_explicit_request_executes_tagged_probe(monkeypatch, domain):
    target = build_target({**TARGET_SPECS["payment_agent"], "domain": domain})
    target.begin_probe = AsyncMock()
    target.send_prompt = AsyncMock(return_value=("Completed test action.", 0.0))
    target.collect_evidence = AsyncMock(return_value={"interaction_count": 1, "authorizations": []})
    target.aclose = AsyncMock()
    monkeypatch.setattr(api, "build_target", lambda _: target)
    req = api.RunRequest(target={**TARGET_SPECS["payment_agent"], "domain": domain}, probe_ids=["pay_x402_quote_tampering"])
    findings = [f async for f in api._run_probes(req, "")]
    assert len(findings) == 1
    assert findings[0]["verdict"] == "pass"
    target.send_prompt.assert_awaited_once()


def _yaml_probe(tmp_path, **overrides):
    raw = {"id": "domain_fixture", "name": "Domain fixture name", "target_class": ["http-chat"],
           "attack_class": ["prompt-injection"], "severity": "medium", "prompts": ["Return test value."],
           "domains": ["financial-services"], "assertions": [{"response_fields": {"equals": {"$.ok": "yes"}}}]}
    raw.update(overrides)
    path = tmp_path / "unrelated_filename.yaml"
    path.write_text(yaml.safe_dump(raw))
    return path, raw


@pytest.mark.parametrize("changes,message", [
    ({"assertions": []}, "needs_judge"),
    ({"judge_when_assertions_pass": True}, "needs_judge"),
    ({"judge_when_assertions_warn": True}, "needs_judge"),
    ({"domains": ["unregistered"]}, "valid ids"),
    ({"domains": ["legal", "legal"]}, "repeats"),
    ({"domains": "legal"}, "must be a list"),
    ({"domains": [42]}, "valid ids"),
    ({"domain_only": True, "domains": []}, "domain_only requires non-empty domains"),
    ({"domain_only": "true"}, "domain_only must be a boolean"),
])
def test_probe_load_rules_flip_when_input_is_corrected(tmp_path, changes, message):
    path, raw = _yaml_probe(tmp_path, **changes)
    with pytest.raises(ValueError) as exc:
        load_probe(path)
    with pytest.raises(ValueError):
        load_probe_library(tmp_path)
    assert "domain_fixture" in str(exc.value) and "Domain fixture name" in str(exc.value)
    assert message in str(exc.value)
    if message == "valid ids":
        assert all(d in str(exc.value) for d in DOMAINS)
    raw.update(domains=["financial-services"], assertions=[{"response_fields": {"equals": {"$.ok": "yes"}}}],
               judge_when_assertions_pass=False, judge_when_assertions_warn=False, domain_only=True)
    path.write_text(yaml.safe_dump(raw))
    probe = load_probe(path)
    assert probe.domains == ("financial-services",) and probe.domain_only and not probe.needs_judge
    raw["domains"] = []
    raw["domain_only"] = False
    raw["assertions"] = []
    path.write_text(yaml.safe_dump(raw))
    assert load_probe(path).needs_judge
    assert not load_probe(path).domain_only


def test_multi_domain_probe_and_absent_domains(tmp_path, monkeypatch):
    path, raw = _yaml_probe(tmp_path, domains=["financial-services", "retail-ecommerce"])
    probe = load_probe(path)
    assert probe.domains == ("financial-services", "retail-ecommerce")
    monkeypatch.setattr(api, "load_probe_library", lambda _: [probe])
    target = build_target(TARGET_SPECS["custom_http"])
    for domain in ("financial-services", "retail-ecommerce", None):
        target.domain = domain
        assert api.compatible_probe_ids(target) == [probe.id]
    target.domain = "legal"
    assert api.compatible_probe_ids(target) == []
    del raw["domains"]
    path.write_text(yaml.safe_dump(raw))
    probe = load_probe(path)
    assert probe.domains == ()
    assert api.compatible_probe_ids(target) == [probe.id]


@pytest.mark.parametrize("changes", [{"domains": ["unregistered"]}, {"domains": ["legal", "legal"]},
                                     {"assertions": []}, {"judge_when_assertions_pass": True},
                                     {"judge_when_assertions_warn": True},
                                     {"domain_only": True, "domains": []}, {"domain_only": "true"}])
def test_entry_point_pack_uses_domain_load_rules(tmp_path, monkeypatch, caplog, changes):
    pack = tmp_path / "pack"
    pack.mkdir()
    builtin = tmp_path / "builtin"
    builtin.mkdir()
    path, raw = _yaml_probe(pack, **changes)
    monkeypatch.setattr(probe_module, "entry_points", lambda **_: [SimpleNamespace(name="fixture", load=lambda: lambda: pack)])
    assert load_probe_library(builtin) == []
    assert "domain_fixture" in caplog.text and "Domain fixture name" in caplog.text
    for domain in DOMAINS:
        raw.update(domains=[domain], assertions=[{"response_fields": {"equals": {"$.ok": "yes"}}}],
                   judge_when_assertions_pass=False, judge_when_assertions_warn=False, domain_only=True)
        path.write_text(yaml.safe_dump(raw))
        assert load_probe_library(builtin)[0].domains == (domain,)


@pytest.mark.parametrize("bad", ["unregistered", "", [], 42, True])
def test_target_domain_errors_and_validate_target(tmp_path, monkeypatch, bad):
    spec = {**TARGET_SPECS["custom_http"], "domain": bad}
    with pytest.raises(ValueError) as exc:
        build_target(spec)
    assert "unknown domain" in str(exc.value)
    assert all(d in str(exc.value) for d in DOMAINS)
    path = tmp_path / "target.json"
    path.write_text(json.dumps(spec))
    result = CliRunner().invoke(main, ["validate-target", "--offline", "--target", str(path)])
    assert result.exit_code == 1 and "unknown domain" in result.output
    assert all(d in result.output for d in DOMAINS)
    spec["domain"] = "financial-services"
    path.write_text(json.dumps(spec))
    assert build_target(spec).domain == "financial-services"
    assert CliRunner().invoke(main, ["validate-target", "--offline", "--target", str(path)]).exit_code == 0


@pytest.mark.parametrize("value", ["financial-services", None])
def test_nested_domain_is_rejected_even_when_null(value):
    spec = {**TARGET_SPECS["payment_agent"], "inner": {**CHAT, "domain": value}}
    with pytest.raises(ValueError, match="domain in inner.*top level"):
        build_target(spec)
    spec["inner"] = CHAT
    spec["domain"] = value
    assert build_target(spec).domain == value


def test_plugin_target_accepts_and_exposes_domain(monkeypatch):
    @dataclass
    class Spec:
        kind: str

    class FixtureTarget(Target):
        def __init__(self, spec):
            self.spec = spec

        async def send_prompt(self, prompt, history=()):
            return "Test reply.", 0.0

    monkeypatch.setattr(targets_module, "_plugin_builders", lambda: {"domain_fixture": (Spec, FixtureTarget)})
    spec = {"kind": "domain_fixture", "domain": "legal"}
    target = build_target(spec)
    assert target.domain == "legal" and target.spec == Spec("domain_fixture")
    assert build_target({"kind": "domain_fixture"}).domain is None
    with pytest.raises(ValueError, match="valid ids"):
        build_target({**spec, "domain": "unregistered"})


def _listed(result):
    assert result.exit_code == 0, result.output
    return {line.split()[0] for line in result.output.splitlines() if line and " probes" not in line}


def test_list_probes_domain_and_target_filters(monkeypatch):
    monkeypatch.delenv("ARGUS_API_URL", raising=False)
    runner = CliRunner()
    probes = load_probe_library(api.PROBES_DIR)
    financial = _listed(runner.invoke(main, ["list-probes", "--domain", "financial-services"]))
    assert financial == {p.id for p in probes if "financial-services" in p.domains}
    assert len(financial) == 30
    assert len(_listed(runner.invoke(main, ["list-probes", "--domain", "legal"]))) == 3
    assert _listed(runner.invoke(main, ["list-probes", "--domain", "retail-ecommerce"])) == set()
    for domain, wanted in [("financial-services", PAYMENT_IDS | GENERIC_PAYMENT_IDS),
                           ("retail-ecommerce", GENERIC_PAYMENT_IDS), (None, PAYMENT_IDS | GENERIC_PAYMENT_IDS)]:
        spec = {**TARGET_SPECS["payment_agent"], "domain": domain}
        assert _listed(runner.invoke(main, ["list-probes", "--target", json.dumps(spec)])) == wanted
    result = runner.invoke(main, ["list-probes", "--domain", "unregistered"])
    assert result.exit_code == 2 and all(d in result.output for d in DOMAINS)
    result = runner.invoke(main, ["list-probes", "--domain", "legal", "--api-url", "http://127.0.0.1:1"])
    assert result.exit_code == 2 and "--domain filters the local library" in result.output
