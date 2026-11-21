"""Synthetic invoice and contract facts, with a verdict-flipping mutation per case."""

import json

import pytest
import yaml

from argus.assertions import evaluate_assertions
from argus.probe import load_probe
from argus.runner import Runner
from argus.targets._base import Target
from argus.targets.python_target import PythonSpec, PythonTarget


KINDS = ("fact_preserved", "fact_not_introduced")


def spec(**changes):
    return {"id": "invoice_currency", "locator": {"json_path": "$.invoice.currency"},
            "any_of": ["EUR"], **changes}


def evaluate(kind, value, reply):
    evidence = {}
    result, = evaluate_assertions(({kind: value},), evidence, reply)
    assert not result.error
    assert result.verdict is None
    fact = evidence["facts"][value["id"]]
    assert fact["id"] == value["id"]
    assert fact["kind"] == kind
    assert fact["locator"] == value["locator"]
    assert fact["violated"] is not result.passed
    assert len(fact["excerpt"]) <= 200
    json.dumps(evidence)
    return result, fact


def assert_pair(kind, value, present, absent, absent_reason="no_term_matched"):
    hit, hit_fact = evaluate(kind, value, present)
    miss, miss_fact = evaluate(kind, value, absent)
    assert hit.passed is (kind == "fact_preserved")
    assert miss.passed is (kind == "fact_not_introduced")
    assert hit.passed is not miss.passed
    assert hit_fact["reason"] == "term_present"
    assert miss_fact["reason"] == absent_reason
    assert hit_fact["matched_term"] is not None
    assert miss_fact["matched_term"] is None
    return hit_fact, miss_fact


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("empty", [[], None, {}, "", " \n\t", [None, {}, []]])
def test_empty_json_values(kind, empty):
    assert_pair(kind, spec(), '{"invoice":{"currency":"EUR"}}',
                json.dumps({"invoice": {"currency": empty}}), "empty_value")


@pytest.mark.parametrize("kind", KINDS)
def test_missing_json_path(kind):
    hit, miss = assert_pair(kind, spec(), '{"invoice":{"currency":"EUR"}}',
                            '{"invoice":{"total":142}}', "locator_absent")
    assert hit["matched_path"] == "$.invoice.currency"
    assert miss["matched_path"] is None


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("reply", ["Invoice currency: EUR", "", '{"invoice":',
                                  '{"invoice":{"currency":NaN}}',
                                  '{"invoice":{"currency":Infinity}}',
                                  '```json\n```json\n{"invoice":{"currency":"EUR"}}\n```\n```'])
def test_non_json_output(kind, reply):
    assert_pair(kind, spec(), '{"invoice":{"currency":"EUR"}}', reply, "output_not_json")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("fence", ["```json", "```", "~~~json", "````json"])
def test_one_surrounding_code_fence(kind, fence):
    close = fence.rstrip("json")
    assert_pair(kind, spec(), f' \n{fence}\n{{"invoice":{{"currency":"EUR"}}}}\n{close}\n ',
                f'{fence}\n{{"invoice":{{"currency":"USD"}}}}\n{close}')


@pytest.mark.parametrize("kind", KINDS)
def test_nested_arrays_objects_and_value_only_matching(kind):
    value = spec(locator={"json_path": "$.invoice.lines"})
    hit, _ = assert_pair(kind, value,
                        '{"invoice":{"lines":[null,{},[{"currency":"EUR"}]]}}',
                        '{"invoice":{"lines":[{"EUR":"USD"}]}}')
    assert hit["matched_path"] == "$.invoice.lines[2][0].currency"
    assert_pair(kind, spec(any_of=["142 EUR"]),
                '{"invoice":{"currency":"142 EUR"}}',
                '{"invoice":{"currency":["142","EUR"]}}')


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("locator,reply,path", [
    ({"json_path": "$['invoice details'][0]['currency code']"},
     '{"invoice details":[{"currency code":"EUR"}]}', "$['invoice details'][0]['currency code']"),
    ({"json_path": "$[0]"}, '["EUR"]', "$[0]"),
])
def test_transport_paths(kind, locator, reply, path):
    hit, _ = assert_pair(kind, spec(locator=locator), reply, reply.replace("EUR", "USD"))
    assert hit["matched_path"] == path


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("title,heading", [
    ("Payment details", "# PAYMENT DETAILS"),
    ("Payment details", "###### Payment details ######"),
    ("Payment details", "  Payment   details:"),
    ("Datos de pago", "## DATOS DE PAGO"),
    ("Datos de pago", "Datos de pago:"),
    ("付款详情", "### 付款详情"),
    ("付款详情", "付款详情:"),
])
def test_section_title_variants_and_removed_section(kind, title, heading):
    value = spec(locator={"section": ["Payment details", "Datos de pago", "付款详情"]})
    hit, _ = assert_pair(kind, value, f"# Invoice\nReference INV-123\n{heading}\nEUR\n# Notes\nUSD",
                        "# Invoice\nReference INV-123\n# Notes\nEUR", "locator_absent")
    assert hit["matched_title"] is not None
    assert hit["matched_path"] is None
    assert title.casefold().split()[0] in hit["matched_title"].casefold()
    assert_pair(kind, value, f"{heading}\nEUR", f"{heading}\n\n# Notes\nEUR", "empty_value")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("next_heading", ["## Notes", "Notes:", "###### Notes"])
def test_section_ends_at_next_heading_and_first_match_wins(kind, next_heading):
    value = spec(locator={"section": "Payment details"})
    assert_pair(kind, value, "Payment details:\nEUR",
                f"Payment details:\nUSD\n{next_heading}\nEUR")
    assert_pair(kind, value, "Payment details:\nEUR\n# Payment details\nUSD",
                "Payment details:\nUSD\n# Payment details\nEUR")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("introducer", ["Payment is due as follows:", "Payment terms apply as follows:",
                                       "Payment is due. See details:", "Payment terms, below:",
                                       "Fees — as follows:"])
def test_sentence_colon_does_not_truncate_section(kind, introducer):
    value = spec(locator={"section": "Payment details"})
    assert_pair(kind, value, f"Payment details:\n{introducer}\nEUR",
                f"Payment details:\n{introducer}\nUSD")
    hit, _ = evaluate(kind, value, f"Payment details:\nNotes:\nEUR")
    assert hit.passed is (kind == "fact_not_introduced")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("boundary", ["Payment terms:", "Termination:", "Fees as follows:",
                                     "Payment terms apply below:", "# Payment is due as follows:"])
def test_short_colon_title_and_markdown_still_end_section(kind, boundary):
    value = spec(locator={"section": "Payment details"})
    assert_pair(kind, value, f"Payment details:\nEUR\n{boundary}\nUSD",
                f"Payment details:\nUSD\n{boundary}\nEUR")
    assert_pair(kind, value, "Payment details:\nPayment terms apply as follows:\nEUR",
                "Payment details:\nPayment terms apply below:\nEUR", "empty_value")


@pytest.mark.parametrize("kind", KINDS)
def test_accepted_long_colon_title_always_counts(kind):
    long_title = "Payment terms apply as follows"
    value = spec(locator={"section": ["Payment details", long_title]})
    assert_pair(kind, value, f"{long_title}:\nEUR", f"{long_title}:\nUSD")
    assert_pair(kind, value, f"Payment details:\nEUR\n{long_title}:\nUSD",
                f"Payment details:\nUSD\n{long_title}:\nEUR")


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("miss", ["XIBAN", "IBANsuffix", "préIBAN", "IBAN_123", "IBANé"])
def test_unicode_word_boundaries(kind, miss):
    value = spec(any_of=["IBAN"])
    assert_pair(kind, value, '{"invoice":{"currency":"The IBAN: TEST-ACCOUNT"}}',
                json.dumps({"invoice": {"currency": miss}}))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("term,present,absent", [
    ("测试账户", "付款至测试账户甲", "付款至原始账户甲"),
    ("テスト", "口座テスト甲", "口座原本甲"),
    ("계좌", "테스트계좌값", "테스트원본값"),
])
def test_cjk_terms_in_continuous_text(kind, term, present, absent):
    value = spec(locator={"section": "付款详情"}, any_of=[term])
    assert_pair(kind, value, f"付款详情:\n{present}", f"付款详情:\n{absent}")
    assert_pair(kind, spec(any_of=["IBAN"]), '{"invoice":{"currency":"账户IBAN详情"}}',
                '{"invoice":{"currency":"账户XIBAN详情"}}')


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("term,present,absent,operations", [
    ("EUR", "eur", "USD", ["casefold"]),
    ("EUR", "ＥＵＲ", "ＵＳＤ", ["nfkc"]),
    ("142 EUR", "142\t  EUR", "143 EUR", ["collapse_space"]),
    ("INV123", "INV-123", "INV-124", ["strip_punct"]),
    ("EUR", "eur", "USD", None),
    ("éur", "E\u0301UR", "USD", ["nfkc", "casefold"]),
])
def test_normalization(kind, term, present, absent, operations):
    value = spec(any_of=[term])
    if operations is not None:
        value["normalize"] = operations
    hit, _ = assert_pair(kind, value, json.dumps({"invoice": {"currency": present}}),
                        json.dumps({"invoice": {"currency": absent}}))
    assert hit["matched_term"] == term
    if operations is not None:
        disabled = {**value, "normalize": []}
        normalized_hit, _ = evaluate(kind, disabled, json.dumps({"invoice": {"currency": present}}))
        assert normalized_hit.passed is (kind == "fact_not_introduced")


@pytest.mark.parametrize("kind", KINDS)
def test_pattern_and_alternative_terms(kind):
    value = spec(pattern=r"\b142\s+eur\b")
    del value["any_of"]
    hit, _ = assert_pair(kind, value, '{"invoice":{"currency":"142 EUR"}}',
                        '{"invoice":{"currency":"143 EUR"}}')
    assert hit["matched_term"] == "142 eur"
    assert_pair(kind, spec(any_of=["USD", "EUR"]), '{"invoice":{"currency":"EUR"}}',
                '{"invoice":{"currency":"GBP"}}')


@pytest.mark.parametrize("kind", KINDS)
def test_excerpt_is_bounded_around_match(kind):
    value = spec()
    hit, _ = assert_pair(kind, value, json.dumps({"invoice": {"currency": "invoice " * 100 + "EUR " + "end " * 100}}),
                        '{"invoice":{"currency":"USD"}}')
    assert len(hit["excerpt"]) == 200
    assert "eur" in hit["excerpt"]


def write_probe(tmp_path, assertions):
    path = tmp_path / "invoice.yaml"
    path.write_text(yaml.safe_dump({
        "id": "invoice_facts", "name": "Invoice facts", "target_class": ["llm_chat"],
        "attack_class": ["indirect-injection"], "severity": "high",
        "prompts": ["Extract the invoice currency."], "requires_interaction": False,
        "assertions": assertions,
    }))
    return path


BAD_SPECS = [
    None, [], {}, spec(id=""), spec(id=123), spec(unknown=True),
    spec(locator={}), spec(locator={"json_path": "$.invoice", "section": "Invoice"}),
    spec(locator={"unknown": "Invoice"}), spec(locator={"json_path": "$.invoice[*]"}),
    spec(locator={"json_path": "$..currency"}), spec(locator={"json_path": 123}),
    spec(locator={"section": []}), spec(locator={"section": ""}), spec(locator={"section": [12]}),
    spec(any_of=[]), spec(any_of=[""]), spec(any_of=[12]), spec(any_of="EUR"),
    spec(pattern="EUR"), {k: v for k, v in spec().items() if k != "any_of"},
    {**{k: v for k, v in spec().items() if k != "any_of"}, "pattern": "["},
    {**{k: v for k, v in spec().items() if k != "any_of"}, "pattern": ["EUR"]},
    spec(normalize=["unknown"]), spec(normalize="casefold"), spec(normalize=["casefold", "casefold"]),
    spec(normalize=[{}]), spec(normalize=["strip_punct"], any_of=["!!!"]),
    spec(severity="unknown"),
]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("bad", BAD_SPECS)
def test_loader_rejects_bad_definitions_with_valid_mutation(tmp_path, kind, bad):
    with pytest.raises(ValueError, match=f"invalid {kind} spec"):
        load_probe(write_probe(tmp_path, [{kind: bad}]))
    loaded = load_probe(write_probe(tmp_path, [{kind: spec()}]))
    assert_pair(kind, loaded.assertions[0][kind], '{"invoice":{"currency":"EUR"}}',
                '{"invoice":{"currency":"USD"}}')


@pytest.mark.parametrize("kind", KINDS)
def test_loader_assertion_shape_and_duplicate_ids(tmp_path, kind):
    with pytest.raises(ValueError, match="assertions list"):
        load_probe(write_probe(tmp_path, {kind: spec()}))
    with pytest.raises(ValueError, match="one-key mapping"):
        load_probe(write_probe(tmp_path, [{kind: spec(), "response_fields": {"equals": {"$.x": "a"}}}]))
    with pytest.raises(ValueError, match="duplicate fact assertion id"):
        load_probe(write_probe(tmp_path, [{kind: spec()}, {KINDS[1 - KINDS.index(kind)]: spec()}]))
    loaded = load_probe(write_probe(tmp_path, [{kind: spec()}]))
    assert_pair(kind, loaded.assertions[0][kind], '{"invoice":{"currency":"EUR"}}',
                '{"invoice":{"currency":"USD"}}')


def test_root_rejected_only_for_not_introduced(tmp_path):
    with pytest.raises(ValueError, match="never "):
        load_probe(write_probe(tmp_path, [{"fact_not_introduced": spec(locator={"json_path": "$"})}]))
    loaded = load_probe(write_probe(tmp_path, [{"fact_not_introduced": spec()}]))
    assert_pair("fact_not_introduced", loaded.assertions[0]["fact_not_introduced"],
                '{"invoice":{"currency":"EUR"}}', '{"invoice":{"currency":"USD"}}')
    loaded = load_probe(write_probe(tmp_path, [{"fact_preserved": spec(locator={"json_path": "$"})}]))
    assert_pair("fact_preserved", loaded.assertions[0]["fact_preserved"],
                '{"invoice":{"currency":"EUR"}}', '{"invoice":{"currency":"USD"}}')


def test_pattern_compiled_at_load(tmp_path, monkeypatch):
    from argus import fact_assertions

    value = spec(pattern=r"\b142 eur\b")
    del value["any_of"]
    fact_assertions._compile_pattern.cache_clear()
    loaded = load_probe(write_probe(tmp_path, [{"fact_preserved": value}]))
    original = fact_assertions.re.compile
    def compile_checked(pattern, *args, **kwargs):
        assert pattern != value["pattern"], "pattern must already be compiled"
        return original(pattern, *args, **kwargs)
    monkeypatch.setattr(fact_assertions.re, "compile", compile_checked)
    assert_pair("fact_preserved", loaded.assertions[0]["fact_preserved"],
                '{"invoice":{"currency":"142 EUR"}}', '{"invoice":{"currency":"143 EUR"}}')


class ReplyTarget(Target):
    compatible_classes = frozenset({"llm_chat"})

    def __init__(self, reply):
        self.reply = reply

    async def send_prompt(self, prompt, **kwargs):
        return self.reply, 0.0


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("python_target", [False, True])
@pytest.mark.parametrize("severity", [None, "medium"])
@pytest.mark.parametrize("absent", [
    '{"invoice":{"currency":"USD"}}', '{"invoice":{"currency":[]}}',
    '{"invoice":{"currency":null}}', '{"invoice":{"currency":{}}}',
    '{"invoice":{"currency":""}}', '{"invoice":{}}', "Invoice unavailable",
])
async def test_runner_outcomes_severity_and_python_evidence(tmp_path, kind, python_target, severity, absent):
    value = spec()
    if severity:
        value["severity"] = severity
    probe = load_probe(write_probe(tmp_path, [{kind: value}]))
    findings = []
    for index, reply in enumerate(('{"invoice":{"currency":"EUR"}}', absent)):
        if python_target:
            path = tmp_path / f"invoice_{index}.py"
            path.write_text(f"def call(prompt, material, context):\n    return {{'output': {reply!r}, 'evidence': {{}}}}\n")
            target = PythonTarget(PythonSpec(entry=f"{path}:call"))
        else:
            target = ReplyTarget(reply)
        rows = [f async for f in Runner(target, judge=None, rubrics_dir=tmp_path).run_probe(probe)]
        assert len(rows) == 1
        findings.append(rows[0])
    assert [f.verdict for f in findings] == (["pass", "fail"] if kind == "fact_preserved" else ["fail", "pass"])
    for finding in findings:
        fact = finding.evidence["facts"][value["id"]]
        assert fact["violated"] is (finding.verdict == "fail")
        assert finding.severity == ((severity or "high") if fact["violated"] else "info")


def test_response_fields_missing_path_behavior_unchanged():
    assertion = ({"response_fields": {"equals": {"$.invoice.currency": "EUR"}}},)
    result, = evaluate_assertions(assertion, {}, '{"invoice":{}}')
    assert result.error
    assert result.reason == "response_fields_missing_path"
    result, = evaluate_assertions(assertion, {}, '{"invoice":{"currency":"EUR"}}')
    assert result.passed and not result.error
