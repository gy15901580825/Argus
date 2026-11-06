import importlib
import json

import pytest
from click.testing import CliRunner

from argus.cli.__main__ import main
from argus.drafting.draft import choose_without_model, compile_draft
from argus.drafting.openapi import catalog_operations, load_openapi
from test_draft_target import agent_document, input_file, invoke


ASK = "/paths/~1ask/post"
REQUEST = ASK + "/requestBody/content/application~1json/schema"
RESPONSE = ASK + "/responses/200/content/application~1json/schema"


def request_schema(document):
    return document["paths"]["/ask"]["post"]["requestBody"]["content"]["application/json"]["schema"]


def response_schema(document):
    return document["paths"]["/ask"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]


def gap_file(out):
    return json.loads(out.with_suffix(".gaps.json").read_text())


def codes(out):
    return {gap["code"] for gap in gap_file(out)["gaps"]}


def unbound_optional_field(document, schema):
    request_schema(document)["properties"]["extra"] = schema


def unbound_error_response(document, schema):
    document["paths"]["/ask"]["post"]["responses"]["400"] = {"description": "Bad request", "content": {
        "application/json": {"schema": {"type": "object", "properties": {"detail": schema}}}}}


def unbound_optional_parameter(document, schema):
    document["paths"]["/ask"]["post"]["parameters"] = [{"name": "trace", "in": "query", "schema": schema}]


@pytest.mark.parametrize("place", [unbound_optional_field, unbound_error_response, unbound_optional_parameter])
@pytest.mark.parametrize("schema", [
    {"type": "string", "format": "uri"},
    {"type": "string", "minLength": 1},
    {"type": "string", "pattern": "^[a-z]+$"},
    {"type": "object", "additionalProperties": {"type": "string"}},
    {"type": "string", "const": "fixed"},
    {"allOf": [{"type": "string"}]},
])
def test_schemas_the_draft_does_not_bind_never_block(tmp_path, place, schema):
    document = agent_document()
    place(document, schema)
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert out.exists()
    assert gap_file(out)["state"] == "needs_review"
    assert not codes(out) & {"operation_unsupported", "schema_constraints_unchecked"}


def test_constraints_on_bound_fields_are_one_review_gap_naming_them(tmp_path):
    document = agent_document()
    request_schema(document)["properties"]["question"].update(minLength=1, maxLength=4000)
    request_schema(document)["additionalProperties"] = {"type": "string"}
    response_schema(document)["properties"]["answer"]["format"] = "markdown"
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert out.exists()
    gaps = [gap for gap in gap_file(out)["gaps"] if gap["code"] == "schema_constraints_unchecked"]
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap["blocking"] is False
    assert "additionalProperties, format, maxLength, minLength" in gap["why"]
    assert [source["pointer"] for source in gap["source"]] == [
        REQUEST, REQUEST + "/properties/question", RESPONSE + "/properties/answer"]
    assert "operation_unsupported" not in codes(out)


def test_unconstrained_draft_has_no_constraint_gap(tmp_path):
    result, out = invoke(tmp_path)
    assert result.exit_code == 3, result.output
    assert "schema_constraints_unchecked" not in codes(out)


@pytest.mark.parametrize("pointer,mutate", [
    (REQUEST + "/properties/question", lambda d: request_schema(d)["properties"]["question"].update(const="fixed")),
    (REQUEST + "/properties/question", lambda d: request_schema(d)["properties"]["question"].update(allOf=[{"minLength": 1}])),
    (REQUEST, lambda d: request_schema(d).update(oneOf=[{"required": ["question"]}])),
    (RESPONSE + "/properties/answer", lambda d: response_schema(d)["properties"]["answer"].update(contentMediaType="text/html")),
    (RESPONSE, lambda d: response_schema(d).update(patternProperties={"^x-": {"type": "string"}})),
    (REQUEST, lambda d: request_schema(d).update(additionalProperties="yes")),
    (ASK + "/requestBody/content/application~1json",
     lambda d: d["paths"]["/ask"]["post"]["requestBody"]["content"]["application/json"].update(encoding={"question": {}})),
])
def test_unsupported_structure_on_a_bound_schema_still_blocks(tmp_path, pointer, mutate):
    document = agent_document()
    mutate(document)
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    blocking = [gap for gap in gap_file(out)["gaps"] if gap["code"] == "operation_unsupported"]
    assert blocking and all(gap["blocking"] for gap in blocking)
    assert pointer in {source["pointer"] for gap in blocking for source in gap["source"]}


@pytest.mark.parametrize("extra,code", [({"pattern": "^[0-9]+$"}, "schema_constraints_unchecked"),
                                        ({"const": "fixed"}, "operation_unsupported")])
def test_bound_parameter_schema_is_gated(tmp_path, extra, code):
    document = agent_document()
    document["paths"]["/ask"]["post"]["parameters"] = [{"name": "tenant", "in": "query", "required": True,
                                                        "schema": {"type": "string", **extra}}]
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    gap = next(gap for gap in gap_file(out)["gaps"] if gap["code"] == code)
    assert gap["source"][-1]["pointer"] == ASK + "/parameters/0/schema"
    assert out.exists() is (code == "schema_constraints_unchecked")


def test_model_index_offers_constrained_fields_but_not_unsupported_ones(tmp_path):
    from argus.drafting.proposal import _reference_index
    document = agent_document()
    request_schema(document)["properties"]["question"]["minLength"] = 1
    request_schema(document)["properties"]["goal"] = {"type": "string", "const": "fixed"}
    request_schema(document)["properties"]["unused"] = {"type": "string", "format": "uri"}
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    prompts = _reference_index(catalog)["ask"]["prompt"]
    assert REQUEST + "/properties/question" in prompts
    assert REQUEST + "/properties/goal" not in prompts


def required_body_field(document, name="url", schema=None):
    request_schema(document)["required"].append(name)
    request_schema(document)["properties"][name] = schema or {"type": "string", "example": "https://example.invalid"}


def test_required_string_body_field_becomes_environment_binding(tmp_path):
    document = agent_document()
    required_body_field(document)
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    transport = json.loads(out.read_text())["transport"]
    assert transport["request"]["body"]["json"] == {"question": {"context": "prompt"}, "url": {"var": "input_url"}}
    assert transport["let"]["run"] == {"input_url": {"env": "TARGET_INPUT_URL"}}
    assert "example.invalid" not in out.read_text()
    gap = next(gap for gap in gap_file(out)["gaps"] if gap["code"] == "body_binding_required")
    assert gap["blocking"] is False and gap["field"] == "/transport/let/run/input_url"
    assert gap["source"][0]["pointer"] == REQUEST + "/properties/url"
    assert "business_input_missing" not in codes(out)
    provenance = json.loads(out.with_suffix(".provenance.json").read_text())
    assert provenance["fields"]["/transport/let/run/input_url"]["basis"] == "non_secret_binding_required"
    assert provenance["validation"]["offline"] == "passed"


@pytest.mark.parametrize("name", ["api_key", "accessToken", "password", "client_secret", "credential", "session_cookie"])
def test_secret_looking_required_body_field_keeps_blocking_gap(tmp_path, name):
    document = agent_document()
    required_body_field(document, name, {"type": "string"})
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "business_input_missing" in codes(out)
    assert "body_binding_required" not in codes(out)
    assert "TARGET_INPUT" not in out.with_suffix(".provenance.json").read_text()


@pytest.mark.parametrize("schema", [{"type": "integer"}, {"type": "string", "enum": ["a", "b"]},
                                    {"type": "string", "readOnly": True}, {"type": "string", "const": "fixed"}])
def test_required_body_field_with_documented_value_or_wrong_type_keeps_blocking_gap(tmp_path, schema):
    document = agent_document()
    required_body_field(document, "mode", schema)
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "business_input_missing" in codes(out)
    assert "body_binding_required" not in codes(out)


def test_required_body_field_colliding_with_parameter_binding_blocks(tmp_path):
    document = agent_document()
    required_body_field(document)
    document["paths"]["/ask"]["post"]["parameters"] = [{"name": "url", "in": "query", "required": True,
                                                        "schema": {"type": "string"}}]
    result, out = invoke(tmp_path, document)
    assert result.exit_code == 3, result.output
    assert not out.exists()
    assert "parameter_collision" in codes(out)


def test_required_body_constraints_join_the_review_gap(tmp_path):
    document = agent_document()
    required_body_field(document, schema={"type": "string", "minLength": 8})
    catalog = catalog_operations(load_openapi(input_file(tmp_path, document)))
    artifacts = compile_draft(catalog, choose_without_model(catalog))
    assert artifacts.spec is not None
    gap = next(gap for gap in artifacts.gaps if gap.code == "schema_constraints_unchecked")
    assert [source.pointer for source in gap.source] == [REQUEST + "/properties/url"]


def scenario_text(version, environment=None):
    data = {"version": version, "source": {"document": "independent.json", "pointers": [ASK]}, "resources": [],
            "operations": [{"id": "ask", "method": "POST", "path": "/ask", "role": "invoke",
                            "calls": {"min": 1, "max": 1},
                            "request": [{"check": "prompt_bound", "at": {"kind": "json", "pointer": "/question"}, "equals": "ping"}],
                            "replies": [{"status": 200, "body": {"status": "completed", "answer": "done"}, "effects": []}]}],
            "expect": {"outcome": "succeeded", "reply": "done", "resources": [], "required_gaps": []}}
    if environment is not None:
        data["environment"] = environment
    return json.dumps(data)


def scenario_file(tmp_path, version, environment=None):
    path = tmp_path / f"scenario-v{version}.json"
    path.write_text(scenario_text(version, environment))
    return path


def verify_cli(tmp_path, document, scenario):
    source = input_file(tmp_path, document)
    out = tmp_path / "target.json"
    result = CliRunner().invoke(main, ["draft-target", "--openapi", str(source), "--out", str(out), "--no-model",
                                       "--verify-local", "--scenario", str(scenario)])
    return result, json.loads(out.with_suffix(".provenance.json").read_text())["validation"]["local"]


def test_version_two_synthetic_environment_lets_required_body_draft_verify(tmp_path):
    document = agent_document()
    required_body_field(document)
    scenario = scenario_file(tmp_path, 2, {"TARGET_INPUT_URL": "https://material.invalid/doc"})
    result, local = verify_cli(tmp_path, document, scenario)
    assert local["status"] == "verified", local
    assert local["execution"]["requests"]["submit"] == 1
    assert result.exit_code == 3, result.output


def test_version_one_scenario_cannot_supply_the_required_body_binding(tmp_path):
    document = agent_document()
    required_body_field(document)
    result, local = verify_cli(tmp_path, document, scenario_file(tmp_path, 1))
    assert result.exit_code == 1, result.output
    assert local["status"] == "failed"
    assert "invoke_not_called" in local["checks"]


def test_version_one_scenario_still_verifies_a_plain_draft(tmp_path):
    result, local = verify_cli(tmp_path, agent_document(), scenario_file(tmp_path, 1))
    assert local["status"] == "verified", local
    assert result.exit_code == 3, result.output


def test_version_two_never_reads_process_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("TARGET_INPUT_URL", "https://material.invalid/doc")
    document = agent_document()
    required_body_field(document)
    result, local = verify_cli(tmp_path, document, scenario_file(tmp_path, 2, {}))
    assert result.exit_code == 1, result.output
    assert local["execution"]["requests"]["submit"] == 0


def scenario_data(version, environment=None):
    return importlib.import_module("argus.drafting.scenario"), json.loads(scenario_text(version, environment))


def test_scenario_versions_parse_their_own_fields():
    parser, v1 = scenario_data(1)
    assert parser.parse_scenario(v1).environment == ()
    _, v2 = scenario_data(2, {"TARGET_INPUT_URL": "https://material.invalid/doc"})
    assert parser.parse_scenario(v2).environment == (("TARGET_INPUT_URL", "https://material.invalid/doc"),)


@pytest.mark.parametrize("version,environment", [
    (1, {}), (1, {"TARGET_INPUT_URL": "x"}), (2, None), (3, None), (3, {}),
    (2, {"TARGET_API_KEY": "x"}), (2, {"FIXTURE_URL": "x"}), (2, {"TARGET_INPUT_": "x"}),
    (2, {"TARGET_INPUT_url": "x"}), (2, {"TARGET_INPUT_ACCESS_TOKEN": "x"}), (2, {"TARGET_INPUT_URL": 1}),
    (2, {"TARGET_INPUT_URL": ""}), (2, {"TARGET_INPUT_URL": "x" * 1025}), (2, {"TARGET_INPUT_URL": "a\nb"}), (2, []),
    (2, {f"TARGET_INPUT_F{index}": "x" for index in range(33)}),
])
def test_scenario_environment_is_version_two_only_and_non_secret(version, environment):
    parser, data = scenario_data(version, environment)
    with pytest.raises(ValueError, match="scenario_invalid"):
        parser.parse_scenario(data)


def test_scenario_environment_accepts_the_runtime_value_limit():
    parser, data = scenario_data(2, {"TARGET_INPUT_URL": "x" * 1024})
    assert parser.parse_scenario(data).environment == (("TARGET_INPUT_URL", "x" * 1024),)
