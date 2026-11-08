import asyncio
import copy
import hashlib
import json

import pytest

from argus.cli.verify_local import LocalFake, StrictLoopbackPolicy
from argus.drafting.openapi import catalog_operations, load_openapi
from argus.drafting.scenario import parse_scenario
from argus_transport import TransportSpecV2, V2Run, with_origin
from argus_transport.spec_v2 import TransportContextV2
from test_draft_bindings import artifacts, draft
from test_draft_setup_steps import blocking, note_step, run_draft, scenario, setup_document, source_step, steps


def multipart_document(properties=True):
    document = setup_document()
    schema = {"type": "object"}
    if properties:
        schema.update(required=["text", "source_id"], properties={
            "text": {"type": "string", "format": "binary"}, "source_id": {"type": "string"}})
    document["paths"]["/notes"]["post"]["requestBody"] = {
        "required": True, "content": {"multipart/form-data": {"schema": schema}}}
    return document


def upload_step(**changes):
    entry = note_step()
    entry.pop("values")
    entry["multipart"] = {"text": {"content": {"context": "material"}},
                          "source_id": {"content": {"var": "source_id"}}}
    return {**entry, **changes}


def multipart_scenario():
    value = scenario()
    upload = value["operations"][1]
    upload["request"][0]["at"] = {"kind": "multipart_file", "name": "text", "filename": "material.txt"}
    upload["request"][1]["at"] = {"kind": "multipart_file", "name": "source_id", "filename": "material.txt"}
    return value


def multipart_draft(tmp_path, upload=None, document=None, *options):
    return draft(tmp_path, document or multipart_document(), steps(source_step(), upload or upload_step()),
                 "--operation", "ask", *options)


def verify_multipart(tmp_path, bindings=None):
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(multipart_scenario()))
    return draft(tmp_path, multipart_document(), bindings or steps(source_step(), upload_step()),
                 "--operation", "ask", "--verify-local", "--scenario", str(path))


def test_multipart_material_setup_runs_and_cleans_every_resource(tmp_path):
    result, out = verify_multipart(tmp_path)
    assert "local.status: verified" in result.output, result.output
    spec, report, provenance = artifacts(out)
    assert blocking(report) == []
    upload = spec["transport"]["lifecycle"]["attempt"][0]
    assert upload["if_present"] == "material"
    assert upload["request"]["body"] == {"multipart": {
        "text": {"content": {"context": "material"}, "filename": {"literal": "material.txt"}, "content_type": "text/plain"},
        "source_id": {"content": {"var": "source_id"}, "filename": {"literal": "material.txt"}, "content_type": "text/plain"}}}
    assert spec["transport"]["budget"] == {"max_requests": 3, "cleanup_reserve": 2}
    local = provenance["validation"]["local"]
    assert [row["operation"] for row in local["trace"]] == ["create_source", "add_note", "ask", "delete_note", "delete_source"]
    assert all(row["state"] == "absent" for row in local["resources"])


def test_removing_multipart_upload_cannot_verify_material_binding(tmp_path):
    result, out = verify_multipart(tmp_path, steps(source_step()))
    assert result.exit_code == 1, result.output
    local = artifacts(out)[2]["validation"]["local"]
    assert local["status"] == "failed"
    assert "material_not_bound" in local["checks"]


def test_supplied_name_outside_documented_multipart_properties_blocks(tmp_path):
    upload = upload_step(multipart={"file": {"content": {"context": "material"}}})
    result, out = multipart_draft(tmp_path, upload)
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    assert any(gap["code"] == "binding_unresolved" and gap["source"][0]["pointer"] == "/steps/1/multipart/file"
               for gap in blocking(report))


def test_schema_without_properties_records_supplied_part_name_and_reason(tmp_path):
    _, out = multipart_draft(tmp_path, document=multipart_document(False))
    spec, report, provenance = artifacts(out)
    assert spec is not None, report
    field = "/transport/lifecycle/attempt/0/request/body/multipart/text/content"
    gap = next(gap for gap in report["gaps"] if gap["field"] == field and gap["code"] == "binding_user_supplied")
    assert "does not name" in gap["why"]
    assert "does not name" in provenance["fields"][field]["why"]


def test_no_material_skips_upload_and_cannot_pass_the_material_scenario(tmp_path):
    _, out = multipart_draft(tmp_path)
    spec = artifacts(out)[0]
    assert spec is not None
    catalog = catalog_operations(load_openapi(tmp_path / "api.json"))

    async def attempt():
        parsed = parse_scenario(multipart_scenario(), catalog=catalog)
        async with LocalFake(catalog, parsed) as fake:
            transport = TransportSpecV2.from_dict(with_origin(copy.deepcopy(spec["transport"]), fake.origin))
            run = V2Run(transport, policy=StrictLoopbackPolicy(fake.origin))
            try:
                result = await run.attempt(TransportContextV2(prompt="ping", material=None))
            finally:
                await run.close()
            return result, [row["operation"] for row in fake.trace], fake.material_observed

    result, trace, observed = asyncio.run(attempt())
    assert "add_note" not in trace and "delete_note" not in trace
    assert not observed
    assert result.outcome.value != "succeeded"


@pytest.mark.parametrize("multipart", [
    {},
    {f"part_{index}": {"content": {"literal": "plain"}} for index in range(5)},
    {"text": {}},
    {"text": {"content": {"literal": "synthetic_secret_marker"}}},
    {"text": {"content": {"literal": {"nested": ["synthetic_token_marker"]}}}},
    {"text": {"content": {"literal": "plain"}, "filename": "synthetic_password_marker.txt"}},
    {"text": {"content": {"context": "prompt"}}},
])
def test_invalid_multipart_parts_write_named_gaps_without_a_spec(tmp_path, multipart):
    result, out = multipart_draft(tmp_path, upload_step(multipart=multipart), multipart_document(False))
    assert result.exit_code == 3, result.output
    spec, report, _ = artifacts(out)
    assert spec is None
    assert blocking(report) and all(gap["code"] == "binding_unresolved" for gap in blocking(report))
    assert "synthetic_secret_marker" not in out.with_suffix(".gaps.json").read_text()
    assert "synthetic_token_marker" not in out.with_suffix(".gaps.json").read_text()


def test_multipart_on_json_only_operation_is_a_named_gap(tmp_path):
    _, out = multipart_draft(tmp_path, document=setup_document())
    spec, report, _ = artifacts(out)
    assert spec is None
    assert any(gap["code"] == "binding_unresolved" and "multipart" in gap["why"] for gap in blocking(report))


def test_json_values_and_multipart_cannot_coexist(tmp_path):
    _, out = multipart_draft(tmp_path, upload_step(values={"/text": {"literal": "plain"}}))
    spec, report, _ = artifacts(out)
    assert spec is None
    assert any(gap["code"] == "binding_unresolved" for gap in blocking(report))


def test_existing_json_step_artifact_bytes_match_main(tmp_path):
    _, out = run_draft(tmp_path, steps())
    expected = {
        "target.json": "16c1392559f15a3efbd8f9e87d3727ada8a73edc6b6d1104a2bdff519e7a90d6",
        "target.gaps.json": "5dd01bf271c4303865123f69a01e16245b86ca00b7f33cb109edd661700f75ec",
        "target.provenance.json": "b9500b281bd74f2a464c52aa02414d15f4a0f5d25cd16e7c906560201ede5c89",
    }
    assert {name: hashlib.sha256((out.parent / name).read_bytes()).hexdigest() for name in expected} == expected


def test_multipart_without_scenario_keeps_setup_unverified(tmp_path):
    result, out = multipart_draft(tmp_path, None, None, "--verify-local")
    assert "local.status: schema_mock_only" in result.output, result.output
    assert "setup_step:note" in artifacts(out)[2]["validation"]["local"]["unverified"]
