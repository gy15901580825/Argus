import pytest
from aiohttp import web

from argus.targets.custom_http import CustomHTTPSpec, CustomHTTPTarget
from argus_transport import TransportSpecV2, local_transport_mode
from test_transport_engine import spec_dict
from test_transport_poll import poll_dict
from transport_v2_fakes import RecordingApp, serve


@pytest.mark.parametrize("parsed", [False, True])
async def test_required_poll_browser_context_rejected_before_submit(parsed):
    app = RecordingApp()

    async def accepted(request):
        return web.json_response({"status": "PENDING", "run_id": "job-1"}, status=202)

    app.route("POST", "/run", accepted)
    async with serve(app) as origin:
        data = poll_dict(origin + "/run")
        data["version"] = 2
        data["delivery"]["request"]["query"] = {
            "scenario": {"context": "scenario_url"}
        }
        transport = TransportSpecV2.from_dict(data) if parsed else data
        with pytest.raises(ValueError, match="scenario_url context requires a browser target"):
            CustomHTTPTarget(CustomHTTPSpec(transport=transport))
        assert app.calls == []


@pytest.mark.parametrize("owner", ["run", "attempt", "submit_query", "poll_query", "json", "text"])
@pytest.mark.parametrize("optional", [False, True])
def test_browser_context_rejected_in_each_v2_expression_owner(owner, optional):
    data = poll_dict("http://127.0.0.1:1/run")
    data["version"] = 2
    expression = {"context": "scenario_url"}
    if optional:
        expression["missing"] = "omit"
    if owner in {"run", "attempt"}:
        data["let"] = {owner: {"ref": expression}}
    elif owner in {"submit_query", "poll_query"}:
        request = data["request"] if owner == "submit_query" else data["delivery"]["request"]
        request["query"] = {"scenario": expression}
    else:
        data["request"]["body"] = (
            {"json": {"scenario": expression}} if owner == "json" else {"text": expression}
        )
    with pytest.raises(ValueError, match="scenario_url context requires a browser target"):
        CustomHTTPSpec(transport=data)


@pytest.mark.parametrize("expression", [
    {"base64": {"context": "scenario_url"}},
    {"concat": [{"literal": "prefix"}, {"context": "scenario_url"}]},
    {"array": [{"object": {"page": {"context": "scenario_url", "missing": "omit"}}}]},
    {"object": {"array": {"array": [{"base64": {"concat": [
        {"literal": "prefix"}, {"context": "scenario_url"}
    ]}}]}}},
])
def test_nested_v2_operators_reject_browser_context(expression):
    data = spec_dict()
    data["version"] = 2
    data["request"]["body"] = {"json": {"value": expression}}
    with pytest.raises(ValueError, match="scenario_url context requires a browser target"):
        CustomHTTPSpec(transport=data)


async def test_literal_contents_and_expression_named_fields_are_ordinary_data():
    app = RecordingApp()
    received = []

    async def completed(request):
        received.append(await request.json())
        return web.json_response({"status": "COMPLETED", "result": "done"})

    app.route("POST", "/run", completed)
    async with serve(app) as origin:
        data = spec_dict(origin + "/run")
        data["version"] = 2
        data["let"] = {
            "run": {"context": {"literal": "scenario_url"}},
            "attempt": {"object": {"literal": "scenario_url"}},
        }
        data["request"]["body"] = {"json": {
            "context": {"literal": "scenario_url"},
            "literal": {"literal": {"context": "scenario_url", "array": [
                {"base64": {"context": "scenario_url"}}
            ]}},
            "object": {"object": {"context": {"literal": "scenario_url"}}},
            "run": {"var": "context"},
            "attempt": {"var": "object"},
        }}
        data["request"]["query"] = {"context": {"literal": "scenario_url"}}
        instance = CustomHTTPTarget(CustomHTTPSpec(transport=data))
        with local_transport_mode():
            assert (await instance.send_prompt("ping"))[0] == "done"
        assert received == [{
            "context": "scenario_url",
            "literal": {"context": "scenario_url", "array": [
                {"base64": {"context": "scenario_url"}}
            ]},
            "object": {"context": "scenario_url"},
            "run": "scenario_url",
            "attempt": "scenario_url",
        }]
        assert [call[:2] for call in app.calls] == [("POST", "/run?context=scenario_url")]


@pytest.mark.parametrize("owner", ["run_request", "attempt_request", "undo_request", "run_prefix", "attempt_prefix"])
@pytest.mark.parametrize("parsed", [False, True])
def test_lifecycle_browser_context_rejected_at_target_boundary(owner, parsed):
    from test_transport_v2_schema import lifecycle_dict

    data = lifecycle_dict()
    expression = {"base64": {"context": "scenario_url", "missing": "omit"}}
    if owner == "run_request":
        data["lifecycle"]["run"][0]["request"]["body"] = {"text": expression}
    elif owner == "attempt_request":
        data["lifecycle"]["attempt"][0]["request"]["query"] = {"scenario": expression}
    elif owner == "undo_request":
        data["lifecycle"]["run"][0]["undo"]["request"]["query"] = {"scenario": expression}
    else:
        scope = "run" if owner == "run_prefix" else "attempt"
        capture = "ref" if scope == "run" else "item"
        data["lifecycle"][scope][0]["capture"][capture]["expect_prefix"] = expression
    transport = TransportSpecV2.from_dict(data) if parsed else data
    with pytest.raises(ValueError, match="scenario_url context requires a browser target"):
        CustomHTTPSpec(transport=transport)
