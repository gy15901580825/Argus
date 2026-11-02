"""argus-probe validate-target — quick reachability check on a target endpoint."""

import asyncio
import json
from dataclasses import replace
from pathlib import Path

import click
import httpx
import yaml

from argus.cli import run_json
from argus.cli.target_loader import TargetLoadError, check_target_spec

# Kinds that answer a chat prompt. The others (A2A, MCP and vLLM servers, testbed agents, uploads)
# are checked by their probes, so a ping proves nothing about them.
_CHAT_KINDS = ("openai_compat", "anthropic_native", "custom_http", "web_chat")


def _failure(exc: Exception) -> str:
    from argus.runner import _named
    from argus.targets._base import TargetBlockedError

    if isinstance(exc, httpx.HTTPStatusError):
        return f"target returned {exc.response.status_code}: {exc.response.text[:200]}"
    if isinstance(exc, TargetBlockedError):
        return f"target withheld its reply: {exc}"
    code = getattr(
        exc, "status_code", None
    )  # SDK errors such as anthropic.APIStatusError
    if isinstance(code, int):
        return f"target returned {code}: {exc}"
    if isinstance(exc, httpx.RequestError):
        return f"network error: {_named(exc)}"
    return f"target request failed: {_named(exc)}"


async def _ping(target) -> str:
    try:
        text, _ = await target.send_prompt("ping")
        return text
    finally:
        await target.aclose()  # web_chat holds a browser


def _parse(text: str):
    # JSON first, as `run` reads it; YAML for specs written before `run` required JSON.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return yaml.safe_load(text)


@click.command()
@click.option(
    "--target",
    "target_file",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
)
@click.option(
    "--offline",
    is_flag=True,
    help="Check configuration without requests or resolving secrets.",
)
@click.option(
    "--sample-response",
    type=click.Path(exists=True, dir_okay=False),
    help="Check a local JSON response while offline.",
)
@click.option(
    "--execute",
    is_flag=True,
    help="Send a benign request. This can use target tools and incur costs.",
)
@click.option(
    "--endpoint-override", help="Send the request to a controlled alternate endpoint."
)
def cmd_validate_target(
    target_file: str,
    offline: bool,
    sample_response: str | None,
    execute: bool,
    endpoint_override: str | None,
):
    """Send one prompt to a chat target the way `run` does and report whether it answered."""
    from argus.targets import build_target

    if offline and execute:
        raise click.UsageError("--offline and --execute are mutually exclusive")
    if sample_response and not offline:
        raise click.UsageError("--sample-response requires --offline")
    if endpoint_override and not execute:
        raise click.UsageError("--endpoint-override requires --execute")
    try:
        raw = _parse(Path(target_file).read_text())
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise click.ClickException(f"cannot read the target file as JSON or YAML: {e}")
    if isinstance(raw, dict) and "kind" not in raw:
        raw = {"kind": "openai_compat", **raw}  # specs written before `kind` existed
    try:
        spec, substituted = check_target_spec(raw)
    except TargetLoadError as e:
        raise click.ClickException(str(e))
    kind = spec["kind"]
    if "transport" in spec:
        return _validate_transport(
            spec,
            offline=offline or not execute,
            sample_response=sample_response,
            endpoint_override=endpoint_override,
        )
    if offline:
        try:
            build_target(spec)
        except Exception as exc:
            raise click.ClickException(
                f"target spec invalid: {type(exc).__name__}"
            ) from exc
        click.echo(
            "legacy configuration: valid; requests.submit=0 requests.poll=0 requests.retry=0"
        )
        if kind == "custom_http":
            _migration_diagnostic(spec)
        return
    if sample_response or endpoint_override:
        raise click.UsageError("these options require a transport specification")
    # The same masking as run's reports: expanded $VARs and secret-named fields.
    secrets = run_json.run_secrets(spec, substituted)

    def fail(message: str):
        raise click.ClickException(run_json.mask_text(message, secrets))

    try:
        target = build_target(spec)
    except (
        Exception
    ) as e:  # spec values the adapter rejects (a bad JSONPath, a wrong type)
        fail(f"target spec invalid: {type(e).__name__}: {e}")
    if kind not in _CHAT_KINDS:
        raise click.UsageError(
            f"validate-target checks chat targets ({', '.join(_CHAT_KINDS)}), not {kind}. "
            f"Run its probes instead: argus-probe run --local --target {target_file} --probes all"
        )
    try:
        text = asyncio.run(_ping(target))
    except Exception as e:  # every failure is the answer this command exists to give
        fail(_failure(e))
    if not text.strip():
        fail(
            "target replied, but the reply text is empty; check the response shape or path"
        )
    where = (
        raw.get("endpoint_url")
        or raw.get("request_url")
        or raw.get("url")
        or f"anthropic {raw['model']}"
    )
    click.echo(
        run_json.mask_text(
            f"OK — target {where} replied with {len(text)} chars", secrets
        )
    )


def _migration_diagnostic(spec):
    from argus.cli.baseline_key import baseline_key

    click.echo(f"baseline.legacy: {baseline_key(spec)}")
    click.echo(
        "Migration changes target identity. Collect a new baseline (rebaseline); existing baselines cannot be compared across identities."
    )
    click.echo(
        "migration.fields: request_url, request_body_template, response_jsonpath"
    )
    candidate = _migration_candidate(spec)
    if candidate is None:
        click.echo(
            "baseline.new: unavailable until the legacy template is manually migrated"
        )
    else:
        click.echo(
            f"baseline.new: {baseline_key({'kind': 'custom_http', 'transport': candidate})}"
        )


def _migration_candidate(spec):
    import re
    from argus_transport import TransportSpec

    body = spec["request_body_template"]
    token = "__ARGUS_PROMPT_CONTEXT__"
    body = re.sub(r"\{\{\s*prompt\s*\|\s*tojson\s*\}\}", json.dumps(token), body)
    if (
        "{{" in body
        or "{%" in body
        or spec.get("api_key")
        or spec.get("request_headers")
    ):
        return None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return None

    def expression(value):
        if value == token:
            return {"context": "prompt"}
        if isinstance(value, dict):
            return {"object": {key: expression(item) for key, item in value.items()}}
        if isinstance(value, list):
            return {"array": [expression(item) for item in value]}
        return {"literal": value}

    if not isinstance(parsed, dict):
        return None
    candidate = {
        "version": 1,
        "request": {
            "url": spec["request_url"],
            "method": spec.get("request_method", "POST"),
            "headers": {},
            "body": {"json": {key: expression(value) for key, value in parsed.items()}},
        },
        "auth": {"kind": "none"},
        "response": {
            "format": "json",
            "text": {
                "paths": [spec["response_jsonpath"]],
                "cast": "string_or_json",
                "empty": "error",
            },
            "metadata": {},
        },
        "outcome": {"kind": "http_only"},
        "delivery": {"kind": "sync"},
        "timeout": {
            "total_deadline_s": spec.get("timeout_s", 120),
            "read_s": spec.get("timeout_s", 120),
        },
        "session": {"mode": "none"},
        "limits": {},
    }
    try:
        TransportSpec.from_dict(candidate)
    except ValueError:
        return None
    return candidate


def _validate_transport(spec, *, offline, sample_response, endpoint_override):
    from argus_transport import (
        TransportContext,
        TransportEngine,
        TransportOutcome,
        TransportSpec,
        evaluate_response,
        local_transport_mode,
        execution_policy,
        render_request,
    )
    from argus.targets import build_target

    try:
        build_target(spec)
        transport = TransportSpec.from_dict(spec["transport"])
        if endpoint_override:
            candidate = transport.to_dict()
            candidate["request"]["url"] = endpoint_override
            transport = TransportSpec.from_dict(candidate)
        if spec["kind"] != "custom_http":
            raise ValueError("browser transport validation requires a scenario context")
        context = TransportContext(prompt="ping")
        body = render_request(transport.request, context)
    except Exception as exc:
        raise click.ClickException(
            f"target spec invalid: {type(exc).__name__}"
        ) from exc
    click.echo(f"spec.transport.version: {transport.version} OK")
    click.echo(f"request.method: {transport.request.method}")
    click.echo("request.url: <configured endpoint>")
    click.echo(
        f"request.body.bytes: {len(body.encode('utf-8')) if isinstance(body, str) else len(body or b'')}"
    )
    bindings = {}
    for key, expression in list(transport.request.body.get("json", {}).items())[:32]:
        name = str(key)[:64]
        if "context" in expression:
            bindings[name] = {"context": expression["context"]}
        elif "literal" in expression:
            bindings[name] = {"literal_type": type(expression["literal"]).__name__}
        else:
            bindings[name] = {
                "structure": "object" if "object" in expression else "array"
            }
    click.echo(f"request.bindings: {json.dumps(bindings, ensure_ascii=True)}")
    for header in transport.auth.headers:
        click.echo(
            f"auth.header: {header.name} = <redacted>; source={header.secret.source}"
        )
    if offline and not sample_response:
        click.echo("requests.submit=0 requests.poll=0 requests.retry=0")
        return
    if sample_response:
        try:
            sample = json.loads(Path(sample_response).read_text())
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
        ) as exc:
            raise click.ClickException(
                "sample response must be a readable JSON document"
            ) from exc
        result = evaluate_response(transport, 200, sample)
        requests = {"submit": 0, "poll": 0, "retry": 0}
    else:

        async def execute_transport():
            with local_transport_mode():
                return await TransportEngine(
                    transport, policy=execution_policy(transport)
                ).run(context)

        result = asyncio.run(execute_transport())
        requests = result.diagnostics.get(
            "requests", {"submit": 1, "poll": 0, "retry": 0}
        )
    if result.outcome == TransportOutcome.SUCCEEDED:
        from argus.targets.custom_http import run_log_from_metadata
        from argus_transport import SafeReasonCode

        try:
            run_log_from_metadata(result.as_dict()["metadata"])
        except (ValueError, TypeError):
            result = replace(
                result,
                outcome=TransportOutcome.TARGET_ERROR,
                response_text=None,
                reason_code=SafeReasonCode.MAPPING_ERROR,
            )
    click.echo(f"HTTP.status: {result.http_status}")
    click.echo(f"outcome.selected: {result.matched_rule_id} -> {result.outcome.value}")
    for path, status in result.diagnostics.get("response_paths", {}).items():
        click.echo(f"response.path: {path} {status}")
    if result.diagnostics.get("top_keys"):
        click.echo(f"response.top_keys: {json.dumps(result.diagnostics['top_keys'])}")
    click.echo(
        " ".join(
            f"requests.{key}={requests.get(key, 0)}"
            for key in ("submit", "poll", "retry")
        )
    )
    if result.outcome not in {TransportOutcome.SUCCEEDED, TransportOutcome.BLOCKED}:
        raise click.ClickException(
            f"transport.{result.reason_code.value}: {result.outcome.value}; check configured response paths"
        )
