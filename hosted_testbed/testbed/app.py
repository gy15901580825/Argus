import argparse
import asyncio
import html
import ipaddress
import json
import logging
import os
import re
import time
from urllib.parse import urlsplit

from aiohttp import web

from .auth import OwnerVerifier
from .memory import MemoryStore
from .service import HostedService, Rejected, digest


SERVICE = web.AppKey("service", HostedService)
VERIFIER = web.AppKey("verifier", OwnerVerifier)
ORIGIN = web.AppKey("origin", str)
PROXIES = web.AppKey("trusted_proxies", tuple)
CLEANUP = web.AppKey("cleanup_task", asyncio.Task)


def _bearer(request):
    value = request.headers.get("Authorization", "")
    if not value.startswith("Bearer ") or not value[7:]:
        raise Rejected(401, "missing_token")
    return value[7:]


def _client_ip(request):
    peer = request.transport.get_extra_info("peername") if request.transport else None
    actual = peer[0] if peer else "unknown"
    try:
        address = ipaddress.ip_address(actual)
    except ValueError:
        return "unknown"
    trusted = request.app[PROXIES]
    if not any(address in network for network in trusted):
        return actual
    chain = request.headers.get("X-Forwarded-For", "")
    if len(chain) > 1024:
        return actual
    try:
        hops = [ipaddress.ip_address(value.strip()) for value in chain.split(",") if value.strip()]
    except ValueError:
        return actual
    for address in reversed(hops):
        if not any(address in network for network in trusted):
            return str(address)
    return actual


@web.middleware
async def errors(request, handler):
    try:
        return await handler(request)
    except Rejected as error:
        return web.json_response({"error": error.code}, status=error.status)
    except web.HTTPException as error:
        return web.json_response({"error": "request_rejected"}, status=error.status)
    except Exception:
        return web.json_response({"error": "service_unavailable"}, status=503)


async def _owner(request, role="HostedRun.Control"):
    owner = await asyncio.to_thread(request.app[VERIFIER].verify, _bearer(request), role)
    await asyncio.to_thread(request.app[SERVICE].rate, "control", owner, 60, 60)
    return owner


async def _json(request):
    if request.content_type != "application/json":
        raise Rejected(400, "json_required")
    try:
        async with asyncio.timeout(5):
            body = await request.read()
        value = json.loads(body)
    except (TimeoutError, ValueError, UnicodeError):
        raise Rejected(400, "invalid_json") from None
    if not isinstance(value, dict):
        raise Rejected(400, "object_required")
    return value


def _fields(data, allowed):
    if not set(data) <= set(allowed):
        raise Rejected(400, "unsupported_field")


async def create_run(request):
    owner = await _owner(request, "HostedRun.Create")
    data = await _json(request)
    _fields(data, {"schema_version", "ttl_seconds"})
    if data.get("schema_version") != 1:
        raise Rejected(400, "unsupported_version")
    result = await asyncio.to_thread(request.app[SERVICE].create_run, owner, ttl_seconds=data.get("ttl_seconds", 86400), idempotency_key=request.headers.get("Idempotency-Key"))
    return web.json_response(result, status=200 if result.get("replayed") else 201)


async def create_probe(request):
    owner = await _owner(request)
    data = await _json(request)
    _fields(data, {"kind", "scenario_id", "payload", "synthetic_markers", "script", "ttl_seconds", "public_token"})
    if data.get("kind") not in {"browser", "ui_phishing"}:
        raise Rejected(400, "unsupported_kind")
    scenario = data.get("scenario_id", "synthetic-page")
    if not isinstance(scenario, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", scenario):
        raise Rejected(400, "invalid_scenario_id")
    script = data.get("script", {})
    if not isinstance(script, dict):
        raise Rejected(400, "invalid_script")
    _fields(script, {"combine_fields"})
    values = data.get("synthetic_markers", [])
    if not isinstance(values, list) or len(values) > 32:
        raise Rejected(400, "invalid_markers")
    markers = {}
    for item in values:
        if not isinstance(item, dict) or set(item) != {"marker_id", "value"} or not isinstance(item["marker_id"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", item["marker_id"]) or item["marker_id"] in markers:
            raise Rejected(400, "invalid_markers")
        markers[item["marker_id"]] = item["value"]
    run = await asyncio.to_thread(request.app[SERVICE]._owner, owner, request.match_info["rid"])
    capability = data.get("public_token")
    if not isinstance(capability, str) or not capability or len(capability) > 128:
        raise Rejected(400, "public_token_required")
    result = await asyncio.to_thread(request.app[SERVICE].create_probe, owner, request.match_info["rid"], payload=data.get("payload", "Synthetic page"), markers=markers, lease_seconds=data.get("ttl_seconds", 10800), combination=script.get("combine_fields", []), capability_hash=digest(capability))
    prefix = f'{request.app[ORIGIN]}/r/{capability}/p/{result["probe_id"]}'
    result.update({"scenario_url": prefix + "/scenario", "sink_url": prefix + "/sink/kyc", "mcp_url": None, "a2a_url": None, "merchant_url": None})
    return web.json_response(result, status=201)


async def seal(request):
    owner = await _owner(request)
    data = await _json(request)
    _fields(data, {"reason"})
    reason = data.get("reason")
    if reason not in {"vendor_terminal", "timeout"}:
        raise Rejected(400, "invalid_seal_reason")
    svc = request.app[SERVICE]
    rid, pid = request.match_info["rid"], request.match_info["pid"]
    pending = await asyncio.to_thread(svc.start_seal, owner, rid, pid)
    deadline = time.monotonic() + 5
    while pending and time.monotonic() < deadline:
        await asyncio.sleep(0.05)
        run = await asyncio.to_thread(svc.store.get, rid, svc.clock())
        pending = run.probes[pid].pending if run and pid in run.probes else 0
    result = await asyncio.to_thread(svc.seal, owner, rid, pid, reason)
    run = await asyncio.to_thread(svc.store.get, rid, svc.clock())
    result["complete"] = run.probes[pid].snapshot["summary"]["complete"]
    return web.json_response(result)


async def rotate(request):
    owner = await _owner(request)
    data = await _json(request)
    _fields(data, {"scope"})
    if data.get("scope") not in {"public", "evidence"}:
        raise Rejected(400, "invalid_scope")
    return web.json_response(await asyncio.to_thread(request.app[SERVICE].rotate, owner, request.match_info["rid"], scope=data["scope"]))


async def delete(request):
    owner = await _owner(request)
    return web.json_response(await asyncio.to_thread(request.app[SERVICE].delete, owner, request.match_info["rid"]))


async def renew(request):
    owner = await _owner(request)
    data = await _json(request)
    _fields(data, {"ttl_seconds"})
    return web.json_response(await asyncio.to_thread(request.app[SERVICE].renew, owner, request.match_info["rid"], request.match_info["pid"], lease_seconds=data.get("ttl_seconds", 10800)))


async def evidence(request):
    token = _bearer(request)
    svc = request.app[SERVICE]
    try:
        limit = int(request.query.get("limit", "100"))
    except ValueError:
        raise Rejected(400, "invalid_limit") from None
    await asyncio.to_thread(svc.authorize_evidence, token, request.match_info["rid"])
    await asyncio.to_thread(svc.rate, "evidence", digest(token), 30, 30)
    result = await asyncio.to_thread(svc.evidence, token, request.match_info["rid"], request.query.get("probe_id", ""), cursor=request.query.get("cursor"), late_cursor=request.query.get("late_cursor"), limit=limit)
    return web.json_response(result, headers={"Cache-Control": "no-store"})


async def public(request):
    svc = request.app[SERVICE]
    pid = request.match_info["pid"]
    token = request.match_info["token"]
    if len(token) > 128:
        raise Rejected(404, "not_found")
    try:
        await asyncio.to_thread(svc.rate, "ip", _client_ip(request), 300, 60)
    except Rejected:
        try:
            identified = await asyncio.to_thread(svc.public, token, pid)
            await asyncio.to_thread(svc.dropped, identified.run_id, pid)
        except Rejected:
            pass
        raise
    run = await asyncio.to_thread(svc.public, token, pid)
    try:
        await asyncio.to_thread(svc.rate, "public", digest(token), 60, 20)
    except Rejected as error:
        if error.status == 429:
            await asyncio.to_thread(svc.dropped, run.run_id, pid)
        raise
    is_sink = "tail" in request.match_info
    if not is_sink and request.method not in {"GET", "HEAD"} or is_sink and request.method not in {"GET", "HEAD", "POST"}:
        raise Rejected(405, "method_not_allowed")
    admitted = await asyncio.to_thread(svc.begin, run.run_id, pid)
    tail = request.match_info.get("tail", "")
    route = "/sink/" + tail if tail in {"kyc", "oauth/grant"} else "/sink/other" if is_sink else "/scenario"
    raw = bytearray()
    complete = True
    status = 204 if is_sink else 200
    try:
        async with asyncio.timeout(5):
            async for chunk in request.content.iter_chunked(8192):
                if len(raw) + len(chunk) > 65536:
                    raw.extend(chunk[:65536 - len(raw)])
                    complete, status = False, 413
                    break
                raw.extend(chunk)
    except (TimeoutError, ConnectionError):
        complete, status = False, 408
    try:
        body = raw.decode("utf-8")
    except UnicodeError:
        body = raw.decode("utf-8", errors="replace")
        complete = False
    parts = {"path": tail[:65536], "query": request.query_string[:65536], "body": body}
    if len(tail) > 65536 or len(request.query_string) > 65536:
        complete = False
    prefetch = any("prefetch" in request.headers.get(name, "").lower() for name in ("Purpose", "Sec-Purpose", "X-Moz"))
    await asyncio.to_thread(svc.record, run.run_id, pid, method=request.method, route_class=route, parts=parts, complete=complete, prefetch=prefetch, admitted=admitted)
    if not admitted:
        return web.json_response({"error": "sealed"}, status=409)
    if status not in {200, 204}:
        return web.json_response({"error": "incomplete_body"}, status=status)
    if is_sink:
        return web.Response(status=204)
    payload = html.escape(run.probes[pid].payload)
    return web.Response(text="<!doctype html><html><head><title>Synthetic page</title></head><body><main>" + payload + "</main></body></html>", content_type="text/html", headers={"Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'none'; frame-ancestors 'none'"})


async def _cleanup_forever(service, *, interval=900):
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(service.cleanup)
        except Exception:
            logging.getLogger(__name__).warning("Cleanup failed; the next scheduled attempt will retry")


async def _lifecycle(app):
    svc = app[SERVICE]
    await asyncio.to_thread(svc.cleanup)

    task = asyncio.create_task(_cleanup_forever(svc))
    app[CLEANUP] = task
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


def create_app(service, verifier, *, public_origin, trusted_proxy_cidrs=()):
    origin = urlsplit(public_origin)
    if origin.scheme != "https" or not origin.netloc or origin.path not in {"", "/"} or origin.query or origin.fragment or origin.username:
        raise ValueError("invalid public origin")
    app = web.Application(middlewares=[errors], client_max_size=65536)
    app[SERVICE], app[VERIFIER], app[ORIGIN] = service, verifier, public_origin.rstrip("/")
    app[PROXIES] = tuple(ipaddress.ip_network(value) for value in trusted_proxy_cidrs)
    app.cleanup_ctx.append(_lifecycle)
    app.router.add_post("/v1/runs", create_run)
    app.router.add_post("/v1/runs/{rid}/probes", create_probe)
    app.router.add_post("/v1/runs/{rid}/probes/{pid}/seal", seal)
    app.router.add_post("/v1/runs/{rid}/probes/{pid}/renew", renew)
    app.router.add_post("/v1/runs/{rid}/tokens/rotate", rotate)
    app.router.add_delete("/v1/runs/{rid}", delete)
    app.router.add_get("/v1/runs/{rid}/evidence", evidence)
    app.router.add_route("*", "/r/{token}/p/{pid}/scenario", public)
    app.router.add_route("*", "/r/{token}/p/{pid}", public)
    app.router.add_route("*", "/r/{token}/p/{pid}/sink/{tail:.*}", public)
    return app


def application_from_environment():
    names = ("HOSTED_ENTRA_TENANT_ID", "HOSTED_ENTRA_AUDIENCE", "HOSTED_TABLES_ENDPOINT", "HOSTED_TABLE_PREFIX", "HOSTED_PUBLIC_ORIGIN")
    values = {name: os.environ.get(name, "") for name in names}
    if any(not value for value in values.values()):
        raise ValueError("required hosted configuration is missing")
    tenant = values["HOSTED_ENTRA_TENANT_ID"]
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", tenant) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,50}", values["HOSTED_TABLE_PREFIX"]):
        raise ValueError("invalid hosted identity or table configuration")
    endpoint = urlsplit(values["HOSTED_TABLES_ENDPOINT"])
    if endpoint.scheme != "https" or not re.fullmatch(r"[a-z0-9]+\.table\.core\.windows\.net", endpoint.netloc) or endpoint.path not in {"", "/"} or endpoint.query or endpoint.fragment:
        raise ValueError("invalid hosted storage endpoint")
    mode = os.environ.get("HOSTED_STORE", "tables")
    if mode == "tables":
        from .tables import TablesStore
        store = TablesStore(values["HOSTED_TABLES_ENDPOINT"], values["HOSTED_TABLE_PREFIX"])
    elif mode == "memory":
        store = MemoryStore()
    else:
        raise ValueError("invalid hosted store")
    return create_app(HostedService(store), OwnerVerifier(tenant, values["HOSTED_ENTRA_AUDIENCE"]), public_origin=values["HOSTED_PUBLIC_ORIGIN"], trusted_proxy_cidrs=tuple(value for value in os.environ.get("HOSTED_TRUSTED_PROXY_CIDRS", "").split(",") if value))


def main():
    parser = argparse.ArgumentParser(description="Hosted synthetic pages and redacted evidence")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    web.run_app(application_from_environment(), host=args.host, port=args.port, access_log=None)


if __name__ == "__main__":
    main()
