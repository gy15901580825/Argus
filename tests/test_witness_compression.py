"""Compressed witness traffic remains observable without changing wire bytes."""
import gzip
import json
import zlib
from dataclasses import asdict

import pytest
from aiohttp import ClientSession

from test_witness import FAKE_KEY, upstream, witness


def compress(body, encoding):
    if encoding in {"gzip", "x-gzip"}:
        return gzip.compress(body)
    if encoding == "raw-deflate":
        compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
        return compressor.compress(body) + compressor.flush()
    return zlib.compress(body)


@pytest.mark.parametrize("encoding", ["gzip", "x-gzip", "deflate", "raw-deflate"])
async def test_compressed_relay_inspects_canary_without_changing_wire_bytes(witness, upstream, encoding):
    body = compress(("%argus_secret% " + witness.canary + " " + FAKE_KEY).encode(), encoding)
    async with ClientSession() as client:
        async with client.post(witness.urls["model_relay"] + "chat", data=body,
                               headers={"Content-Encoding": encoding.removeprefix("raw-"),
                                        "Authorization": "Bearer " + FAKE_KEY}) as response:
            assert await response.read() == b"".join(upstream["chunks"])
    assert upstream["requests"][0][3] == body
    record = witness.relay_records[0]
    assert record.canary_seen is True and record.placeholder_seen is True
    assert record.inspected is True and record.inspection_error is None
    assert record.body_size == len(body)
    assert witness.marker in record.excerpt
    assert witness.canary not in json.dumps(asdict(record))
    assert FAKE_KEY not in json.dumps(asdict(record))


@pytest.mark.parametrize("content_type", ["application/json", "application/x-protobuf"])
async def test_gzip_otlp_inspects_json_and_protobuf(witness, content_type):
    witness.register_values(["control", "absent"])
    if content_type == "application/json":
        decoded = json.dumps({"resourceSpans": [{"scopeSpans": [{"spans": [
            {"attributes": [{"key": "filled", "value": {"stringValue": witness.canary}}]},
            {"name": "control"}]}]}]}).encode()
    else:
        value = witness.canary.encode()
        decoded = b"\x0a" + bytes([len(value)]) + value + b"control"
    body = gzip.compress(decoded)
    async with ClientSession() as client:
        async with client.post(witness.urls["otlp"] + "v1/traces", data=body,
                               headers={"Content-Type": content_type, "Content-Encoding": "gzip"}) as response:
            assert response.status == 200
            assert response.content_type == content_type
            assert await response.read() == (b"{}" if content_type == "application/json" else b"")
    record = witness.export_records[0]
    assert record.canary_seen is True and record.values_seen == (True, False)
    assert record.inspected is True and record.inspection_error is None
    assert record.span_count == (2 if content_type == "application/json" else None)
    assert record.size == len(body)
    assert witness.canary not in json.dumps(asdict(record))


@pytest.mark.parametrize("channel", ["model_relay", "otlp"])
@pytest.mark.parametrize("encoding,body,reason", [
    ("unknown", b"opaque", "unsupported_encoding"),
    ("br", b"opaque", "unsupported_encoding"),
    ("zstd", b"opaque", "unsupported_encoding"),
    ("gzip", b"invalid", "decode_error"),
    ("deflate", b"invalid", "decode_error"),
])
async def test_uninspectable_body_is_explicit_and_still_delivered(witness, upstream, channel, encoding, body, reason):
    path = "chat" if channel == "model_relay" else "v1/traces"
    async with ClientSession() as client:
        async with client.post(witness.urls[channel] + path, data=body,
                               headers={"Content-Type": "application/json", "Content-Encoding": encoding}) as response:
            assert response.status == 200
            await response.read()
    record = (witness.relay_records if channel == "model_relay" else witness.export_records)[0]
    assert record.inspected is False and record.inspection_error == reason
    assert record.canary_seen is False
    if channel == "model_relay":
        assert upstream["requests"][0][3] == body
        assert record.placeholder_seen is False and record.excerpt is None
    else:
        assert record.span_count is None


@pytest.mark.parametrize("channel", ["model_relay", "otlp"])
async def test_decoded_size_limit_is_explicit_and_preserves_delivery(witness, upstream, monkeypatch, channel):
    import argus.witness as module
    monkeypatch.setattr(module, "_DECODE_LIMIT", 512, raising=False)
    body = gzip.compress(b"x" * 513 + witness.canary.encode())
    path = "chat" if channel == "model_relay" else "v1/traces"
    async with ClientSession() as client:
        async with client.post(witness.urls[channel] + path, data=body,
                               headers={"Content-Type": "application/json", "Content-Encoding": "gzip"}) as response:
            assert response.status == 200
            await response.read()
    record = (witness.relay_records if channel == "model_relay" else witness.export_records)[0]
    assert record.inspected is False and record.inspection_error == "decode_limit"
    if channel == "model_relay":
        assert upstream["requests"][0][3] == body


@pytest.mark.parametrize("separate_headers", [False, True])
async def test_stacked_and_concatenated_encoding_is_inspected(witness, upstream, separate_headers):
    body = zlib.compress(gzip.compress(b"prefix ") + gzip.compress(witness.canary.encode()))
    headers = [("Content-Encoding", "gzip"), ("Content-Encoding", "deflate")] if separate_headers else {"Content-Encoding": "gzip, deflate"}
    async with ClientSession() as client:
        async with client.post(witness.urls["model_relay"] + "chat", data=body,
                               headers=headers) as response:
            await response.read()
    record = witness.relay_records[0]
    assert record.inspected is True and record.canary_seen is True
    assert upstream["requests"][0][3] == body


async def test_truncated_compressed_body_is_not_reported_as_inspected(witness):
    body = gzip.compress(witness.canary.encode())[:-4]
    async with ClientSession() as client:
        async with client.post(witness.urls["otlp"] + "v1/traces", data=body,
                               headers={"Content-Type": "application/x-protobuf", "Content-Encoding": "gzip"}) as response:
            assert response.status == 200
    record = witness.export_records[0]
    assert record.inspected is False and record.inspection_error == "decode_error"


async def test_exact_decoded_limit_is_inspected(witness, monkeypatch):
    import argus.witness as module
    decoded = witness.canary.encode()
    monkeypatch.setattr(module, "_DECODE_LIMIT", len(decoded), raising=False)
    async with ClientSession() as client:
        async with client.post(witness.urls["otlp"] + "v1/traces", data=gzip.compress(decoded),
                               headers={"Content-Type": "application/x-protobuf", "Content-Encoding": "gzip"}) as response:
            assert response.status == 200
    record = witness.export_records[0]
    assert record.inspected is True and record.canary_seen is True
