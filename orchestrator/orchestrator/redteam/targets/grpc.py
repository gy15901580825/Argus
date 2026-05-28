"""gRPC adapter — server-reflection-based dynamic message construction.

Customer's gRPC server MUST have reflection enabled (grpc-reflection v1alpha).
We discover the service schema, build the request message dynamically, and
read the configured response_field from the reply.

Limitations (v0):
- prompt_field and response_field must be top-level string fields
- nested message types are out-of-scope
- mutual TLS deferred to Plan 6+; only one-way TLS via system trust store
"""
from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from typing import Any, Callable, ClassVar

import grpc
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from grpc_reflection.v1alpha import reflection_pb2, reflection_pb2_grpc

from orchestrator.redteam.targets._base import Target


@dataclass(frozen=True)
class GRPCSpec:
    kind: str = "grpc"
    endpoint: str = ""
    service_method: str = ""  # e.g. "pkg.Service/Method"
    prompt_field: str = "user_input"
    response_field: str = "response"
    tls: bool = True
    timeout_s: float = 60.0

    def __post_init__(self) -> None:
        if self.kind != "grpc":
            raise ValueError(f"kind must be 'grpc', got {self.kind!r}")
        if not self.endpoint:
            raise ValueError("endpoint is required (host:port)")
        if not self.service_method or "/" not in self.service_method:
            raise ValueError("service_method required: 'pkg.Service/Method'")


@contextlib.asynccontextmanager
async def _make_channel(endpoint: str, tls: bool):
    if tls:
        credentials = grpc.ssl_channel_credentials()
        async with grpc.aio.secure_channel(endpoint, credentials) as channel:
            yield channel
    else:
        async with grpc.aio.insecure_channel(endpoint) as channel:
            yield channel


async def _resolve_descriptors(channel, service_name: str) -> descriptor_pool.DescriptorPool:
    """Walk reflection bidi stream + recursive deps, return populated DescriptorPool.

    Standard grpc-reflection cookbook adapted to grpc.aio (async) — bidi stream
    is fed via async generator; responses iterated via async-for.
    """
    refl_stub = reflection_pb2_grpc.ServerReflectionStub(channel)
    pool = descriptor_pool.DescriptorPool()
    seen: set[str] = set()

    async def _request(lookup_kind: str, value: str) -> None:
        async def _stream():
            yield reflection_pb2.ServerReflectionRequest(**{lookup_kind: value})

        async for resp in refl_stub.ServerReflectionInfo(_stream()):
            for fdp_bytes in resp.file_descriptor_response.file_descriptor_proto:
                fdp = descriptor_pb2.FileDescriptorProto.FromString(fdp_bytes)
                if fdp.name in seen:
                    continue
                seen.add(fdp.name)
                # Recursively resolve dependencies first
                for dep in fdp.dependency:
                    if dep not in seen:
                        await _request("file_by_filename", dep)
                try:
                    pool.Add(fdp)
                except TypeError:
                    pass  # already in pool

    await _request("file_containing_symbol", service_name)
    return pool


async def _build_dynamic_request_async(
    channel,
    service_method: str,
    prompt_field: str,
    prompt: str,
) -> tuple[Any, type, type]:
    """Returns (request_message, request_class, response_class).

    Resolves the service schema via gRPC server reflection, then constructs
    the request message with prompt_field set to prompt.
    """
    service_name, method_name = service_method.rsplit("/", 1)
    pool = await _resolve_descriptors(channel, service_name)
    service_desc = pool.FindServiceByName(service_name)
    method_desc = service_desc.FindMethodByName(method_name)
    request_class = message_factory.GetMessageClass(method_desc.input_type)
    response_class = message_factory.GetMessageClass(method_desc.output_type)
    request = request_class(**{prompt_field: prompt})
    return request, request_class, response_class


# Sync stubs retained for legacy mock-test API compatibility; tests may still patch these.
def _build_dynamic_request(channel, service_method: str, prompt_field: str, prompt: str):
    raise NotImplementedError(
        "call _build_dynamic_request_async; sync stub kept for legacy mock test compatibility"
    )


def _build_response_parser(channel, service_method: str, response_field: str) -> Callable[[Any], str]:
    raise NotImplementedError(
        "call _build_dynamic_request_async then getattr; sync stub kept for legacy mock test compatibility"
    )


class GRPCTarget(Target):
    # Plan 4 name + Plan 2 legacy alias ("tool-using").
    compatible_classes: ClassVar[frozenset[str]] = frozenset({
        "agent_with_tools",
        "tool-using",
    })

    def __init__(self, spec: GRPCSpec) -> None:
        self.spec = spec

    async def send_prompt(self, prompt: str) -> tuple[str, float]:
        async with _make_channel(self.spec.endpoint, self.spec.tls) as channel:
            request, request_class, response_class = await _build_dynamic_request_async(
                channel, self.spec.service_method, self.spec.prompt_field, prompt
            )
            method_path = "/" + self.spec.service_method
            start = time.monotonic()
            stub = channel.unary_unary(
                method_path,
                request_serializer=request_class.SerializeToString,
                response_deserializer=response_class.FromString,
            )
            response = await stub(request, timeout=self.spec.timeout_s)
            latency_ms = (time.monotonic() - start) * 1000.0
            return getattr(response, self.spec.response_field, ""), latency_ms
