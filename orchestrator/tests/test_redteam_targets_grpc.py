from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from orchestrator.redteam.targets.grpc import GRPCSpec, GRPCTarget


def test_grpc_spec_validates_required_fields():
    with pytest.raises(ValueError, match="endpoint"):
        GRPCSpec(kind="grpc", endpoint="", service_method="x.Y/Z")
    with pytest.raises(ValueError, match="service_method"):
        GRPCSpec(kind="grpc", endpoint="host:50051", service_method="")


def test_grpc_spec_rejects_wrong_kind():
    with pytest.raises(ValueError, match="kind must be"):
        GRPCSpec(kind="wrong", endpoint="h:1", service_method="p.S/M")


def test_grpc_spec_rejects_malformed_service_method():
    """service_method must be 'pkg.Service/Method' (with slash)."""
    with pytest.raises(ValueError, match="service_method"):
        GRPCSpec(kind="grpc", endpoint="h:1", service_method="not_slashed")


@pytest.mark.asyncio
async def test_grpc_send_prompt_via_mocked_reflection():
    spec = GRPCSpec(
        kind="grpc",
        endpoint="agent.example:50051",
        service_method="agent.AgentService/Chat",
        prompt_field="user_input",
        response_field="response",
        tls=False,
    )
    fake_request_class = MagicMock()
    fake_request_class.SerializeToString = MagicMock(return_value=b"")
    fake_response_class = MagicMock()
    fake_response_class.FromString = MagicMock(return_value=MagicMock(response="agent says hi"))
    fake_request_msg = MagicMock()

    with patch(
        "orchestrator.redteam.targets.grpc._build_dynamic_request_async",
        new=AsyncMock(return_value=(fake_request_msg, fake_request_class, fake_response_class)),
    ), patch(
        "orchestrator.redteam.targets.grpc._make_channel"
    ) as channel_factory:
        channel = MagicMock()
        fake_stub = AsyncMock(return_value=MagicMock(response="agent says hi"))
        channel.unary_unary = MagicMock(return_value=fake_stub)
        channel_factory.return_value.__aenter__ = AsyncMock(return_value=channel)
        channel_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        text, latency_ms = await GRPCTarget(spec).send_prompt("hi")

    assert text == "agent says hi"
    assert latency_ms > 0


def test_factory_builds_grpc():
    from orchestrator.redteam.targets import build_target
    target = build_target({
        "kind": "grpc",
        "endpoint": "h:50051",
        "service_method": "p.S/M",
    })
    assert isinstance(target, GRPCTarget)


@pytest.mark.asyncio
async def test_grpc_adapter_against_in_memory_echo_servicer():
    """End-to-end: adapter resolves schema via reflection and round-trips a request.
    Uses grpc.aio.server with reflection enabled — no external server needed."""
    import grpc
    import grpc.aio
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
    from grpc_reflection.v1alpha import reflection

    # Hand-rolled file descriptor for echo.Echo/Chat with user_input + response strings
    pool = descriptor_pool.DescriptorPool()
    fdp = descriptor_pb2.FileDescriptorProto()
    fdp.name = "echo_test.proto"
    fdp.package = "echo"
    fdp.syntax = "proto3"
    # Request message
    req_type = fdp.message_type.add()
    req_type.name = "ChatRequest"
    req_field = req_type.field.add()
    req_field.name = "user_input"
    req_field.number = 1
    req_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    req_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    # Response message
    resp_type = fdp.message_type.add()
    resp_type.name = "ChatResponse"
    resp_field = resp_type.field.add()
    resp_field.name = "response"
    resp_field.number = 1
    resp_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
    resp_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
    # Service
    svc = fdp.service.add()
    svc.name = "Echo"
    method = svc.method.add()
    method.name = "Chat"
    method.input_type = ".echo.ChatRequest"
    method.output_type = ".echo.ChatResponse"
    pool.Add(fdp)

    request_class = message_factory.GetMessageClass(pool.FindMessageTypeByName("echo.ChatRequest"))
    response_class = message_factory.GetMessageClass(pool.FindMessageTypeByName("echo.ChatResponse"))

    async def echo_handler(request, context):
        return response_class(response=f"echo: {request.user_input}")

    server = grpc.aio.server()
    rpc_method_handlers = {
        "Chat": grpc.unary_unary_rpc_method_handler(
            echo_handler,
            request_deserializer=request_class.FromString,
            response_serializer=response_class.SerializeToString,
        )
    }
    generic_handler = grpc.method_handlers_generic_handler("echo.Echo", rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    # Pass pool so the reflection servicer serves the hand-rolled descriptor
    reflection.enable_server_reflection(["echo.Echo", reflection.SERVICE_NAME], server, pool=pool)
    port = server.add_insecure_port("127.0.0.1:0")
    await server.start()

    try:
        from orchestrator.redteam.targets.grpc import GRPCSpec, GRPCTarget
        spec = GRPCSpec(
            kind="grpc",
            endpoint=f"127.0.0.1:{port}",
            service_method="echo.Echo/Chat",
            prompt_field="user_input",
            response_field="response",
            tls=False,
        )
        text, latency_ms = await GRPCTarget(spec).send_prompt("hello world")
        assert text == "echo: hello world"
        assert latency_ms > 0
    finally:
        await server.stop(grace=0.1)
