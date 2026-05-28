import json
import logging
import os
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import StreamingResponse
import httpx

from auth import get_current_user
from models import UserResponse
from database import database
from subscription_middleware import get_user_plan, validate_model_access
from stripe_config import MODEL_PRICING

router = APIRouter()
logger = logging.getLogger("LLMProxy")

# Azure OpenAI configuration
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")  # e.g. https://openai-argus.openai.azure.com
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")


def _build_azure_url(deployment_name: str) -> str:
    """Build Azure OpenAI chat completions URL for a given deployment."""
    base = AZURE_OPENAI_ENDPOINT.rstrip("/")
    return f"{base}/openai/deployments/{deployment_name}/chat/completions?api-version={AZURE_OPENAI_API_VERSION}"


def _build_azure_responses_url() -> str:
    """Build Azure OpenAI Responses API URL (model is specified in the body)."""
    base = AZURE_OPENAI_ENDPOINT.rstrip("/")
    return f"{base}/openai/responses?api-version=2025-03-01-preview"


async def _record_token_usage(
    user_id, model: str, input_tokens: int, output_tokens: int,
    plan: str = None, task_id: str = None, routing_reason: str = None,
):
    """Record token usage and calculated cost to ai_token_usage table."""
    pricing = MODEL_PRICING.get(model, {"input": 0.001, "output": 0.004})
    cost_usd = (input_tokens / 1000) * pricing["input"] + (output_tokens / 1000) * pricing["output"]
    total_tokens = input_tokens + output_tokens

    try:
        await database.execute(
            """INSERT INTO ai_token_usage
               (user_id, model_name, model_provider, input_tokens, output_tokens,
                total_tokens, cost_usd, request_type,
                subscription_plan, task_id, routing_reason)
               VALUES (:uid, :model, 'azure_openai', :inp, :out,
                :total, :cost, 'llm_proxy',
                :plan, :tid, :reason)""",
            {
                "uid": user_id, "model": model,
                "inp": input_tokens, "out": output_tokens,
                "total": total_tokens, "cost": cost_usd,
                "plan": plan, "tid": task_id, "reason": routing_reason,
            },
        )
        logger.info(f"Token usage: user={user_id} model={model} in={input_tokens} out={output_tokens} cost=${cost_usd:.6f}")
    except Exception as e:
        logger.error(f"Failed to record token usage: {e}")


@router.post("/llm/chat/completions")
async def proxy_chat_completions(
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    """
    OpenAI-compatible proxy that forwards to Azure OpenAI.
    Client agents call this instead of OpenAI directly so the API key
    never leaves the server.
    """
    if not AZURE_OPENAI_ENDPOINT or not AZURE_OPENAI_API_KEY:
        raise HTTPException(status_code=503, detail="Azure OpenAI not configured on server")

    body = await request.body()

    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # The model field doubles as the Azure deployment name
    model = payload.get("model", "gpt-5.4-mini")
    is_stream = payload.get("stream", False)

    # Validate model access based on subscription plan
    await validate_model_access(current_user.id, model)
    user_plan = await get_user_plan(current_user.id)

    target_url = _build_azure_url(model)
    headers = {
        "api-key": AZURE_OPENAI_API_KEY,
        "Content-Type": "application/json",
    }

    logger.info(f"LLM proxy: user={current_user.id}, model={model}, stream={is_stream}, plan={user_plan}")

    if is_stream:
        return await _proxy_stream(headers, body, target_url)
    else:
        resp = await _proxy_normal_with_tracking(headers, body, target_url, current_user.id, model, user_plan)
        return resp


async def _proxy_normal(headers: dict, body: bytes, url: str):
    async with httpx.AsyncClient(timeout=300) as client:
        try:
            resp = await client.post(url, headers=headers, content=body)
            return StreamingResponse(
                content=resp.aiter_bytes(),
                status_code=resp.status_code,
                headers={
                    "content-type": resp.headers.get("content-type", "application/json"),
                },
            )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Azure OpenAI request timed out")
        except Exception as e:
            logger.error(f"LLM proxy error: {e}")
            raise HTTPException(status_code=502, detail="Failed to proxy request to Azure OpenAI")


@router.post("/llm/responses")
async def proxy_responses(
    request: Request,
    current_user: UserResponse = Depends(get_current_user),
):
    """
    Proxy for Azure OpenAI Responses API.
    Used by models like gpt-5.3-codex that don't support chat completions.
    """
    if not AZURE_OPENAI_ENDPOINT or not AZURE_OPENAI_API_KEY:
        raise HTTPException(status_code=503, detail="Azure OpenAI not configured on server")

    body = await request.body()

    try:
        payload = json.loads(body)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    model = payload.get("model", "gpt-5.3-codex")

    # Validate model access based on subscription plan
    await validate_model_access(current_user.id, model)
    user_plan = await get_user_plan(current_user.id)

    logger.info(f"LLM responses proxy: user={current_user.id}, model={model}, plan={user_plan}")

    target_url = _build_azure_responses_url()
    headers = {
        "api-key": AZURE_OPENAI_API_KEY,
        "Content-Type": "application/json",
    }

    return await _proxy_normal_with_tracking(headers, body, target_url, current_user.id, model, user_plan)


async def _proxy_normal_with_tracking(headers: dict, body: bytes, url: str, user_id, model: str, plan: str):
    """Proxy request, parse response to extract token usage, record it, then return."""
    async with httpx.AsyncClient(timeout=300) as client:
        try:
            resp = await client.post(url, headers=headers, content=body)
            resp_body = resp.content

            # Try to extract token usage from response
            if resp.status_code == 200:
                try:
                    resp_json = json.loads(resp_body)
                    usage = resp_json.get("usage", {})
                    input_tokens = usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0)
                    output_tokens = usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)
                    if input_tokens or output_tokens:
                        await _record_token_usage(user_id, model, input_tokens, output_tokens, plan)
                except Exception as e:
                    logger.debug(f"Could not parse token usage from response: {e}")

            from fastapi.responses import Response
            return Response(
                content=resp_body,
                status_code=resp.status_code,
                headers={"content-type": resp.headers.get("content-type", "application/json")},
            )
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="Azure OpenAI request timed out")
        except Exception as e:
            logger.error(f"LLM proxy error: {e}")
            raise HTTPException(status_code=502, detail="Failed to proxy request to Azure OpenAI")


async def _proxy_stream(headers: dict, body: bytes, url: str):
    async def event_generator():
        async with httpx.AsyncClient(timeout=300) as client:
            async with client.stream("POST", url, headers=headers, content=body) as resp:
                if resp.status_code != 200:
                    error_body = await resp.aread()
                    yield error_body
                    return
                async for chunk in resp.aiter_bytes():
                    yield chunk

    return StreamingResponse(
        content=event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
