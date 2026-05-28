import logging
import os
import json
import re
import io
import time
import base64
import ipaddress
import tempfile
import zipfile
from dotenv import load_dotenv
from typing import Optional, Dict, Any, List

import httpx
import google.generativeai as genai

from fastapi import FastAPI, Form, File, UploadFile
from fastapi.responses import StreamingResponse, HTMLResponse
from pydantic import BaseModel, field_validator
from starlette.templating import Jinja2Templates
from starlette.requests import Request
from openai import AsyncAzureOpenAI

from remote_executor import RemoteExecutor

from google.adk.agents.llm_agent import LlmAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.run_config import RunConfig
from google.adk.sessions.session import Session
from google.adk.sessions.in_memory_session_service import InMemorySessionService

from utils import CloudflareR2Manager

load_dotenv()

# Configure Google GenAI
if os.getenv("GOOGLE_API_KEY"):
    genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("api-testing-service")

app = FastAPI(title="ApiTestingAgent Service")

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

GEMINI_MODEL = os.getenv("GEMINI_MODEL_NAME", "gemini-3-pro-preview")
AZURE_OPENAI_MODEL = os.getenv("AZURE_OPENAI_MODEL", "gpt-5.4-mini")
AZURE_OPENAI_ENDPOINT = os.getenv("AZURE_OPENAI_ENDPOINT", "")
AZURE_OPENAI_API_KEY = os.getenv("AZURE_OPENAI_API_KEY", "")
AZURE_OPENAI_API_VERSION = os.getenv("AZURE_OPENAI_API_VERSION", "2024-12-01-preview")
TEST_RUNNER_URL = os.getenv("TEST_RUNNER_URL", "http://test-runner.test-runner.svc.cluster.local:8000")

API_TESTING_PROMPT = """
You are a Senior SDET specializing in Python API test automation with pytest and requests.

## Task
Generate a complete, runnable pytest test suite based on the API analysis data below.

## API Analysis Data
{+content_analysis+}

## Scenario Detection
First, check the `is_api_doc` field in the analysis data:

- If `is_api_doc` is true: Use `api_spec` and `tool_output` as endpoint sources. Use the `base_url` from the spec for all requests.
- If `is_api_doc` is false or missing: Use the `crawled_apis` list as endpoint source. Use the exact `full_url` from each entry (APIs may span multiple domains — do NOT use a shared base_url).

Generate a test case for EVERY endpoint found. Do not skip any.

## Tech Stack
Python 3.10+, pytest, requests, pydantic, faker

## Test Requirements

### conftest.py
- Global fixtures: base_url (Scenario A only), auth headers, session setup
- Reusable request helper fixtures
- Extract any authentication details (API keys, tokens, required headers) from the analysis data
- If the analysis data contains request headers (e.g., x-write-key, Authorization, x-api-key), include them in a default headers fixture so tests authenticate properly

### test_functional.py
- Happy path tests for each endpoint (expected 2xx)
- Error case tests: 400, 404, 405 responses
- Use pytest.mark.parametrize for multiple data scenarios
- Schema validation against expected response structure
- All requests MUST include the authentication headers from conftest fixtures

### test_security.py
- Auth bypass: requests deliberately WITHOUT auth headers (expect 401/403 — this is a PASS)
- IDOR: access resources with unauthorized IDs (expect 401/403, NOT 404)
- SQL injection and XSS payloads in input fields — send WITH valid auth headers (expect 400/401/403/422, verify payloads not reflected)
- Mass assignment: send unexpected extra fields WITH valid auth headers
- SSRF: internal IP payloads must be rejected
- A 404 response does NOT count as a security pass — expect 400/401/403/422
- CRITICAL: For auth bypass tests, 401/403 means the endpoint IS properly protected — assert this as a PASS
- CRITICAL: For input validation tests (injection, mass assignment, invalid JSON), send requests WITH valid auth so you actually reach the input validation layer, not the auth layer
- CRITICAL: For ALL security tests, 401/403 is ALWAYS a valid passing response — it means the endpoint is protected. Even if you expect 400/422 for bad input, the auth layer may reject first, which is equally secure. Always include 401 and 403 in acceptable status codes.

### Handling Authentication
- Inspect the crawled_apis or api_spec data for headers like x-write-key, Authorization, x-api-key, Bearer tokens, etc.
- Create a conftest fixture that provides these headers
- Functional tests: always include auth headers
- Security auth-bypass tests: deliberately omit auth headers and assert 401/403 as PASSING
- Security input-validation tests: include auth headers so the test reaches the validation logic

### Assertion Rules
- Use strict status code checks: assert response.status_code == 200, not in [200, 201]
- Always include response body in assertion messages: assert response.status_code == 200, "Failed: " + str(response.status_code) + " - " + response.text
- For auth bypass tests: assert response.status_code in [401, 403] — this is a PASS (endpoint is protected)
- For security input validation tests (invalid JSON, injection payloads, mass assignment, SSRF): assert response.status_code in [400, 401, 403, 422] — a 401/403 means the auth layer rejected the request before reaching input parsing, which is equally secure and counts as a PASS

### Exception Handling
- Never use bare except or except: pass
- Catch requests.exceptions.ConnectionError and call pytest.skip("Endpoint unreachable: " + str(ex))

## Output Format (STRICT)
You MUST output EXACTLY 5 fenced code blocks, each labeled with the filename.
Do NOT output any other code blocks — no examples, no snippets, no inline code fences.
Use this exact format:

<!-- FILE: conftest.py -->
```python
# conftest.py content here
```

<!-- FILE: test_functional.py -->
```python
# test_functional.py content here
```

<!-- FILE: test_security.py -->
```python
# test_security.py content here
```

<!-- FILE: requirements.txt -->
```text
# requirements.txt content here
```

<!-- FILE: README.md -->
```markdown
# README.md content here
```

IMPORTANT: Output ONLY these 5 code blocks. No additional code blocks anywhere in your response.
"""

# # --- Agent Definition ---

# api_testing_agent = LlmAgent(
#     name="ApiTestingAgent",
#     model=GEMINI_MODEL,
#     instruction=API_TESTING_PROMPT,
#     description="Executes API tests using HTTP requests and validates responses",
#     tools=[
#     ],
#     output_key="api_test_results"
# )

# TODO: Optional Claude Agent configuration (uncomment and configure if needed)
# from claude_sdk import ClaudeAgentOptions, query
# 
# claude_api_testing_options = ClaudeAgentOptions(
#     system_prompt="You are a Staff SDET (Software Development Engineer in Test) and a Cybersecurity Analyst.",
#     cwd="/app",
#     setting_sources=["user", "project"],
#     allowed_tools=["Skill", "Read", "Write", "Bash"]
# )

def extract_code_blocks(full_text: str) -> Dict[str, str]:
    """
    Extracts code blocks from the LLM response using FILE markers or positional fallback.
    """
    files = {}
    expected_files = ["conftest.py", "test_functional.py", "test_security.py", "requirements.txt", "README.md"]

    # Strategy 1: Use <!-- FILE: filename --> markers (most reliable)
    marker_pattern = r"<!--\s*FILE:\s*(?P<filename>[\w\.\-]+)\s*-->\s*```[\w]*\n(?P<code>.*?)```"
    marker_matches = list(re.finditer(marker_pattern, full_text, re.DOTALL))

    if marker_matches:
        for match in marker_matches:
            filename = match.group("filename").strip()
            code = match.group("code").strip() + "\n"
            files[filename] = code
        return files

    # Strategy 2: Look for filename in comments at start of code block
    # e.g. ```python\n# conftest.py\n...```
    comment_pattern = r"```[\w]*\n#\s*(?P<filename>[\w\.\-]+)\s*\n(?P<code>.*?)```"
    comment_matches = list(re.finditer(comment_pattern, full_text, re.DOTALL))

    if len(comment_matches) >= 3:
        for match in comment_matches:
            filename = match.group("filename").strip()
            if filename in expected_files:
                code = match.group("code").strip() + "\n"
                files[filename] = code
        if len(files) >= 3:
            return files

    # Strategy 3: Positional fallback — only use code blocks that look like real files
    # (contain import/def/class for .py, or multi-line content for .txt/.md)
    files = {}
    block_pattern = r"```[\w\+\-]*\n(?P<code>.*?)```"
    all_blocks = list(re.finditer(block_pattern, full_text, re.DOTALL))

    # Filter to substantial blocks (>2 lines) to skip inline examples
    substantial = [m for m in all_blocks if m.group("code").strip().count("\n") >= 2]

    for i, match in enumerate(substantial):
        if i < len(expected_files):
            files[expected_files[i]] = match.group("code").strip() + "\n"

    return files

# --- Endpoint ---

class RunRequest(BaseModel):
    session_state: Dict[str, Any]
    input_text: Optional[str] = None
    invocation_id: str = "default_invocation"
    user_id: str = "default_user"
    app_name: str = "default_app"
    events: Optional[List[Dict[str, Any]]] = None  # Placeholder for history if needed
    model_provider: str = "azure"  # "azure", "gemini", or "claude"

@app.post("/agent/run")
async def run_agent(req: RunRequest):
    async def event_generator():
        full_response = ""
        try:
            # Reconstruct Session and Context
            session = Session(
                id="remote_session",
                app_name=req.app_name,
                user_id=req.user_id,
                state=req.session_state
            )
            
            session_service = InMemorySessionService()
            # Try to enable streaming if supported by RunConfig
            try:
                run_config = RunConfig(stream=True)
            except Exception:
                logger.warning("RunConfig does not accept 'stream' parameter. Using default.")
                run_config = RunConfig()

            # --- PROMPT DYNAMIC INJECTION ---
            # Extract content_analysis from session state
            content_analysis = req.session_state.get("content_analysis", "{}")
            
            # Select model based on model_provider
            logger.info(f"Using model provider: {req.model_provider}")
            
            # === AZURE OPENAI PATH ===
            if req.model_provider in ("azure", "claude"):
                logger.info(f"Using Azure OpenAI with model: {AZURE_OPENAI_MODEL}")

                system_role = "You are a Staff SDET (Software Development Engineer in Test) and a Cybersecurity Analyst."

                content_str = str(content_analysis)

                MAX_CONTENT_LENGTH = 100000
                if len(content_str) > MAX_CONTENT_LENGTH:
                    logger.warning(f"content_analysis too large ({len(content_str)} bytes). Truncating to {MAX_CONTENT_LENGTH} bytes.")
                    content_str = content_str[:MAX_CONTENT_LENGTH] + "\n... [TRUNCATED due to size limit] ..."

                user_instruction = API_TESTING_PROMPT.replace("{+content_analysis+}", content_str)
                logger.info(f"Azure OpenAI instruction length: {len(user_instruction)}")

                try:
                    azure_client = AsyncAzureOpenAI(
                        azure_endpoint=AZURE_OPENAI_ENDPOINT,
                        api_key=AZURE_OPENAI_API_KEY,
                        api_version=AZURE_OPENAI_API_VERSION,
                    )

                    stream = await azure_client.chat.completions.create(
                        model=AZURE_OPENAI_MODEL,
                        messages=[
                            {"role": "system", "content": system_role},
                            {"role": "user", "content": user_instruction},
                        ],
                        max_completion_tokens=32768,
                        stream=True,
                    )

                    async for chunk in stream:
                        if chunk.choices and chunk.choices[0].delta.content:
                            message_text = chunk.choices[0].delta.content
                            full_response += message_text

                            event_payload = {
                                "invocation_id": req.invocation_id,
                                "author": "ApiTestingAgent",
                                "content": {
                                    "parts": [{"text": message_text}]
                                }
                            }
                            yield json.dumps(event_payload) + "\n"

                    await azure_client.close()
                except Exception as e:
                    logger.error(f"Azure OpenAI query failed: {e}", exc_info=True)
                    error_payload = {
                        "invocation_id": req.invocation_id,
                        "author": "ApiTestingAgent",
                        "content": {
                            "parts": [{"text": f"Error calling Azure OpenAI: {str(e)}"}]
                        }
                    }
                    yield json.dumps(error_payload) + "\n"
                    
            # === GOOGLE ADK PATH ===
            else:
                logger.info(f"Using Google ADK with model: {GEMINI_MODEL}")
                
                # Create a request-scoped agent with the specific instruction
                current_agent = LlmAgent(
                    name="ApiTestingAgent",
                    model=GEMINI_MODEL,
                    instruction=API_TESTING_PROMPT,  # Use the template directly, let ADK handle {+content_analysis+}
                    description="Executes API tests using HTTP requests and validates responses",
                    tools=[],
                    output_key="api_test_results"
                )

                ctx = InvocationContext(
                    invocation_id=req.invocation_id,
                    session=session,
                    agent=current_agent,
                    session_service=session_service,
                    run_config=run_config
                )
                
                # Run the dynamic agent
                async for event in current_agent.run_async(ctx):
                    # Serialize event to JSON
                    event_json = event.model_dump_json()
                    yield event_json + "\n"
                    
                    # Accumulate text for code extraction
                    try:
                        event_data = json.loads(event_json)
                        
                        # Log event keys for debugging purposes
                        logger.info(f"Event keys: {list(event_data.keys())}")
                        
                        # Check common fields for text content (adjust based on actual Event model)
                        if "text" in event_data and event_data["text"]:
                            full_response += event_data["text"]
                        elif "content" in event_data:
                            content = event_data["content"]
                            if isinstance(content, str):
                                full_response += content
                            elif isinstance(content, dict) and "parts" in content:
                                for part in content["parts"]:
                                    if "text" in part and part["text"]:
                                        full_response += part["text"]
                        # Some agents stream deltas
                        elif "delta" in event_data:
                             full_response += str(event_data["delta"])
                        # Check for parts (Gemini style)
                        elif "parts" in event_data:
                            for part in event_data["parts"]:
                                if "text" in part:
                                    full_response += part["text"]
                    except Exception:
                        pass  # Ignore extraction errors during stream

                
            # After stream ends, process the full response
            logger.info(f"Full response length: {len(full_response)}")
            logger.info(f"Full response content: {full_response}")
            if full_response:
                try:
                    logger.info("Extracting code blocks from response...")
                    files = extract_code_blocks(full_response)
                    
                    if files:
                        logger.info(f"Found {len(files)} files. Zipping and uploading to R2...")
                        r2 = CloudflareR2Manager()
                        
                        timestamp = int(time.time())
                        zip_filename = f"api_tests_{req.invocation_id}_{timestamp}.zip"
                        
                        # Create in-memory zip
                        zip_buffer = io.BytesIO()
                        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                            for filename, code in files.items():
                                zip_file.writestr(filename, code)
                        
                        zip_buffer.seek(0)
                        
                        object_key = f"api-tests/{req.invocation_id}/{timestamp}/{zip_filename}"
                        
                        result = r2.upload_file_object(
                            file_obj=zip_buffer,
                            object_key=object_key,
                            content_type="application/zip",
                            metadata={"invocation_id": req.invocation_id, "type": "generated_test_zip"}
                        )

                        logger.info(f"Upload result: {result}")
                        
                        if result['success']:
                            # Generate a presigned URL for downloading (valid for 1 hour)
                            # This avoids issues if public access domain is not configured correctly
                            presigned_res = r2.generate_presigned_url(object_key, expiration=3600)
                            if presigned_res['success']:
                                download_url = presigned_res['presigned_url']
                            else:
                                # Fallback to the URL from upload result (might be raw endpoint if misconfigured)
                                download_url = result.get('download_url')

                            # Yield standard Event structure compatible with RemoteAgent
                            event_payload = {
                                "invocation_id": req.invocation_id,
                                "author": "ApiTestingAgent",
                                "content": {
                                    "parts": [{
                                        "text": json.dumps({
                                            "type": "artifacts",
                                            "files": [{
                                                "filename": zip_filename,
                                                "download_url": download_url
                                            }]
                                        })
                                    }]
                                }
                            }
                            yield json.dumps(event_payload) + "\n"
                        else:
                            logger.error(f"Failed to upload zip: {result.get('error')}")

                        # --- Remote Test Execution (via test-runner service or SSH fallback) ---
                        ssh_config = req.session_state.get("ssh_config")
                        remote_test_enabled = req.session_state.get("remote_test_enabled", False)

                        if files and (remote_test_enabled or ssh_config):
                            # Use SSH if user provided a valid ssh_config (with host, username, and pem key);
                            # otherwise fall back to the in-cluster test-runner service.
                            use_ssh = bool(
                                ssh_config
                                and ssh_config.get("remote_ip")
                                and ssh_config.get("username")
                                and ssh_config.get("pem_key_base64")
                            )

                            if use_ssh:
                                # --- Legacy SSH execution ---
                                yield json.dumps({
                                    "invocation_id": req.invocation_id,
                                    "author": "ApiTestingAgent",
                                    "content": {"parts": [{"text": json.dumps({"type": "log", "stage": "ssh", "message": "Connecting to remote host for test execution..."})}]}
                                }) + "\n"

                                pem_data = None
                                try:
                                    pem_data = base64.b64decode(ssh_config["pem_key_base64"]).decode("utf-8")
                                    pytest_args = ssh_config.get("pytest_args", "--alluredir=./allure-results -v")

                                    with RemoteExecutor(
                                        host=ssh_config["remote_ip"],
                                        username=ssh_config["username"],
                                        pkey_data=pem_data,
                                    ) as executor:
                                        setup_result = executor.execute("mktemp -d /tmp/argus_tests_XXXXXX")
                                        remote_dir = setup_result["stdout"].strip()

                                        sftp = executor._client.open_sftp()
                                        try:
                                            for fname, code in files.items():
                                                remote_path = f"{remote_dir}/{fname}"
                                                with sftp.open(remote_path, "w") as rf:
                                                    rf.write(code)
                                        finally:
                                            sftp.close()

                                        container_workdir = f"/app/tests/{os.path.basename(remote_dir)}"
                                        executor.execute(f"docker exec -i runner mkdir -p {container_workdir}")
                                        executor.execute(f"docker cp {remote_dir}/. runner:{container_workdir}")

                                        if "requirements.txt" in files:
                                            yield json.dumps({
                                                "invocation_id": req.invocation_id,
                                                "author": "ApiTestingAgent",
                                                "content": {"parts": [{"text": json.dumps({"type": "log", "stage": "ssh", "message": "Installing test dependencies..."})}]}
                                            }) + "\n"
                                            install_cmd = f"cd {container_workdir} && pip install -r requirements.txt"
                                            executor.execute(f"docker exec -i runner bash -c '{install_cmd}'")

                                        pytest_cmd = f"cd {container_workdir} && pytest {pytest_args}"
                                        test_result = executor.execute(f"docker exec -i runner bash -c '{pytest_cmd}'")
                                        executor.execute(f"docker cp runner:{container_workdir}/allure-results {remote_dir}/allure-results")
                                        executor.execute(f"docker exec -i runner rm -rf {container_workdir}")

                                        allure_results_url = None
                                        try:
                                            with tempfile.TemporaryDirectory() as tmpdir:
                                                local_allure = os.path.join(tmpdir, "allure-results")
                                                executor.download_directory(f"{remote_dir}/allure-results", local_allure)
                                                allure_zip = io.BytesIO()
                                                with zipfile.ZipFile(allure_zip, "w", zipfile.ZIP_DEFLATED) as zf:
                                                    for root, _dirs, fnames in os.walk(local_allure):
                                                        for fn in fnames:
                                                            abs_p = os.path.join(root, fn)
                                                            arc = os.path.relpath(abs_p, tmpdir)
                                                            zf.write(abs_p, arc)
                                                allure_zip.seek(0)
                                                ts = int(time.time())
                                                allure_key = f"allure-results/{req.invocation_id}/{ts}/allure-results.zip"
                                                r2 = CloudflareR2Manager()
                                                upload_res = r2.upload_file_object(file_obj=allure_zip, object_key=allure_key, content_type="application/zip", metadata={"type": "allure_results"})
                                                if upload_res["success"]:
                                                    presigned = r2.generate_presigned_url(allure_key, expiration=3600)
                                                    allure_results_url = presigned.get("presigned_url") if presigned["success"] else upload_res.get("download_url")
                                        except Exception as allure_err:
                                            logger.warning("Could not download allure-results: %s", allure_err)

                                        executor.execute(f"rm -rf {remote_dir}")

                                        ssh_result_data = {
                                            "type": "ssh_result",
                                            "ssh_result": {
                                                "success": test_result["exit_code"] == 0,
                                                "stdout": test_result["stdout"],
                                                "stderr": test_result["stderr"],
                                                "exit_code": test_result["exit_code"],
                                                "allure_results_url": allure_results_url,
                                            }
                                        }
                                        yield json.dumps({
                                            "invocation_id": req.invocation_id,
                                            "author": "ApiTestingAgent",
                                            "content": {"parts": [{"text": json.dumps(ssh_result_data)}]}
                                        }) + "\n"

                                except Exception as ssh_err:
                                    logger.error("SSH execution failed: %s", ssh_err, exc_info=True)
                                    yield json.dumps({
                                        "invocation_id": req.invocation_id,
                                        "author": "ApiTestingAgent",
                                        "content": {"parts": [{"text": json.dumps({"type": "ssh_result", "ssh_result": {"success": False, "stdout": "", "stderr": str(ssh_err), "exit_code": -1}})}]}
                                    }) + "\n"
                                finally:
                                    if pem_data is not None:
                                        pem_data = ""

                            else:
                                # --- Test Runner Service execution (new default) ---
                                yield json.dumps({
                                    "invocation_id": req.invocation_id,
                                    "author": "ApiTestingAgent",
                                    "content": {"parts": [{"text": json.dumps({"type": "log", "stage": "remote", "message": "Submitting tests to remote test runner..."})}]}
                                }) + "\n"

                                try:
                                    # Find the main test file and extra files
                                    test_script = ""
                                    extra_files = {}
                                    for fname, code in files.items():
                                        if fname.startswith("test_"):
                                            test_script = code
                                        else:
                                            extra_files[fname] = code

                                    # If no test_ prefixed file, use the first .py file
                                    if not test_script:
                                        for fname, code in files.items():
                                            if fname.endswith(".py"):
                                                test_script = code
                                                break

                                    # Extract target URL from session state
                                    target_url = req.session_state.get("target_url") or req.session_state.get("url", "")

                                    # Submit to test-runner service
                                    async with httpx.AsyncClient(timeout=360) as client:
                                        run_resp = await client.post(
                                            f"{TEST_RUNNER_URL}/api/v1/run",
                                            json={
                                                "task_id": req.invocation_id,
                                                "test_script": test_script,
                                                "test_type": "api",
                                                "target_url": target_url,
                                                "timeout": 300,
                                                "extra_files": extra_files,
                                            }
                                        )
                                        run_data = run_resp.json()
                                        task_id = run_data.get("task_id", req.invocation_id)

                                    yield json.dumps({
                                        "invocation_id": req.invocation_id,
                                        "author": "ApiTestingAgent",
                                        "content": {"parts": [{"text": json.dumps({"type": "log", "stage": "remote", "message": f"Test submitted (task_id: {task_id}). Waiting for results..."})}]}
                                    }) + "\n"

                                    # Poll for completion
                                    import asyncio
                                    max_wait = 300
                                    poll_interval = 3
                                    elapsed = 0

                                    while elapsed < max_wait:
                                        await asyncio.sleep(poll_interval)
                                        elapsed += poll_interval

                                        async with httpx.AsyncClient(timeout=30) as client:
                                            status_resp = await client.get(f"{TEST_RUNNER_URL}/api/v1/status/{task_id}")
                                            status_data = status_resp.json()

                                        if status_data["status"] in ("completed", "failed", "cancelled"):
                                            break

                                        if elapsed % 15 == 0:
                                            yield json.dumps({
                                                "invocation_id": req.invocation_id,
                                                "author": "ApiTestingAgent",
                                                "content": {"parts": [{"text": json.dumps({"type": "log", "stage": "remote", "message": f"Test running... ({elapsed}s elapsed)"})}]}
                                            }) + "\n"

                                    # Build result
                                    ssh_result_data = {
                                        "type": "ssh_result",
                                        "ssh_result": {
                                            "success": status_data.get("exit_code") == 0,
                                            "stdout": status_data.get("stdout", ""),
                                            "stderr": status_data.get("stderr", ""),
                                            "exit_code": status_data.get("exit_code", -1),
                                            "summary": status_data.get("summary"),
                                        }
                                    }
                                    yield json.dumps({
                                        "invocation_id": req.invocation_id,
                                        "author": "ApiTestingAgent",
                                        "content": {"parts": [{"text": json.dumps(ssh_result_data)}]}
                                    }) + "\n"

                                except Exception as runner_err:
                                    logger.error("Test runner execution failed: %s", runner_err, exc_info=True)
                                    yield json.dumps({
                                        "invocation_id": req.invocation_id,
                                        "author": "ApiTestingAgent",
                                        "content": {"parts": [{"text": json.dumps({"type": "ssh_result", "ssh_result": {"success": False, "stdout": "", "stderr": str(runner_err), "exit_code": -1}})}]}
                                    }) + "\n"

                except Exception as e:
                    logger.error(f"Error processing generated code: {e}", exc_info=True)

        except Exception as e:
            logger.error(f"Agent execution failed: {e}", exc_info=True)
            # Create a basic error event structure or just json error
            yield json.dumps({"error": str(e)}) + "\n"

    return StreamingResponse(event_generator(), media_type="application/x-ndjson")

# ---------------------------------------------------------------------------
# SSH Remote Execution
# ---------------------------------------------------------------------------

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_\-]{1,32}$")


class SSHConfigRequest(BaseModel):
    remote_ip: str
    username: str

    @field_validator("remote_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.IPv4Address(v)
        except ValueError:
            raise ValueError(f"Invalid IPv4 address: {v}")
        return v

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not _USERNAME_RE.match(v):
            raise ValueError(
                "Username must be alphanumeric/underscore/hyphen, 1-32 chars"
            )
        return v


@app.get("/ssh-config", response_class=HTMLResponse)
async def ssh_config_page(request: Request):
    return templates.TemplateResponse("ssh_config.html", {"request": request})


@app.post("/ssh/execute")
async def ssh_execute(
    remote_ip: str = Form(...),
    username: str = Form(...),
    pem_file: UploadFile = File(...),
    pytest_args: str = Form("--alluredir=./allure-results -v"),
):
    # --- Validate inputs via Pydantic ---
    try:
        cfg = SSHConfigRequest(remote_ip=remote_ip, username=username)
    except Exception as e:
        return {"success": False, "error": f"Validation error: {e}"}

    pem_data: str | None = None
    try:
        # Read PEM into memory — never write to disk
        raw = await pem_file.read()
        pem_data = raw.decode("utf-8")

        with RemoteExecutor(
            host=cfg.remote_ip,
            username=cfg.username,
            pkey_data=pem_data,
        ) as executor:
            # Run pytest inside container
            # This endpoint is currently NOT updated to use the containerized flow as per request scope.
            # It executes directly on the host.
            command = f"pytest {pytest_args}"
            result = executor.execute(command)

            # Attempt to download allure-results via SFTP
            allure_results_url: str | None = None
            try:
                with tempfile.TemporaryDirectory() as tmpdir:
                    local_allure = os.path.join(tmpdir, "allure-results")
                    executor.download_directory("./allure-results", local_allure)

                    # Zip the downloaded allure-results
                    zip_buffer = io.BytesIO()
                    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                        for root, _dirs, files in os.walk(local_allure):
                            for fname in files:
                                abs_path = os.path.join(root, fname)
                                arc_name = os.path.relpath(abs_path, tmpdir)
                                zf.write(abs_path, arc_name)
                    zip_buffer.seek(0)

                    # Upload to R2
                    ts = int(time.time())
                    object_key = f"allure-results/{cfg.remote_ip}/{ts}/allure-results.zip"
                    r2 = CloudflareR2Manager()
                    upload = r2.upload_file_object(
                        file_obj=zip_buffer,
                        object_key=object_key,
                        content_type="application/zip",
                        metadata={"host": cfg.remote_ip, "type": "allure_results"},
                    )
                    if upload["success"]:
                        presigned = r2.generate_presigned_url(object_key, expiration=3600)
                        if presigned["success"]:
                            allure_results_url = presigned["presigned_url"]
                        else:
                            allure_results_url = upload.get("download_url")
            except Exception as dl_err:
                logger.warning("Could not download allure-results: %s", dl_err)

            return {
                "success": True,
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "exit_code": result["exit_code"],
                "allure_results_url": allure_results_url,
            }

    except Exception as e:
        logger.error("SSH execution failed: %s", e, exc_info=True)
        return {"success": False, "error": str(e)}
    finally:
        # Clear PEM from memory
        if pem_data is not None:
            pem_data = ""  # noqa: F841


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
