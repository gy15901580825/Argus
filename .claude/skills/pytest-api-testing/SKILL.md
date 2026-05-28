---
name: pytest-api-testing
description: Pytest API testing skill focused on crawled_apis-driven generation (exact full_url), plus functional/security coverage and strict assertion rules.
---

# Pytest API Testing & Security Skill (Crawled APIs First)

A comprehensive pytest skill for API functional and security testing, with a **crawled_apis-first workflow**. Tests are generated **per crawled_apis record**, using the **exact full_url** as provided.

- **Functional Testing**: CRUD operations, input validation, error handling
- **Security Testing**: OWASP API Top 10, injection attacks, authorization bypass
- **Performance Testing**: Rate limiting, throttling validation
- **Strict URL Rules**: Always use full_url verbatim

> Load this skill first, then read `references/pytest_api_testing_guide.md` for detailed patterns.

---

## Use Cases

- Build automated API test suites with pytest + requests/httpx
- Generate tests directly from crawled_apis data (multi-domain safe)
- Implement security testing following OWASP guidelines
- Generate reusable fixtures and parameterized tests

---

## Quick Start

**1) Prepare crawled_apis input**

Ensure your context includes a `crawled_apis` list. Each record must generate at least one test case.

**2) Manual Test Example (Crawled APIs)**

```python
import httpx

def test_crawled_api_endpoint_returns_200():
    # Use EXACT full_url from crawled_apis
    response = httpx.get("https://api.example.com/users/123")
    assert response.status_code == 200, "Failed: " + str(response.status_code) + " - " + response.text
    assert "data" in response.json()
```

---

## Input Data (Primary Source)

**Test object analysis result:**
{+content_analysis+}

if result["is_api_doc"] == False:
Get result["crawled_apis"] data to generate tests, generate cases for all items in result["crawled_apis"].

### ✅ Primary Data Source: `crawled_apis`
Your test generation MUST be driven by the `crawled_apis` list inside the analysis result.
For **every** item in `result["crawled_apis"]`, generate a corresponding test case.
Do not skip any entry. Treat this list as the authoritative source of endpoints.

if result["is_api_doc"] == True:
Get result["tool_output"] and result["api_spec"] data to generate tests, generate cases for all endpoints defined in result["api_spec"] and result["tool_output"].

### ✅ Primary Data Source: `tool_output` and `api_spec`
Your test generation MUST be driven by the `tool_output` and `api_spec` list inside the analysis result.
For **every** item in `result["tool_output"] and result["api_spec"]`, generate a corresponding test case.
Do not skip any entry. Treat this list as the authoritative source of endpoints.

---

## Standard Workflow (Crawled APIs First)

1. **Confirm Input**: `crawled_apis` list must be present in context.
2. **Parse crawled_apis**: Each record becomes **one or more** tests (functional + security).
3. **Build Structure**: `tests/` + `conftest.py` + reusable fixtures.
4. **Write Assertions**: Strict status codes and descriptive errors.
5. **Run & Report**: Execute with pytest, use parameterization and logging.

---

## Project Structure

```
project/
  tests/
    conftest.py           # Shared fixtures
    test_functional.py    # Functional API tests
    test_security.py      # Security-focused tests
    test_auth.py          # Authorization tests
```

**Recommended Fixtures**:
- `auth_headers`: Encapsulate authentication token
- `api_client`: Wrap httpx.Client or requests.Session
## Crawled APIs: Non-Negotiable Rules

When `crawled_apis` is present, you MUST follow these rules:

1. **Use `full_url` verbatim** for every request.
    - ✅ `client.get("https://api.example.com/users/123")`
    - ❌ `client.get("/users/123")`
2. **No URL construction**. Do not parse, join, or rebuild URLs.
3. **One record → one test case minimum**. Each crawled_apis record must generate a test.


---

## Security Testing Checklist

### 1. Authorization Bypass (CRITICAL)

#### BOLA/IDOR (Broken Object Level Authorization)
Test if changing resource IDs allows access to other users' data.

```python
@pytest.mark.parametrize("entry", [
    {"full_url": "https://api.example.com/users/own_id/profile", "expected_status": 200},
    {"full_url": "https://api.example.com/users/other_user_id/profile", "expected_status": 403},
])
def test_bola_cannot_access_other_users_data(api_client, entry, auth_headers):
    """Verify users cannot access resources belonging to others by changing ID"""
    response = api_client.get(entry["full_url"], headers=auth_headers)
    assert response.status_code == entry["expected_status"], "Failed: " + str(response.status_code) + " - " + response.text
```

#### Privilege Escalation
Test if regular users can call admin-only endpoints.

```python
def test_regular_user_cannot_access_admin_endpoints(api_client, regular_user_headers):
    """Verify regular users cannot access admin APIs"""
    admin_urls = [
        "https://api.example.com/admin/users",
        "https://api.example.com/admin/config",
        "https://api.example.com/admin/logs",
    ]
    for full_url in admin_urls:
        response = api_client.get(full_url, headers=regular_user_headers)
        assert response.status_code == 403, "Failed: " + str(response.status_code) + " - " + response.text
```

---

### 2. Injection Attacks (INPUT)

#### SQL Injection
```python
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "1; DROP TABLE users--",
    "1 UNION SELECT * FROM users--",
    "'; EXEC xp_cmdshell('dir')--",
]

@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_sql_injection_in_query_params(api_client, payload):
    """Verify SQL injection payloads are properly sanitized"""
    full_url = "https://api.example.com/users?id=" + payload
    response = api_client.get(full_url)
    assert response.status_code == 400, "Failed: " + str(response.status_code) + " - " + response.text
    assert "sql" not in response.text.lower()
```

#### Command Injection
```python
COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "$(whoami)",
    "`id`",
]

@pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS)
def test_command_injection(api_client, payload):
    """Verify command injection payloads are sanitized"""
    full_url = "https://api.example.com/process"
    response = api_client.post(full_url, json={"filename": payload})
    assert response.status_code == 400, "Failed: " + str(response.status_code) + " - " + response.text
```

#### XSS (Cross-Site Scripting)
```python
XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
    "<svg onload=alert('xss')>",
]

@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_xss_payloads_are_escaped(api_client, payload):
    """Verify XSS payloads are properly escaped in responses"""
    full_url = "https://api.example.com/comments"
    response = api_client.post(full_url, json={"content": payload})
    assert response.status_code == 200, "Failed: " + str(response.status_code) + " - " + response.text
    assert payload not in response.text, "XSS payload reflected without escaping"
```

#### SSRF (Server-Side Request Forgery)
```python
SSRF_PAYLOADS = [
    "http://localhost:22",
    "http://127.0.0.1:3306",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "file:///etc/passwd",
]

@pytest.mark.parametrize("url", SSRF_PAYLOADS)
def test_ssrf_internal_urls_blocked(api_client, url):
    """Verify internal/metadata URLs are blocked"""
    full_url = "https://api.example.com/fetch-url"
    response = api_client.post(full_url, json={"url": url})
    assert response.status_code == 403, "Failed: " + str(response.status_code) + " - " + response.text
```

---

### 3. Mass Assignment
Test if readonly fields can be forcefully modified.

```python
def test_mass_assignment_readonly_fields(api_client, auth_headers):
    """Verify readonly fields cannot be modified via mass assignment"""
    payload = {
        "name": "New Name",  # Allowed
        "role": "admin",     # Should be readonly
        "balance": 999999,   # Should be readonly
        "is_verified": True, # Should be readonly
    }
    full_url = "https://api.example.com/users/me"
    response = api_client.patch(full_url, json=payload, headers=auth_headers)
    assert response.status_code == 200, "Failed: " + str(response.status_code) + " - " + response.text
    user = response.json()
    assert user.get("role") != "admin", "Mass assignment: role field vulnerable"
    assert user.get("balance") != 999999, "Mass assignment: balance field vulnerable"
```

---

### 4. Sensitive Data Exposure (OUTPUT)

#### Check for Leaked Sensitive Fields
```python
SENSITIVE_FIELDS = ["password", "password_hash", "ssn", "credit_card", "secret", "token", "api_key"]

def test_no_sensitive_data_in_response(api_client, auth_headers):
    """Verify sensitive fields are not exposed in API responses"""
    full_url = "https://api.example.com/users/me"
    response = api_client.get(full_url, headers=auth_headers)
    assert response.status_code == 200, "Failed: " + str(response.status_code) + " - " + response.text
    response_text = response.text.lower()
    for field in SENSITIVE_FIELDS:
        assert field not in response_text, "Sensitive data exposed: " + field
```

#### Check Error Messages Don't Leak Stack Traces
```python
def test_error_responses_no_stack_trace(api_client):
    """Verify error responses don't expose internal details"""
    full_url = "https://api.example.com/forbidden"
    response = api_client.get(full_url)
    assert response.status_code == 403, "Failed: " + str(response.status_code) + " - " + response.text
    error_indicators = ["traceback", "exception", "stack trace", "at line", "mysql", "postgresql"]
    response_lower = response.text.lower()
    for indicator in error_indicators:
        assert indicator not in response_lower, "Error leaks internal info: " + indicator
```

---

### 5. Rate Limiting (ABUSE PREVENTION)

```python
def test_rate_limiting_enforced(api_client, auth_headers):
    """Verify rate limiting returns 429 after threshold"""
    full_url = "https://api.example.com/api/login"
    last_response = None
    
    # Send rapid requests
    for _ in range(100):
        last_response = api_client.post(full_url, json={"user": "test", "pass": "test"})
        if last_response.status_code == 429:
            break
    
    assert last_response is not None
    assert last_response.status_code == 429, "Failed: " + str(last_response.status_code) + " - " + last_response.text
    
    # Verify rate limit headers exist
    assert "X-RateLimit-Limit" in last_response.headers or "Retry-After" in last_response.headers
```

---

## Common Assertion Patterns

```python
# Status code (strict)
assert response.status_code == 200, "Failed: " + str(response.status_code) + " - " + response.text

# JSON field existence
assert "data" in response.json()

# JSON field value
assert response.json()["data"][0]["id"] == 1

# Response header
assert response.headers["Content-Type"].startswith("application/json")

# Error scenarios
assert response.status_code == expected_status, "Failed: " + str(response.status_code) + " - " + response.text

# Response time
assert response.elapsed.total_seconds() < 2.0
```

---

## Available Scripts

| Script | Purpose | Description |
|--------|---------|-------------|
| `scripts/scaffold_pytest_api_suite.py` | Generate test scaffold | Creates `tests/`, `conftest.py`, sample tests |

---

## References

- [Pytest API Testing Guide](references/pytest_api_testing_guide.md)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

---

## Execution Checklist (Crawled APIs Focus)

- [ ] Confirm crawled_apis exists in context
- [ ] Use exact full_url only
- [ ] Cover all core resources and HTTP methods
- [ ] Test BOLA/IDOR with different user IDs
- [ ] Test privilege escalation (regular user → admin)
- [ ] Test SQL injection in query/body parameters
- [ ] Test XSS in input fields
- [ ] Test SSRF in URL parameters
- [ ] Test mass assignment on sensitive fields
- [ ] Verify no sensitive data in responses
- [ ] Verify error messages don't leak internals
- [ ] Test rate limiting enforcement
- [ ] Document reusable fixtures

## Assertion & Error Handling Rules (Universal)

1. **Strict status codes**: use `==` comparisons (no `in [200, 201]`).
2. **Descriptive errors**: always include `response.text` in assert messages.
3. **Skip on connection error** (never silently pass):
4. **Security tests**: 404 is not a passing result; prefer 400/401/403/422.

```python
except requests.exceptions.ConnectionError as ex:
    pytest.skip("Endpoint unreachable: " + str(ex))
```
