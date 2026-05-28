# Pytest API Testing Guide

A concise reference for API testing with pytest + requests/httpx.

## Goals

- Verify APIs meet functional and business requirements
- Validate error handling and edge cases are robust
- Improve release quality and maintainability

## Test Categories

### Functional Tests
- **CRUD Operations**: GET, POST, PUT, PATCH, DELETE
- **Input Validation**: Missing fields, invalid types, boundary values
- **Authentication**: Unauthenticated, expired tokens, insufficient permissions

### Security Tests
- **Authorization Bypass**: BOLA/IDOR, privilege escalation
- **Injection Attacks**: SQL injection, command injection, XSS
- **Data Exposure**: Sensitive data in responses, stack traces in errors
- **Abuse Prevention**: Rate limiting, brute force protection

### Integration Tests
- Database interactions
- Third-party service integrations

## Common Assertions

```python
# Status codes
assert response.status_code == 200  # Success
assert response.status_code == 201  # Created
assert response.status_code == 204  # No Content
assert response.status_code == 400  # Bad Request
assert response.status_code == 401  # Unauthorized
assert response.status_code == 403  # Forbidden
assert response.status_code == 404  # Not Found
assert response.status_code == 429  # Rate Limited
assert response.status_code == 500  # Server Error

# Headers
assert response.headers["Content-Type"].startswith("application/json")

# Response body
assert "data" in response.json()
assert response.json()["id"] == expected_id
assert isinstance(response.json()["items"], list)
```

## Minimum Test Coverage

1. **List Resources**: `GET /resources`
2. **Get Single Resource**: `GET /resources/{id}`
3. **Create Resource**: `POST /resources`
4. **Update Resource**: `PUT/PATCH /resources/{id}`
5. **Delete Resource**: `DELETE /resources/{id}`
6. **Error Cases**: Missing fields, 404 not found
7. **Security Cases**: BOLA, injection, rate limiting

## Best Practices

- Use `conftest.py` for shared fixtures
- Use `@pytest.mark.parametrize` for data-driven tests
- Use `httpx.Client()` or `requests.Session()` for connection reuse
- Run with `-rP` flag for debug output
- Tag security tests with `@pytest.mark.security`

## Code Example

```python
import httpx
import pytest

@pytest.fixture
def api_client(base_url, auth_headers):
    with httpx.Client(base_url=base_url, headers=auth_headers) as client:
        yield client

def test_get_users_list(api_client):
    response = api_client.get("/api/users")
    assert response.status_code == 200
    assert "data" in response.json()

@pytest.mark.security
def test_cannot_access_other_user_data(api_client):
    response = api_client.get("/api/users/other_user_id/profile")
    assert response.status_code in (403, 404)
```

## Important Notes

- Avoid write operations on production; use sandbox or mocks
- Prepare reversible data before delete/update tests
- Make explicit assertions on critical fields, not just status 200
- Always test both positive and negative scenarios
