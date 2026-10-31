import pytest
from testbed import app as mod

@pytest.fixture(autouse=True)
def configured_control_token(monkeypatch):
    monkeypatch.setattr(mod, 'CONTROL_TOKEN', 'test-control-token')

@pytest.fixture
def control_headers():
    return {'Authorization': 'Bearer test-control-token'}
