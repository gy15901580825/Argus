import pytest


@pytest.fixture
def mock_invocation_context():
    """Minimal InvocationContext stand-in for planner tests."""
    class _Session:
        def __init__(self):
            self.id = "test-session-id"
            self.state = {}
            self.history = []

    class _Ctx:
        def __init__(self):
            self.invocation_id = "inv-1"
            self.session = _Session()
            self.user_content = None

    return _Ctx()
