from argus.cli.baseline_key import baseline_key

T = {"kind": "openai_compat", "endpoint_url": "https://x", "model": "m"}


def test_same_key_when_only_api_key_differs():
    assert baseline_key({**T, "api_key": "a"}) == baseline_key({**T, "api_key": "b"})


def test_different_key_when_endpoint_differs():
    assert baseline_key(T) != baseline_key({**T, "endpoint_url": "https://y"})


def test_nested_api_key_ignored():
    assert baseline_key({**T, "inner": {"api_key": "a", "x": 1}}) == baseline_key({**T, "inner": {"api_key": "b", "x": 1}})


def test_headers_ignored_and_lists_cleaned():
    a = {**T, "headers": {"X-A": "1"}, "steps": [{"cookie": "c1", "n": 1}]}
    b = {**T, "headers": {"X-B": "2"}, "steps": [{"cookie": "c2", "n": 1}]}
    assert baseline_key(a) == baseline_key(b)
    assert len(baseline_key(a)) == 32



def test_trap_settings_do_not_change_the_key():
    b = {"kind": "browser_use", "agent_url": "http://a", "scenario_kind": "dom_injection"}
    lan = {**b, "trap_host": "0.0.0.0", "trap_port": 8765, "trap_public_url": "http://10.0.0.5:8765"}
    assert baseline_key({**lan, "trap_public_url": "http://10.0.0.9:8765"}) == baseline_key(lan) == baseline_key(b)
    assert baseline_key({**b, "agent_url": "http://other"}) != baseline_key(b)
