from web_ui_phases.parser import extract_json_tail


def test_extract_json_tail_basic():
    text = 'I did some steps.\n```json\n{"features": [{"name": "a"}]}\n```\n'
    r = extract_json_tail(text)
    assert r == {"features": [{"name": "a"}]}


def test_extract_json_tail_picks_last_block():
    text = (
        'First try:\n```json\n{"features": []}\n```\n'
        'Final:\n```json\n{"features": [{"name": "login"}]}\n```\n'
    )
    r = extract_json_tail(text)
    assert r["features"][0]["name"] == "login"


def test_extract_json_tail_no_fence_returns_empty():
    r = extract_json_tail("no json here")
    assert r == {}


def test_extract_json_tail_malformed_returns_empty():
    text = '```json\n{not valid json\n```'
    r = extract_json_tail(text)
    assert r == {}


def test_extract_json_tail_bare_object_without_fence():
    text = 'blah blah\n{"bugs": [{"severity": "high"}]}\n'
    r = extract_json_tail(text)
    assert r == {"bugs": [{"severity": "high"}]}
