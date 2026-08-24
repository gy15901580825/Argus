"""报告渲染必须转义 target 回复 —— 那是攻击者可影响的文本。"""
from redteam.reports import render_html


def test_target_response_is_escaped():
    run = {
        "id": "11111111-1111-1111-1111-111111111111",
        "status": "completed",
        "findings": [{
            "probe_id": "owasp_01_prompt_injection_basic",
            "verdict": "fail",
            "severity": "high",
            "confidence": 0.9,
            "attack_prompt": "hello",
            "target_response": "<script>alert('xss')</script>",
            "reasoning": "r",
            "atlas_id": [],
            "owasp_id": [],
            "nist_id": [],
            "eu_ai_act_id": [],
            "judge_model": "gpt-4",
            "escalated_model": None,
            "target_latency_ms": 100,
            "probed_at": "2026-08-23T12:00:00Z",
        }],
    }
    html = render_html(run)
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html
