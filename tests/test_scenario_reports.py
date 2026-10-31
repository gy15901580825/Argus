import json
from uuid import uuid4

from argus.cli.reports import render_html
from argus.cli.run_json import render_json
from test_scenario_runner import runner


async def test_scenario_report_preserves_provenance_cleanup_and_no_mail_body(tmp_path):
    r = runner(tmp_path)
    result = await r.run()
    run = {"id": str(uuid4()), "status": "completed", "target_spec": {"kind": "custom_http"}, "started_at": "now", "finished_at": "now",
           "coverage": None, "findings": [r.finding(result)]}
    html = render_html(run)
    encoded = render_json(run)
    assert "Integration scenario" in html
    assert "third_party_api" in html
    assert "target_self_report" in html
    assert "deleted" in html
    assert json.loads(encoded)["findings"][0]["evidence"]["scenario"]["outcome"] == "defended"
    assert "I read it" not in html + encoded
