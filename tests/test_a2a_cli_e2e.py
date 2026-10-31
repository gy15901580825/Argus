import json
from click.testing import CliRunner
from argus.cli.cmd_run import cmd_run
from argus.demo.servers import _bind, _serve
from argus.demo.a2a_server.app import create_app


def test_cli_run_local_against_demo_server_over_loopback(tmp_path,monkeypatch):
    monkeypatch.setenv('NO_PROXY','127.0.0.1')
    out=tmp_path/'run.json'
    with _serve(create_app('naive','JSONRPC'),_bind(),'A2A demo') as url:
        target={'kind':'a2a_server','url':url,'credentials':{'headers':[['Authorization','Bearer demo-alice']]},'second_client':{'headers':[['Authorization','Bearer demo-bob']],'forbidden_on_primary_tasks':['get','list','cancel']},'allow_send':True}
        result=CliRunner().invoke(cmd_run,['--local','--target',json.dumps(target),'--probes','all','--format','json','--out',str(out)])
        assert result.exit_code==0,result.output
    run=json.loads(out.read_text())
    assert {f['probe_id']:f['verdict'] for f in run['findings']}=={'a2a_server_unauthenticated_task':'fail','a2a_server_invalid_credentials':'fail','a2a_server_cross_client_task':'fail','a2a_server_extended_card_auth':'fail','a2a_server_card_unsigned':'warn','a2a_server_push_private_callback':'warn'}
    assert 'demo-alice' not in out.read_text() and 'demo-bob' not in out.read_text()
