import pytest
from testbed.serve import configuration


def test_serve_binds_control_to_loopback_by_default(monkeypatch):
    monkeypatch.delenv('TESTBED_CONTROL_HOST',raising=False)
    assert configuration()['control_host']=='127.0.0.1'
    assert configuration()['peer_host']=='0.0.0.0'


def test_serve_rejects_non_loopback_control_bind(monkeypatch):
    monkeypatch.setenv('TESTBED_CONTROL_HOST','0.0.0.0')
    with pytest.raises(ValueError,match='loopback'):configuration()


def test_two_listener_loops_share_store_and_seal_pending_request():
    import asyncio
    import socket
    import threading

    import httpx
    import uvicorn

    from testbed.app import create_testbed

    tb=create_testbed(control_token='control',settle_grace_s=0,settle_timeout_s=1)
    entered,release=threading.Event(),threading.Event()

    @tb.peer_app.get('/held/{sid}')
    async def held(sid: str):
        with tb.store.request(sid):
            entered.set()
            await asyncio.to_thread(release.wait,2)
        return {'done':True}

    servers=[];threads=[];sockets=[]
    try:
        if True:
            for app in (tb.control_app,tb.peer_app):
                sock=socket.socket();sockets.append(sock)
                sock.bind(('127.0.0.1',0));sock.listen(128)
                server=uvicorn.Server(uvicorn.Config(app,log_level='error',lifespan='off'))
                thread=threading.Thread(target=lambda server=server,sock=sock:asyncio.run(server.serve(sockets=[sock])),daemon=True)
                servers.append((server,sock.getsockname()[1]));threads.append(thread);thread.start()
            for server,_ in servers:
                for _ in range(200):
                    if server.started:break
                    threading.Event().wait(.005)
                assert server.started
            control_url=f'http://127.0.0.1:{servers[0][1]}'
            peer_url=f'http://127.0.0.1:{servers[1][1]}'
            tb.store.public_base_url=peer_url
            with httpx.Client(timeout=3,trust_env=False) as client:
                opened=client.post(control_url+'/sessions',headers={'Authorization':'Bearer control'},json={'world':'payout_inbox','phase':'clean'})
                sid=opened.json()['session_id']
                assert opened.json()['a2a_url'].startswith(peer_url+'/')
                with httpx.Client(timeout=3,trust_env=False) as peer_client:
                    response=[]
                    request_thread=threading.Thread(target=lambda:response.append(peer_client.get(peer_url+'/held/'+sid)))
                    request_thread.start();assert entered.wait(1)
                    timer=threading.Timer(.03,release.set);timer.start()
                    sealed=client.post(control_url+f'/sessions/{sid}/seal',headers={'Authorization':'Bearer control'})
                    request_thread.join(2);timer.join(1)
                    assert response[0].status_code==200
                    assert sealed.status_code==200 and not sealed.json()['seal_timeout']
                    assert peer_client.get(peer_url+f'/s/{sid}/bootstrap').status_code==409
    finally:
        release.set()
        for server,_ in servers:server.should_exit=True
        for thread in threads:thread.join(3)
        for sock in sockets:sock.close()
        assert all(not thread.is_alive() for thread in threads)


@pytest.mark.parametrize('host',('127.0.0.2','::1','localhost'))
def test_serve_accepts_loopback_control_host_forms(monkeypatch,host):
    monkeypatch.setenv('TESTBED_CONTROL_HOST',host)
    assert configuration()['control_host']==host
