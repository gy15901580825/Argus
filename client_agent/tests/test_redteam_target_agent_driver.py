"""Observe the preserved legacy request at a real loopback HTTP endpoint."""
from __future__ import annotations

import pytest
from aiohttp import web
from redteam_runner.target_agent_driver import TargetAgentDriver
from argus_transport import TransportOutcome


@pytest.mark.asyncio
async def test_driver_posts_url_and_prompt_to_agent():
    received = []
    async def handle(request):
        received.append(await request.json())
        return web.json_response({"final_text": "done", "screenshots": []})
    app = web.Application()
    app.router.add_post('/agent', handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '127.0.0.1', 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        result = await TargetAgentDriver(agent_url=f'http://127.0.0.1:{port}/agent',
                    scenario_url='http://127.0.0.1:18080/scenario', prompt='Click the link', timeout_s=30).run()
    finally:
        await runner.cleanup()
    assert result.outcome == TransportOutcome.SUCCEEDED
    assert result.response_text == 'done'
    assert received == [{'url':'http://127.0.0.1:18080/scenario','prompt':'Click the link'}]
