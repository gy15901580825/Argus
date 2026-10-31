"""Run the private controller and public peer listeners in one process."""
import asyncio
import os

import uvicorn

from .app import create_testbed


def configuration():
    host=os.getenv('TESTBED_CONTROL_HOST','127.0.0.1')
    if host not in ('127.0.0.1','localhost','::1'):
        raise ValueError('the control interface must bind to a loopback host')
    return {'control_host':host,'control_port':int(os.getenv('TESTBED_CONTROL_PORT','8081')),
            'peer_host':'0.0.0.0','peer_port':int(os.getenv('PORT','8080'))}


async def main():
    config=configuration()
    tb=create_testbed(control_token=os.getenv('TESTBED_CONTROL_TOKEN',''),public_base_url=os.getenv('TESTBED_PUBLIC_URL',''),plaintext_base_url=os.getenv('TESTBED_PLAINTEXT_URL',''))
    if not tb.store.public_base_url:tb.store.public_base_url=f'http://127.0.0.1:{config["peer_port"]}'
    control=uvicorn.Server(uvicorn.Config(tb.control_app,host=config['control_host'],port=config['control_port']))
    peer=uvicorn.Server(uvicorn.Config(tb.peer_app,host=config['peer_host'],port=config['peer_port']))
    await asyncio.gather(control.serve(),peer.serve())


if __name__=='__main__':asyncio.run(main())
