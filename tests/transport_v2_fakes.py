import asyncio
import concurrent.futures
import threading
from contextlib import asynccontextmanager, contextmanager
from email import policy
from email.parser import BytesParser
from typing import AsyncIterator, Iterator

from aiohttp import web


class VendorAThreadsFake:
    def __init__(self):
        self.recorder = RecordingApp()
        self.app = self.recorder.app
        self.calls = self.recorder.calls
        self.sources = {}
        self.messages = {}
        self.runs = {}
        self.submissions = []
        self.recorder.route('POST', '/v1/sources', self.create_source)
        self.recorder.route('DELETE', '/v1/sources/{ident}', self.delete_source)
        self.recorder.route('POST', '/v1/messages', self.ingest)
        self.recorder.route('DELETE', '/v1/messages', self.delete_message)
        self.recorder.route('POST', '/v1/ask', self.ask)
        self.recorder.route('GET', '/v1/ask/{thread}/{run}', self.poll)

    async def create_source(self, request):
        body = await request.json()
        if any(source['name'] == body['name'] for source in self.sources.values()):
            return web.Response(status=409)
        ident = f'source-{len(self.sources) + 1}'
        self.sources[ident] = body
        return web.json_response({'id': ident}, status=201)

    async def delete_source(self, request):
        ident = request.match_info['ident']
        if any(message['sourceId'] == ident for message in self.messages.values()):
            return web.Response(status=409)
        if self.sources.pop(ident, None) is None:
            return web.Response(status=404)
        return web.json_response({})

    async def ingest(self, request):
        body = await request.json()
        if body['sourceId'] not in self.sources:
            return web.Response(status=404)
        self.messages[(body['sourceId'], body['id'])] = body
        return web.json_response({'recordId': body['id'], 'sourceId': body['sourceId']}, status=201)

    async def delete_message(self, request):
        ident = (request.query['sourceId'], request.query['remoteId'])
        if self.messages.pop(ident, None) is None:
            return web.Response(status=404)
        return web.json_response({})

    async def ask(self, request):
        body = await request.json()
        if not isinstance(body.get('message'), str):
            return web.Response(status=400)
        thread = next(iter(self.messages.values()))['threadId'] if self.messages else 'thread-plain'
        reply = {'threadId': thread, 'runId': f'run-{len(self.submissions) + 1}', 'status': 'running'}
        self.submissions.append(reply.copy())
        self.runs[(thread, reply['runId'])] = 0
        return web.json_response(reply, status=202, headers={
            'Location': f"/v1/ask/{thread}/{reply['runId']}", 'Retry-After': '0',
        })

    async def poll(self, request):
        ident = (request.match_info['thread'], request.match_info['run'])
        if ident not in self.runs:
            return web.Response(status=404)
        self.runs[ident] += 1
        reply = {'threadId': ident[0], 'runId': ident[1], 'status': 'running'}
        if self.runs[ident] == 2:
            reply.update(status='completed', output='Sample handled.')
            self.runs.pop(ident)
        return web.json_response(reply, headers={'Retry-After': '0'})


class VendorBAutomationFake:
    def __init__(self, *, automation_count=1, delete_mode='normal'):
        self.recorder = RecordingApp()
        self.app = self.recorder.app
        self.calls = self.recorder.calls
        self.automation_count = automation_count
        self.delete_mode = delete_mode
        self.org_id = 'neutral-org-' + 'o' * 30
        self.ws_id = 'neutral-workspace-' + 'w' * 30
        self.automation_id = 'neutral-automation-' + 'a' * 30
        self.workspace_name = f'organizations/{self.org_id}/workspaces/{self.ws_id}'
        self.automation_name = self.workspace_name + '/automations/' + self.automation_id
        self.automation_path = '/api/v1/' + self.automation_name
        self.files_path = '/api/v1/' + self.workspace_name + '/files'
        self.find_paths = [
            '/api/v1/me/organizations',
            '/api/v1/me/organizations/' + self.org_id + '/workspaces',
            '/api/v1/' + self.workspace_name + '/automations',
        ]
        self.files = {}
        self.uploads = []
        self.invocations = []
        self.runs = {}
        self.run_names = []
        for path, handler in zip(self.find_paths, [self.organizations, self.workspaces, self.automations]):
            self.recorder.route('GET', path, handler)
        self.recorder.route('POST', self.files_path + ':upload', self.upload)
        self.recorder.route('DELETE', self.files_path + '/{ident}', self.delete_file)
        self.recorder.route('GET', self.files_path + '/{ident}/metadata', self.metadata)
        self.recorder.route('POST', self.automation_path + ':invoke', self.invoke)
        self.recorder.route('GET', self.automation_path + '/runs/{ident}', self.poll)

    async def organizations(self, request):
        return web.json_response({'user_organizations': [{'name': 'organizations/' + self.org_id}], 'next_page_token': ''})

    async def workspaces(self, request):
        return web.json_response({'user_workspaces': [{'name': self.workspace_name}], 'next_page_token': ''})

    async def automations(self, request):
        return web.json_response({'automations': [
            {'name': self.automation_name, 'display_name': 'Neutral invoice reader'}
            for _ in range(self.automation_count)
        ], 'next_page_token': ''})

    async def upload(self, request):
        if not request.content_type.startswith('multipart/'):
            return web.Response(status=400)
        message = BytesParser(policy=policy.default).parsebytes(
            b'Content-Type: ' + request.headers['Content-Type'].encode('ascii')
            + b'\r\nMIME-Version: 1.0\r\n\r\n' + await request.read()
        )
        parts = list(message.iter_parts())
        if len(parts) != 1:
            return web.Response(status=400)
        part = parts[0]
        if part.get_param('name', header='content-disposition') != 'file' or not part.get_filename():
            return web.Response(status=400)
        content = part.get_payload(decode=True)
        ident = f'sample--{len(self.uploads) + 1}.txt'
        name = self.workspace_name + '/files/' + ident
        metadata = {'name': name, 'filename': part.get_filename(), 'sizeBytes': len(content),
                    'mimeType': part.get_content_type(), 'createTime': '2026-01-01T00:00:00Z'}
        self.files[ident] = metadata
        self.uploads.append({'name': name, 'content': content, 'filename': part.get_filename(),
                             'content_type': metadata['mimeType']})
        return web.json_response({'metadata': metadata}, status=201, headers={'Location': name})

    async def delete_file(self, request):
        ident = request.match_info['ident']
        if self.delete_mode == 'present':
            return web.Response(status=500)
        if self.files.pop(ident, None) is None or self.delete_mode == 'gone':
            return web.Response(status=500)
        return web.json_response({})

    async def metadata(self, request):
        item = self.files.get(request.match_info['ident'])
        if item is None:
            return web.Response(status=404)
        return web.json_response({'name': item['name'], 'filename': item['filename'],
                                  'size_bytes': item['sizeBytes'], 'mime_type': item['mimeType'],
                                  'create_time': item['createTime']})

    async def invoke(self, request):
        body = await request.json()
        self.invocations.append(body)
        file = body.get('inputs', {}).get('invoice_file', {}).get('file', {})
        valid = set(file) == {'remote'} and any(item['name'] == file['remote'] for item in self.files.values())
        ident = f'run--{len(self.run_names) + 1}'
        name = self.automation_name + '/runs/' + ident
        self.run_names.append(name)
        self.runs[ident] = {'name': name, 'polls': 0, 'valid': valid}
        return web.json_response({'run_id': name, 'state': {'pending': {}}}, headers={'Retry-After': '0'})

    async def poll(self, request):
        ident = request.match_info['ident']
        run = self.runs.get(ident)
        if run is None:
            return web.Response(status=404)
        run['polls'] += 1
        if not run['valid']:
            state = {'awaiting_guidance': {}}
        elif run['polls'] < 2:
            state = {'executing': {}}
        else:
            state = {'completed': {'outputs': {'answer': 'Sample handled.'}}}
            self.runs.pop(ident)
        return web.json_response({'run_id': run['name'], 'state': state}, headers={'Retry-After': '0'})


class RecordingApp:
    def __init__(self):
        self.app = web.Application()
        self.calls: list[tuple[str, str, dict, bytes]] = []

    def route(self, method, path, handler):
        async def record(request):
            self.calls.append(
                (
                    request.method,
                    request.raw_path,
                    dict(request.headers),
                    await request.read(),
                )
            )
            return await handler(request)

        self.app.router.add_route(method, path, record)


@asynccontextmanager
async def serve(app: RecordingApp) -> AsyncIterator[str]:
    runner = web.AppRunner(app.app, shutdown_timeout=0.1, handler_cancellation=True)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        yield f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    finally:
        await runner.cleanup()


@contextmanager
def serve_in_thread(app: RecordingApp) -> Iterator[str]:
    ready = concurrent.futures.Future()
    loop = asyncio.new_event_loop()
    stop = None

    async def run():
        nonlocal stop
        stop = asyncio.Event()
        try:
            async with serve(app) as origin:
                ready.set_result(origin)
                await stop.wait()
        except BaseException as exc:
            if not ready.done():
                ready.set_exception(exc)
            else:
                raise

    def worker():
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run())
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()

    thread = threading.Thread(target=worker)
    thread.start()
    try:
        yield ready.result(timeout=5)
    finally:
        if stop is not None and not loop.is_closed():
            loop.call_soon_threadsafe(stop.set)
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError('fake HTTP server did not stop')
