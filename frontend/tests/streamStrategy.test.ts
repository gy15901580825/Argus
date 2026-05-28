import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { streamStrategy, type TypedStreamChunk } from '@/lib/api'

// Mock the auth store so it returns a deterministic API token.
vi.mock('@/store/useAuthStore', () => ({
  useAuthStore: {
    getState: () => ({ apiToken: 'test-token' }),
  },
}))

// Build a fake Response whose body is a ReadableStream yielding the given UTF-8 chunks.
function makeSSEResponse(
  chunks: string[],
  { ok = true, status = 200 }: { ok?: boolean; status?: number } = {}
): Response {
  const encoder = new TextEncoder()
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const c of chunks) controller.enqueue(encoder.encode(c))
      controller.close()
    },
  })
  // @ts-expect-error — jsdom's Response constructor accepts ReadableStream bodies in Vitest's node runtime
  return new Response(stream, { status, statusText: ok ? 'OK' : 'Error' })
}

// Turn a JS event into a single "data: ...\n\n" SSE frame.
function sseFrame(obj: unknown): string {
  return `data: ${JSON.stringify(obj)}\n\n`
}

describe('streamStrategy — SSE parsing', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    vi.restoreAllMocks()
  })

  afterEach(() => {
    global.fetch = originalFetch
  })

  it('routes log events to onTypedChunk with isThinking=true and prefixed stage', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        makeSSEResponse([
          sseFrame({ type: 'log', stage: 'discover', message: 'Found 3 endpoints' }),
        ])
      ) as typeof fetch

    const chunks: string[] = []
    const typed: TypedStreamChunk[] = []

    await streamStrategy(
      { content: 'hi' },
      (c) => chunks.push(c),
      undefined,
      undefined,
      (t) => typed.push(t)
    )

    expect(typed).toHaveLength(1)
    expect(typed[0].type).toBe('log')
    expect(typed[0].isThinking).toBe(true)
    expect(typed[0].content).toBe('[discover] Found 3 endpoints')
    expect(chunks[0]).toBe('[discover] Found 3 endpoints\n')
  })

  it('treats discovery_progress the same as log', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        makeSSEResponse([sseFrame({ type: 'discovery_progress', message: 'scanning' })])
      ) as typeof fetch

    const typed: TypedStreamChunk[] = []
    await streamStrategy(
      { content: 'hi' },
      () => {},
      undefined,
      undefined,
      (t) => typed.push(t)
    )

    expect(typed[0].type).toBe('log')
    expect(typed[0].isThinking).toBe(true)
    expect(typed[0].content).toBe('scanning')
  })

  it('routes progress events to log typed chunks (thinking)', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        makeSSEResponse([sseFrame({ type: 'progress', text: 'step 1' })])
      ) as typeof fetch

    const typed: TypedStreamChunk[] = []
    await streamStrategy(
      { content: 'x' },
      () => {},
      undefined,
      undefined,
      (t) => typed.push(t)
    )

    expect(typed).toEqual([
      expect.objectContaining({ type: 'log', isThinking: true, content: 'step 1' }),
    ])
  })

  it('routes result events to result typed chunks', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        makeSSEResponse([sseFrame({ type: 'result', text: 'Hello world' })])
      ) as typeof fetch

    const chunks: string[] = []
    const typed: TypedStreamChunk[] = []
    await streamStrategy(
      { content: 'x' },
      (c) => chunks.push(c),
      undefined,
      undefined,
      (t) => typed.push(t)
    )

    expect(chunks).toEqual(['Hello world'])
    expect(typed).toEqual([{ type: 'result', content: 'Hello world' }])
  })

  it('emits ssh_result typed chunk with parsed ssh_result payload (direct fields)', async () => {
    const sshPayload = {
      type: 'ssh_result',
      ssh_result: {
        success: true,
        stdout: '1 passed',
        stderr: '',
        exit_code: 0,
        allure_results_url: 'https://r2/allure.zip',
      },
    }
    global.fetch = vi
      .fn()
      .mockResolvedValue(makeSSEResponse([sseFrame(sshPayload)])) as typeof fetch

    const chunks: string[] = []
    const typed: TypedStreamChunk[] = []
    await streamStrategy(
      { content: 'x' },
      (c) => chunks.push(c),
      undefined,
      undefined,
      (t) => typed.push(t)
    )

    expect(typed).toHaveLength(1)
    expect(typed[0].type).toBe('ssh_result')
    expect(typed[0].sshResult).toEqual(sshPayload.ssh_result)
    // Summary chunk text should indicate PASSED
    expect(chunks[0]).toContain('PASSED')
    expect(chunks[0]).toContain('exit code: 0')
  })

  it('ssh_result with success=false labels as FAILED', async () => {
    const payload = {
      type: 'ssh_result',
      ssh_result: { success: false, stdout: '', stderr: 'boom', exit_code: 1 },
    }
    global.fetch = vi.fn().mockResolvedValue(makeSSEResponse([sseFrame(payload)])) as typeof fetch

    const chunks: string[] = []
    await streamStrategy({ content: 'x' }, (c) => chunks.push(c))
    expect(chunks[0]).toContain('FAILED')
    expect(chunks[0]).toContain('exit code: 1')
  })

  it('emits error chunk, calls onError, and stops processing further events', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      makeSSEResponse([
        sseFrame({ type: 'error', error: 'Timeout' }),
        // This should never be emitted because the stream is cancelled on error.
        sseFrame({ type: 'result', text: 'should-not-appear' }),
      ])
    ) as typeof fetch

    const chunks: string[] = []
    const typed: TypedStreamChunk[] = []
    const onError = vi.fn()

    await streamStrategy(
      { content: 'x' },
      (c) => chunks.push(c),
      onError,
      undefined,
      (t) => typed.push(t)
    )

    expect(onError).toHaveBeenCalledOnce()
    expect(onError.mock.calls[0][0]).toBeInstanceOf(Error)
    expect((onError.mock.calls[0][0] as Error).message).toBe('Timeout')
    expect(typed.some((t) => t.type === 'error')).toBe(true)
    // Result event must NOT have been processed.
    expect(chunks.some((c) => c.includes('should-not-appear'))).toBe(false)
  })

  it('captures script_url from a direct artifact event and passes it to onComplete', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        makeSSEResponse([
          sseFrame({ type: 'artifact', script_url: 'https://r2/script.py' }),
          sseFrame({ type: 'result', text: 'Done' }),
        ])
      ) as typeof fetch

    const onComplete = vi.fn()
    await streamStrategy({ content: 'x' }, () => {}, undefined, onComplete)

    expect(onComplete).toHaveBeenCalledWith('https://r2/script.py')
  })

  it('captures script_url from nested content.parts[0].text artifacts payload', async () => {
    const nested = {
      content: {
        parts: [
          {
            text: JSON.stringify({
              type: 'artifacts',
              files: [{ download_url: 'https://r2/nested.py' }],
            }),
          },
        ],
      },
    }
    global.fetch = vi.fn().mockResolvedValue(makeSSEResponse([sseFrame(nested)])) as typeof fetch

    const onComplete = vi.fn()
    await streamStrategy({ content: 'x' }, () => {}, undefined, onComplete)
    expect(onComplete).toHaveBeenCalledWith('https://r2/nested.py')
  })

  it('artifact events do NOT produce visible chunks', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        makeSSEResponse([sseFrame({ type: 'artifact', script_url: 'https://r2/a.py' })])
      ) as typeof fetch

    const chunks: string[] = []
    const typed: TypedStreamChunk[] = []
    await streamStrategy(
      { content: 'x' },
      (c) => chunks.push(c),
      undefined,
      undefined,
      (t) => typed.push(t)
    )
    expect(chunks).toHaveLength(0)
    expect(typed).toHaveLength(0)
  })

  it('unknown "type" with text falls back to result chunk', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        makeSSEResponse([sseFrame({ type: 'misc_event', message: 'hi there' })])
      ) as typeof fetch

    const typed: TypedStreamChunk[] = []
    await streamStrategy(
      { content: 'x' },
      () => {},
      undefined,
      undefined,
      (t) => typed.push(t)
    )
    expect(typed).toEqual([{ type: 'result', content: 'hi there' }])
  })

  it('handles split SSE frames across ReadableStream chunks', async () => {
    // Split the SSE frame in half across two reads so the parser must buffer.
    const frame = sseFrame({ type: 'result', text: 'Hello, world!' })
    const mid = Math.floor(frame.length / 2)
    global.fetch = vi
      .fn()
      .mockResolvedValue(makeSSEResponse([frame.slice(0, mid), frame.slice(mid)])) as typeof fetch

    const chunks: string[] = []
    await streamStrategy({ content: 'x' }, (c) => chunks.push(c))
    expect(chunks).toEqual(['Hello, world!'])
  })

  it('treats a bare "event: done" frame as clean completion', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      makeSSEResponse([
        sseFrame({ type: 'result', text: 'before done' }),
        'event: done\n\n',
        // Anything after event: done should be ignored because we return.
        sseFrame({ type: 'result', text: 'after-done' }),
      ])
    ) as typeof fetch

    const chunks: string[] = []
    const onComplete = vi.fn()
    await streamStrategy({ content: 'x' }, (c) => chunks.push(c), undefined, onComplete)
    expect(chunks).toEqual(['before done'])
    expect(onComplete).toHaveBeenCalledOnce()
  })

  it('throws (via onError) when the HTTP response is not ok', async () => {
    // Non-ok response: mimics the Response shape streamStrategy reads (.json()).
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      body: null,
      json: () => Promise.resolve({ detail: 'boom' }),
    }) as unknown as typeof fetch

    const onError = vi.fn()
    await streamStrategy({ content: 'x' }, () => {}, onError)
    expect(onError).toHaveBeenCalledOnce()
    expect((onError.mock.calls[0][0] as Error).message).toContain('boom')
  })

  it('skips malformed JSON "data:" lines without throwing', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValue(
        makeSSEResponse([
          'data: not json at all\n\n',
          sseFrame({ type: 'result', text: 'after-bad' }),
        ])
      ) as typeof fetch

    const chunks: string[] = []
    await streamStrategy({ content: 'x' }, (c) => chunks.push(c))
    // "not json at all" is treated as plain text chunk (since it's not `{}`).
    expect(chunks).toEqual(['not json at all', 'after-bad'])
  })

  it('sends SSH config and CDP URL in request body when provided', async () => {
    const fetchMock = vi.fn().mockResolvedValue(makeSSEResponse([]))
    global.fetch = fetchMock as typeof fetch

    await streamStrategy(
      {
        content: 'go',
        sshConfig: { remote_ip: '1.1.1.1', username: 'u', pem_key_base64: 'PEM' },
        cdpUrl: 'http://localhost:9222',
      },
      () => {}
    )

    const call = fetchMock.mock.calls[0]
    const body = JSON.parse(call[1].body as string)
    expect(body.ssh_config).toEqual({ remote_ip: '1.1.1.1', username: 'u', pem_key_base64: 'PEM' })
    expect(body.cdp_url).toBe('http://localhost:9222')
  })

  it('injects x-api-token and Authorization headers from the auth store', async () => {
    const fetchMock = vi.fn().mockResolvedValue(makeSSEResponse([]))
    global.fetch = fetchMock as typeof fetch

    await streamStrategy({ content: 'go' }, () => {})

    const headers = fetchMock.mock.calls[0][1].headers as Record<string, string>
    expect(headers['x-api-token']).toBe('test-token')
    expect(headers['Authorization']).toBe('Bearer test-token')
  })

  it('routes web_ui_artifact to a typed chunk with webUiArtifactData (cloud Web UI test)', async () => {
    const script = "import pytest\n\ndef test_home(page):\n    page.goto('https://example.com')\n"
    global.fetch = vi.fn().mockResolvedValue(
      makeSSEResponse([
        sseFrame({
          type: 'web_ui_artifact',
          artifact_type: 'web_ui_tests',
          name: 'web_ui_test_abc.py',
          content: script,
          task_id: 'abc-123',
          url: 'https://example.com',
          source: 'cloud',
        }),
      ])
    ) as typeof fetch

    const chunks: string[] = []
    const typed: TypedStreamChunk[] = []
    await streamStrategy(
      { content: 'run' },
      (c) => chunks.push(c),
      undefined,
      undefined,
      (t) => typed.push(t)
    )

    expect(typed).toHaveLength(1)
    expect(typed[0].type).toBe('web_ui_artifact')
    expect(typed[0].webUiArtifactData?.script).toBe(script)
    expect(typed[0].webUiArtifactData?.name).toBe('web_ui_test_abc.py')
    expect(typed[0].webUiArtifactData?.task_id).toBe('abc-123')
    expect(chunks).toEqual([])
  })

  it('routes web_ui_bug to a typed chunk with webUiBugData', async () => {
    global.fetch = vi.fn().mockResolvedValue(
      makeSSEResponse([
        sseFrame({
          type: 'web_ui_bug',
          bug_counts: { critical: 0, high: 1, medium: 1, low: 7 },
          steps_done: 26,
          url: 'https://example.com',
          task_id: 'abc-123',
          tests_url: 'https://r2/tests',
          bug_report_url: 'https://r2/bugs',
          screenshot_urls: ['https://r2/s0.png'],
        }),
      ])
    ) as typeof fetch

    const typed: TypedStreamChunk[] = []
    await streamStrategy(
      { content: 'run' },
      () => {},
      undefined,
      undefined,
      (t) => typed.push(t)
    )

    expect(typed).toHaveLength(1)
    expect(typed[0].type).toBe('web_ui_bug')
    expect(typed[0].webUiBugData?.bug_counts).toEqual({
      critical: 0,
      high: 1,
      medium: 1,
      low: 7,
    })
    expect(typed[0].webUiBugData?.steps_done).toBe(26)
    expect(typed[0].webUiBugData?.task_id).toBe('abc-123')
    expect(typed[0].webUiBugData?.screenshot_urls).toEqual(['https://r2/s0.png'])
  })

  it('AbortError from fetch is treated as clean completion (calls onComplete, not onError)', async () => {
    const abortErr = new DOMException('aborted', 'AbortError')
    global.fetch = vi.fn().mockRejectedValue(abortErr) as typeof fetch

    const onComplete = vi.fn()
    const onError = vi.fn()
    await streamStrategy({ content: 'x' }, () => {}, onError, onComplete)

    expect(onError).not.toHaveBeenCalled()
    expect(onComplete).toHaveBeenCalledOnce()
  })
})
