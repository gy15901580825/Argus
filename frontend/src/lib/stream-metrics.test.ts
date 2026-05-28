import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

describe('stream-metrics', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.spyOn(console, 'log').mockImplementation(() => {})
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
    vi.unstubAllEnvs()
    vi.resetModules()
  })

  it('is a no-op when debug is false', async () => {
    vi.stubEnv('NODE_ENV', 'development')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_DEBUG', 'false')
    vi.resetModules()
    const { streamMetrics } = await import('./stream-metrics')
    streamMetrics.startSession()
    streamMetrics.markFlush(5)
    streamMetrics.markBoundaryHit('fence', 123)
    vi.advanceTimersByTime(1500)
    expect(console.log).not.toHaveBeenCalled()
    const summary = streamMetrics.endSession()
    expect(summary.flushRateHz).toBe(0)
  })

  it('emits rolling rate logs every 1s when debug is true', async () => {
    vi.stubEnv('NODE_ENV', 'development')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_DEBUG', 'true')
    vi.resetModules()
    const { streamMetrics } = await import('./stream-metrics')
    streamMetrics.startSession()
    streamMetrics.markFlush(3)
    streamMetrics.markFlush(4)
    streamMetrics.markBoundaryHit('paragraph', 10)
    vi.advanceTimersByTime(1100)
    expect(console.log).toHaveBeenCalled()
    const summary = streamMetrics.endSession()
    expect(summary.flushRateHz).toBeGreaterThan(0)
    expect(summary.boundaryDistribution.paragraph).toBe(1)
  })

  it('endSession clears state so subsequent startSession is fresh', async () => {
    vi.stubEnv('NODE_ENV', 'development')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_DEBUG', 'true')
    vi.resetModules()
    const { streamMetrics } = await import('./stream-metrics')
    streamMetrics.startSession()
    streamMetrics.markFlush(1)
    streamMetrics.endSession()
    streamMetrics.startSession()
    const summary = streamMetrics.endSession()
    expect(summary.flushRateHz).toBe(0)
  })
})
