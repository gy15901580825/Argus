import { describe, it, expect } from 'vitest'
import { pLimitFetch } from './p-limit-fetch'

describe('pLimitFetch', () => {
  it('preserves input order in results', async () => {
    const inputs = [1, 2, 3, 4, 5]
    // Earlier indices resolve later than later indices, to prove order is by input not by completion
    const result = await pLimitFetch(inputs, 2, async (n) => {
      await new Promise((r) => setTimeout(r, (6 - n) * 10))
      return n * 2
    })
    expect(result).toEqual([2, 4, 6, 8, 10])
  })

  it('respects the concurrency limit', async () => {
    let inFlight = 0
    let maxInFlight = 0
    const inputs = Array.from({ length: 10 }, (_, i) => i)
    await pLimitFetch(inputs, 3, async (n) => {
      inFlight++
      maxInFlight = Math.max(maxInFlight, inFlight)
      await new Promise((r) => setTimeout(r, 5))
      inFlight--
      return n
    })
    expect(maxInFlight).toBe(3)
  })

  it('does not throw if the worker rejects — workers must catch their own errors', async () => {
    const result = await pLimitFetch([1, 2, 3], 2, async (n) => {
      try {
        if (n === 2) throw new Error('boom')
        return { ok: true, n }
      } catch (e) {
        return { ok: false, error: (e as Error).message }
      }
    })
    expect(result).toEqual([
      { ok: true, n: 1 },
      { ok: false, error: 'boom' },
      { ok: true, n: 3 },
    ])
  })

  it('returns empty array for empty input', async () => {
    const result = await pLimitFetch<number, number>([], 4, async (n) => n)
    expect(result).toEqual([])
  })
})
