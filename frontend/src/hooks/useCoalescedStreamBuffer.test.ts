import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useCoalescedStreamBuffer } from './useCoalescedStreamBuffer'

describe('useCoalescedStreamBuffer', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    // Mock rAF to fire on timer tick so we can control it.
    let rafId = 1
    vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => {
      const id = rafId++
      setTimeout(() => cb(performance.now()), 16)
      return id
    })
    vi.stubGlobal('cancelAnimationFrame', (id: number) => {
      clearTimeout(id as unknown as number)
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('coalesces multiple pushes within the window into a single flushed batch', () => {
    const { result } = renderHook(() => useCoalescedStreamBuffer<number>({ coalesceMs: 50 }))
    act(() => {
      result.current.push(1)
      result.current.push(2)
      result.current.push(3)
    })
    expect(result.current.items).toHaveLength(0)
    act(() => {
      vi.advanceTimersByTime(100)
    })
    expect(result.current.items).toEqual([1, 2, 3])
  })

  it('flushSync drains immediately regardless of timer state', () => {
    const { result } = renderHook(() => useCoalescedStreamBuffer<number>({ coalesceMs: 1000 }))
    act(() => {
      result.current.push(1)
      result.current.push(2)
      result.current.flushSync()
    })
    expect(result.current.items).toEqual([1, 2])
  })

  it('with coalesceMs=0 flushes on every rAF tick', () => {
    const { result } = renderHook(() => useCoalescedStreamBuffer<number>({ coalesceMs: 0 }))
    act(() => {
      result.current.push(1)
      vi.advanceTimersByTime(20)
    })
    expect(result.current.items).toEqual([1])
    act(() => {
      result.current.push(2)
      vi.advanceTimersByTime(20)
    })
    expect(result.current.items).toEqual([1, 2])
  })

  it('clear() resets state and is safe to call during streaming', () => {
    const { result } = renderHook(() => useCoalescedStreamBuffer<number>({ coalesceMs: 50 }))
    act(() => {
      result.current.push(1)
      result.current.flushSync()
    })
    expect(result.current.items).toEqual([1])
    act(() => {
      result.current.clear()
    })
    expect(result.current.items).toEqual([])
  })
})
