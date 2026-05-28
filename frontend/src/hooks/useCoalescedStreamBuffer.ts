import { useCallback, useEffect, useLayoutEffect, useRef, useSyncExternalStore } from 'react'
import { streamMetrics } from '@/lib/stream-metrics'

interface Options {
  coalesceMs: number
}

interface Buffer<T> {
  items: T[]
  push: (item: T) => void
  flushSync: () => void
  clear: () => void
}

export function useCoalescedStreamBuffer<T>({ coalesceMs }: Options): Buffer<T> {
  const pendingRef = useRef<T[]>([])
  const flushedRef = useRef<T[]>([])
  const subscribersRef = useRef(new Set<() => void>())
  const rafIdRef = useRef<number | null>(null)
  const heartbeatRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const lastFlushAtRef = useRef<number>(0)

  const notify = useCallback(() => {
    subscribersRef.current.forEach((cb) => cb())
  }, [])

  const flushRef = useRef<() => void>(() => {})

  const flush = useCallback(() => {
    rafIdRef.current = null
    if (pendingRef.current.length === 0) return
    const elapsed = Date.now() - lastFlushAtRef.current
    if (coalesceMs > 0 && elapsed < coalesceMs) {
      // Not yet — reschedule via the ref to avoid a self-reference.
      rafIdRef.current = requestAnimationFrame(() => flushRef.current())
      return
    }
    const batch = pendingRef.current
    pendingRef.current = []
    flushedRef.current = [...flushedRef.current, ...batch]
    lastFlushAtRef.current = Date.now()
    streamMetrics.markFlush(batch.length)
    notify()
  }, [coalesceMs, notify])

  useLayoutEffect(() => {
    flushRef.current = flush
  }, [flush])

  const schedule = useCallback(() => {
    if (rafIdRef.current !== null) return
    rafIdRef.current = requestAnimationFrame(flush)
  }, [flush])

  const push = useCallback(
    (item: T) => {
      pendingRef.current.push(item)
      schedule()
    },
    [schedule]
  )

  const flushSync = useCallback(() => {
    if (rafIdRef.current !== null) {
      cancelAnimationFrame(rafIdRef.current)
      rafIdRef.current = null
    }
    if (pendingRef.current.length === 0) return
    const batch = pendingRef.current
    pendingRef.current = []
    flushedRef.current = [...flushedRef.current, ...batch]
    lastFlushAtRef.current = Date.now()
    streamMetrics.markFlush(batch.length)
    notify()
  }, [notify])

  const clear = useCallback(() => {
    if (rafIdRef.current !== null) {
      cancelAnimationFrame(rafIdRef.current)
      rafIdRef.current = null
    }
    pendingRef.current = []
    flushedRef.current = []
    notify()
  }, [notify])

  const subscribe = useCallback((cb: () => void) => {
    subscribersRef.current.add(cb)
    return () => {
      subscribersRef.current.delete(cb)
    }
  }, [])

  const getSnapshot = useCallback(() => flushedRef.current, [])

  const items = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)

  // Backup heartbeat for background-tab scenarios where rAF is paused.
  useEffect(() => {
    const beat = Math.max(coalesceMs * 2, 100)
    heartbeatRef.current = setInterval(() => {
      if (pendingRef.current.length > 0) flush()
    }, beat)
    return () => {
      if (heartbeatRef.current) clearInterval(heartbeatRef.current)
      if (rafIdRef.current !== null) cancelAnimationFrame(rafIdRef.current)
    }
  }, [coalesceMs, flush])

  return { items, push, flushSync, clear }
}
