'use client'

type EventParams = Record<string, string | number | boolean | undefined | null>

declare global {
  interface Window {
    gtag?: (command: string, action: string, params?: Record<string, unknown>) => void
  }
}

function clean(params: EventParams): Record<string, string | number | boolean> {
  const out: Record<string, string | number | boolean> = {}
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null) continue
    out[k] = v
  }
  return out
}

export function track(eventName: string, params: EventParams = {}): void {
  if (typeof window === 'undefined' || typeof window.gtag !== 'function') return
  try {
    window.gtag('event', eventName, clean(params))
  } catch (e) {
    console.warn('[analytics] track failed:', eventName, e)
  }
}

export function identify(userId: string, props: EventParams = {}): void {
  if (typeof window === 'undefined' || typeof window.gtag !== 'function') return
  try {
    window.gtag('set', 'user_properties', clean({ ...props }))
    window.gtag('config', process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID || '', {
      user_id: userId,
      send_page_view: false,
    })
  } catch (e) {
    console.warn('[analytics] identify failed:', e)
  }
}

export function hostOf(url: string | null | undefined): string | undefined {
  if (!url) return undefined
  try {
    const base = typeof window !== 'undefined' ? window.location.origin : 'https://example.com'
    return new URL(url, base).host
  } catch {
    return undefined
  }
}
