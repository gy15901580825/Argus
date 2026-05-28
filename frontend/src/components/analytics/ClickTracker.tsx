'use client'

import { useEffect } from 'react'
import { track } from '@/lib/analytics'

const MAX_TEXT = 80

export function ClickTracker() {
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const target = e.target as HTMLElement | null
      if (!target) return
      const el = target.closest('a[href], button[data-track]') as
        | HTMLAnchorElement
        | HTMLButtonElement
        | null
      if (!el) return

      const tag = el.tagName.toLowerCase()
      const href = tag === 'a' ? (el as HTMLAnchorElement).getAttribute('href') : null
      const text = (el.textContent || '').trim().slice(0, MAX_TEXT)
      const trackId = el.getAttribute('data-track') || undefined

      let external = false
      let pathname: string | undefined
      if (href) {
        try {
          const u = new URL(href, window.location.origin)
          external = u.origin !== window.location.origin
          pathname = external ? undefined : u.pathname
        } catch {
          pathname = href.startsWith('#') || href.startsWith('/') ? href : undefined
        }
      }

      track('link_click', {
        link_id: trackId,
        link_text: text || undefined,
        link_href: href || undefined,
        link_path: pathname,
        external,
        location_path: window.location.pathname,
      })
    }

    document.addEventListener('click', handler, true)
    return () => document.removeEventListener('click', handler, true)
  }, [])

  return null
}
