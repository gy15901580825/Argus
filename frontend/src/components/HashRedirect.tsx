'use client'

import { useEffect } from 'react'
import { useRouter, usePathname } from 'next/navigation'

export function HashRedirect() {
  const router = useRouter()
  const pathname = usePathname()

  useEffect(() => {
    // Handle hash-based navigation for old links
    const hash = window.location.hash

    if (hash === '#docs') {
      router.replace('/docs')
      return
    }

    if (hash === '#blog') {
      router.replace('/blog')
      return
    }
  }, [router, pathname])

  return null
}
