'use client'

import { useEffect } from 'react'
import { useAuthStore } from '@/store/useAuthStore'
import { getSubscriptionStatus } from '@/lib/api'
import { identify } from '@/lib/analytics'

export function AnalyticsIdentify() {
  const user = useAuthStore((s) => s.user)

  useEffect(() => {
    if (!user?.id) return
    getSubscriptionStatus()
      .then((status) => {
        identify(user.id, { plan: status.plan, role: user.role || 'user' })
      })
      .catch(() => {
        identify(user.id, { role: user.role || 'user' })
      })
  }, [user])

  return null
}
