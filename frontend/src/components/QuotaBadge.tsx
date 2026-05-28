'use client'

import { useEffect, useState } from 'react'
import { getSubscriptionStatus, type SubscriptionStatus } from '@/lib/api'
import { useAuthStore } from '@/store/useAuthStore'

export function QuotaBadge() {
  const { user } = useAuthStore()
  const [status, setStatus] = useState<SubscriptionStatus | null>(null)

  useEffect(() => {
    if (!user) return
    getSubscriptionStatus()
      .then(setStatus)
      .catch(() => {})
  }, [user])

  if (!user || !status) return null

  const used = status.test_cases_used
  const limit = status.test_cases_limit
  const remaining = Math.max(0, limit - used)
  const pct = limit > 0 ? Math.min(100, Math.round((used / limit) * 100)) : 0

  const isLow = remaining <= 1 && limit > 0
  const isExhausted = remaining === 0 && limit > 0

  const barColor = isExhausted ? 'bg-red-500' : isLow ? 'bg-amber-500' : 'bg-primary'

  const textColor = isExhausted
    ? 'text-red-600'
    : isLow
      ? 'text-amber-600'
      : 'text-muted-foreground'

  const planLabel = status.plan.charAt(0).toUpperCase() + status.plan.slice(1)

  return (
    <div className="rounded-lg border bg-card px-4 py-3 space-y-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            {planLabel} Plan
          </span>
        </div>
        <span className={`text-sm font-semibold ${textColor}`}>
          {remaining} / {limit} remaining
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>

      {isExhausted && (
        <p className="text-xs text-red-600 font-medium">
          Monthly limit reached.{' '}
          <a href="/dashboard/subscription" className="underline hover:text-red-700">
            Upgrade your plan
          </a>
        </p>
      )}
      {isLow && !isExhausted && (
        <p className="text-xs text-amber-600">
          Running low on tests this month.{' '}
          <a href="/dashboard/subscription" className="underline hover:text-amber-700">
            Upgrade
          </a>
        </p>
      )}
    </div>
  )
}
