'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Button } from '@/components/ui/button'
import { useAuthStore } from '@/store/useAuthStore'
import {
  getSubscriptionStatus,
  getSubscriptionUsage,
  createPortalSession,
  createCheckoutSession,
  type SubscriptionStatus,
  type UsageDetails,
} from '@/lib/api'
import { track } from '@/lib/analytics'

export default function SubscriptionPage() {
  const user = useAuthStore((s) => s.user)
  const [status, setStatus] = useState<SubscriptionStatus | null>(null)
  const [usage, setUsage] = useState<UsageDetails | null>(null)
  const [loading, setLoading] = useState(true)
  const [portalLoading, setPortalLoading] = useState(false)

  useEffect(() => {
    if (!user) return
    Promise.all([getSubscriptionStatus(), getSubscriptionUsage()])
      .then(([s, u]) => {
        setStatus(s)
        setUsage(u)
      })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [user])

  const handleManageBilling = async () => {
    track('subscription_manage_billing_click', { plan: status?.plan })
    setPortalLoading(true)
    try {
      const { portal_url } = await createPortalSession()
      window.location.href = portal_url
    } catch (err) {
      console.error('Portal error:', err)
      setPortalLoading(false)
    }
  }

  const handleUpgrade = async (plan: string) => {
    track('subscription_upgrade_click', { from_plan: status?.plan, to_plan: plan })
    try {
      const { checkout_url } = await createCheckoutSession(plan)
      window.location.href = checkout_url
    } catch (err) {
      console.error('Checkout error:', err)
    }
  }

  if (!user) {
    return (
      <div className="min-h-screen pt-24 px-4 text-center">
        <p className="text-muted-foreground">Please log in to view your subscription.</p>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="min-h-screen pt-24 px-4 text-center">
        <p className="text-muted-foreground">Loading subscription details...</p>
      </div>
    )
  }

  const usagePercent =
    status && status.test_cases_limit > 0
      ? Math.min((status.test_cases_used / status.test_cases_limit) * 100, 100)
      : 0
  const isUnlimited = status?.test_cases_limit === 0 && status?.plan !== 'free'

  return (
    <div className="min-h-screen pt-24 pb-16 px-4">
      <div className="max-w-3xl mx-auto space-y-8">
        <div>
          <h1 className="text-3xl font-bold mb-2">Subscription</h1>
          <p className="text-muted-foreground">Manage your plan and usage.</p>
        </div>

        {/* Current Plan */}
        <div className="rounded-xl border p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold">Current Plan</h2>
              <p className="text-2xl font-bold capitalize mt-1">{status?.plan || 'free'}</p>
              <p className="text-sm text-muted-foreground">
                Status: <span className="capitalize">{status?.status || 'active'}</span>
                {status?.cancel_at_period_end && (
                  <span className="text-yellow-600 ml-2">(Cancels at period end)</span>
                )}
              </p>
              {status?.current_period_end && (
                <p className="text-sm text-muted-foreground">
                  Renews: {new Date(status.current_period_end).toLocaleDateString()}
                </p>
              )}
            </div>
            <div className="flex gap-2">
              {status?.plan !== 'free' && (
                <Button variant="outline" onClick={handleManageBilling} disabled={portalLoading}>
                  {portalLoading ? 'Opening...' : 'Manage Billing'}
                </Button>
              )}
              {status?.plan === 'free' && (
                <Button onClick={() => handleUpgrade('starter')}>Upgrade to Starter</Button>
              )}
              {status?.plan === 'starter' && (
                <Button onClick={() => handleUpgrade('pro')}>Upgrade to Pro</Button>
              )}
            </div>
          </div>
        </div>

        {/* Usage */}
        <div className="rounded-xl border p-6 space-y-4">
          <h2 className="text-lg font-semibold">Usage This Period</h2>

          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span>Test Cases</span>
              <span>
                {status?.test_cases_used || 0}
                {isUnlimited ? ' (unlimited)' : ` / ${status?.test_cases_limit || 5}`}
              </span>
            </div>
            {!isUnlimited && (
              <div className="w-full bg-muted rounded-full h-2.5">
                <div
                  className={`h-2.5 rounded-full transition-all ${
                    usagePercent > 90
                      ? 'bg-red-500'
                      : usagePercent > 70
                        ? 'bg-yellow-500'
                        : 'bg-primary'
                  }`}
                  style={{ width: `${usagePercent}%` }}
                />
              </div>
            )}
          </div>

          {usage && (
            <div className="grid grid-cols-2 gap-4 pt-4 border-t">
              <div>
                <p className="text-sm text-muted-foreground">Period</p>
                <p className="text-sm font-medium">
                  {usage.period_start
                    ? `${new Date(usage.period_start).toLocaleDateString()} - ${new Date(usage.period_end!).toLocaleDateString()}`
                    : 'N/A'}
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">LLM Cost</p>
                <p className="text-sm font-medium">${usage.llm_cost_usd.toFixed(4)}</p>
              </div>
            </div>
          )}
        </div>

        {/* Quick Links */}
        <div className="flex gap-4">
          <Link href="/pricing">
            <Button variant="outline">View All Plans</Button>
          </Link>
          <Link href="/dashboard">
            <Button variant="ghost">Back to Dashboard</Button>
          </Link>
        </div>
      </div>
    </div>
  )
}
