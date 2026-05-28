'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/useAuthStore'
import { createTrialToken, getSubscriptionStatus, type SubscriptionStatus } from '@/lib/api'

const ALLOWED_TRIAL_USERS = ['tester', 'w.lee']

export default function DashboardPage() {
  const router = useRouter()
  const { user, _hasHydrated } = useAuthStore()

  const [email, setEmail] = useState('')
  const [targetUrl, setTargetUrl] = useState('')
  const [expiresHours, setExpiresHours] = useState(168)
  const [trialUrl, setTrialUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const [subStatus, setSubStatus] = useState<SubscriptionStatus | null>(null)

  useEffect(() => {
    if (_hasHydrated && !user) {
      router.push('/login')
    }
  }, [user, _hasHydrated, router])

  useEffect(() => {
    if (user) {
      getSubscriptionStatus()
        .then(setSubStatus)
        .catch(() => {})
    }
  }, [user])

  const canCreateTrial = user && ALLOWED_TRIAL_USERS.includes(user.name)

  const handleCreateTrial = async () => {
    if (!email || !targetUrl) {
      setError('Email and target URL are required.')
      return
    }
    setLoading(true)
    setError('')
    setTrialUrl('')
    try {
      const result = await createTrialToken(email, targetUrl, expiresHours)
      setTrialUrl(result.trial_url)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create trial token')
    } finally {
      setLoading(false)
    }
  }

  const handleCopy = async () => {
    await navigator.clipboard.writeText(trialUrl)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="container flex h-16 items-center px-4">
          <div className="font-bold text-xl text-primary">Argus Dashboard</div>
        </div>
      </header>
      <main className="container mx-auto py-10 px-4">
        <h1 className="text-3xl font-bold mb-8">Overview</h1>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {/* Subscription Plan Card */}
          <Link
            href="/dashboard/subscription"
            className="rounded-xl border bg-card text-card-foreground shadow p-6 hover:border-primary/50 transition-colors"
          >
            <div className="flex flex-row items-center justify-between space-y-0 pb-2">
              <h3 className="tracking-tight text-sm font-medium">Current Plan</h3>
            </div>
            <div className="text-2xl font-bold capitalize">{subStatus?.plan || '—'}</div>
            <p className="text-xs text-muted-foreground">
              {subStatus?.status === 'active' ? 'Active' : subStatus?.status || 'Loading...'}
              {subStatus?.cancel_at_period_end && ' · Canceling'}
            </p>
          </Link>

          {/* Usage Card */}
          <Link
            href="/dashboard/subscription"
            className="rounded-xl border bg-card text-card-foreground shadow p-6 hover:border-primary/50 transition-colors"
          >
            <div className="flex flex-row items-center justify-between space-y-0 pb-2">
              <h3 className="tracking-tight text-sm font-medium">Test Cases Used</h3>
            </div>
            <div className="text-2xl font-bold">
              {subStatus ? subStatus.test_cases_used : '—'}
              <span className="text-sm font-normal text-muted-foreground">
                {subStatus && subStatus.test_cases_limit > 0
                  ? ` / ${subStatus.test_cases_limit}`
                  : subStatus?.plan !== 'free'
                    ? ' / ∞'
                    : ' / 5'}
              </span>
            </div>
            {subStatus && subStatus.test_cases_limit > 0 && (
              <div className="mt-2 w-full bg-muted rounded-full h-1.5">
                <div
                  className={`h-1.5 rounded-full ${
                    subStatus.test_cases_used / subStatus.test_cases_limit > 0.9
                      ? 'bg-red-500'
                      : subStatus.test_cases_used / subStatus.test_cases_limit > 0.7
                        ? 'bg-yellow-500'
                        : 'bg-primary'
                  }`}
                  style={{
                    width: `${Math.min((subStatus.test_cases_used / subStatus.test_cases_limit) * 100, 100)}%`,
                  }}
                />
              </div>
            )}
            <p className="text-xs text-muted-foreground mt-1">This billing period</p>
          </Link>

          <div className="rounded-xl border bg-card text-card-foreground shadow p-6">
            <div className="flex flex-row items-center justify-between space-y-0 pb-2">
              <h3 className="tracking-tight text-sm font-medium">Total Test Cases</h3>
            </div>
            <div className="text-2xl font-bold">1,234</div>
            <p className="text-xs text-muted-foreground">+20.1% from last month</p>
          </div>
          <div className="rounded-xl border bg-card text-card-foreground shadow p-6">
            <div className="flex flex-row items-center justify-between space-y-0 pb-2">
              <h3 className="tracking-tight text-sm font-medium">Pass Rate</h3>
            </div>
            <div className="text-2xl font-bold">98.5%</div>
            <p className="text-xs text-muted-foreground">+1.2% from last week</p>
          </div>
        </div>

        {canCreateTrial && (
          <div className="mt-10">
            <div className="rounded-xl border bg-card text-card-foreground shadow p-6 max-w-xl">
              <h2 className="text-xl font-bold mb-4">Create Trial Link</h2>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium mb-1">Email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="user@example.com"
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Target URL</label>
                  <input
                    type="url"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://example.com"
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-1">Expiry (hours)</label>
                  <input
                    type="number"
                    value={expiresHours}
                    onChange={(e) => setExpiresHours(Number(e.target.value))}
                    min={1}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  />
                </div>
                <button
                  onClick={handleCreateTrial}
                  disabled={loading}
                  className="inline-flex items-center justify-center rounded-md bg-primary text-primary-foreground px-4 py-2 text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
                >
                  {loading ? 'Generating...' : 'Generate Trial Link'}
                </button>
                {error && <p className="text-sm text-destructive">{error}</p>}
                {trialUrl && (
                  <div className="mt-4 rounded-md border bg-muted p-3">
                    <p className="text-sm font-medium mb-2">Trial Link:</p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 text-xs break-all bg-background rounded px-2 py-1">
                        {trialUrl}
                      </code>
                      <button
                        onClick={handleCopy}
                        className="shrink-0 inline-flex items-center rounded-md border bg-background px-3 py-1 text-xs font-medium hover:bg-accent"
                      >
                        {copied ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
