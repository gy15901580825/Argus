'use client'

import { useState } from 'react'
import { useAuthStore } from '@/store/useAuthStore'
import { fetchClient } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Icons } from '@/components/ui/icons'

// Microsoft Entra External ID falls back to these synthetic suffixes when its
// sign-up flow doesn't capture the user's real email. Anyone whose stored
// email matches isn't reachable by us, so we prompt them to fix it.
const SYNTHETIC_EMAIL_SUFFIXES = ['@yourtenant.onmicrosoft.com', '@argus.local']

function isSyntheticEmail(email: string | undefined | null): boolean {
  if (!email) return false
  return SYNTHETIC_EMAIL_SUFFIXES.some((s) => email.endsWith(s))
}

export function EmailCaptureBanner() {
  const user = useAuthStore((s) => s.user)
  const updateUser = useAuthStore((s) => s.updateUser)

  const [open, setOpen] = useState(false)
  const [newEmail, setNewEmail] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!user || !isSyntheticEmail(user.email)) {
    return null
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const updated = await fetchClient<{ email: string }>('/api/v1/profile', {
        method: 'PATCH',
        body: JSON.stringify({ email: newEmail.trim().toLowerCase() }),
      })
      updateUser({ email: updated.email })
      setOpen(false)
      setNewEmail('')
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <>
      <div className="bg-amber-50 border-b border-amber-200 px-4 py-2 text-sm">
        <div className="container mx-auto flex flex-wrap items-center justify-between gap-2">
          <div className="text-amber-900">
            <strong>Action required:</strong> your account email is auto-generated and not
            deliverable. Set your real email so we can reach you about findings, alerts, and account
            updates.
          </div>
          <Button
            size="sm"
            variant="default"
            className="bg-amber-600 hover:bg-amber-700"
            onClick={() => setOpen(true)}
          >
            Set email
          </Button>
        </div>
      </div>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <form
            onSubmit={handleSubmit}
            className="w-full max-w-md rounded-lg border bg-card p-6 shadow-lg space-y-4"
          >
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold">Set your email</h2>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="text-muted-foreground hover:text-foreground"
              >
                ✕
              </button>
            </div>

            <div className="text-sm text-muted-foreground">
              We&apos;ll use this address for welcome messages, cost alerts, and any reports we
              generate. You can change it again later from your profile.
            </div>

            <div className="space-y-2">
              <Label>Email *</Label>
              <Input
                type="email"
                placeholder="cto@your-company.com"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                required
                autoFocus
              />
            </div>

            {error && <div className="rounded-md bg-red-50 p-3 text-sm text-red-700">{error}</div>}

            <div className="flex gap-2">
              <Button
                type="button"
                variant="outline"
                className="flex-1"
                onClick={() => setOpen(false)}
              >
                Cancel
              </Button>
              <Button type="submit" className="flex-1" disabled={submitting || !newEmail.trim()}>
                {submitting ? (
                  <>
                    <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                    Saving...
                  </>
                ) : (
                  'Save'
                )}
              </Button>
            </div>
          </form>
        </div>
      )}
    </>
  )
}
