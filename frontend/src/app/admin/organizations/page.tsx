'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { useAuthStore } from '@/store/useAuthStore'
import { fetchClient } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Icons } from '@/components/ui/icons'
import { cn } from '@/lib/utils'

interface OrgItem {
  id: string
  name: string
  slug: string
  contact_email: string | null
  plan_tier: string
  is_active: boolean
  member_count: number
  run_count: number
  created_at: string
}

const PLAN_TIERS = ['free', 'team', 'enterprise', 'design_partner'] as const

function planBadge(tier: string) {
  const colors: Record<string, string> = {
    free: 'bg-muted text-muted-foreground',
    team: 'bg-primary/10 text-primary',
    enterprise: 'bg-gradient-to-r from-purple-500 to-blue-500 text-white',
    design_partner: 'bg-amber-100 text-amber-700',
  }
  return colors[tier] || colors.free
}

function Modal({
  title,
  onClose,
  children,
}: {
  title: string
  onClose: () => void
  children: React.ReactNode
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-md rounded-lg border bg-card p-6 shadow-lg">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

export default function AdminOrganizationsPage() {
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const [orgs, setOrgs] = useState<OrgItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({
    name: '',
    contact_email: '',
    plan_tier: 'design_partner',
  })
  const [actionLoading, setActionLoading] = useState(false)

  const fetchOrgs = useCallback(async () => {
    try {
      const data = await fetchClient<OrgItem[]>('/api/v1/admin/organizations')
      setOrgs(data)
      setError(null)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!user) {
      router.push('/login')
      return
    }
    fetchOrgs()
  }, [user, router, fetchOrgs])

  const showSuccess = (msg: string) => {
    setSuccess(msg)
    setTimeout(() => setSuccess(null), 3000)
  }

  const handleCreate = async () => {
    setActionLoading(true)
    try {
      const resp = await fetchClient<{ id: string; slug: string; name: string }>(
        '/api/v1/organizations',
        {
          method: 'POST',
          body: JSON.stringify(createForm),
        }
      )
      showSuccess(`Created ${resp.name}`)
      setShowCreate(false)
      setCreateForm({ name: '', contact_email: '', plan_tier: 'design_partner' })
      await fetchOrgs()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Icons.spinner className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background pt-20 pb-12">
      <div className="container mx-auto max-w-6xl px-4">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Organizations</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {orgs.length} total · {orgs.filter((o) => o.is_active).length} active
            </p>
          </div>
          <Button onClick={() => setShowCreate(true)}>Create Organization</Button>
        </div>

        {error && (
          <div className="rounded-md bg-red-50 p-3 text-sm text-red-600 mb-4">
            {error}
            <button className="ml-2 underline" onClick={() => setError(null)}>
              dismiss
            </button>
          </div>
        )}
        {success && (
          <div className="rounded-md bg-green-50 p-3 text-sm text-green-600 mb-4">{success}</div>
        )}

        <div className="rounded-lg border bg-card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left p-3 font-medium">Name</th>
                <th className="text-left p-3 font-medium">Plan</th>
                <th className="text-left p-3 font-medium">Contact</th>
                <th className="text-right p-3 font-medium">Members</th>
                <th className="text-right p-3 font-medium">Runs</th>
                <th className="text-left p-3 font-medium">Status</th>
                <th className="text-left p-3 font-medium">Created</th>
                <th className="text-right p-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {orgs.map((o) => (
                <tr key={o.id} className="border-b last:border-0 hover:bg-muted/30">
                  <td className="p-3">
                    <div className="font-medium">{o.name}</div>
                    <div className="text-xs text-muted-foreground font-mono">{o.slug}</div>
                  </td>
                  <td className="p-3">
                    <span
                      className={cn(
                        'text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full',
                        planBadge(o.plan_tier)
                      )}
                    >
                      {o.plan_tier.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="p-3 text-xs">{o.contact_email || '–'}</td>
                  <td className="p-3 text-right">{o.member_count}</td>
                  <td className="p-3 text-right">
                    {o.run_count > 0 ? (
                      <span className="font-semibold">{o.run_count}</span>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </td>
                  <td className="p-3">
                    <span
                      className={cn(
                        'text-xs px-2 py-0.5 rounded-full',
                        o.is_active
                          ? 'bg-green-100 text-green-700'
                          : 'bg-muted text-muted-foreground'
                      )}
                    >
                      {o.is_active ? 'Active' : 'Archived'}
                    </span>
                  </td>
                  <td className="p-3 text-xs text-muted-foreground">
                    {new Date(o.created_at).toLocaleDateString()}
                  </td>
                  <td className="p-3 text-right">
                    <Link href={`/admin/organizations/${o.id}`}>
                      <Button variant="ghost" size="sm">
                        Manage
                      </Button>
                    </Link>
                  </td>
                </tr>
              ))}
              {orgs.length === 0 && (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-muted-foreground">
                    No organizations yet. Click &quot;Create Organization&quot; to add one.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {showCreate && (
        <Modal title="Create Organization" onClose={() => setShowCreate(false)}>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Name *</Label>
              <Input
                placeholder="ACME Corp"
                value={createForm.name}
                onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
              />
              <div className="text-xs text-muted-foreground">
                Auto-generates a unique slug like <code>acme-corp-a1b2c3</code>.
              </div>
            </div>
            <div className="space-y-2">
              <Label>Contact Email</Label>
              <Input
                type="email"
                placeholder="cto@acme.com"
                value={createForm.contact_email}
                onChange={(e) => setCreateForm({ ...createForm, contact_email: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Plan Tier</Label>
              <select
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                value={createForm.plan_tier}
                onChange={(e) => setCreateForm({ ...createForm, plan_tier: e.target.value })}
              >
                {PLAN_TIERS.map((t) => (
                  <option key={t} value={t}>
                    {t.replace('_', ' ')}
                  </option>
                ))}
              </select>
            </div>
            <Button
              className="w-full"
              disabled={actionLoading || !createForm.name}
              onClick={handleCreate}
            >
              {actionLoading ? (
                <>
                  <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                  Creating...
                </>
              ) : (
                'Create Organization'
              )}
            </Button>
            <div className="text-xs text-muted-foreground">
              You will be added as <strong>OWNER</strong> of the new organization.
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}
