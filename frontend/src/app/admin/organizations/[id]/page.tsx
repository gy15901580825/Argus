'use client'

import { useEffect, useState, useCallback, use } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { useAuthStore } from '@/store/useAuthStore'
import { fetchClient } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Icons } from '@/components/ui/icons'
import { cn } from '@/lib/utils'

interface Member {
  user_id: string
  username: string
  email: string
  display_name: string | null
  role: string
  joined_at: string
}

interface OrgMembersResponse {
  organization: { id: string; name: string; slug: string }
  members: Member[]
}

const ROLES = ['VIEWER', 'MEMBER', 'ADMIN', 'OWNER'] as const

function roleBadge(role: string) {
  const colors: Record<string, string> = {
    OWNER: 'bg-red-100 text-red-700',
    ADMIN: 'bg-amber-100 text-amber-700',
    MEMBER: 'bg-primary/10 text-primary',
    VIEWER: 'bg-muted text-muted-foreground',
  }
  return colors[role] || colors.VIEWER
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

export default function AdminOrganizationDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id: orgId } = use(params)
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const [data, setData] = useState<OrgMembersResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const [showInvite, setShowInvite] = useState(false)
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('MEMBER')
  const [actionLoading, setActionLoading] = useState(false)

  const [roleEditMember, setRoleEditMember] = useState<Member | null>(null)
  const [selectedRole, setSelectedRole] = useState('MEMBER')

  const fetchMembers = useCallback(async () => {
    try {
      const resp = await fetchClient<OrgMembersResponse>(
        `/api/v1/admin/organizations/${orgId}/members`
      )
      setData(resp)
      setError(null)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [orgId])

  useEffect(() => {
    if (!user) {
      router.push('/login')
      return
    }
    fetchMembers()
  }, [user, router, fetchMembers])

  const showSuccess = (msg: string) => {
    setSuccess(msg)
    setTimeout(() => setSuccess(null), 3000)
  }

  const handleInvite = async () => {
    setActionLoading(true)
    try {
      await fetchClient(`/api/v1/organizations/${orgId}/members`, {
        method: 'POST',
        body: JSON.stringify({ user_email: inviteEmail, role: inviteRole }),
      })
      showSuccess(`Added ${inviteEmail} as ${inviteRole}`)
      setShowInvite(false)
      setInviteEmail('')
      setInviteRole('MEMBER')
      await fetchMembers()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  const handleRoleChange = async () => {
    if (!roleEditMember) return
    setActionLoading(true)
    try {
      await fetchClient(`/api/v1/organizations/${orgId}/members/${roleEditMember.user_id}`, {
        method: 'PATCH',
        body: JSON.stringify({ role: selectedRole }),
      })
      showSuccess(`Role updated to ${selectedRole}`)
      setRoleEditMember(null)
      await fetchMembers()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  const handleRemove = async (m: Member) => {
    if (!confirm(`Remove ${m.email} from this organization?`)) return
    try {
      await fetchClient(`/api/v1/organizations/${orgId}/members/${m.user_id}`, {
        method: 'DELETE',
      })
      showSuccess('Member removed')
      await fetchMembers()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  if (loading && !data) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Icons.spinner className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background pt-20 pb-12">
      <div className="container mx-auto max-w-6xl px-4">
        <div className="mb-4">
          <Link
            href="/admin/organizations"
            className="text-sm text-muted-foreground hover:underline"
          >
            ← All organizations
          </Link>
        </div>
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">{data?.organization.name}</h1>
            <p className="text-sm text-muted-foreground mt-1 font-mono">
              {data?.organization.slug}
            </p>
          </div>
          <div className="flex gap-2">
            <Link href={`/admin/organizations/${orgId}/audit`}>
              <Button variant="outline">Audit log</Button>
            </Link>
            <Link href={`/admin/organizations/${orgId}/runs`}>
              <Button variant="outline">View runs</Button>
            </Link>
            <Button onClick={() => setShowInvite(true)}>Add Member</Button>
          </div>
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

        <h2 className="text-lg font-semibold mb-3">Members ({data?.members.length || 0})</h2>
        <div className="rounded-lg border bg-card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left p-3 font-medium">Member</th>
                <th className="text-left p-3 font-medium">Role</th>
                <th className="text-left p-3 font-medium">Joined</th>
                <th className="text-right p-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {data?.members.map((m) => (
                <tr key={m.user_id} className="border-b last:border-0 hover:bg-muted/30">
                  <td className="p-3">
                    <div className="font-medium">{m.display_name || m.username}</div>
                    <div className="text-xs text-muted-foreground">{m.email}</div>
                  </td>
                  <td className="p-3">
                    <span
                      className={cn(
                        'text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full',
                        roleBadge(m.role)
                      )}
                    >
                      {m.role}
                    </span>
                  </td>
                  <td className="p-3 text-xs text-muted-foreground">
                    {new Date(m.joined_at).toLocaleDateString()}
                  </td>
                  <td className="p-3 text-right space-x-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => {
                        setRoleEditMember(m)
                        setSelectedRole(m.role)
                      }}
                    >
                      Role
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-red-600 hover:bg-red-50"
                      onClick={() => handleRemove(m)}
                    >
                      Remove
                    </Button>
                  </td>
                </tr>
              ))}
              {data?.members.length === 0 && (
                <tr>
                  <td colSpan={4} className="p-8 text-center text-muted-foreground">
                    No members yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Invite member */}
      {showInvite && (
        <Modal title="Add member" onClose={() => setShowInvite(false)}>
          <div className="space-y-4">
            <div className="text-sm text-muted-foreground">
              Add an existing Argus user to this organization by email. Email-invitation to new
              users (auto-create account) is a Y4 follow-up.
            </div>
            <div className="space-y-2">
              <Label>User Email *</Label>
              <Input
                type="email"
                placeholder="appsec@acme.com"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <select
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value)}
              >
                {ROLES.filter((r) => r !== 'OWNER').map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              <div className="text-xs text-muted-foreground">
                OWNER role cannot be assigned via Add. Promote a member later via Role.
              </div>
            </div>
            <Button
              className="w-full"
              disabled={actionLoading || !inviteEmail}
              onClick={handleInvite}
            >
              {actionLoading ? (
                <>
                  <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                  Adding...
                </>
              ) : (
                'Add Member'
              )}
            </Button>
          </div>
        </Modal>
      )}

      {/* Edit role */}
      {roleEditMember && (
        <Modal
          title={`Change role: ${roleEditMember.email}`}
          onClose={() => setRoleEditMember(null)}
        >
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Role</Label>
              <select
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                value={selectedRole}
                onChange={(e) => setSelectedRole(e.target.value)}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
              <div className="text-xs text-muted-foreground">
                Demoting the last OWNER is blocked at the API; promote someone else first if needed.
              </div>
            </div>
            <Button
              className="w-full"
              disabled={actionLoading || selectedRole === roleEditMember.role}
              onClick={handleRoleChange}
            >
              {actionLoading ? (
                <>
                  <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                  Updating...
                </>
              ) : (
                'Save'
              )}
            </Button>
          </div>
        </Modal>
      )}
    </div>
  )
}
