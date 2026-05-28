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

interface UserItem {
  id: string
  username: string
  email: string
  display_name: string | null
  role: string
  is_active: boolean
  plan: string | null
  terms_accepted_at: string | null
  created_at: string
  updated_at: string
}

const ROLES = ['ORDINARY_USER', 'CONTENT_ADMIN', 'SUPER_ADMIN'] as const
const PLANS = ['free', 'starter', 'pro'] as const

function roleBadge(role: string) {
  const colors: Record<string, string> = {
    SUPER_ADMIN: 'bg-red-100 text-red-700',
    CONTENT_ADMIN: 'bg-amber-100 text-amber-700',
    ORDINARY_USER: 'bg-gray-100 text-gray-600',
  }
  return colors[role] || colors.ORDINARY_USER
}

function planBadge(plan: string) {
  const colors: Record<string, string> = {
    pro: 'bg-gradient-to-r from-purple-500 to-blue-500 text-white',
    starter: 'bg-primary/10 text-primary',
    free: 'bg-muted text-muted-foreground',
  }
  return colors[plan] || colors.free
}

export default function AdminUsersPage() {
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const [users, setUsers] = useState<UserItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Edit modal state
  const [editUser, setEditUser] = useState<UserItem | null>(null)
  const [editForm, setEditForm] = useState({
    username: '',
    email: '',
    display_name: '',
    role: '',
    is_active: true,
  })

  // Plan modal state
  const [planUser, setPlanUser] = useState<UserItem | null>(null)
  const [selectedPlan, setSelectedPlan] = useState('free')

  // Create modal state
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState({
    username: '',
    email: '',
    display_name: '',
    role: 'ORDINARY_USER',
    api_token_only: true,
  })

  // Confirm delete
  const [deleteUser, setDeleteUser] = useState<UserItem | null>(null)

  // Token reveal/rotate inside the Edit modal. `currentToken` is the token
  // currently displayed (either revealed from server or freshly rotated);
  // `confirmingRotate` toggles the 2-step confirm UI in-place.
  const [currentToken, setCurrentToken] = useState<string | null>(null)
  const [confirmingRotate, setConfirmingRotate] = useState(false)
  const [showTokenOnCreate, setShowTokenOnCreate] = useState<{
    email: string
    token: string
  } | null>(null)

  const [actionLoading, setActionLoading] = useState(false)

  const fetchUsers = useCallback(async () => {
    try {
      const data = await fetchClient<UserItem[]>('/api/v1/admin/users')
      setUsers(data)
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
    fetchUsers()
  }, [user, router, fetchUsers])

  const showSuccess = (msg: string) => {
    setSuccess(msg)
    setTimeout(() => setSuccess(null), 3000)
  }

  const handleCreate = async () => {
    setActionLoading(true)
    try {
      const resp = await fetchClient<{ id: string; api_token?: string; message: string }>(
        '/api/v1/admin/users',
        {
          method: 'POST',
          body: JSON.stringify(createForm),
        }
      )
      showSuccess('User created')
      setShowCreate(false)
      setCreateForm({
        username: '',
        email: '',
        display_name: '',
        role: 'ORDINARY_USER',
        api_token_only: true,
      })
      // Surface the freshly-minted token in a copy-once modal so the admin
      // can paste it into the welcome email immediately.
      if (resp.api_token) {
        setShowTokenOnCreate({ email: createForm.email, token: resp.api_token })
      }
      await fetchUsers()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  const handleRevealToken = async () => {
    if (!editUser) return
    setActionLoading(true)
    try {
      const resp = await fetchClient<{ api_token: string }>(
        `/api/v1/admin/users/${editUser.id}/api-token`
      )
      setCurrentToken(resp.api_token)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  const handleRotateToken = async () => {
    if (!editUser) return
    setActionLoading(true)
    try {
      const resp = await fetchClient<{ api_token: string }>(
        `/api/v1/admin/users/${editUser.id}/rotate-token`,
        { method: 'POST' }
      )
      setCurrentToken(resp.api_token)
      setConfirmingRotate(false)
      showSuccess('Token rotated — old one no longer works')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  const handleEdit = async () => {
    if (!editUser) return
    setActionLoading(true)
    try {
      await fetchClient(`/api/v1/admin/users/${editUser.id}`, {
        method: 'PATCH',
        body: JSON.stringify(editForm),
      })
      showSuccess('User updated')
      setEditUser(null)
      await fetchUsers()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  const handleToggleActive = async (u: UserItem) => {
    try {
      await fetchClient(`/api/v1/admin/users/${u.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ is_active: !u.is_active }),
      })
      showSuccess(`User ${u.is_active ? 'deactivated' : 'activated'}`)
      await fetchUsers()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const handleDelete = async () => {
    if (!deleteUser) return
    setActionLoading(true)
    try {
      await fetchClient(`/api/v1/admin/users/${deleteUser.id}`, { method: 'DELETE' })
      showSuccess('User deleted')
      setDeleteUser(null)
      await fetchUsers()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  const handlePlanUpdate = async () => {
    if (!planUser) return
    setActionLoading(true)
    try {
      await fetchClient(`/api/v1/admin/users/${planUser.id}/plan`, {
        method: 'PATCH',
        body: JSON.stringify({ plan: selectedPlan }),
      })
      showSuccess(`Plan updated to ${selectedPlan}`)
      setPlanUser(null)
      await fetchUsers()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setActionLoading(false)
    }
  }

  const openEdit = (u: UserItem) => {
    setEditUser(u)
    // Reset the token-section state — token is not auto-revealed; admin
    // must click "Reveal" inside the modal.
    setCurrentToken(null)
    setConfirmingRotate(false)
    setEditForm({
      username: u.username,
      email: u.email,
      display_name: u.display_name || '',
      role: u.role,
      is_active: u.is_active,
    })
  }

  const openPlan = (u: UserItem) => {
    setPlanUser(u)
    setSelectedPlan(u.plan || 'free')
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
        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold">User Management</h1>
          <Button onClick={() => setShowCreate(true)}>Add User</Button>
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

        {/* Users table */}
        <div className="rounded-lg border bg-card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left p-3 font-medium">User</th>
                <th className="text-left p-3 font-medium">Role</th>
                <th className="text-left p-3 font-medium">Plan</th>
                <th className="text-left p-3 font-medium">Status</th>
                <th className="text-left p-3 font-medium">Terms</th>
                <th className="text-left p-3 font-medium">Created</th>
                <th className="text-right p-3 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-b last:border-0 hover:bg-muted/30">
                  <td className="p-3">
                    <div className="font-medium">{u.display_name || u.username}</div>
                    <div className="text-xs text-muted-foreground">{u.email}</div>
                  </td>
                  <td className="p-3">
                    <span
                      className={cn(
                        'text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full',
                        roleBadge(u.role)
                      )}
                    >
                      {u.role.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="p-3">
                    <button
                      onClick={() => openPlan(u)}
                      className={cn(
                        'text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full cursor-pointer hover:opacity-80',
                        planBadge(u.plan || 'free')
                      )}
                    >
                      {u.plan || 'free'}
                    </button>
                  </td>
                  <td className="p-3">
                    <button
                      onClick={() => handleToggleActive(u)}
                      className={cn(
                        'text-xs font-medium px-2 py-0.5 rounded-full cursor-pointer',
                        u.is_active
                          ? 'bg-green-100 text-green-700 hover:bg-green-200'
                          : 'bg-red-100 text-red-700 hover:bg-red-200'
                      )}
                    >
                      {u.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td className="p-3">
                    <span className="text-xs text-muted-foreground">
                      {u.terms_accepted_at
                        ? new Date(u.terms_accepted_at).toLocaleDateString()
                        : '-'}
                    </span>
                  </td>
                  <td className="p-3 text-xs text-muted-foreground">
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  <td className="p-3 text-right space-x-1">
                    <Link href={`/admin/users/${u.id}/runs`}>
                      <Button variant="ghost" size="sm">
                        Runs
                      </Button>
                    </Link>
                    <Button variant="ghost" size="sm" onClick={() => openEdit(u)}>
                      Edit
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-red-600 hover:text-red-700 hover:bg-red-50"
                      onClick={() => setDeleteUser(u)}
                      disabled={u.id === user?.id}
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
              {users.length === 0 && (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-muted-foreground">
                    No users found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create User Modal */}
      {showCreate && (
        <Modal title="Add User" onClose={() => setShowCreate(false)}>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Username *</Label>
              <Input
                value={createForm.username}
                onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Email *</Label>
              <Input
                type="email"
                value={createForm.email}
                onChange={(e) => setCreateForm({ ...createForm, email: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Display Name</Label>
              <Input
                value={createForm.display_name}
                onChange={(e) => setCreateForm({ ...createForm, display_name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <select
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                value={createForm.role}
                onChange={(e) => setCreateForm({ ...createForm, role: e.target.value })}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r.replace('_', ' ')}
                  </option>
                ))}
              </select>
            </div>
            <label className="flex items-start gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                className="mt-1"
                checked={createForm.api_token_only}
                onChange={(e) => setCreateForm({ ...createForm, api_token_only: e.target.checked })}
              />
              <span>
                <span className="font-medium">API-token-only customer</span>{' '}
                <span className="text-muted-foreground">
                  (skip Azure CIAM directory write — for design partners who only use the CLI/CI,
                  not web login)
                </span>
              </span>
            </label>
            <Button
              className="w-full"
              disabled={actionLoading || !createForm.username || !createForm.email}
              onClick={handleCreate}
            >
              {actionLoading ? (
                <>
                  <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                  Creating...
                </>
              ) : (
                'Create User'
              )}
            </Button>
          </div>
        </Modal>
      )}

      {/* Token freshly minted on create — copy-once modal */}
      {showTokenOnCreate && (
        <Modal title="Save this token now" onClose={() => setShowTokenOnCreate(null)}>
          <div className="space-y-4">
            <div className="text-sm text-amber-700 bg-amber-50 rounded p-3">
              This is the only time the token is shown automatically. You can re-reveal or rotate it
              later from the user row, but capture it now so you can paste it into the welcome email
              for <strong>{showTokenOnCreate.email}</strong>.
            </div>
            <div className="rounded-md border bg-muted p-3 font-mono text-sm break-all select-all">
              {showTokenOnCreate.token}
            </div>
            <Button
              className="w-full"
              onClick={() => {
                navigator.clipboard.writeText(showTokenOnCreate.token)
                showSuccess('Token copied to clipboard')
              }}
            >
              Copy token
            </Button>
          </div>
        </Modal>
      )}

      {/* Edit User Modal */}
      {editUser && (
        <Modal title={`Edit: ${editUser.username}`} onClose={() => setEditUser(null)}>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label>Username</Label>
              <Input
                value={editForm.username}
                onChange={(e) => setEditForm({ ...editForm, username: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Email</Label>
              <Input
                type="email"
                value={editForm.email}
                onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Display Name</Label>
              <Input
                value={editForm.display_name}
                onChange={(e) => setEditForm({ ...editForm, display_name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label>Role</Label>
              <select
                className="w-full rounded-md border bg-background px-3 py-2 text-sm"
                value={editForm.role}
                onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {r.replace('_', ' ')}
                  </option>
                ))}
              </select>
            </div>
            <Button className="w-full" disabled={actionLoading} onClick={handleEdit}>
              {actionLoading ? (
                <>
                  <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : (
                'Save Changes'
              )}
            </Button>

            {/* API Token section — reveal + rotate, inline */}
            <div className="border-t pt-4 mt-2 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium">API Token</div>
                  <div className="text-xs text-muted-foreground">
                    Reveal is audit-logged. Rotate invalidates the old token immediately.
                  </div>
                </div>
                <div className="flex gap-2 shrink-0">
                  {!currentToken && !confirmingRotate && (
                    <>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleRevealToken}
                        disabled={actionLoading}
                      >
                        Reveal
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        className="text-amber-700 hover:bg-amber-50"
                        onClick={() => setConfirmingRotate(true)}
                        disabled={actionLoading}
                      >
                        Rotate
                      </Button>
                    </>
                  )}
                </div>
              </div>

              {confirmingRotate && (
                <div className="rounded-md border border-red-200 bg-red-50 p-3 space-y-2">
                  <div className="text-sm text-red-700">
                    <strong>Confirm rotate:</strong> the current token stops working immediately.
                    Any CI / CLI using it will return 401 until the customer is given the new token.
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      onClick={() => setConfirmingRotate(false)}
                    >
                      Cancel
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      className="flex-1"
                      disabled={actionLoading}
                      onClick={handleRotateToken}
                    >
                      {actionLoading ? (
                        <>
                          <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                          Rotating...
                        </>
                      ) : (
                        'Rotate now'
                      )}
                    </Button>
                  </div>
                </div>
              )}

              {currentToken && (
                <div className="rounded-md border bg-muted p-3 space-y-2">
                  <div className="font-mono text-xs break-all select-all">{currentToken}</div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      onClick={() => {
                        navigator.clipboard.writeText(currentToken)
                        showSuccess('Token copied to clipboard')
                      }}
                    >
                      Copy
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => setCurrentToken(null)}>
                      Hide
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </Modal>
      )}

      {/* Plan Update Modal */}
      {planUser && (
        <Modal title={`Subscription: ${planUser.username}`} onClose={() => setPlanUser(null)}>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Current plan: <span className="font-medium">{planUser.plan || 'free'}</span>
            </p>
            <div className="space-y-2">
              <Label>Select Plan</Label>
              <div className="grid gap-2">
                {PLANS.map((p) => (
                  <button
                    key={p}
                    onClick={() => setSelectedPlan(p)}
                    className={cn(
                      'flex items-center justify-between rounded-lg border p-3 text-left transition-colors',
                      selectedPlan === p ? 'border-primary bg-primary/5' : 'hover:bg-muted/50'
                    )}
                  >
                    <div>
                      <div className="font-medium capitalize">{p}</div>
                      <div className="text-xs text-muted-foreground">
                        {p === 'free' && '5 test cases/month'}
                        {p === 'starter' && '500 test cases/month - $29/mo'}
                        {p === 'pro' && 'Unlimited test cases - $129/mo'}
                      </div>
                    </div>
                    {selectedPlan === p && <div className="h-4 w-4 rounded-full bg-primary" />}
                  </button>
                ))}
              </div>
            </div>
            <Button className="w-full" disabled={actionLoading} onClick={handlePlanUpdate}>
              {actionLoading ? (
                <>
                  <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                  Updating...
                </>
              ) : (
                'Update Plan'
              )}
            </Button>
          </div>
        </Modal>
      )}

      {/* Delete Confirmation Modal */}
      {deleteUser && (
        <Modal title="Confirm Delete" onClose={() => setDeleteUser(null)}>
          <div className="space-y-4">
            <p className="text-sm">
              Are you sure you want to delete user <strong>{deleteUser.username}</strong> (
              {deleteUser.email})? This action cannot be undone.
            </p>
            <div className="flex gap-2">
              <Button variant="outline" className="flex-1" onClick={() => setDeleteUser(null)}>
                Cancel
              </Button>
              <Button
                variant="destructive"
                className="flex-1"
                disabled={actionLoading}
                onClick={handleDelete}
              >
                {actionLoading ? (
                  <>
                    <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                    Deleting...
                  </>
                ) : (
                  'Delete'
                )}
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  )
}

function Modal({
  title,
  children,
  onClose,
}: {
  title: string
  children: React.ReactNode
  onClose: () => void
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-lg bg-background border shadow-lg p-6 mx-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">{title}</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground text-lg">
            &times;
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}
