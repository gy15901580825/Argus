'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/useAuthStore'
import { getProfile, updateProfile, type ProfileResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Icons } from '@/components/ui/icons'

export default function ProfilePage() {
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const updateUser = useAuthStore((s) => s.updateUser)

  const [profile, setProfile] = useState<ProfileResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Form fields
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')

  useEffect(() => {
    if (!user) {
      router.push('/login')
      return
    }
    getProfile()
      .then((p) => {
        setProfile(p)
        setUsername(p.username)
        setEmail(p.email)
        setDisplayName(p.display_name || '')
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [user, router])

  const handleSave = async () => {
    if (!profile) return
    setError(null)
    setSuccess(null)
    setSaving(true)

    try {
      const updates: Record<string, string> = {}
      if (username !== profile.username) updates.username = username
      if (email !== profile.email) updates.email = email
      if ((displayName || '') !== (profile.display_name || '')) updates.display_name = displayName

      if (Object.keys(updates).length === 0) {
        setSuccess('No changes to save.')
        setSaving(false)
        return
      }

      const updated = await updateProfile(updates)
      setProfile(updated)

      // Sync Zustand store so Header reflects changes immediately
      updateUser({
        name: updated.username,
        email: updated.email,
      })

      setSuccess('Profile updated successfully.')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setSaving(false)
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
      <div className="container mx-auto max-w-lg px-4">
        <h1 className="text-2xl font-bold mb-6">Profile Settings</h1>

        {error && <div className="rounded-md bg-red-50 p-3 text-sm text-red-600 mb-4">{error}</div>}
        {success && (
          <div className="rounded-md bg-green-50 p-3 text-sm text-green-600 mb-4">{success}</div>
        )}

        <div className="space-y-5">
          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input id="username" value={username} onChange={(e) => setUsername(e.target.value)} />
          </div>

          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="displayName">Display Name</Label>
            <Input
              id="displayName"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Optional display name"
            />
          </div>

          <div className="space-y-2">
            <Label>Role</Label>
            <Input value={profile?.role || ''} disabled />
          </div>

          <div className="space-y-2">
            <Label>Member Since</Label>
            <Input
              value={profile?.created_at ? new Date(profile.created_at).toLocaleDateString() : ''}
              disabled
            />
          </div>

          <Button onClick={handleSave} disabled={saving} className="w-full">
            {saving ? (
              <>
                <Icons.spinner className="mr-2 h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              'Save Changes'
            )}
          </Button>
        </div>
      </div>
    </div>
  )
}
