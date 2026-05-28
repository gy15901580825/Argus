'use client'

import { useEffect, useState, useCallback, use } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { useAuthStore } from '@/store/useAuthStore'
import { fetchClient } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Icons } from '@/components/ui/icons'

interface AuditEntry {
  id: string
  organization_id: string | null
  user_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  metadata: Record<string, unknown>
  created_at: string
}

interface AuditResponse {
  organization_id: string
  limit: number
  offset: number
  logs: AuditEntry[]
}

function actionLabel(action: string): string {
  return action.replace(/_/g, ' ')
}

function actionColor(action: string): string {
  if (action.includes('rotate') || action.includes('removed') || action.includes('demote')) {
    return 'bg-amber-100 text-amber-800'
  }
  if (action.includes('added') || action.includes('created')) {
    return 'bg-green-100 text-green-700'
  }
  if (action.includes('reveal')) {
    return 'bg-blue-100 text-blue-700'
  }
  return 'bg-muted text-muted-foreground'
}

export default function OrgAuditLogPage({ params }: { params: Promise<{ id: string }> }) {
  const { id: orgId } = use(params)
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const [data, setData] = useState<AuditResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchLogs = useCallback(async () => {
    setLoading(true)
    try {
      const resp = await fetchClient<AuditResponse>(
        `/api/v1/organizations/${orgId}/audit-logs?limit=100`
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
    fetchLogs()
  }, [user, router, fetchLogs])

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
            href={`/admin/organizations/${orgId}`}
            className="text-sm text-muted-foreground hover:underline"
          >
            ← Back to organization
          </Link>
        </div>
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold">Audit log</h1>
            <p className="text-sm text-muted-foreground mt-1">
              Last 100 actions, newest first. ADMIN role required.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={fetchLogs}>
            Refresh
          </Button>
        </div>

        {error && (
          <div className="rounded-md bg-red-50 p-3 text-sm text-red-600 mb-4">
            {error}
            <button className="ml-2 underline" onClick={() => setError(null)}>
              dismiss
            </button>
          </div>
        )}

        <div className="rounded-lg border bg-card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left p-3 font-medium">When</th>
                <th className="text-left p-3 font-medium">Actor</th>
                <th className="text-left p-3 font-medium">Action</th>
                <th className="text-left p-3 font-medium">Resource</th>
                <th className="text-left p-3 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              {data?.logs.map((e) => (
                <tr key={e.id} className="border-b last:border-0 hover:bg-muted/30 align-top">
                  <td className="p-3 text-xs text-muted-foreground whitespace-nowrap">
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td className="p-3 text-xs font-mono text-muted-foreground">
                    {e.user_id?.slice(0, 8) || 'system'}
                  </td>
                  <td className="p-3">
                    <span
                      className={`text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full ${actionColor(e.action)}`}
                    >
                      {actionLabel(e.action)}
                    </span>
                  </td>
                  <td className="p-3 text-xs">
                    <div>{e.resource_type || '–'}</div>
                    <div className="font-mono text-[10px] text-muted-foreground/70">
                      {e.resource_id?.slice(0, 8) || ''}
                    </div>
                  </td>
                  <td className="p-3 text-xs">
                    {Object.keys(e.metadata || {}).length > 0 ? (
                      <pre className="text-[10px] whitespace-pre-wrap break-all bg-muted/50 p-2 rounded max-w-md">
                        {JSON.stringify(e.metadata, null, 2)}
                      </pre>
                    ) : (
                      <span className="text-muted-foreground">–</span>
                    )}
                  </td>
                </tr>
              ))}
              {data?.logs.length === 0 && (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-muted-foreground">
                    No audit entries yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
