'use client'

import { useEffect, useState, useCallback, use } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { useAuthStore } from '@/store/useAuthStore'
import { fetchClient } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Icons } from '@/components/ui/icons'
import { cn } from '@/lib/utils'

interface Run {
  id: string
  submitter_email: string | null
  probe_suite: string
  status: string
  target_kind: string | null
  started_at: string | null
  finished_at: string | null
  findings_count: number
  fails_count: number
}

interface RunsResponse {
  organization: { id: string; name: string }
  total: number
  limit: number
  offset: number
  runs: Run[]
}

function statusBadge(status: string) {
  const colors: Record<string, string> = {
    completed: 'bg-green-100 text-green-700',
    running: 'bg-blue-100 text-blue-700',
    queued: 'bg-gray-100 text-gray-700',
    failed: 'bg-red-100 text-red-700',
    cancelled: 'bg-muted text-muted-foreground',
  }
  return colors[status] || colors.queued
}

function formatDuration(start: string | null, end: string | null): string {
  if (!start || !end) return '–'
  const ms = new Date(end).getTime() - new Date(start).getTime()
  if (ms < 1000) return '<1s'
  if (ms < 60_000) return `${Math.round(ms / 1000)}s`
  const m = Math.floor(ms / 60_000)
  const s = Math.round((ms % 60_000) / 1000)
  return `${m}m ${s}s`
}

export default function OrgRunsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id: orgId } = use(params)
  const router = useRouter()
  const user = useAuthStore((s) => s.user)
  const apiToken = useAuthStore((s) => s.apiToken)
  const [data, setData] = useState<RunsResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [offset, setOffset] = useState(0)
  const PAGE_SIZE = 50

  const fetchRuns = useCallback(async () => {
    setLoading(true)
    try {
      const resp = await fetchClient<RunsResponse>(
        `/api/v1/admin/organizations/${orgId}/redteam-runs?limit=${PAGE_SIZE}&offset=${offset}`
      )
      setData(resp)
      setError(null)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [orgId, offset])

  useEffect(() => {
    if (!user) {
      router.push('/login')
      return
    }
    fetchRuns()
  }, [user, router, fetchRuns])

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
            <h1 className="text-2xl font-bold">Red-team runs</h1>
            <p className="text-sm text-muted-foreground mt-1">
              {data?.organization.name}
              {data && ` · ${data.total} total`}
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={fetchRuns}>
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
                <th className="text-left p-3 font-medium">Started</th>
                <th className="text-left p-3 font-medium">Submitter</th>
                <th className="text-left p-3 font-medium">Probe suite</th>
                <th className="text-left p-3 font-medium">Target</th>
                <th className="text-left p-3 font-medium">Status</th>
                <th className="text-right p-3 font-medium">Findings</th>
                <th className="text-right p-3 font-medium">Fails</th>
                <th className="text-right p-3 font-medium">Duration</th>
                <th className="text-right p-3 font-medium">Report</th>
              </tr>
            </thead>
            <tbody>
              {data?.runs.map((r) => (
                <tr key={r.id} className="border-b last:border-0 hover:bg-muted/30">
                  <td className="p-3">
                    <div className="text-xs text-muted-foreground">
                      {r.started_at ? new Date(r.started_at).toLocaleString() : '–'}
                    </div>
                    <div className="font-mono text-[10px] text-muted-foreground/70">
                      {r.id.slice(0, 8)}
                    </div>
                  </td>
                  <td className="p-3 text-xs">{r.submitter_email || '–'}</td>
                  <td className="p-3 max-w-xs truncate" title={r.probe_suite}>
                    {r.probe_suite}
                  </td>
                  <td className="p-3 text-xs">{r.target_kind || '–'}</td>
                  <td className="p-3">
                    <span
                      className={cn(
                        'text-[10px] font-semibold uppercase px-2 py-0.5 rounded-full',
                        statusBadge(r.status)
                      )}
                    >
                      {r.status}
                    </span>
                  </td>
                  <td className="p-3 text-right">{r.findings_count}</td>
                  <td className="p-3 text-right">
                    {r.fails_count > 0 ? (
                      <span className="font-semibold text-red-600">{r.fails_count}</span>
                    ) : (
                      <span className="text-muted-foreground">0</span>
                    )}
                  </td>
                  <td className="p-3 text-right text-xs text-muted-foreground">
                    {formatDuration(r.started_at, r.finished_at)}
                  </td>
                  <td className="p-3 text-right">
                    <a
                      href={`/api/v1/redteam/runs/${r.id}/report?format=html&token=${encodeURIComponent(apiToken || '')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-primary hover:underline"
                    >
                      HTML
                    </a>
                  </td>
                </tr>
              ))}
              {data?.runs.length === 0 && (
                <tr>
                  <td colSpan={9} className="p-8 text-center text-muted-foreground">
                    No runs yet for this organization.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {data && data.total > PAGE_SIZE && (
          <div className="flex justify-between items-center mt-4 text-sm">
            <div className="text-muted-foreground">
              Showing {offset + 1}–{Math.min(offset + PAGE_SIZE, data.total)} of {data.total}
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                disabled={offset === 0}
                onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              >
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={offset + PAGE_SIZE >= data.total}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                Next
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
