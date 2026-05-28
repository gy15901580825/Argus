'use client'

import { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { getScripts, deleteScript, ScriptResponse } from '@/lib/api'
import { useAuthStore } from '@/store/useAuthStore'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Icons } from '@/components/ui/icons'

export default function ScriptsPage() {
  const user = useAuthStore((state) => state.user)
  const router = useRouter()
  const [scripts, setScripts] = useState<ScriptResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [isCheckingAuth, setIsCheckingAuth] = useState(true)

  // Check authentication on mount
  useEffect(() => {
    // Give a moment for auth state to initialize
    const timer = setTimeout(() => {
      setIsCheckingAuth(false)
      if (!user) {
        // Redirect to login if not authenticated
        router.push('/login?redirect=/scripts')
      }
    }, 500)

    return () => clearTimeout(timer)
  }, [user, router])

  const loadScripts = async () => {
    try {
      setLoading(true)
      const data = await getScripts()
      setScripts(data)
      setError(null)
    } catch (err: any) {
      console.error('Failed to load scripts:', err)
      setError('Failed to load scripts')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (user) {
      loadScripts()
    }
  }, [user])

  const handleDelete = async (scriptId: string) => {
    try {
      await deleteScript(scriptId)
      setScripts(scripts.filter((s) => s.id !== scriptId))
      setDeleteConfirm(null)
      setError(null)
    } catch (err: any) {
      console.error('Failed to delete script:', err)
      setError('Failed to delete script')
    }
  }

  const handleDownload = (scriptAddress: string, scriptName: string) => {
    if (scriptAddress.startsWith('data:')) {
      // For base64 data URI, create a blob and trigger download
      const link = document.createElement('a')
      link.href = scriptAddress
      link.download = scriptName
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
    } else {
      // For R2 URLs, open in new tab to download
      window.open(scriptAddress, '_blank')
    }
  }

  // Show loading while checking authentication
  if (isCheckingAuth) {
    return (
      <div className="container mx-auto py-8">
        <div className="flex items-center justify-center py-12">
          <Icons.spinner className="h-8 w-8 animate-spin" />
        </div>
      </div>
    )
  }

  // Show authentication required message (should rarely be seen due to redirect)
  if (!user) {
    return (
      <div className="container mx-auto py-8">
        <Card>
          <CardHeader>
            <CardTitle>Authentication Required</CardTitle>
            <CardDescription>
              Please sign in to view your scripts. Redirecting to login...
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-center py-4">
              <Icons.spinner className="h-6 w-6 animate-spin" />
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="container mx-auto py-8">
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Script Management</h1>
          <p className="mt-1 text-sm text-gray-600">Manage your generated test scripts</p>
        </div>
        <Button onClick={loadScripts} disabled={loading}>
          <Icons.spinner className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {error && <div className="mb-4 rounded-md bg-red-50 p-4 text-red-600">{error}</div>}

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Icons.spinner className="h-8 w-8 animate-spin" />
        </div>
      ) : scripts.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Icons.sparkles className="mx-auto mb-4 h-12 w-12 text-gray-400" />
            <h3 className="mb-2 text-lg font-semibold">No scripts yet</h3>
            <p className="text-gray-600">
              Generated scripts will appear here. Go to the{' '}
              <a href="/chat" className="text-blue-600 hover:underline">
                Chat page
              </a>{' '}
              to create your first test script.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {scripts.map((script) => (
            <Card key={script.id} className="flex flex-col">
              <CardHeader>
                <CardTitle className="line-clamp-1">{script.name}</CardTitle>
                {script.version && <CardDescription>Version: {script.version}</CardDescription>}
              </CardHeader>
              <CardContent className="flex-1">
                {script.description && (
                  <p className="mb-4 line-clamp-2 text-sm text-gray-600">{script.description}</p>
                )}
                <div className="text-xs text-gray-500">
                  <p>Created: {new Date(script.created_at).toLocaleString()}</p>
                  <p>Updated: {new Date(script.updated_at).toLocaleString()}</p>
                </div>
              </CardContent>
              <div className="border-t p-4">
                <div className="flex gap-2">
                  <Button
                    onClick={() => handleDownload(script.script_address, script.name)}
                    className="flex-1"
                    variant="default"
                  >
                    <Icons.sparkles className="mr-2 h-4 w-4" />
                    Download
                  </Button>
                  {deleteConfirm === script.id ? (
                    <>
                      <Button
                        onClick={() => handleDelete(script.id)}
                        variant="destructive"
                        size="sm"
                      >
                        Confirm
                      </Button>
                      <Button onClick={() => setDeleteConfirm(null)} variant="outline" size="sm">
                        Cancel
                      </Button>
                    </>
                  ) : (
                    <Button onClick={() => setDeleteConfirm(script.id)} variant="ghost" size="sm">
                      <svg
                        className="h-4 w-4"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                        />
                      </svg>
                    </Button>
                  )}
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
