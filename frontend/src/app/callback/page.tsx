'use client'

import { useEffect, useState, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/useAuthStore'
import { fetchClient } from '@/lib/api'
import { getMsalInstance } from '@/lib/msal'
import { track } from '@/lib/analytics'

export default function CallbackPage() {
  const router = useRouter()
  const login = useAuthStore((state) => state.login)
  const [status, setStatus] = useState('Callback page loaded...')
  const [error, setError] = useState<string | null>(null)
  const processing = useRef(false)

  useEffect(() => {
    if (processing.current) return
    processing.current = true

    // Immediately log - this proves the callback page was reached
    const url = window.location.href
    console.log('=== [CallbackPage] PAGE LOADED ===')
    console.log('[CallbackPage] URL:', url)
    console.log('[CallbackPage] SessionStorage keys:', Object.keys(sessionStorage))

    const handleAuth = async () => {
      setStatus(`Processing auth... URL: ${url}`)
      try {
        const msalInstance = getMsalInstance()
        await msalInstance.initialize()

        console.log('[CallbackPage] Calling handleRedirectPromise...')
        const response = await msalInstance.handleRedirectPromise()
        console.log('[CallbackPage] Response:', response)

        if (!response) {
          setError(
            `handleRedirectPromise returned null.\n\nFull URL: ${url}\n\nSessionStorage keys: ${Object.keys(sessionStorage).join(', ')}`
          )
          return
        }

        const claims = response.idTokenClaims as Record<string, unknown>
        console.log('[CallbackPage] idTokenClaims:', JSON.stringify(claims, null, 2))

        // CIAM oid is a UUID; sub is base64-encoded — prefer oid for DB compatibility
        const userId = (claims.oid as string) || (claims.sub as string) || ''
        const username =
          (claims.name as string) ||
          (claims.given_name as string) ||
          (claims.preferred_username as string) ||
          (claims.displayName as string) ||
          (response.account?.name as string) ||
          (response.account?.username as string) ||
          ''
        const emails = (claims.emails as string[]) || []
        const email =
          emails[0] ||
          (claims.email as string) ||
          (response.account?.username as string) ||
          `${username || userId}@argus.local`

        if (!userId || !username) {
          setError(`Missing user info.\nClaims: ${JSON.stringify(claims, null, 2)}`)
          return
        }

        setStatus('Exchanging token...')
        // Check if user accepted terms during sign-up flow
        const termsAcceptedAt = sessionStorage.getItem('terms_accepted_at')
        if (termsAcceptedAt) {
          sessionStorage.removeItem('terms_accepted_at')
        }
        const tokenData = await fetchClient<{ token: string; role?: string }>('/api/v1/get_token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            user_id: userId,
            username,
            email,
            terms_accepted_at: termsAcceptedAt || undefined,
          }),
        })

        if (tokenData?.token) {
          const isNewUser = Boolean(termsAcceptedAt)
          track(isNewUser ? 'sign_up_success' : 'sign_in_success', {
            provider: 'entra_id',
            role: tokenData.role || 'user',
          })
          login({ name: username, email, id: userId, role: tokenData.role }, tokenData.token)
          router.push('/chat')
        } else {
          track('sign_in_error', { stage: 'token_exchange' })
          setError('No token in API response')
        }
      } catch (err) {
        console.error('[CallbackPage] Error:', err)
        track('sign_in_error', { stage: 'callback' })
        setError(err instanceof Error ? err.message : JSON.stringify(err))
      }
    }

    handleAuth()
  }, [login, router])

  if (error) {
    return (
      <div className="flex h-screen w-screen flex-col items-center justify-center gap-4 p-8">
        <h2 className="text-xl font-bold">Callback Page - Error</h2>
        <div className="max-w-2xl whitespace-pre-wrap break-all rounded bg-red-50 p-4 text-sm text-red-600">
          {error}
        </div>
        <button
          onClick={() => router.push('/login')}
          className="rounded bg-blue-500 px-4 py-2 text-white hover:bg-blue-600"
        >
          Back to Login
        </button>
      </div>
    )
  }

  return (
    <div className="flex h-screen w-screen flex-col items-center justify-center gap-2">
      <h2 className="text-xl font-bold">Callback Page</h2>
      <p className="text-sm text-muted-foreground">{status}</p>
    </div>
  )
}
