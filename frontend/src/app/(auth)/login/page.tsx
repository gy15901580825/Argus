'use client'

import { useEffect, useRef, useState } from 'react'
import { useRouter } from 'next/navigation'
import Link from 'next/link'
import { getMsalInstance, loginRequest, signUpRequest } from '@/lib/msal'
import { Icons } from '@/components/ui/icons'
import { Button } from '@/components/ui/button'
import { useAuthStore } from '@/store/useAuthStore'
import { TermsContent } from '@/app/terms/page'
import { track } from '@/lib/analytics'

export default function LoginPage() {
  const router = useRouter()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showTerms, setShowTerms] = useState(false)
  const [termsAccepted, setTermsAccepted] = useState(false)
  const processing = useRef(false)

  useEffect(() => {
    if (processing.current) return
    processing.current = true

    const init = async () => {
      // If user is already logged in via Zustand, go to chat
      const existingUser = useAuthStore.getState().user
      if (existingUser) {
        router.push('/chat')
        return
      }

      // Clear any stale MSAL interaction state (e.g., "interaction_in_progress")
      try {
        const msalInstance = getMsalInstance()
        await msalInstance.initialize()
        await msalInstance.handleRedirectPromise()
      } catch (err) {
        console.warn('[Login] handleRedirectPromise error (ignored):', err)
      }

      setLoading(false)
    }

    init()
  }, [router])

  const handleLogin = async () => {
    track('sign_in_start', { provider: 'entra_id' })
    try {
      setError(null)
      const msalInstance = getMsalInstance()
      await msalInstance.initialize()
      // redirectStartPage = /callback ensures MSAL processes the auth response
      // on the callback page instead of navigating back to /login
      await msalInstance.loginRedirect({
        ...loginRequest,
        redirectStartPage: window.location.origin + '/callback',
      })
    } catch (err) {
      console.error('[Login] loginRedirect error:', err)
      track('sign_in_error', { stage: 'redirect' })
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  const handleSignUpClick = () => {
    track('sign_up_start', { provider: 'entra_id' })
    setError(null)
    setShowTerms(true)
    setTermsAccepted(false)
  }

  const handleAcceptAndContinue = async () => {
    track('sign_up_terms_accept', {})
    try {
      setError(null)
      // Store acceptance timestamp in sessionStorage so callback can record it
      sessionStorage.setItem('terms_accepted_at', new Date().toISOString())
      const msalInstance = getMsalInstance()
      await msalInstance.initialize()
      await msalInstance.loginRedirect({
        ...signUpRequest,
        redirectStartPage: window.location.origin + '/callback',
      })
    } catch (err) {
      console.error('[SignUp] loginRedirect error:', err)
      track('sign_up_error', { stage: 'redirect' })
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Icons.spinner className="h-8 w-8 animate-spin" />
      </div>
    )
  }

  // Terms of Service agreement view
  if (showTerms) {
    return (
      <div className="min-h-screen bg-background py-8 px-4">
        <div className="mx-auto max-w-3xl">
          <div className="mb-6">
            <button
              onClick={() => setShowTerms(false)}
              className="text-sm text-muted-foreground hover:text-primary transition-colors"
            >
              &larr; Back to Login
            </button>
          </div>

          <h1 className="text-3xl font-bold mb-2">Terms of Service</h1>
          <p className="text-sm text-muted-foreground mb-8">
            Please read and accept the following terms before creating your account.
          </p>

          <div className="rounded-lg border bg-card p-6 mb-6 max-h-[60vh] overflow-y-auto">
            <TermsContent />
          </div>

          {error && (
            <div className="rounded-md bg-red-50 p-4 text-sm text-red-600 mb-4">{error}</div>
          )}

          <div className="space-y-4">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={termsAccepted}
                onChange={(e) => setTermsAccepted(e.target.checked)}
                className="mt-1 h-4 w-4 rounded border-gray-300"
              />
              <span className="text-sm">
                I have read and agree to the{' '}
                <Link href="/terms" target="_blank" className="text-primary hover:underline">
                  Terms of Service
                </Link>
                . I understand that I am solely responsible for ensuring I have proper authorization
                to test any target systems and that I bear full legal responsibility for my use of
                the Platform.
              </span>
            </label>

            <Button
              size="lg"
              className="w-full"
              disabled={!termsAccepted}
              onClick={handleAcceptAndContinue}
            >
              Accept and Continue
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-6 bg-background p-4">
      <div className="w-full max-w-md space-y-8 text-center">
        <div className="space-y-2">
          <h1 className="text-3xl font-bold tracking-tight">Welcome to Argus</h1>
          <p className="text-muted-foreground">Sign in or create an account to get started</p>
        </div>

        {error && <div className="rounded-md bg-red-50 p-4 text-sm text-red-600">{error}</div>}

        <div className="grid gap-4">
          <Button size="lg" className="w-full" onClick={handleLogin}>
            Sign in with Microsoft
          </Button>
          <Button size="lg" variant="outline" className="w-full" onClick={handleSignUpClick}>
            Create an account
          </Button>
        </div>

        <p className="text-xs text-muted-foreground">
          By signing in, you agree to our{' '}
          <Link href="/terms" className="text-primary hover:underline">
            Terms of Service
          </Link>
        </p>
      </div>
    </div>
  )
}
