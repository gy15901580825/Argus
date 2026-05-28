import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import LoginPage from '@/app/(auth)/login/page'

// Mock useRouter
vi.mock('next/navigation', () => ({
  useRouter: () => ({
    push: vi.fn(),
  }),
}))

// Mock MSAL — both initialize() and handleRedirectPromise() must resolve so
// the login page flips its `loading` state to false and renders the main UI.
vi.mock('@/lib/msal', () => ({
  getMsalInstance: () => ({
    initialize: vi.fn().mockResolvedValue(undefined),
    handleRedirectPromise: vi.fn().mockResolvedValue(null),
    loginRedirect: vi.fn().mockResolvedValue(undefined),
  }),
  loginRequest: { scopes: ['openid', 'profile'] },
  signUpRequest: { scopes: ['openid', 'profile'] },
}))

// /terms page is imported by the login page for TermsContent — stub it out.
vi.mock('@/app/terms/page', () => ({
  TermsContent: () => <div>Terms of Service content</div>,
}))

describe('LoginPage', () => {
  it('renders the welcome heading and the two auth buttons after MSAL init settles', async () => {
    render(<LoginPage />)
    // Wait for the loading spinner to clear.
    await waitFor(() => {
      expect(screen.getByText('Welcome to Argus')).toBeInTheDocument()
    })
    expect(screen.getByText('Sign in or create an account to get started')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Sign in with Microsoft' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create an account' })).toBeInTheDocument()
  })
})
