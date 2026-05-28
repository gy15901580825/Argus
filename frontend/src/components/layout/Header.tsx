'use client'

import { useState, useEffect, useRef } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Menu, X, ChevronDown } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAuthStore } from '@/store/useAuthStore'
import { getSubscriptionStatus, type SubscriptionStatus } from '@/lib/api'
import { getMsalInstance, getCachedIdToken } from '@/lib/msal'

import { Button } from '@/components/ui/button'
import { EmailCaptureBanner } from '@/components/layout/EmailCaptureBanner'

export function Header() {
  const [isMenuOpen, setIsMenuOpen] = useState(false)
  const [isScrolled, setIsScrolled] = useState(false)
  const user = useAuthStore((state) => state.user)
  const [subStatus, setSubStatus] = useState<SubscriptionStatus | null>(null)

  const logout = useAuthStore((state) => state.logout)
  const router = useRouter()
  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 50)
    }
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => {
    if (user) {
      getSubscriptionStatus()
        .then(setSubStatus)
        .catch(() => {})
    } else {
      setSubStatus(null)
    }
  }, [user])

  const toggleMenu = () => {
    setIsMenuOpen(!isMenuOpen)
  }

  const handleLogin = () => {
    router.push('/login')
  }

  const handleLogout = async () => {
    // 1. Clear Zustand auth state (localStorage)
    logout()

    // 2. End CIAM server-side SSO session via logoutRedirect
    try {
      const msalInstance = getMsalInstance()
      await msalInstance.initialize()
      // Clear any stale "interaction_in_progress" state before calling logoutRedirect
      await msalInstance.handleRedirectPromise().catch(() => {})
      const accounts = msalInstance.getAllAccounts()

      // Extract id_token_hint from MSAL cache (if account exists).
      // With id_token_hint: CIAM auto-clears SSO cookie and redirects back.
      // Without: CIAM shows a confirmation page (still clears SSO if confirmed).
      const account = accounts.length > 0 ? accounts[0] : undefined
      let idToken: string | null = null
      if (account) {
        idToken = getCachedIdToken(account.homeAccountId)
      }
      console.log('[Logout] accounts:', accounts.length, 'id_token_hint:', !!idToken)

      // ALWAYS call logoutRedirect — even without accounts.
      // This navigates to CIAM's end_session_endpoint to clear the SSO cookie.
      await msalInstance.logoutRedirect({
        account: account || undefined,
        idTokenHint: idToken || undefined,
        postLogoutRedirectUri: window.location.origin,
      })
      return // logoutRedirect navigates away
    } catch (e) {
      console.warn('[Logout] MSAL logout error:', e)
    }
    // Fallback: if no MSAL accounts, just clear sessionStorage and navigate
    sessionStorage.clear()
    router.push('/')
  }

  const AdminDropdown = () => {
    const [open, setOpen] = useState(false)
    const ref = useRef<HTMLDivElement>(null)

    useEffect(() => {
      const handler = (e: MouseEvent) => {
        if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false)
      }
      document.addEventListener('mousedown', handler)
      return () => document.removeEventListener('mousedown', handler)
    }, [])

    return (
      <div className="relative" ref={ref}>
        <button
          onClick={() => setOpen(!open)}
          className="text-sm font-medium hover:text-primary transition-colors flex items-center gap-1"
        >
          Admin
          <ChevronDown className={cn('w-3.5 h-3.5 transition-transform', open && 'rotate-180')} />
        </button>
        {open && (
          <div className="absolute top-full right-0 mt-2 w-44 bg-background border rounded-lg shadow-lg py-1 z-50">
            <Link
              href="/admin/blog"
              className="block px-4 py-2 text-sm hover:bg-muted transition-colors"
              onClick={() => setOpen(false)}
            >
              Blog Management
            </Link>
            <Link
              href="/admin/media"
              className="block px-4 py-2 text-sm hover:bg-muted transition-colors"
              onClick={() => setOpen(false)}
            >
              Media Library
            </Link>
            <Link
              href="/admin/users"
              className="block px-4 py-2 text-sm hover:bg-muted transition-colors"
              onClick={() => setOpen(false)}
            >
              Users
            </Link>
            <Link
              href="/admin/organizations"
              className="block px-4 py-2 text-sm hover:bg-muted transition-colors"
              onClick={() => setOpen(false)}
            >
              Organizations
            </Link>
          </div>
        )}
      </div>
    )
  }

  return (
    <header
      className={cn(
        'fixed top-0 left-0 right-0 z-50 transition-all duration-300',
        isScrolled ? 'bg-background/95 backdrop-blur-md shadow-sm border-b' : 'bg-transparent'
      )}
    >
      <div className="container mx-auto px-4 h-16 flex items-center justify-between">
        <Link
          href="/"
          className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-blue-600"
        >
          Argus
        </Link>

        {/* Desktop Menu */}
        <nav className="hidden md:flex items-center gap-8">
          <Link
            href="/#features"
            className="text-sm font-medium hover:text-primary transition-colors"
          >
            Features
          </Link>
          <Link
            href="/#customers"
            className="text-sm font-medium hover:text-primary transition-colors"
          >
            Customers
          </Link>
          <Link
            href="/#enterprise"
            className="text-sm font-medium hover:text-primary transition-colors"
          >
            Enterprise
          </Link>
          <Link href="/docs" className="text-sm font-medium hover:text-primary transition-colors">
            Docs
          </Link>
          <Link href="/blog" className="text-sm font-medium hover:text-primary transition-colors">
            Blog
          </Link>
          <Link
            href="/pricing"
            className="text-sm font-medium hover:text-primary transition-colors"
          >
            Pricing
          </Link>
          {user && (
            <>
              <Link
                href="/chat"
                className="text-sm font-medium hover:text-primary transition-colors"
              >
                AI Chat
              </Link>
              <Link
                href="/scripts"
                className="text-sm font-medium hover:text-primary transition-colors"
              >
                Scripts
              </Link>
              {(user.role === 'SUPER_ADMIN' || user.role === 'CONTENT_ADMIN') && <AdminDropdown />}
            </>
          )}
          {user ? (
            <div className="flex items-center gap-4">
              <Link
                href="/dashboard/profile"
                className="flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-primary transition-colors"
              >
                {user.name}
                {subStatus && (
                  <span
                    className={cn(
                      'text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded-full',
                      subStatus.plan === 'pro'
                        ? 'bg-gradient-to-r from-purple-500 to-blue-500 text-white'
                        : subStatus.plan === 'starter'
                          ? 'bg-primary/10 text-primary'
                          : 'bg-muted text-muted-foreground'
                    )}
                  >
                    {subStatus.plan}
                  </span>
                )}
              </Link>
              <button
                onClick={handleLogout}
                className="text-sm font-medium hover:text-primary transition-colors"
              >
                Log out
              </button>
            </div>
          ) : (
            <button
              onClick={handleLogin}
              className="text-sm font-medium hover:text-primary transition-colors"
            >
              Log in
            </button>
          )}
          {!user && (
            <Button asChild size="sm">
              <Link href="/login">Get Demo</Link>
            </Button>
          )}
        </nav>

        {/* Mobile Menu Toggle */}
        <button className="md:hidden p-2" onClick={toggleMenu} aria-label="Toggle menu">
          {isMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
        </button>
      </div>

      {/* Mobile Menu */}
      {isMenuOpen && (
        <div className="md:hidden absolute top-16 left-0 right-0 bg-background border-b shadow-lg p-4 flex flex-col gap-4 animate-in slide-in-from-top-2">
          <Link
            href="/#features"
            className="text-sm font-medium p-2 hover:bg-muted rounded-md"
            onClick={() => setIsMenuOpen(false)}
          >
            Features
          </Link>
          <Link
            href="/#customers"
            className="text-sm font-medium p-2 hover:bg-muted rounded-md"
            onClick={() => setIsMenuOpen(false)}
          >
            Customers
          </Link>
          <Link
            href="/#enterprise"
            className="text-sm font-medium p-2 hover:bg-muted rounded-md"
            onClick={() => setIsMenuOpen(false)}
          >
            Enterprise
          </Link>
          <Link
            href="/docs"
            className="text-sm font-medium p-2 hover:bg-muted rounded-md"
            onClick={() => setIsMenuOpen(false)}
          >
            Docs
          </Link>
          <Link
            href="/blog"
            className="text-sm font-medium p-2 hover:bg-muted rounded-md"
            onClick={() => setIsMenuOpen(false)}
          >
            Blog
          </Link>
          <Link
            href="/pricing"
            className="text-sm font-medium p-2 hover:bg-muted rounded-md"
            onClick={() => setIsMenuOpen(false)}
          >
            Pricing
          </Link>
          {user && (
            <>
              <Link
                href="/chat"
                className="text-sm font-medium p-2 hover:bg-muted rounded-md"
                onClick={() => setIsMenuOpen(false)}
              >
                AI Chat
              </Link>
              <Link
                href="/scripts"
                className="text-sm font-medium p-2 hover:bg-muted rounded-md"
                onClick={() => setIsMenuOpen(false)}
              >
                Scripts
              </Link>
              {(user.role === 'SUPER_ADMIN' || user.role === 'CONTENT_ADMIN') && (
                <>
                  <div className="text-xs font-semibold text-muted-foreground uppercase tracking-wider px-2 pt-2">
                    Admin
                  </div>
                  <Link
                    href="/admin/blog"
                    className="text-sm font-medium p-2 pl-4 hover:bg-muted rounded-md"
                    onClick={() => setIsMenuOpen(false)}
                  >
                    Blog Management
                  </Link>
                  <Link
                    href="/admin/media"
                    className="text-sm font-medium p-2 pl-4 hover:bg-muted rounded-md"
                    onClick={() => setIsMenuOpen(false)}
                  >
                    Media Library
                  </Link>
                  <Link
                    href="/admin/users"
                    className="text-sm font-medium p-2 pl-4 hover:bg-muted rounded-md"
                    onClick={() => setIsMenuOpen(false)}
                  >
                    Users
                  </Link>
                  <Link
                    href="/admin/organizations"
                    className="text-sm font-medium p-2 pl-4 hover:bg-muted rounded-md"
                    onClick={() => setIsMenuOpen(false)}
                  >
                    Organizations
                  </Link>
                </>
              )}
            </>
          )}
          {user ? (
            <>
              <Link
                href="/dashboard/profile"
                className="text-sm font-medium p-2 text-muted-foreground flex items-center gap-2"
                onClick={() => setIsMenuOpen(false)}
              >
                Signed in as {user.name}
                {subStatus && (
                  <span
                    className={cn(
                      'text-[10px] font-semibold uppercase px-1.5 py-0.5 rounded-full',
                      subStatus.plan === 'pro'
                        ? 'bg-gradient-to-r from-purple-500 to-blue-500 text-white'
                        : subStatus.plan === 'starter'
                          ? 'bg-primary/10 text-primary'
                          : 'bg-muted text-muted-foreground'
                    )}
                  >
                    {subStatus.plan}
                  </span>
                )}
              </Link>
              <button
                onClick={() => {
                  setIsMenuOpen(false)
                  handleLogout()
                }}
                className="text-sm font-medium p-2 hover:bg-muted rounded-md text-left"
              >
                Log out
              </button>
            </>
          ) : (
            <button
              onClick={() => {
                setIsMenuOpen(false)
                handleLogin()
              }}
              className="text-sm font-medium p-2 hover:bg-muted rounded-md text-left"
            >
              Log in
            </button>
          )}
          {!user && (
            <Button asChild className="w-full" onClick={() => setIsMenuOpen(false)}>
              <Link href="/login">Get Demo</Link>
            </Button>
          )}
        </div>
      )}
      <EmailCaptureBanner />
    </header>
  )
}
