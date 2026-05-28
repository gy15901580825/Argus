import { describe, it, expect, beforeEach } from 'vitest'
import { useAuthStore } from '@/store/useAuthStore'

const snapshot = () => useAuthStore.getState()

describe('useAuthStore', () => {
  beforeEach(() => {
    // Reset to initial state before each test. Zustand persist will still be
    // configured, but in jsdom localStorage is available and isolated per run.
    snapshot().logout()
    window.localStorage.clear()
  })

  it('has null user and apiToken by default', () => {
    const s = snapshot()
    expect(s.user).toBeNull()
    expect(s.apiToken).toBeNull()
  })

  it('login() populates user and apiToken', () => {
    snapshot().login({ id: 'u1', name: 'Alice', email: 'a@example.com' }, 'secret-token')
    const s = snapshot()
    expect(s.user).toEqual({ id: 'u1', name: 'Alice', email: 'a@example.com' })
    expect(s.apiToken).toBe('secret-token')
  })

  it('logout() clears user and apiToken', () => {
    snapshot().login({ id: 'u', name: 'A', email: 'x' }, 'tok')
    snapshot().logout()
    const s = snapshot()
    expect(s.user).toBeNull()
    expect(s.apiToken).toBeNull()
  })

  it('updateUser() merges updates into existing user', () => {
    snapshot().login({ id: 'u', name: 'Old', email: 'o@x.com' }, 'tok')
    snapshot().updateUser({ name: 'New', role: 'admin' })
    const s = snapshot()
    expect(s.user).toEqual({ id: 'u', name: 'New', email: 'o@x.com', role: 'admin' })
    // apiToken untouched
    expect(s.apiToken).toBe('tok')
  })

  it('updateUser() is a no-op when user is null (does not create a user)', () => {
    snapshot().updateUser({ name: 'Ghost' })
    expect(snapshot().user).toBeNull()
  })

  it('setHasHydrated() toggles the hydration flag', () => {
    snapshot().setHasHydrated(true)
    expect(snapshot()._hasHydrated).toBe(true)
    snapshot().setHasHydrated(false)
    expect(snapshot()._hasHydrated).toBe(false)
  })

  it('persists to localStorage under key "auth-storage" after login', () => {
    snapshot().login({ id: 'u2', name: 'P', email: 'p@x.com' }, 'persisted-token')
    const raw = window.localStorage.getItem('auth-storage')
    expect(raw).not.toBeNull()
    const parsed = JSON.parse(raw as string)
    expect(parsed.state.user).toMatchObject({ id: 'u2', email: 'p@x.com' })
    expect(parsed.state.apiToken).toBe('persisted-token')
  })
})
