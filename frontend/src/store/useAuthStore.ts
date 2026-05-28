import { create } from 'zustand'
import { persist } from 'zustand/middleware'
// import { fetchClient } from '@/lib/api'

interface AuthUser {
  name: string
  email: string
  id: string
  role?: string
}

interface AuthState {
  user: AuthUser | null
  apiToken: string | null
  _hasHydrated: boolean
  login: (user: AuthUser, apiToken: string) => void
  logout: () => void
  updateUser: (updates: Partial<AuthUser>) => void
  setHasHydrated: (state: boolean) => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      apiToken: null,
      _hasHydrated: false,
      login: (user, apiToken) => set({ user, apiToken }),
      logout: () => set({ user: null, apiToken: null }),
      updateUser: (updates) =>
        set((state) => ({
          user: state.user ? { ...state.user, ...updates } : null,
        })),
      setHasHydrated: (state) => set({ _hasHydrated: state }),
    }),
    {
      name: 'auth-storage',
      onRehydrateStorage: () => (state) => {
        state?.setHasHydrated(true)
      },
    }
  )
)
