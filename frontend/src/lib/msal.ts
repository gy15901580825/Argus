import { PublicClientApplication, Configuration, LogLevel } from '@azure/msal-browser'

const CIAM_TENANT_NAME = process.env.NEXT_PUBLIC_CIAM_TENANT_NAME || ''
const CIAM_CLIENT_ID = process.env.NEXT_PUBLIC_CIAM_CLIENT_ID || ''

// Entra External ID (CIAM) authority — no policy path unlike B2C
const ciamAuthority = `https://${CIAM_TENANT_NAME}.ciamlogin.com/`

function createMsalConfig(): Configuration {
  return {
    auth: {
      clientId: CIAM_CLIENT_ID,
      authority: ciamAuthority,
      knownAuthorities: [`${CIAM_TENANT_NAME}.ciamlogin.com`],
      redirectUri: `${window.location.origin}/callback`,
      postLogoutRedirectUri: window.location.origin,
    },
    cache: {
      cacheLocation: 'sessionStorage',
    },
    system: {
      loggerOptions: {
        logLevel: LogLevel.Verbose,
        loggerCallback: (level, message) => {
          console.log(`[MSAL:${LogLevel[level]}]`, message)
        },
      },
    },
  }
}

// prompt: 'login' forces CIAM to show the login page even if SSO cookie exists
export const loginRequest = {
  scopes: ['openid', 'profile', 'email'],
  prompt: 'login' as const,
}

// prompt: 'create' tells CIAM to show the sign-up form
export const signUpRequest = {
  scopes: ['openid', 'profile', 'email'],
  prompt: 'create' as const,
}

let msalInstance: PublicClientApplication | null = null

export function getMsalInstance(): PublicClientApplication {
  if (!msalInstance) {
    msalInstance = new PublicClientApplication(createMsalConfig())
  }
  return msalInstance
}

/**
 * Get the cached id_token for an account (needed for logout id_token_hint).
 * Searches sessionStorage for MSAL id_token cache entries.
 */
export function getCachedIdToken(accountHomeId: string): string | null {
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i)
    if (key && key.includes('idtoken') && key.includes(CIAM_CLIENT_ID.toLowerCase())) {
      try {
        const entry = JSON.parse(sessionStorage.getItem(key) || '')
        if (entry.secret && entry.home_account_id === accountHomeId) {
          return entry.secret
        }
      } catch {
        // skip malformed entries
      }
    }
  }
  return null
}
