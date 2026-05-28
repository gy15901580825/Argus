/**
 * One-shot auth capture against https://dev.example.com.
 *
 * Run:
 *   npx playwright test --project=setup-dev --headed
 *
 * Opens a real Chromium window, waits for you to complete the CIAM login,
 * then snapshots cookies + localStorage to `tests/e2e/.auth/dev.json`.
 * Subsequent wizard specs (project=wizard-dev) reuse that storageState.
 */
import { test as setup, expect } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'

const AUTH_DIR = path.join(__dirname, '.auth')
const AUTH_FILE = path.join(AUTH_DIR, 'dev.json')
const MAX_AGE_MS = 12 * 60 * 60 * 1000 // 12h — re-login if older

// Up to 10 min for the user to finish CIAM login in the opened window.
setup.setTimeout(11 * 60_000)

setup('capture dev.example.com auth', async ({ page, context }) => {
  if (fs.existsSync(AUTH_FILE) && Date.now() - fs.statSync(AUTH_FILE).mtimeMs < MAX_AGE_MS) {
    setup.skip(true, `Reusing ${AUTH_FILE} (<12h old).`)
  }

  fs.mkdirSync(AUTH_DIR, { recursive: true })

  await page.goto('https://dev.example.com/chat')
  console.log(
    '\n👉 Sign in via CIAM in the opened window. The script will save auth automatically once the Zustand store populates.\n'
  )

  // Poll every 3s for up to 10 min. Surface progress so the user knows
  // the script is alive AND can see what state Zustand is in.
  const deadline = Date.now() + 10 * 60_000
  let saved = false
  while (Date.now() < deadline) {
    const raw = await page.evaluate(() => localStorage.getItem('auth-storage'))
    if (raw) {
      try {
        const parsed = JSON.parse(raw)
        const apiToken = parsed?.state?.apiToken
        const user = parsed?.state?.user
        if (apiToken) {
          await context.storageState({ path: AUTH_FILE })
          console.log(
            `\n✅ Saved storageState → ${AUTH_FILE}\n   user.email=${user?.email ?? '(unknown)'}`
          )
          saved = true
          break
        }
        console.log(
          `…seen auth-storage but apiToken not yet populated (user=${user?.email ?? 'null'}). Continuing to poll.`
        )
      } catch (e) {
        console.log(`…auth-storage present but unparseable: ${e}`)
      }
    } else {
      console.log(`…still waiting for login (url=${page.url()})`)
    }
    await page.waitForTimeout(3000)
  }
  expect(saved, 'login did not complete in 10 minutes').toBe(true)
})
