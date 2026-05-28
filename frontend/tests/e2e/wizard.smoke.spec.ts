/**
 * Sanity check that the saved storageState authenticates against
 * https://dev.example.com — without this, the A-E wizard specs can't run.
 */
import { test, expect } from '@playwright/test'

test('reaches /chat with apiToken populated from storageState', async ({ page }) => {
  await page.goto('/chat')
  // useAuthStore should already be hydrated from the storageState we
  // injected; the chat input must render (proves we are not on /login).
  const textarea = page.getByPlaceholder(
    /Enter a URL, project description, or requirements|Enter web app URL/
  )
  await expect(textarea).toBeVisible({ timeout: 15_000 })

  const apiToken = await page.evaluate(() => {
    const raw = localStorage.getItem('auth-storage')
    if (!raw) return null
    try {
      return JSON.parse(raw)?.state?.apiToken ?? null
    } catch {
      return null
    }
  })
  expect(apiToken, 'apiToken must be hydrated from storageState').not.toBeNull()
})
