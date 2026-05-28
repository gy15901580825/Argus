import { test, expect } from '@playwright/test'

test.describe('chat streaming rollback path (MARKDOWN_MODE=off)', () => {
  test.skip(
    process.env.CHAT_STREAM_MODE_OFF_E2E !== '1',
    'Only runs when frontend is built with NEXT_PUBLIC_CHAT_STREAM_MARKDOWN_MODE=off'
  )

  test('renders result without streaming-tail element', async ({ page }) => {
    await page.goto('/chat')
    await page.getByRole('textbox').fill('hello')
    await page.getByRole('button', { name: /send/i }).click()

    await expect(page.locator('.streaming-tail')).toHaveCount(0, { timeout: 30_000 })
    await expect(page.locator('.prose').first()).toBeVisible()
  })
})
