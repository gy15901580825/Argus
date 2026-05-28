import { test, expect } from '@playwright/test'

test('homepage has title and links to intro', async ({ page }) => {
  await page.goto('http://localhost:3000/')

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/Argus/)

  // Find the login link.
  const loginLink = page.getByRole('link', { name: 'Log in' })

  // Expect the link to be visible
  await expect(loginLink).toBeVisible()

  // Click the login link
  await loginLink.click()

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Log in to your account' })).toBeVisible()
})
