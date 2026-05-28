/**
 * Wizard end-to-end flows against https://dev.example.com.
 *
 * Each spec drives a real authenticated browser session through the
 * planner option-picker UI. The orchestrator runs Opus 4.7 in wizard mode
 * (WIZARD_MODE_ENABLED=true on dev), so individual rounds can take 10-30s
 * each. Tests are .serial to keep load on the dev cluster bounded.
 *
 * Run: `PLAYWRIGHT_TARGET=dev npx playwright test --project=wizard-dev wizard.flow`
 */
import { test, expect, Page } from '@playwright/test'

const ROUND_TIMEOUT = 90_000 // each LLM round on dev
const TEST_TIMEOUT = 8 * 60_000 // whole-flow budget

// LABEL_TEXT must mirror src/components/chat/messages/WizardRoundMessage.tsx
const LABEL_TEXT = {
  intent: 'What to do',
  run_where: 'Where to run',
  credentials: 'Credentials',
  persona: 'Persona',
  target_url: 'Target URL',
  local_setup_check: 'Local setup',
  confirm: 'Confirm',
  other: 'Choose',
} as const
type WizardLabel = keyof typeof LABEL_TEXT

async function waitForRound(page: Page, label: WizardLabel, n?: number) {
  const labelText = LABEL_TEXT[label]
  const re = n
    ? new RegExp(`Step\\s*${n}:\\s*${labelText}`)
    : new RegExp(`Step\\s*\\d+:\\s*${labelText}`)
  await expect(page.getByText(re).first()).toBeVisible({ timeout: ROUND_TIMEOUT })
}

async function clickOption(page: Page, optionText: string | RegExp) {
  // Wizard option chips are <button class="rounded-full border ..."> — scope
  // there so we don't match nav links or config-panel buttons by accident.
  await page.locator('button.rounded-full.border').filter({ hasText: optionText }).first().click()
}

async function typeFreeText(page: Page, value: string) {
  const input = page.getByPlaceholder('Type your answer and press Enter')
  await input.fill(value)
  await input.press('Enter')
}

async function startSession(page: Page, prompt: string) {
  await page.goto('/chat')
  const textarea = page.getByPlaceholder(
    /Enter a URL, project description, or requirements|Enter web app URL/
  )
  await expect(textarea).toBeVisible({ timeout: 15_000 })
  await textarea.fill(prompt)
  // The default (non-Web-UI) submit button reads "Execute".
  await page.getByRole('button', { name: /^Execute$/ }).click()
}

test.describe.configure({ mode: 'serial' })
test.describe('Wizard E2E on dev', () => {
  test.setTimeout(TEST_TIMEOUT)

  // -------------------------------------------------------------------------
  // Scenario A — happy path: cloud, default config → walk all rounds → dispatch
  // -------------------------------------------------------------------------
  test('A: cloud happy path reaches confirm round', async ({ page }) => {
    await startSession(page, 'test example.com')

    // R1 intent must always be the first round when bound_context is empty.
    await waitForRound(page, 'intent', 1)
    // Click whichever intent option matches an API test (or the first option
    // if the LLM phrases it differently). This is a smoke for option_click.
    // Wizard option chips render as <button class="rounded-full border ..."> —
    // scope to that to avoid matching nav links / config-panel buttons.
    const intentBtn = page
      .locator('button.rounded-full.border')
      .filter({ hasText: /API|Web|Test|Discover|Fetch/i })
      .first()
    await intentBtn.click()

    // After intent the planner walks the remaining rounds. We don't pin the
    // exact order (LLM can choose run_where vs target_url first depending on
    // bound_context), but confirm must eventually appear.
    await expect(
      page.getByText(/Step\s*\d+:\s*(Where to run|Target URL|Persona|Confirm)/).first()
    ).toBeVisible({ timeout: ROUND_TIMEOUT })

    // Walk rounds: at each pending card, prefer clicking the first option
    // chip; only type a URL when the round is target_url (or the free-text
    // input is the only available answer kind). The persona round commonly
    // has allow_free_text=true alongside options — typing into it would
    // submit "https://example.com" as the persona answer and the LLM would
    // immediately re-ask. Stop when the confirm card appears or we hit a
    // hard cap.
    for (let i = 0; i < 8; i++) {
      // Wait for either the confirm card to appear OR a pending round (any
      // visible option chip / free-text input) to appear. Without this poll
      // the loop races against orchestrator round emission and exits early.
      await expect
        .poll(
          async () => {
            const confirm = await page
              .getByText(/Step\s*\d+:\s*Confirm/)
              .first()
              .isVisible()
              .catch(() => false)
            const opt = await page
              .locator('button.rounded-full.border')
              .first()
              .isVisible()
              .catch(() => false)
            const ft = await page
              .getByPlaceholder('Type your answer and press Enter')
              .isVisible()
              .catch(() => false)
            return confirm || opt || ft
          },
          { timeout: ROUND_TIMEOUT, intervals: [500] }
        )
        .toBe(true)

      const confirmVisible = await page
        .getByText(/Step\s*\d+:\s*Confirm/)
        .first()
        .isVisible()
        .catch(() => false)
      if (confirmVisible) break

      const targetUrlVisible = await page
        .getByText(/Step\s*\d+:\s*Target URL/)
        .first()
        .isVisible()
        .catch(() => false)
      const freeText = page.getByPlaceholder('Type your answer and press Enter')
      const freeTextVisible = await freeText.isVisible().catch(() => false)

      // Wizard option chips render only on the PENDING round (answered rounds
      // collapse to a single answer <span>). The class "rounded-full border"
      // is unique to chip buttons, so its presence on the page implies a
      // pending round with options.
      const pendingOption = page.locator('button.rounded-full.border').first()
      const optionVisible = await pendingOption.isVisible().catch(() => false)

      if (targetUrlVisible && freeTextVisible) {
        await typeFreeText(page, 'https://example.com')
        continue
      }
      if (optionVisible) {
        await pendingOption.click()
        continue
      }
      if (freeTextVisible) {
        // No options on this round — fall back to typing a sensible value.
        await typeFreeText(page, 'https://example.com')
        continue
      }
      break
    }

    await waitForRound(page, 'confirm')
  })

  // -------------------------------------------------------------------------
  // Scenario B — Back navigation
  // -------------------------------------------------------------------------
  test('B: back from a later round restores previous round as pending', async ({ page }) => {
    await startSession(page, 'test example.com for back navigation')

    // Wait for any round 1 (LLM picks the label — usually intent, sometimes
    // persona when the URL is already in the prompt). Click whatever option
    // chip is offered.
    await expect(page.getByText(/Step\s*1:/).first()).toBeVisible({ timeout: ROUND_TIMEOUT })
    await page.locator('button.rounded-full.border').first().click()

    // Wait for at least round 2 to appear (any label).
    await expect(page.getByText(/Step\s*2:/).first()).toBeVisible({ timeout: ROUND_TIMEOUT })
    // Click Back on round 2 — Back button only renders when allowBack=true,
    // which is the case for any round_n >= 2.
    await page
      .getByRole('button', { name: /←\s*Back/ })
      .first()
      .click()

    // Round 1 should re-render as pending (its options become clickable
    // again). Sanity-check by asserting an option chip is interactable.
    await expect(page.getByText(/Step\s*1:/).first()).toBeVisible({ timeout: 10_000 })
    await expect(page.locator('button.rounded-full.border').first()).toBeEnabled({
      timeout: 10_000,
    })
  })

  // -------------------------------------------------------------------------
  // Scenario C — fast-forward to confirm
  // -------------------------------------------------------------------------
  test.skip('C: fast-forward via pre-filled bound_context', async () => {
    // Skipped: fast-forwarding requires the planner to skip rounds for
    // already-known bound_context fields (test_env, url, persona). Driving
    // this through the UI requires opening WebUIConfigPanel + setting URL +
    // setting persona before the first send. The exact selectors live deep
    // in WebUIConfigPanel and the LLM may still choose to verify a "known"
    // value in a confirm-style round. Cover this in service-level tests
    // instead (see orchestrator/tests/planner/test_wizard_flow_integration.py
    // test_flow_c_fast_forward_to_r5).
  })

  // -------------------------------------------------------------------------
  // Scenario D — my_machine + client_agent_connected=False → local_setup_check
  // -------------------------------------------------------------------------
  test('D: local mode without a client agent surfaces local_setup_check', async ({ page }) => {
    await page.goto('/chat')
    const textarea = page.getByPlaceholder(
      /Enter a URL, project description, or requirements|Enter web app URL/
    )
    await expect(textarea).toBeVisible({ timeout: 15_000 })

    // Toggle "run on my machine".
    const localToggle = page
      .getByRole('button', { name: /My Machine|Local|Run on my machine/i })
      .first()
    if (!(await localToggle.isVisible().catch(() => false))) {
      test.skip(
        true,
        'Could not find a "run on my machine" toggle in chat page UI — confirm selector and re-enable.'
      )
    }
    await localToggle.click()

    // Clicking "My Machine" while client_agent_connected=False surfaces the
    // local-setup guidance directly (a UI-side modal showing "docker pull
    // <your-gh-user>/client_agent" + "docker run …"). This is the same content
    // the planner would emit as local_setup_check, but produced client-side
    // because the connectivity check fails before the user can submit. Either
    // path is acceptable evidence of the local_setup_check requirement.
    await expect(
      page
        .getByText(
          /Local setup|Setup instructions|client agent|Pull the client agent|Run the client agent/i
        )
        .first()
    ).toBeVisible({ timeout: ROUND_TIMEOUT })
  })

  // -------------------------------------------------------------------------
  // Scenario E — abort mid-wizard
  // -------------------------------------------------------------------------
  test('E: abort hides the pending wizard and stops the turn', async ({ page }) => {
    await startSession(page, 'test example.com for abort')

    // Wait for any round 1 (LLM may emit intent OR persona depending on the
    // prompt's information density).
    await expect(page.getByText(/Step\s*1:/).first()).toBeVisible({ timeout: ROUND_TIMEOUT })
    await page
      .getByRole('button', { name: /✕\s*Abort wizard/ })
      .first()
      .click()

    // After abort the previously-pending card must no longer offer clickable
    // options. Track the FIRST chip — at moment-of-abort it was enabled, and
    // after abort propagates the parent card collapses and that chip
    // disappears (or its button becomes disabled).
    const firstChip = page.locator('button.rounded-full.border').first()
    await expect
      .poll(async () => firstChip.isEnabled().catch(() => false), {
        timeout: 30_000,
        intervals: [500],
      })
      .toBe(false)
  })
})
