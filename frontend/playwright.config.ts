import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'

const DEV_AUTH = path.join(__dirname, 'tests/e2e/.auth/dev.json')

// Run dev-targeting projects (setup-dev / wizard-dev) by passing
// PLAYWRIGHT_TARGET=dev. Defaults to local for backwards compatibility.
const target = process.env.PLAYWRIGHT_TARGET ?? 'local'

export default defineConfig({
  testDir: './tests/e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  use: {
    baseURL: 'http://localhost:3000',
    trace: 'on-first-retry',
  },
  projects:
    target === 'dev'
      ? [
          {
            name: 'setup-dev',
            testMatch: /auth\.setup\.ts/,
            use: { ...devices['Desktop Chrome'], headless: false },
          },
          {
            name: 'wizard-dev',
            testMatch: /wizard\..*\.spec\.ts/,
            dependencies: ['setup-dev'],
            use: {
              ...devices['Desktop Chrome'],
              baseURL: 'https://dev.example.com',
              storageState: DEV_AUTH,
              headless: false,
            },
          },
          {
            name: 'chat-bulk-dev',
            testMatch: /chat-bulk-actions\.dev\.spec\.ts/,
            dependencies: ['setup-dev'],
            use: {
              ...devices['Desktop Chrome'],
              baseURL: 'https://dev.example.com',
              storageState: DEV_AUTH,
              headless: false,
            },
          },
        ]
      : [
          {
            name: 'chromium',
            testIgnore: [/auth\.setup\.ts/, /wizard\..*\.spec\.ts/, /\.dev\.spec\.ts$/],
            use: { ...devices['Desktop Chrome'] },
          },
        ],
  webServer:
    target === 'dev'
      ? undefined
      : {
          command: 'npm run dev',
          url: 'http://localhost:3000',
          reuseExistingServer: !process.env.CI,
        },
})
