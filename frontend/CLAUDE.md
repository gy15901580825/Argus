# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run dev          # Dev server with Turbopack (localhost:3000)
npm run build        # Production build (Next.js)
npm run lint         # ESLint
npm run format       # Prettier
npm run test         # Unit tests (Vitest, jsdom)
npm run test:e2e     # E2E tests (Playwright, chromium only)

# Run a single unit test file
npx vitest run src/path/to/file.test.ts

# Run a single e2e test
npx playwright test tests/e2e/file.spec.ts
```

## Production Deployment

The frontend is containerized and deployed to AKS via Helm chart (`kubernets/charts/frontend/`).
`NEXT_PUBLIC_*` env vars are baked in at `docker build` time (Next.js limitation).

## Architecture

Next.js 16 App Router with React 19. All pages are client-side rendered (`'use client'`). No SSR data fetching.

### Auth Flow

Authentication uses **Microsoft Entra External ID (CIAM)** via `@azure/msal-browser` / `@azure/msal-react`. The flow:

1. User clicks "Sign in" → MSAL `loginRedirect()` redirects to `{tenant}.ciamlogin.com`
2. `/callback` page calls `handleRedirectPromise()` → extracts claims (sub/oid, name, emails)
3. Callback calls `POST /api/v1/get_token` with user info → receives API token
4. Client stores user + `apiToken` in Zustand (`useAuthStore`, persisted to localStorage as `auth-storage`)

All API calls go through `fetchClient()` in `src/lib/api.ts`, which auto-injects `x-api-token` header from the auth store. The backend API base URL defaults to `https://api.example.com` (env: `NEXT_PUBLIC_API_URL`).

### Key Pages

- `/chat` — Main chat interface. Streams SSE responses from orchestrator (`/api/v1/orchestrator/strategy/stream`). Supports normal chat + web UI test mode. Chat sessions persist server-side.
- `/web-ui-test` — Dedicated web UI testing page. Configures target URL, persona, CDP URL, max steps. Shows live progress, bug counts, screenshot replay, and test artifacts.
- `/scripts` — Manage test scripts stored in R2.
- `/blog`, `/docs` — Content pages (blog posts, documentation).
- `/dashboard` — User dashboard with agent list.

### SSE Streaming Pattern

The chat and web-ui-test pages consume Server-Sent Events from the orchestrator. `streamStrategy()` in `src/lib/api.ts` handles SSE parsing, classifying chunks into typed events (`log`, `result`, `error`, `ssh_result`, `artifact`). The `useWebUITest` hook (`src/hooks/useWebUITest.ts`) wraps this for the web UI test flow.

### State Management

- **Zustand** (`src/store/useAuthStore.ts`) — Auth state (user, apiToken), persisted to localStorage
- **TanStack React Query** — Wrapped via `Providers` component in layout. Used for data fetching/caching.
- **Local component state** — Most page-level state is `useState` within the page component

### UI Components

- `src/components/ui/` — shadcn/ui primitives (button, card, dialog, input, label)
- `src/components/layout/` — Header, Footer (shared layout)
- `src/components/business/` — Landing page sections (Hero, Features, CTA, FAQ, Customers)
- `src/components/chat/messages/` — Chat message taxonomy: `ChatMessage` dispatcher + `groupChunks`, 9 primitive types (`ResultMessage`, `ErrorMessage`, `ThinkingMessage`, `ProgressMessage`, `SystemMessage`, `CodeArtifact`, `TestResultArtifact`, `TestScriptArtifact`, `BugReportArtifact`), `MessageShell` primitive, design tokens
- Top-level components — Feature-specific: `WebUIConfigPanel`, `CDPConfigDialog`, `PhaseProgressBar`, `PlannerTimeline`

### Backend Integration

This frontend talks to multiple backend services, all behind the same API gateway:

- **API Service** (`/api/v1/`) — CRUD for tasks, scripts, blogs, docs, chat sessions, screenshots
- **Orchestrator** (`/api/v1/orchestrator/`) — Agent commands, strategy streaming (SSE)
- Screenshot proxy: `GET /api/v1/web-ui-tasks/{task_id}/screenshots/{step_index}?token=` — API service proxies R2-stored screenshots. The `?token=` query param is needed because `<img src>` cannot send Authorization headers.
