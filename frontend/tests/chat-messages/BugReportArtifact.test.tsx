import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { BugReportArtifact } from '@/components/chat/messages/BugReportArtifact'
import type { StreamChunk } from '@/lib/chat-types'

vi.mock('@/store/useAuthStore', () => ({
  useAuthStore: Object.assign(
    (selector: (s: { apiToken: null }) => unknown) => selector({ apiToken: null }),
    { getState: () => ({ apiToken: null }) }
  ),
}))

const bugChunk = (): StreamChunk => ({
  type: 'web_ui_bug',
  content: '',
  webUiBugData: {
    bug_counts: { critical: 1, high: 1, total: 2 },
    url: 'https://example.com',
    task_id: 't1',
  },
})

describe('BugReportArtifact', () => {
  it('summary header shows total issue count', () => {
    render(<BugReportArtifact chunks={[bugChunk()]} />)
    expect(screen.getByText(/2 issues/)).toBeDefined()
  })

  it('renders a critical severity badge with the critical count', () => {
    render(<BugReportArtifact chunks={[bugChunk()]} />)
    const critical = screen.getByText(/CRITICAL/i)
    expect(critical).toBeDefined()
    expect(critical.parentElement?.textContent).toMatch(/1/)
  })

  it('expands details on click of the View Details button', () => {
    render(<BugReportArtifact chunks={[bugChunk()]} />)
    // Tabs (Bugs / Summary / Recording) are inside the collapsible panel,
    // and only render once the user expands the card.
    expect(screen.queryByText(/Recording/)).toBeNull()
    fireEvent.click(screen.getByText(/View Details/))
    expect(screen.getByText(/Recording/)).toBeDefined()
  })
})
