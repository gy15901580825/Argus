import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { TestScriptArtifact } from '@/components/chat/messages/TestScriptArtifact'
import type { StreamChunk } from '@/lib/chat-types'

vi.mock('@/store/useAuthStore', () => ({
  useAuthStore: Object.assign(
    (selector: (s: { apiToken: null }) => unknown) => selector({ apiToken: null }),
    { getState: () => ({ apiToken: null }) }
  ),
}))

const artifactChunk = (script: string, name = 'test_login.py'): StreamChunk => ({
  type: 'web_ui_artifact',
  content: '',
  webUiArtifactData: { script, name },
})

describe('TestScriptArtifact', () => {
  it('summary shows filename, size, and line count', () => {
    const script = Array.from({ length: 10 }, (_, i) => `line ${i}`).join('\n')
    render(<TestScriptArtifact chunks={[artifactChunk(script)]} />)
    expect(screen.getByText(/test_login\.py/)).toBeDefined()
    expect(screen.getByText(/10 lines/)).toBeDefined()
  })

  it('expanded by default and toggles on header click', () => {
    render(<TestScriptArtifact chunks={[artifactChunk('print("x")')]} />)
    // Default expanded → script body is visible
    expect(screen.getByText(/print/)).toBeDefined()
    // Click header (the first button = expand toggle, the second is CodeBlock's copy)
    const toggle = screen.getAllByRole('button')[0]
    fireEvent.click(toggle)
    expect(screen.queryByText(/print/)).toBeNull()
  })
})
