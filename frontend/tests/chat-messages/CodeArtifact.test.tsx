import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { CodeArtifact } from '@/components/chat/messages/CodeArtifact'
import type { StreamChunk } from '@/lib/chat-types'

vi.mock('@/store/useAuthStore', () => ({
  useAuthStore: { getState: () => ({ apiToken: null }) },
}))

const codeChunk = (content: string, language?: string): StreamChunk => ({
  type: 'code',
  content,
  language,
})

describe('CodeArtifact', () => {
  it('summary shows size and line count', () => {
    const code = Array.from({ length: 10 }, (_, i) => `line ${i}`).join('\n')
    render(<CodeArtifact chunks={[codeChunk(code, 'python')]} />)
    expect(screen.getByText(/10 lines/)).toBeDefined()
  })

  it('collapsed by default; expands to show code', () => {
    const code = 'print("hi")'
    render(<CodeArtifact chunks={[codeChunk(code, 'python')]} />)
    expect(screen.queryByText('print("hi")')).toBeNull()
    fireEvent.click(screen.getByRole('button'))
    expect(screen.getByText(/print/)).toBeDefined()
  })
})
