import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ChatMessage, groupChunks } from '@/components/chat/messages'
import type { StreamChunk } from '@/lib/chat-types'

vi.mock('@/store/useAuthStore', () => ({
  useAuthStore: { getState: () => ({ apiToken: null }) },
}))

describe('groupChunks', () => {
  it('batches consecutive same-type chunks', () => {
    const chunks: StreamChunk[] = [
      { type: 'log', content: 'a' },
      { type: 'log', content: 'b' },
      { type: 'result', content: 'r' },
    ]
    const groups = groupChunks(chunks)
    expect(groups).toHaveLength(2)
    expect(groups[0].type).toBe('thinking')
    expect(groups[0].chunks).toHaveLength(2)
    expect(groups[1].type).toBe('result')
  })

  it('keeps web_ui_bug and web_ui_artifact as singletons', () => {
    const chunks: StreamChunk[] = [
      { type: 'web_ui_bug', content: '', webUiBugData: { bug_counts: {} } },
      { type: 'web_ui_bug', content: '', webUiBugData: { bug_counts: {} } },
    ]
    const groups = groupChunks(chunks)
    expect(groups).toHaveLength(2)
  })

  it('treats log/discovery_progress/planner_step as the same thinking group', () => {
    const chunks: StreamChunk[] = [
      { type: 'log', content: 'a' },
      { type: 'planner_step', content: 'b' },
      { type: 'discovery_progress', content: 'c' },
    ]
    const groups = groupChunks(chunks)
    expect(groups).toHaveLength(1)
    expect(groups[0].type).toBe('thinking')
    expect(groups[0].chunks).toHaveLength(3)
  })
})

describe('ChatMessage dispatcher', () => {
  it('routes log type to ThinkingMessage', () => {
    const group = { type: 'thinking' as const, chunks: [{ type: 'log' as const, content: 'x' }] }
    render(<ChatMessage group={group} />)
    expect(screen.getAllByText('Thinking').length).toBeGreaterThan(0)
  })

  it('routes result type to ResultMessage (no shell header)', () => {
    const group = { type: 'result' as const, chunks: [{ type: 'result' as const, content: 'hi' }] }
    render(<ChatMessage group={group} />)
    expect(screen.queryByText('Response')).toBeNull()
    expect(screen.getByText('hi')).toBeDefined()
  })

  it('routes ssh_result to TestResultArtifact', () => {
    const group = {
      type: 'ssh_result' as const,
      chunks: [
        {
          type: 'ssh_result' as const,
          content: '',
          sshResult: { success: true, stdout: '3 passed in 1.0s', stderr: '', exit_code: 0 },
        },
      ],
    }
    render(<ChatMessage group={group} />)
    expect(screen.getByText(/3 passed/)).toBeDefined()
  })

  it('returns null for unknown types', () => {
    const group = { type: 'unknown' as 'thinking', chunks: [] }
    const { container } = render(<ChatMessage group={group} />)
    expect(container.firstChild).toBeNull()
  })
})
