import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SystemMessage } from '@/components/chat/messages/SystemMessage'
import type { StreamChunk } from '@/lib/chat-types'

describe('SystemMessage', () => {
  it('renders the system event content as the summary (always visible)', () => {
    const chunks: StreamChunk[] = [{ type: 'system', content: 'Session started' }]
    render(<SystemMessage chunks={chunks} />)
    expect(screen.getByText('Session started')).toBeDefined()
  })

  it('joins multiple system chunks', () => {
    const chunks: StreamChunk[] = [
      { type: 'system', content: 'a' },
      { type: 'system', content: 'b' },
    ]
    render(<SystemMessage chunks={chunks} />)
    expect(screen.getByText(/a.*b/)).toBeDefined()
  })
})
