import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ErrorMessage } from '@/components/chat/messages/ErrorMessage'
import type { StreamChunk } from '@/lib/chat-types'

describe('ErrorMessage', () => {
  it('renders the first line as the summary', () => {
    const chunks: StreamChunk[] = [{ type: 'error', content: 'Connection failed\nstack trace' }]
    render(<ErrorMessage chunks={chunks} />)
    expect(screen.getByText('Connection failed')).toBeDefined()
  })

  it('applies critical severity tint to the summary', () => {
    const chunks: StreamChunk[] = [{ type: 'error', content: 'Boom' }]
    const { container } = render(<ErrorMessage chunks={chunks} />)
    const summary = container.querySelector('[data-message-summary]')
    expect(summary?.className).toContain('text-red-700')
  })

  it('renders full error body (expanded by default)', () => {
    const chunks: StreamChunk[] = [{ type: 'error', content: 'First line\nDetail line' }]
    render(<ErrorMessage chunks={chunks} />)
    expect(screen.getByText(/Detail line/)).toBeDefined()
  })
})
