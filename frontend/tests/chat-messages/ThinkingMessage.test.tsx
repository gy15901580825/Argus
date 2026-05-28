import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ThinkingMessage } from '@/components/chat/messages/ThinkingMessage'
import type { StreamChunk } from '@/lib/chat-types'

const mkChunk = (over: Partial<StreamChunk> = {}): StreamChunk => ({
  type: 'log',
  content: 'line',
  ...over,
})

describe('ThinkingMessage', () => {
  it('renders "Planned N steps" summary for N>1 chunks', () => {
    const chunks = [mkChunk({ content: 'a' }), mkChunk({ content: 'b' })]
    render(<ThinkingMessage chunks={chunks} />)
    expect(screen.getByText(/Planned 2 steps/)).toBeDefined()
  })

  it('renders author · stage summary for a single log chunk', () => {
    const chunks = [mkChunk({ author: 'planner', stage: 'refine', content: 'line' })]
    render(<ThinkingMessage chunks={chunks} />)
    expect(screen.getByText(/planner.*refine/)).toBeDefined()
  })

  it('is collapsed by default and reveals log lines on expand', () => {
    const chunks = [mkChunk({ content: 'hidden detail' })]
    render(<ThinkingMessage chunks={chunks} />)
    expect(screen.queryByText('hidden detail')).toBeNull()
    fireEvent.click(screen.getByRole('button'))
    expect(screen.getByText('hidden detail')).toBeDefined()
  })

  it('treats planner_step and discovery_progress chunks like log', () => {
    const chunks = [
      mkChunk({ type: 'planner_step', content: 'step 1' }),
      mkChunk({ type: 'discovery_progress', content: 'step 2' }),
    ]
    render(<ThinkingMessage chunks={chunks} />)
    expect(screen.getByText(/Planned 2 steps/)).toBeDefined()
  })
})
