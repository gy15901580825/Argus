import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ProgressMessage } from '@/components/chat/messages/ProgressMessage'
import type { StreamChunk } from '@/lib/chat-types'

const progressChunk = (content: string): StreamChunk => ({ type: 'progress', content })

describe('ProgressMessage', () => {
  it('renders a progress summary with the latest chunk content', () => {
    const chunks = [progressChunk('Step 1 done'), progressChunk('Step 2 running')]
    render(<ProgressMessage chunks={chunks} />)
    expect(screen.getByText(/Step 2 running/)).toBeDefined()
  })

  it('renders all steps in the expanded body', () => {
    const chunks = [progressChunk('Step 1'), progressChunk('Step 2')]
    const { container } = render(<ProgressMessage chunks={chunks} />)
    fireEvent.click(screen.getByRole('button'))

    // Body is a <ul> with <li>s — grab the list items specifically.
    const items = container.querySelectorAll('li')
    const texts = Array.from(items).map((el) => el.textContent)
    expect(texts).toContain('Step 1')
    expect(texts).toContain('Step 2')
    expect(items.length).toBe(2)
  })
})
