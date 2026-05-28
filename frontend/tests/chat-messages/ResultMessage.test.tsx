import { describe, it, expect, vi, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ResultMessage } from '@/components/chat/messages/ResultMessage'
import type { StreamChunk } from '@/lib/chat-types'

const { mockedMode } = vi.hoisted(() => ({ mockedMode: { current: 'balanced' as string } }))

vi.mock('@/lib/stream-config', () => ({
  getMarkdownMode: () => mockedMode.current,
  getDebug: () => false,
}))

afterEach(() => {
  mockedMode.current = 'balanced'
})

const resultChunk = (content: string): StreamChunk => ({ type: 'result', content })

describe('ResultMessage', () => {
  it('renders final markdown as prose when isStreaming=false', () => {
    render(<ResultMessage chunks={[resultChunk('# Hello world')]} isStreaming={false} />)
    expect(screen.getByRole('heading', { level: 1 })).toBeDefined()
  })

  it('joins multiple chunk contents before rendering', () => {
    render(
      <ResultMessage chunks={[resultChunk('# Hello'), resultChunk(' world')]} isStreaming={false} />
    )
    expect(screen.getByText(/Hello world/)).toBeDefined()
  })

  it('renders a streaming-tail element when isStreaming=true and content has open markdown', () => {
    const { container } = render(
      <ResultMessage
        chunks={[resultChunk('# Closed\n\nOpen start **boldish')]}
        isStreaming={true}
      />
    )
    expect(container.querySelector('.streaming-tail')).toBeDefined()
  })

  it('omits streaming-tail when content is fully closed even if isStreaming=true', () => {
    const { container } = render(
      <ResultMessage chunks={[resultChunk('# All closed')]} isStreaming={true} />
    )
    expect(container.querySelector('.streaming-tail')).toBeNull()
  })

  it('does not render a shell header (flows as pure prose)', () => {
    render(<ResultMessage chunks={[resultChunk('Hi')]} isStreaming={false} />)
    expect(screen.queryByText('Response')).toBeNull()
  })

  it('renders full content in streaming-tail pre when mode=defer', () => {
    mockedMode.current = 'defer'
    const { container } = render(
      <ResultMessage chunks={[resultChunk('# Closed\n\nOpen tail')]} isStreaming={true} />
    )
    const tail = container.querySelector('.streaming-tail')
    expect(tail).not.toBeNull()
    expect(tail?.textContent).toContain('# Closed')
    expect(tail?.textContent).toContain('Open tail')
  })

  it('renders content through markdown (no streaming-tail) when split falls back with no committed portion', () => {
    // Content has no paragraph break → splitClosedAndOpen returns { closed: '', open: content }
    const { container } = render(
      <ResultMessage chunks={[resultChunk('# Single line no break')]} isStreaming={true} />
    )
    expect(container.querySelector('.streaming-tail')).toBeNull()
    expect(container.querySelector('h1')?.textContent).toBe('Single line no break')
  })
})
