import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MessageShell } from '@/components/chat/messages/MessageShell'

describe('MessageShell', () => {
  it('renders icon, label, and summary for the given category', () => {
    render(
      <MessageShell category="thinking" summary="Planned 4 steps">
        <p>body detail</p>
      </MessageShell>
    )
    expect(screen.getByText('Thinking')).toBeDefined()
    expect(screen.getByText('Planned 4 steps')).toBeDefined()
  })

  it('hides body when collapsed by default', () => {
    render(
      <MessageShell category="thinking" summary="summary">
        <p>body detail</p>
      </MessageShell>
    )
    expect(screen.queryByText('body detail')).toBeNull()
  })

  it('shows body when defaultCollapsed=false', () => {
    render(
      <MessageShell category="bugReport" summary="2 bugs">
        <p>body detail</p>
      </MessageShell>
    )
    expect(screen.getByText('body detail')).toBeDefined()
  })

  it('toggles body visibility on click', () => {
    render(
      <MessageShell category="thinking" summary="summary">
        <p>body detail</p>
      </MessageShell>
    )
    expect(screen.queryByText('body detail')).toBeNull()
    fireEvent.click(screen.getByRole('button'))
    expect(screen.getByText('body detail')).toBeDefined()
  })

  it('omits shell entirely when category=result', () => {
    render(
      <MessageShell category="result" summary={null}>
        <div data-testid="raw-body">raw prose</div>
      </MessageShell>
    )
    expect(screen.queryByText('Response')).toBeNull()
    expect(screen.getByTestId('raw-body')).toBeDefined()
  })

  it('applies severity tint class to summary line', () => {
    const { container } = render(
      <MessageShell category="testResult" summary="3 passed, 1 failed" severityTint="critical">
        body
      </MessageShell>
    )
    const summary = container.querySelector('[data-message-summary]')
    expect(summary?.className).toContain('text-red-700')
  })

  it('renders body but disables toggle button when bodyAlwaysVisible=true', () => {
    render(
      <MessageShell category="system" summary="Session started" bodyAlwaysVisible>
        <p>extra detail</p>
      </MessageShell>
    )
    expect(screen.getByText('extra detail')).toBeDefined()
    expect(screen.getByRole('button')).toHaveAttribute('disabled')
  })

  it('honors defaultCollapsed prop over category default', () => {
    render(
      <MessageShell category="thinking" summary="x" defaultCollapsed={false}>
        <p>expanded body</p>
      </MessageShell>
    )
    expect(screen.getByText('expanded body')).toBeDefined()
  })
})
