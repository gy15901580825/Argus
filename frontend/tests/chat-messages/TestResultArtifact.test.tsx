import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { TestResultArtifact } from '@/components/chat/messages/TestResultArtifact'
import type { StreamChunk } from '@/lib/chat-types'

const sshChunk = (): StreamChunk => ({
  type: 'ssh_result',
  content: '',
  sshResult: {
    success: true,
    stdout: '============= 3 passed, 1 failed in 12.4s =============',
    stderr: '',
    exit_code: 0,
  },
})

describe('TestResultArtifact', () => {
  it('summary shows pass/fail counts parsed from pytest output', () => {
    render(<TestResultArtifact chunks={[sshChunk()]} />)
    expect(screen.getByText(/3 passed.*1 failed/)).toBeDefined()
  })

  it('applies critical severity tint when any test failed', () => {
    const { container } = render(<TestResultArtifact chunks={[sshChunk()]} />)
    const summary = container.querySelector('[data-message-summary]')
    expect(summary?.className).toContain('text-red')
  })

  it('is expanded by default (body visible)', () => {
    render(<TestResultArtifact chunks={[sshChunk()]} />)
    expect(screen.getByText(/passed, 1 failed in/)).toBeDefined()
  })

  const sshChunkFrom = (stdout: string): StreamChunk => ({
    type: 'ssh_result',
    content: '',
    sshResult: { success: true, stdout, stderr: '', exit_code: 0 },
  })

  it('parses all-failing output (failed-only, no passed)', () => {
    const { container } = render(
      <TestResultArtifact chunks={[sshChunkFrom('============= 5 failed in 3.0s =============')]} />
    )
    const summary = container.querySelector('[data-message-summary]')
    expect(summary?.textContent).toMatch(/5 failed/)
    expect(summary?.className).toContain('text-red')
  })

  it('parses output with warnings appended', () => {
    render(
      <TestResultArtifact chunks={[sshChunkFrom('======= 3 passed, 1 warning in 2.0s =======')]} />
    )
    expect(screen.getByText(/3 passed/)).toBeDefined()
  })

  it('parses output with deselected and skipped', () => {
    render(
      <TestResultArtifact
        chunks={[sshChunkFrom('== 2 passed, 1 skipped, 5 deselected in 2.0s ==')]}
      />
    )
    expect(screen.getByText(/2 passed/)).toBeDefined()
    expect(screen.getByText(/1 skipped/)).toBeDefined()
  })

  it('returns null-like summary when stdout has no "in <secs>s" duration', () => {
    const { container } = render(
      <TestResultArtifact chunks={[sshChunkFrom('nothing parseable here')]} />
    )
    const summary = container.querySelector('[data-message-summary]')
    expect(summary?.textContent).toContain('Test run complete')
  })
})
