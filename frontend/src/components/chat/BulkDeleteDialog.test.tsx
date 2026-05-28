import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { BulkDeleteDialog } from '@/components/chat/BulkDeleteDialog'

const noop = () => {}

function makeTitles(n: number) {
  return Array.from({ length: n }, (_, i) => `Session ${i + 1}`)
}

describe('BulkDeleteDialog', () => {
  it('does not render when isOpen is false', () => {
    render(
      <BulkDeleteDialog
        isOpen={false}
        onClose={noop}
        onConfirm={noop}
        sessionTitles={makeTitles(3)}
        isDeleting={false}
      />
    )
    expect(screen.queryByText(/Delete .* sessions\?/)).toBeNull()
  })

  it('renders count and all 3 titles when given 3', () => {
    render(
      <BulkDeleteDialog
        isOpen={true}
        onClose={noop}
        onConfirm={noop}
        sessionTitles={makeTitles(3)}
        isDeleting={false}
      />
    )
    expect(screen.getByText('Delete 3 sessions?')).toBeDefined()
    expect(screen.getByText('Session 1')).toBeDefined()
    expect(screen.getByText('Session 2')).toBeDefined()
    expect(screen.getByText('Session 3')).toBeDefined()
    expect(screen.queryByText(/and \d+ more/)).toBeNull()
  })

  it('renders first 5 titles + "and N more" when given 15', () => {
    render(
      <BulkDeleteDialog
        isOpen={true}
        onClose={noop}
        onConfirm={noop}
        sessionTitles={makeTitles(15)}
        isDeleting={false}
      />
    )
    expect(screen.getByText('Delete 15 sessions?')).toBeDefined()
    for (let i = 1; i <= 5; i++) {
      expect(screen.getByText(`Session ${i}`)).toBeDefined()
    }
    expect(screen.queryByText('Session 6')).toBeNull()
    expect(screen.getByText(/and 10 more/)).toBeDefined()
  })

  it('disables the Delete button and shows spinner when isDeleting is true', () => {
    render(
      <BulkDeleteDialog
        isOpen={true}
        onClose={noop}
        onConfirm={noop}
        sessionTitles={makeTitles(2)}
        isDeleting={true}
      />
    )
    const deleteBtn = screen.getByRole('button', { name: /delete \(2\)/i }) as HTMLButtonElement
    expect(deleteBtn.disabled).toBe(true)
    // Spinner is rendered inside the button (look for an svg or role=status)
    expect(deleteBtn.querySelector('svg')).not.toBeNull()
  })

  it('calls onClose when Cancel is clicked', () => {
    const onClose = vi.fn()
    render(
      <BulkDeleteDialog
        isOpen={true}
        onClose={onClose}
        onConfirm={noop}
        sessionTitles={makeTitles(2)}
        isDeleting={false}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: /cancel/i }))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('calls onConfirm when Delete is clicked and not deleting', () => {
    const onConfirm = vi.fn()
    render(
      <BulkDeleteDialog
        isOpen={true}
        onClose={noop}
        onConfirm={onConfirm}
        sessionTitles={makeTitles(2)}
        isDeleting={false}
      />
    )
    fireEvent.click(screen.getByRole('button', { name: /delete \(2\)/i }))
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it('singularizes title and body copy when count is 1', () => {
    render(
      <BulkDeleteDialog
        isOpen={true}
        onClose={noop}
        onConfirm={noop}
        sessionTitles={['Only Session']}
        isDeleting={false}
      />
    )
    expect(screen.getByText('Delete 1 session?')).toBeDefined()
    // Body should mention "1 chat session" (singular) and "its messages"
    expect(screen.getByText(/1 chat session and all its messages/)).toBeDefined()
  })
})
