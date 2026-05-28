import { render, screen, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi } from 'vitest'
import { WizardRoundMessage } from './WizardRoundMessage'

const base = {
  roundN: 1,
  roundLabel: 'intent' as const,
  question: 'What do you want to do?',
  options: ['Web UI test', 'API test'],
  allowFreeText: false,
  allowBack: false,
  onSelect: vi.fn(),
  onBack: vi.fn(),
  onAbort: vi.fn(),
}

describe('WizardRoundMessage', () => {
  it('renders question and options in pending state', () => {
    render(<WizardRoundMessage {...base} status="pending" />)
    expect(screen.getByText(base.question)).toBeInTheDocument()
    expect(screen.getByText('Web UI test')).toBeInTheDocument()
  })

  it('calls onSelect when an option is clicked', () => {
    const onSelect = vi.fn()
    render(<WizardRoundMessage {...base} onSelect={onSelect} status="pending" />)
    fireEvent.click(screen.getByText('Web UI test'))
    expect(onSelect).toHaveBeenCalledWith('Web UI test')
  })

  it('hides back button when allowBack is false', () => {
    render(<WizardRoundMessage {...base} status="pending" allowBack={false} />)
    expect(screen.queryByText(/back/i)).toBeNull()
  })

  it('shows back button when allowBack is true', () => {
    render(<WizardRoundMessage {...base} status="pending" allowBack={true} />)
    expect(screen.getByText(/back/i)).toBeInTheDocument()
  })

  it('renders free-text input when allowFreeText=true', () => {
    render(<WizardRoundMessage {...base} status="pending" allowFreeText={true} />)
    expect(screen.getByPlaceholderText(/type your answer/i)).toBeInTheDocument()
  })

  it('submits free-text via onSelect', () => {
    const onSelect = vi.fn()
    render(
      <WizardRoundMessage {...base} onSelect={onSelect} status="pending" allowFreeText={true} />
    )
    const input = screen.getByPlaceholderText(/type your answer/i)
    fireEvent.change(input, { target: { value: 'custom answer' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(onSelect).toHaveBeenCalledWith('custom answer')
  })

  it('greys out options when status=stale', () => {
    const onSelect = vi.fn()
    render(<WizardRoundMessage {...base} onSelect={onSelect} status="stale" />)
    const btn = screen.getByText('Web UI test')
    fireEvent.click(btn)
    expect(onSelect).not.toHaveBeenCalled()
  })

  it('shows selected answer as a single filled pill when status=answered', () => {
    render(<WizardRoundMessage {...base} status="answered" selectedAnswer="Web UI test" />)
    expect(screen.getByText('Web UI test')).toBeInTheDocument()
    // Unselected options should NOT render in answered state
    expect(screen.queryByText('API test')).toBeNull()
  })
})
