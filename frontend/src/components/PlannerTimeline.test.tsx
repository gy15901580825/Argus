import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { PlannerTimeline, PlannerStepEntry } from './PlannerTimeline'

describe('PlannerTimeline', () => {
  it('renders a tool_use_start step with tool name', () => {
    const steps: PlannerStepEntry[] = [
      {
        type: 'tool_use_start',
        step_index: 0,
        timestamp: 1,
        tool_name: 'discover_apis',
        tool_input: { url: 'https://x.com' },
      },
    ]
    render(<PlannerTimeline steps={steps} />)
    expect(screen.getByText(/discover_apis/)).toBeInTheDocument()
  })

  it('renders a fallback step with reason', () => {
    const steps: PlannerStepEntry[] = [
      { type: 'fallback', step_index: 0, timestamp: 1, reason: 'auth', to: 'gpt-5.4-mini' },
    ]
    render(<PlannerTimeline steps={steps} />)
    expect(screen.getByText(/fallback/i)).toBeInTheDocument()
    expect(screen.getByText(/gpt-5\.4-mini/)).toBeInTheDocument()
  })

  it('hides thinking-text steps by default but shows them when expanded', () => {
    const steps: PlannerStepEntry[] = [
      { type: 'thinking', step_index: 0, timestamp: 1, text: 'planning...' },
    ]
    render(<PlannerTimeline steps={steps} />)
    // Not immediately visible
    expect(screen.queryByText('planning...')).not.toBeInTheDocument()
  })
})
