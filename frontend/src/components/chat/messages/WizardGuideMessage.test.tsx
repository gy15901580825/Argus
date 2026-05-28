import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { WizardGuideMessage } from './WizardGuideMessage'

describe('WizardGuideMessage', () => {
  it('renders the client_agent_install guide markdown', () => {
    render(
      <WizardGuideMessage guideKind="client_agent_install" markdown="# Install\n\nSome text." />
    )
    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent('Install')
  })

  it('shows the correct title for client_agent_install', () => {
    render(<WizardGuideMessage guideKind="client_agent_install" markdown="..." />)
    expect(screen.getByText(/client agent install/i)).toBeInTheDocument()
  })

  it('shows the correct title for cdp_browser_launch', () => {
    render(<WizardGuideMessage guideKind="cdp_browser_launch" markdown="..." />)
    expect(screen.getByText(/cdp browser launch/i)).toBeInTheDocument()
  })
})
