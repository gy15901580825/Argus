import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import Page from '@/app/page'

// Mock the components since we are testing the page integration
// and not the individual components deeply here (integration test)
// But for unit test we can just mock them to ensure they render
vi.mock('@/components/business/Hero', () => ({
  Hero: () => <div data-testid="hero">Hero Section</div>,
}))
vi.mock('@/components/business/Features', () => ({
  Features: () => <div data-testid="features">Features Section</div>,
}))
vi.mock('@/components/business/Customers', () => ({
  Customers: () => <div data-testid="customers">Customers Section</div>,
}))
vi.mock('@/components/business/FAQ', () => ({
  FAQ: () => <div data-testid="faq">FAQ Section</div>,
}))
vi.mock('@/components/business/CTA', () => ({
  CTA: () => <div data-testid="cta">CTA Section</div>,
}))

describe('Home Page', () => {
  it('renders all sections', () => {
    render(<Page />)
    expect(screen.getByTestId('hero')).toBeInTheDocument()
    expect(screen.getByTestId('features')).toBeInTheDocument()
    expect(screen.getByTestId('customers')).toBeInTheDocument()
    expect(screen.getByTestId('faq')).toBeInTheDocument()
    expect(screen.getByTestId('cta')).toBeInTheDocument()
  })
})
