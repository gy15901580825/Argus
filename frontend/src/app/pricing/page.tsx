import Link from 'next/link'
import { Check } from 'lucide-react'

const TIERS = [
  {
    name: 'OSS',
    price: 'Free',
    priceSuffix: undefined,
    sub: undefined,
    features: [
      'All 145+ probes',
      'CLI + GitHub Action',
      'SARIF / HTML / JUnit reports',
      'Community support',
    ],
    cta: { text: 'Get Started Free', href: '/docs/onboarding/quickstart' },
    highlight: false,
    badge: undefined,
  },
  {
    name: 'Team',
    price: '$200',
    priceSuffix: '/seat/mo',
    sub: '5 seat min',
    features: [
      'Everything in OSS',
      'Hosted run history (coming Q3 2026)',
      'Email + Slack alerts (coming Q3 2026)',
      'Priority support',
    ],
    cta: { text: 'Start Trial', href: '/request-demo?tier=team' },
    highlight: true,
    badge: 'Most Popular',
  },
  {
    name: 'Enterprise',
    price: '$50K+',
    priceSuffix: '/yr',
    sub: 'Request quote',
    features: [
      'Everything in Team',
      'Dedicated SLA',
      'Custom probe authoring',
      'Private deployment option',
      'Compliance reports (SOC 2, ISO 27001)',
    ],
    cta: { text: 'Request Quote', href: '/request-demo?tier=enterprise' },
    highlight: false,
    badge: undefined,
  },
]

export default function PricingPage() {
  return (
    <div className="min-h-screen pt-24 pb-16 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">Pricing</h1>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Self-hosted CLI is free forever. Hosted features and enterprise support available in
            Team and Enterprise tiers.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {TIERS.map((tier) => (
            <div
              key={tier.name}
              className={`relative rounded-2xl border p-8 flex flex-col ${
                tier.highlight
                  ? 'border-primary shadow-lg shadow-primary/10 scale-105'
                  : 'border-border'
              }`}
            >
              {tier.badge && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2 bg-primary text-primary-foreground text-xs font-semibold px-3 py-1 rounded-full">
                  {tier.badge}
                </div>
              )}

              <h2 className="text-xl font-bold mb-1">{tier.name}</h2>

              <div className="mt-4 mb-2">
                <span className="text-4xl font-bold">{tier.price}</span>
                {tier.priceSuffix && (
                  <span className="text-muted-foreground">{tier.priceSuffix}</span>
                )}
              </div>
              {tier.sub && <p className="text-sm text-muted-foreground mb-4">{tier.sub}</p>}

              <ul className="space-y-3 mb-8 flex-1">
                {tier.features.map((feat) => (
                  <li key={feat} className="flex items-start gap-2 text-sm">
                    <Check className="w-4 h-4 mt-0.5 shrink-0 text-primary" />
                    <span>{feat}</span>
                  </li>
                ))}
              </ul>

              <Link
                href={tier.cta.href}
                className={`block w-full text-center py-2 rounded-lg text-sm font-semibold transition-colors ${
                  tier.highlight
                    ? 'bg-primary text-primary-foreground hover:bg-primary/90'
                    : 'border border-border hover:bg-muted'
                }`}
              >
                {tier.cta.text}
              </Link>
            </div>
          ))}
        </div>

        <p className="text-center text-sm text-muted-foreground mt-12">
          Looking for early-access pricing?{' '}
          <Link href="/design-partners" className="text-primary underline underline-offset-4">
            Apply to the design partner program
          </Link>{' '}
          — 6 months free at Team tier.
        </p>
      </div>
    </div>
  )
}
