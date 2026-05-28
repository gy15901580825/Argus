import Link from 'next/link'
import { Check, MapPin } from 'lucide-react'

export default function DesignPartnersPage() {
  return (
    <div className="min-h-screen pt-24 pb-16 px-4">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold mb-4">We&apos;re recruiting 3 design partners</h1>
        <p className="text-lg text-muted-foreground mb-8">
          Help us build the AI agent red-team tool you wish existed. Free 6 months of Team tier,
          priority support, and a co-branded case study.
        </p>

        <h2 className="text-2xl font-bold mt-8 mb-4">What you get</h2>
        <ul className="space-y-3 mb-8">
          <li className="flex items-start gap-2 text-sm">
            <Check className="w-4 h-4 mt-0.5 shrink-0 text-primary" />
            <span>
              <strong>6 months free</strong> at Team tier ($1,200 value/seat)
            </span>
          </li>
          <li className="flex items-start gap-2 text-sm">
            <Check className="w-4 h-4 mt-0.5 shrink-0 text-primary" />
            <span>
              <strong>24-hour priority support</strong> from the founding team
            </span>
          </li>
          <li className="flex items-start gap-2 text-sm">
            <Check className="w-4 h-4 mt-0.5 shrink-0 text-primary" />
            <span>
              <strong>Co-branded case study</strong> (or anonymous, your choice)
            </span>
          </li>
          <li className="flex items-start gap-2 text-sm">
            <Check className="w-4 h-4 mt-0.5 shrink-0 text-primary" />
            <span>
              <strong>Roadmap influence</strong> — your blockers go to the top of the queue
            </span>
          </li>
        </ul>

        <h2 className="text-2xl font-bold mt-8 mb-4">What we ask</h2>
        <ul className="space-y-3 mb-8">
          <li className="flex items-start gap-2 text-sm">
            <MapPin className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
            <span>An AI agent in production OR ready to deploy within 30 days</span>
          </li>
          <li className="flex items-start gap-2 text-sm">
            <MapPin className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
            <span>Willing to run Argus probe-suite at least once a week</span>
          </li>
          <li className="flex items-start gap-2 text-sm">
            <MapPin className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
            <span>30-minute monthly check-in with the founding team</span>
          </li>
          <li className="flex items-start gap-2 text-sm">
            <MapPin className="w-4 h-4 mt-0.5 shrink-0 text-muted-foreground" />
            <span>
              Honest feedback — we want to hear what&apos;s broken, not what&apos;s polite
            </span>
          </li>
        </ul>

        <h2 className="text-2xl font-bold mt-8 mb-4">Who we&apos;re looking for</h2>
        <p className="text-sm text-muted-foreground mb-8">
          AppSec engineers, security managers, or AI infra leads at companies shipping AI agents.
          Pen-test consultancies and GRC firms with AI clients are also a great fit.
        </p>

        <div className="text-center mt-12">
          <Link
            href="/request-demo?tier=design-partner"
            className="inline-block bg-primary text-primary-foreground px-8 py-3 rounded-lg text-lg font-semibold hover:bg-primary/90 transition-colors"
          >
            Apply Now
          </Link>
        </div>
      </div>
    </div>
  )
}
