'use client'

import { useSearchParams } from 'next/navigation'
import { Suspense } from 'react'

// IMPORTANT: replace TALLY_FORM_ID after operator creates the form in Tally UI
// per docs/operations/plan-5-manual-ops.md (T6 deploy gate).
const TALLY_FORM_ID = 'REPLACE_WITH_TALLY_FORM_ID'

function RequestDemoContent() {
  const searchParams = useSearchParams()
  const tier = searchParams.get('tier') || 'team'

  return (
    <div className="min-h-screen pt-24 pb-16 px-4">
      <div className="max-w-3xl mx-auto">
        <h1 className="text-4xl font-bold mb-4">Request a demo</h1>
        <p className="text-lg text-muted-foreground mb-8">
          Tell us about your AI agent and we&apos;ll get back within 24 hours.
          {tier === 'design-partner' &&
            " You're applying to the design partner program — see /design-partners for details."}
        </p>
        <iframe
          src={`https://tally.so/embed/${TALLY_FORM_ID}?alignLeft=1&hideTitle=0&transparentBackground=1&dynamicHeight=1&tier=${tier}`}
          loading="lazy"
          width="100%"
          height="800"
          style={{ border: 'none' }}
          title="Argus Demo Request"
        />
      </div>
    </div>
  )
}

export default function RequestDemoPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen pt-24 pb-16 px-4">
          <div className="max-w-3xl mx-auto text-muted-foreground">Loading...</div>
        </div>
      }
    >
      <RequestDemoContent />
    </Suspense>
  )
}
