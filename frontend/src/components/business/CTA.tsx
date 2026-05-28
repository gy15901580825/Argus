'use client'

import { useRouter } from 'next/navigation'
import { ArrowRight } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { FadeIn } from '@/components/ui/fade-in'
import { useAuthStore } from '@/store/useAuthStore'
import { track } from '@/lib/analytics'

export function CTA() {
  const user = useAuthStore((state) => state.user)
  const router = useRouter()

  const handleClick = () => {
    track('cta_trial_click', { authenticated: Boolean(user), location: 'home_cta' })
    router.push(user ? '/chat' : '/login')
  }

  return (
    <section id="demo" className="relative bg-slate-950 text-white py-32 overflow-hidden">
      {/* Cyan glow */}
      <div className="pointer-events-none absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-cyan-400/15 rounded-full blur-[120px]" />

      <div className="relative container mx-auto px-4 text-center">
        <FadeIn>
          <h2 className="text-4xl md:text-5xl font-extrabold mb-6">
            Ship AI Agents With Confidence
          </h2>
        </FadeIn>
        <FadeIn delay={0.2}>
          <p className="text-xl text-slate-300 mb-10 max-w-2xl mx-auto">
            Run a free reliability &amp; security test on your agent and get an EU AI Act evidence
            pack you can hand to your auditor.
          </p>
        </FadeIn>
        <FadeIn delay={0.4}>
          <Button
            size="lg"
            onClick={handleClick}
            className="text-lg h-14 px-8 bg-cyan-400 text-slate-950 hover:bg-cyan-300 font-semibold shadow-xl shadow-cyan-400/20 hover:-translate-y-1 transition-all"
          >
            {user ? 'Open Workspace' : 'Start Free Trial'}
            <ArrowRight className="ml-2 h-5 w-5" />
          </Button>
        </FadeIn>
      </div>
    </section>
  )
}
