'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Activity, ShieldCheck, FileCheck, ArrowRight } from 'lucide-react'
import { useAuthStore } from '@/store/useAuthStore'
import { Button } from '@/components/ui/button'
import { track } from '@/lib/analytics'

const PILLARS = [
  {
    icon: Activity,
    title: 'Reliability',
    body: 'Score task success, tool-call accuracy, and recovery — track regressions in CI.',
  },
  {
    icon: ShieldCheck,
    title: 'Security',
    body: 'Built-in adversarial probes for prompt injection, jailbreaks, and tool abuse.',
  },
  {
    icon: FileCheck,
    title: 'Compliance',
    body: 'Every test run becomes EU AI Act / NIST AI RMF audit evidence — exportable in one click.',
  },
] as const

export function Hero() {
  const user = useAuthStore((state) => state.user)
  const router = useRouter()

  const handleTrialClick = () => {
    track('hero_cta_trial_click', { authenticated: Boolean(user) })
    router.push(user ? '/chat' : '/login')
  }

  return (
    <section className="relative bg-slate-950 text-white overflow-hidden">
      {/* Cyan glow vignette */}
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(34,211,238,0.10),transparent_60%)]" />
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_bottom_right,rgba(124,58,237,0.08),transparent_60%)]" />

      <div className="relative container mx-auto px-4 pt-32 pb-24 md:pt-40 md:pb-32">
        <div className="max-w-4xl mx-auto text-center space-y-8">
          {/* Eyebrow */}
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-cyan-400/30 bg-cyan-400/5 text-cyan-300 text-xs font-semibold tracking-widest uppercase animate-fadeInUp [animation-delay:0.1s] opacity-0 [animation-fill-mode:forwards]">
            <ShieldCheck className="h-3.5 w-3.5" />
            AI Agent Testing Platform
          </div>

          {/* Headline */}
          <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight animate-fadeInUp [animation-delay:0.2s] opacity-0 [animation-fill-mode:forwards]">
            Test AI Agents for
            <br className="hidden md:block" />{' '}
            <span className="bg-clip-text text-transparent bg-gradient-to-r from-cyan-300 to-cyan-500">
              Reliability, Security &amp; Compliance
            </span>
          </h1>

          {/* Subline */}
          <p className="text-lg md:text-xl text-slate-300 max-w-2xl mx-auto leading-relaxed animate-fadeInUp [animation-delay:0.4s] opacity-0 [animation-fill-mode:forwards]">
            Argus proves your AI agent is reliable, secure, and audit-ready — before you ship,
            and on every deploy.
          </p>

          {/* CTA row */}
          <div className="flex flex-col sm:flex-row gap-4 justify-center pt-2 animate-fadeInUp [animation-delay:0.6s] opacity-0 [animation-fill-mode:forwards]">
            <Button
              size="lg"
              onClick={handleTrialClick}
              className="h-12 px-8 bg-cyan-400 text-slate-950 hover:bg-cyan-300 font-semibold shadow-lg shadow-cyan-400/20 transition-all hover:-translate-y-0.5"
            >
              Start Free Trial
              <ArrowRight className="ml-1 h-4 w-4" />
            </Button>
            <Button
              asChild
              size="lg"
              variant="outline"
              className="h-12 px-8 border-white/20 bg-transparent text-white hover:bg-white/10 hover:text-white"
            >
              <Link href="#features" onClick={() => track('hero_cta_learn_more_click', {})}>
                See How It Works
              </Link>
            </Button>
          </div>
        </div>

        {/* Three pillar cards */}
        <div className="mt-20 grid grid-cols-1 md:grid-cols-3 gap-6 max-w-6xl mx-auto animate-fadeInUp [animation-delay:0.8s] opacity-0 [animation-fill-mode:forwards]">
          {PILLARS.map((p) => (
            <div
              key={p.title}
              className="rounded-2xl border border-white/10 bg-white/5 backdrop-blur-sm p-6 hover:border-cyan-400/30 hover:bg-white/[0.07] transition-colors"
            >
              <div className="inline-flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-400/10 text-cyan-400 mb-4">
                <p.icon className="h-5 w-5" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">{p.title}</h3>
              <p className="text-sm text-slate-300 leading-relaxed">{p.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
