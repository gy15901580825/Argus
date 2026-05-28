import { Activity, ShieldCheck, FileCheck } from 'lucide-react'
import { FadeIn } from '@/components/ui/fade-in'
import { TrustScoreMockup } from '@/components/business/TrustScoreMockup'

const PILLARS = [
  {
    tag: 'Reliability',
    icon: Activity,
    title: 'Test Whether Your Agent Actually Works',
    body: 'Define success in YAML. Replay scenarios across model versions. Catch tool-call errors and infinite loops before production.',
    metric: '94% task success across 1,284 scenarios',
  },
  {
    tag: 'Security',
    icon: ShieldCheck,
    title: 'Test for Attacks Before Attackers Do',
    body: 'Prompt injection, indirect attacks, jailbreaks, tool abuse — adversarial probes ship with every reliability run.',
    metric: '312 probes, continuous cadence',
  },
  {
    tag: 'Compliance',
    icon: FileCheck,
    title: 'Every Test Run Becomes Audit Evidence',
    body: 'Continuous monitoring, risk classification, signed traces. Export EU AI Act Article 85 / NIST AI RMF artifacts in one click.',
    metric: '12-month signed history',
  },
] as const

export function Features() {
  return (
    <section id="features" className="py-24 bg-secondary/30">
      <div className="container mx-auto px-4">
        {/* Dashboard mockup — product peek */}
        <FadeIn className="mb-20">
          <TrustScoreMockup />
        </FadeIn>

        {/* Section heading */}
        <FadeIn className="text-center max-w-2xl mx-auto mb-12">
          <h2 className="text-3xl md:text-4xl font-bold mb-4">Three Pillars of Agent Testing</h2>
          <p className="text-lg text-muted-foreground">
            One platform. Reliability, security, and compliance — measured continuously, on every
            deploy.
          </p>
        </FadeIn>

        {/* Three-column card grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-6xl mx-auto">
          {PILLARS.map((p, i) => (
            <FadeIn
              key={p.tag}
              className="bg-background border border-border rounded-2xl p-6 flex flex-col gap-4 hover:border-primary/40 hover:shadow-lg transition-all"
              delay={i * 0.1}
            >
              <div className="inline-flex items-center gap-2">
                <span className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <p.icon className="h-4 w-4" />
                </span>
                <span className="px-2.5 py-0.5 rounded-full bg-primary/10 text-primary text-xs font-semibold">
                  {p.tag}
                </span>
              </div>
              <h3 className="text-xl font-semibold leading-snug">{p.title}</h3>
              <p className="text-muted-foreground leading-relaxed flex-1">{p.body}</p>
              <div className="pt-2 mt-auto border-t border-border">
                <div className="text-sm font-bold text-primary">{p.metric}</div>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  )
}
