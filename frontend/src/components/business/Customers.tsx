import { FadeIn } from '@/components/ui/fade-in'

export function Customers() {
  return (
    <section id="customers" className="py-24 bg-background">
      <div className="container mx-auto px-4 text-center">
        <FadeIn>
          <div className="inline-block px-3 py-1 rounded-full bg-primary/10 text-primary text-sm font-semibold mb-4">
            Why Agent Testing Matters
          </div>
          <h2 className="text-3xl font-bold mb-4">
            Untested Agents Don&apos;t Ship. Tested Agents Don&apos;t Get Breached.
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-12">
            The numbers behind why reliability and security testing is the new gate for shipping AI
            agents.
          </p>
        </FadeIn>

        <FadeIn delay={0.2}>
          <div className="grid md:grid-cols-3 gap-8 max-w-5xl mx-auto">
            <div className="p-8 rounded-xl bg-secondary/20 border border-border">
              <div className="text-5xl font-extrabold text-primary mb-2">89%</div>
              <div className="font-semibold mb-2">of AI pilots never reach production</div>
              <p className="text-sm text-muted-foreground">
                Source: Deloitte State of AI 2024. Reliability is the gate.
              </p>
            </div>
            <div className="p-8 rounded-xl bg-secondary/20 border border-border">
              <div className="text-5xl font-extrabold text-primary mb-2">52%</div>
              <div className="font-semibold mb-2">of shipped agents hit a serious incident</div>
              <p className="text-sm text-muted-foreground">
                Source: PwC CISO Pulse 2025. Hallucination, data leak, prompt injection — within 12
                months.
              </p>
            </div>
            <div className="p-8 rounded-xl bg-secondary/20 border border-border">
              <div className="text-5xl font-extrabold text-primary mb-2">Aug 2026</div>
              <div className="font-semibold mb-2">EU AI Act conformity goes live</div>
              <p className="text-sm text-muted-foreground">
                Article 85: high-risk AI systems must produce continuous testing evidence.
              </p>
            </div>
          </div>
        </FadeIn>

        <FadeIn delay={0.4}>
          <div className="mt-16 p-8 rounded-xl bg-gradient-to-br from-primary/5 to-blue-500/5 border border-primary/20 max-w-3xl mx-auto">
            <div className="text-sm uppercase tracking-wide text-primary font-bold mb-3">
              Early Access Program
            </div>
            <h3 className="text-2xl font-bold mb-3">
              Get a free reliability &amp; security test run for your agent
            </h3>
            <p className="text-muted-foreground">
              We&apos;re onboarding a limited cohort of design partners ahead of the EU AI Act
              deadline. Bring your agent endpoint — leave with a Trust Score and an evidence pack.
            </p>
          </div>
        </FadeIn>
      </div>
    </section>
  )
}
