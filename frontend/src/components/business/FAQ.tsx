'use client'
import { useState } from 'react'
import { cn } from '@/lib/utils'
import { FadeIn } from '@/components/ui/fade-in'

const faqs = [
  {
    q: 'What kinds of AI agents can Argus test?',
    a: 'Any agent reachable via HTTP, WebSocket, or a SaaS API: customer-support agents, internal copilots, RAG pipelines, browser-using agents, multi-tool function-calling agents. Connect by endpoint or by SDK adapter — no source-code access required.',
  },
  {
    q: 'How is this different from LLM eval tools like Promptfoo or Braintrust?',
    a: 'LLM eval tools score single prompt-response pairs. Argus tests the agent: multi-turn flows, tool selection, recovery from tool failures, and end-to-end task success. We treat the LLM as one component inside the system you actually shipped.',
  },
  {
    q: 'How does the security testing work?',
    a: 'We maintain a continuously updated probe library covering prompt injection, indirect attacks (poisoned docs, malicious tool outputs), jailbreaks, tool abuse, and data exfiltration patterns. Probes run alongside reliability scenarios — same trace, same dashboard, same CI gate.',
  },
  {
    q: 'Will the evidence pack actually satisfy an EU AI Act auditor?',
    a: 'The pack is designed against Article 85 conformity assessment requirements and NIST AI RMF profiles, with continuous monitoring logs, risk classification, and signed traces retained for 12+ months. We work with Big 4 audit partners; final acceptance always sits with your designated notified body.',
  },
  {
    q: 'How does Argus plug into our CI/CD?',
    a: 'GitHub Actions, GitLab CI, and a pytest plugin out of the box. Reliability and security tests run on every PR, fail the build on regressions against your baseline, and post a Trust Score diff back to the pull request.',
  },
]

export function FAQ() {
  const [openIndex, setOpenIndex] = useState<number | null>(null)

  const toggleFAQ = (index: number) => {
    setOpenIndex(openIndex === index ? null : index)
  }

  return (
    <section className="py-24 bg-secondary/10">
      <div className="container mx-auto px-4 max-w-3xl">
        <FadeIn>
          <h2 className="text-3xl font-bold text-center mb-12">Frequently Asked Questions</h2>
        </FadeIn>
        <div className="space-y-4">
          {faqs.map((faq, index) => (
            <FadeIn key={index} delay={index * 0.1}>
              <div className="border-b border-border pb-4">
                <button
                  className="w-full flex justify-between items-center py-4 text-left font-semibold text-lg hover:text-primary transition-colors"
                  onClick={() => toggleFAQ(index)}
                >
                  {faq.q}
                  <span
                    className={cn(
                      'text-2xl transition-transform duration-300',
                      openIndex === index ? 'rotate-45' : ''
                    )}
                  >
                    +
                  </span>
                </button>
                <div
                  className={cn(
                    'overflow-hidden transition-all duration-300 ease-in-out',
                    openIndex === index ? 'max-h-96 opacity-100 mb-4' : 'max-h-0 opacity-0'
                  )}
                >
                  <p className="text-muted-foreground leading-relaxed">{faq.a}</p>
                </div>
              </div>
            </FadeIn>
          ))}
        </div>
      </div>
    </section>
  )
}
