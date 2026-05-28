'use client'

import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { WizardGuideEvent } from '@/lib/wizard-types'

const TITLES: Record<WizardGuideEvent['kind'], string> = {
  client_agent_install: 'Client Agent Install',
  cdp_browser_launch: 'CDP Browser Launch',
}

export interface WizardGuideMessageProps {
  guideKind: WizardGuideEvent['kind']
  markdown: string
}

export function WizardGuideMessage({ guideKind, markdown }: WizardGuideMessageProps) {
  return (
    <div className="rounded-lg border bg-blue-50 dark:bg-blue-950 p-4">
      <div className="text-xs font-semibold mb-2">{TITLES[guideKind]}</div>
      <div className="prose prose-sm dark:prose-invert max-w-none">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{markdown}</ReactMarkdown>
      </div>
    </div>
  )
}
