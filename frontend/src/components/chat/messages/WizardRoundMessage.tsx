'use client'

import { useState } from 'react'
import type { WizardRoundLabel } from '@/lib/wizard-types'
import { cn } from '@/lib/utils'

export interface WizardRoundMessageProps {
  roundN: number
  roundLabel: WizardRoundLabel
  question: string
  options: string[]
  allowFreeText: boolean
  allowBack: boolean
  status: 'pending' | 'answered' | 'stale'
  selectedAnswer?: string
  onSelect: (value: string) => void
  onBack: () => void
  onAbort: () => void
}

const LABEL_TEXT: Record<WizardRoundLabel, string> = {
  intent: 'What to do',
  run_where: 'Where to run',
  credentials: 'Credentials',
  persona: 'Persona',
  target_url: 'Target URL',
  local_setup_check: 'Local setup',
  confirm: 'Confirm',
  other: 'Choose',
}

export function WizardRoundMessage({
  roundN,
  roundLabel,
  question,
  options,
  allowFreeText,
  allowBack,
  status,
  selectedAnswer,
  onSelect,
  onBack,
  onAbort,
}: WizardRoundMessageProps) {
  const [freeText, setFreeText] = useState('')
  const disabled = status !== 'pending'

  if (status === 'answered') {
    return (
      <div className="rounded-lg border bg-muted/50 p-4">
        <div className="text-xs text-muted-foreground mb-1">
          Step {roundN}: {LABEL_TEXT[roundLabel]}
        </div>
        <div className="text-sm mb-2">{question}</div>
        <span className="inline-block rounded-full bg-primary/10 px-3 py-1 text-sm">
          {selectedAnswer}
        </span>
      </div>
    )
  }

  return (
    <div
      className={cn(
        'rounded-lg border p-4',
        status === 'stale' && 'opacity-40 pointer-events-none'
      )}
    >
      <div className="text-xs text-muted-foreground mb-1">
        Step {roundN}: {LABEL_TEXT[roundLabel]}
      </div>
      <div className="text-sm mb-3">{question}</div>
      <div className="flex flex-wrap gap-2 mb-3">
        {options.map((opt) => (
          <button
            key={opt}
            type="button"
            disabled={disabled}
            onClick={() => onSelect(opt)}
            className="rounded-full border px-3 py-1 text-sm hover:bg-accent"
          >
            {opt}
          </button>
        ))}
      </div>
      {allowFreeText && (
        <input
          type="text"
          placeholder="Type your answer and press Enter"
          value={freeText}
          onChange={(e) => setFreeText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && freeText.trim()) {
              onSelect(freeText.trim())
              setFreeText('')
            }
          }}
          disabled={disabled}
          className="w-full rounded border px-2 py-1 text-sm mb-3"
        />
      )}
      <div className="flex gap-2 text-xs">
        {allowBack && (
          <button
            type="button"
            onClick={onBack}
            className="text-muted-foreground hover:text-foreground"
          >
            ← Back
          </button>
        )}
        <button
          type="button"
          onClick={onAbort}
          className="ml-auto text-muted-foreground hover:text-destructive"
        >
          ✕ Abort wizard
        </button>
      </div>
    </div>
  )
}
