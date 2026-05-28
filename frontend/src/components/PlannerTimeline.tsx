'use client'

import { useState } from 'react'

export interface PlannerStepEntry {
  type:
    | 'thinking'
    | 'tool_use_start'
    | 'tool_use_end'
    | 'tool_error'
    | 'fallback'
    | 'malformed'
    | 'max_steps_hit'
    | 'done'
  step_index: number
  timestamp: number
  text?: string
  tool_name?: string
  tool_input?: Record<string, unknown>
  tool_summary?: string
  error?: string
  reason?: string
  to?: string
}

export function PlannerTimeline({ steps }: { steps: PlannerStepEntry[] }) {
  const [expanded, setExpanded] = useState(false)

  const renderable = steps.filter((s) => s.type !== 'thinking' || expanded)

  return (
    <div className="rounded border border-gray-200 bg-gray-50 p-3 text-sm">
      <div className="flex items-center justify-between mb-2">
        <span className="font-semibold">Planner</span>
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="text-xs text-gray-500 hover:text-gray-800"
        >
          {expanded ? 'Hide thinking' : 'Show thinking'}
        </button>
      </div>
      <ol className="space-y-1">
        {renderable.map((s, i) => (
          <li key={`${s.step_index}-${i}`} className="flex gap-2">
            <span className="text-gray-400 w-6 shrink-0">#{s.step_index}</span>
            <span className="flex-1">{renderStep(s)}</span>
          </li>
        ))}
      </ol>
    </div>
  )
}

function renderStep(s: PlannerStepEntry): React.ReactNode {
  switch (s.type) {
    case 'thinking':
      return <span className="text-gray-600 italic">{s.text}</span>
    case 'tool_use_start':
      return (
        <span>
          → <code className="font-mono">{s.tool_name}</code>(
          <code className="text-xs text-gray-500">{JSON.stringify(s.tool_input || {})}</code>)
        </span>
      )
    case 'tool_use_end':
      return (
        <span className="text-green-700">
          ✓ <code className="font-mono">{s.tool_name}</code> — {s.tool_summary}
        </span>
      )
    case 'tool_error':
      return (
        <span className="text-red-700">
          ✗ <code className="font-mono">{s.tool_name}</code>: {s.error}
        </span>
      )
    case 'fallback':
      return (
        <span className="text-amber-700">
          ⚠ fallback ({s.reason}) → {s.to}
        </span>
      )
    case 'malformed':
      return <span className="text-amber-700">⚠ malformed output, retrying</span>
    case 'max_steps_hit':
      return <span className="text-amber-700">⚠ max steps hit, forcing summary</span>
    case 'done':
      return <span className="text-gray-500">— done</span>
    default:
      return <span>{JSON.stringify(s)}</span>
  }
}
