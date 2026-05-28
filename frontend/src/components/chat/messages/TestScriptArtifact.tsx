'use client'

import { useState } from 'react'
import { ChevronDown, ChevronRight, FileText } from 'lucide-react'
import type { StreamChunk } from '@/lib/chat-types'
import { CodeBlock } from '@/components/chat/CodeBlock'

interface Props {
  chunks: StreamChunk[]
  onSaveScript?: (script: string, name: string) => void
}

// Self-contained card with a clearly clickable header row. The previous
// MessageShell wrapper started collapsed by default and exposed only a tiny
// chevron, which users couldn't find — they reported the card couldn't be clicked to expand.
export function TestScriptArtifact({ chunks, onSaveScript }: Props) {
  const data = chunks[0]?.webUiArtifactData
  const [expanded, setExpanded] = useState(true)
  if (!data) return null
  const { script, name = 'test_script.py' } = data

  const lineCount = script.split('\n').length
  const kb = (new Blob([script]).size / 1024).toFixed(1)

  return (
    <div className="my-3 rounded-xl border border-blue-100 bg-gradient-to-br from-blue-50 to-indigo-50 shadow-sm overflow-hidden">
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        aria-expanded={expanded}
        className="flex w-full items-center gap-2 px-4 py-3 text-left hover:bg-blue-100/50 transition-colors"
      >
        <FileText className="h-4 w-4 shrink-0 text-blue-600" />
        <span className="flex-1 min-w-0">
          <span className="block text-xs uppercase tracking-wider text-blue-700 font-semibold">
            Test script
          </span>
          <span className="block text-sm text-gray-800 truncate">
            {name} · {kb} KB · {lineCount} lines
          </span>
        </span>
        {expanded ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-gray-500" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-gray-500" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-blue-100 bg-white px-4 py-3">
          <CodeBlock language="python" code={script} />
          {onSaveScript && (
            <button
              type="button"
              onClick={() => onSaveScript(script, name)}
              className="mt-3 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-700"
            >
              Save to scripts
            </button>
          )}
        </div>
      )}
    </div>
  )
}
