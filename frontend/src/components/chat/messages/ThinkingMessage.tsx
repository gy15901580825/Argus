'use client'

import type { StreamChunk } from '@/lib/chat-types'
import { MessageShell } from './MessageShell'

interface Props {
  chunks: StreamChunk[]
}

export function ThinkingMessage({ chunks }: Props) {
  const single = chunks.length === 1 ? chunks[0] : null
  const summary = single
    ? [single.author, single.stage].filter(Boolean).join(' · ') || 'Thinking'
    : `Planned ${chunks.length} steps`

  return (
    <MessageShell category="thinking" summary={summary}>
      <ul className="space-y-1 font-mono text-xs text-gray-600">
        {chunks.map((c, i) => (
          <li key={i} className="whitespace-pre-wrap">
            {c.author && <span className="text-blue-600">[{c.author}]</span>}
            {c.stage && <span className="text-purple-600"> ({c.stage})</span>}
            {(c.author || c.stage) && ' '}
            {c.content}
          </li>
        ))}
      </ul>
    </MessageShell>
  )
}
