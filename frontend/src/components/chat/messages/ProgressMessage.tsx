'use client'

import type { StreamChunk } from '@/lib/chat-types'
import { MessageShell } from './MessageShell'

interface Props {
  chunks: StreamChunk[]
}

export function ProgressMessage({ chunks }: Props) {
  const latest = chunks[chunks.length - 1]?.content ?? ''
  return (
    <MessageShell category="progress" summary={latest}>
      <ul className="space-y-1 text-xs text-gray-600">
        {chunks.map((c, i) => (
          <li key={i} className="whitespace-pre-wrap">
            {c.content}
          </li>
        ))}
      </ul>
    </MessageShell>
  )
}
