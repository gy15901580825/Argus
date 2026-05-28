'use client'

import type { StreamChunk } from '@/lib/chat-types'
import { MessageShell } from './MessageShell'

interface Props {
  chunks: StreamChunk[]
}

export function ErrorMessage({ chunks }: Props) {
  const text = chunks.map((c) => c.content).join('\n\n')
  const [firstLine, ...rest] = text.split('\n')
  const hasDetail = rest.join('\n').trim().length > 0

  return (
    <MessageShell category="error" summary={firstLine} severityTint="critical">
      {hasDetail ? (
        <pre className="whitespace-pre-wrap font-mono text-xs text-red-900">{rest.join('\n')}</pre>
      ) : null}
    </MessageShell>
  )
}
