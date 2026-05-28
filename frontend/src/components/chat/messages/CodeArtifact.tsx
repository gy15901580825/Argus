'use client'

import type { StreamChunk } from '@/lib/chat-types'
import { CodeBlock } from '@/components/chat/CodeBlock'
import { MessageShell } from './MessageShell'

interface Props {
  chunks: StreamChunk[]
}

export function CodeArtifact({ chunks }: Props) {
  const content = chunks.map((c) => c.content).join('')
  const language = chunks[0]?.language ?? 'text'
  const lineCount = content.split('\n').length
  const bytes = new Blob([content]).size
  const kb = (bytes / 1024).toFixed(1)
  const summary = `${language} · ${kb} KB · ${lineCount} lines`

  return (
    <MessageShell category="code" summary={summary}>
      <CodeBlock language={language} code={content} />
    </MessageShell>
  )
}
