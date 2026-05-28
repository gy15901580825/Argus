'use client'

import type { StreamChunk } from '@/lib/chat-types'
import { MessageShell } from './MessageShell'

interface Props {
  chunks: StreamChunk[]
}

export function SystemMessage({ chunks }: Props) {
  const text = chunks.map((c) => c.content).join(' · ')
  return <MessageShell category="system" summary={text} bodyAlwaysVisible />
}
