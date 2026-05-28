'use client'

import type { StreamChunk, StreamChunkType } from '@/lib/chat-types'
import { ThinkingMessage } from './ThinkingMessage'
import { ProgressMessage } from './ProgressMessage'
import { SystemMessage } from './SystemMessage'
import { ResultMessage } from './ResultMessage'
import { ErrorMessage } from './ErrorMessage'
import { CodeArtifact } from './CodeArtifact'
import { TestResultArtifact } from './TestResultArtifact'
import { TestScriptArtifact } from './TestScriptArtifact'
import { BugReportArtifact } from './BugReportArtifact'

export type GroupType =
  | 'thinking'
  | 'progress'
  | 'result'
  | 'code'
  | 'ssh_result'
  | 'web_ui_bug'
  | 'web_ui_artifact'
  | 'error'
  | 'system'

export interface ChunkGroup {
  type: GroupType
  chunks: StreamChunk[]
}

const SINGLETON_TYPES: StreamChunkType[] = ['web_ui_bug', 'web_ui_artifact', 'ssh_result']

function toGroupType(t: StreamChunkType): GroupType | null {
  switch (t) {
    case 'log':
    case 'discovery_progress':
    case 'planner_step':
      return 'thinking'
    case 'progress':
      return 'progress'
    case 'result':
      return 'result'
    case 'code':
      return 'code'
    case 'ssh_result':
      return 'ssh_result'
    case 'web_ui_bug':
      return 'web_ui_bug'
    case 'web_ui_artifact':
      return 'web_ui_artifact'
    case 'error':
      return 'error'
    case 'system':
      return 'system'
    default: {
      const _exhaustive: never = t
      void _exhaustive
      return null
    }
  }
}

export function groupChunks(chunks: StreamChunk[]): ChunkGroup[] {
  const groups: ChunkGroup[] = []
  for (const chunk of chunks) {
    const groupType = toGroupType(chunk.type)
    if (!groupType) continue
    const last = groups[groups.length - 1]
    const singleton = SINGLETON_TYPES.includes(chunk.type)
    if (last && last.type === groupType && !singleton) {
      last.chunks.push(chunk)
    } else {
      groups.push({ type: groupType, chunks: [chunk] })
    }
  }
  return groups
}

export interface ChatMessageProps {
  group: ChunkGroup
  isStreaming?: boolean
  onRerunWebUI?: (url: string) => void
  onSaveScript?: (script: string, name: string) => void
}

export function ChatMessage({
  group,
  isStreaming = false,
  onRerunWebUI,
  onSaveScript,
}: ChatMessageProps) {
  switch (group.type) {
    case 'thinking':
      return <ThinkingMessage chunks={group.chunks} />
    case 'progress':
      return <ProgressMessage chunks={group.chunks} />
    case 'result':
      return <ResultMessage chunks={group.chunks} isStreaming={isStreaming} />
    case 'code':
      return <CodeArtifact chunks={group.chunks} />
    case 'ssh_result':
      return <TestResultArtifact chunks={group.chunks} />
    case 'web_ui_artifact':
      return <TestScriptArtifact chunks={group.chunks} onSaveScript={onSaveScript} />
    case 'web_ui_bug':
      return <BugReportArtifact chunks={group.chunks} onRerunWebUI={onRerunWebUI} />
    case 'error':
      return <ErrorMessage chunks={group.chunks} />
    case 'system':
      return <SystemMessage chunks={group.chunks} />
    default: {
      const _exhaustive: never = group.type
      void _exhaustive
      if (process.env.NODE_ENV !== 'production') {
        console.warn('[ChatMessage] unknown group type:', (group as { type: string }).type)
      }
      return null
    }
  }
}
