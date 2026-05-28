'use client'

import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import rehypeHighlight from 'rehype-highlight'
import type { StreamChunk } from '@/lib/chat-types'
import { splitClosedAndOpen } from '@/lib/stream-split'
import { remarkCollapseStreamingBreaks } from '@/lib/remark-collapse-streaming-breaks'
import { getMarkdownMode } from '@/lib/stream-config'
import { resultMessageComponents } from '@/components/chat/markdown-components'

interface Props {
  chunks: StreamChunk[]
  isStreaming?: boolean
}

export function ResultMessage({ chunks, isStreaming = false }: Props) {
  const content = chunks.map((c) => c.content).join('')
  const mode = getMarkdownMode()
  const useStreaming = isStreaming && mode !== 'off'

  if (!useStreaming) {
    // Non-streaming: legacy ResultMessage output — remarkGfm only, no streaming plugin
    return (
      <div className="prose prose-sm max-w-none font-sans">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[rehypeHighlight]}
          components={resultMessageComponents}
        >
          {content}
        </ReactMarkdown>
      </div>
    )
  }

  // Streaming: defer mode renders full content in .streaming-tail pre
  if (mode === 'defer') {
    return (
      <div className="prose prose-sm max-w-none font-sans">
        <pre className="streaming-tail whitespace-pre-wrap font-mono text-sm text-gray-600">
          {content}
        </pre>
      </div>
    )
  }

  // Streaming: balanced or lenient — use split-tail rendering
  const { closed, open } = splitClosedAndOpen(content)
  const remarkPlugins =
    mode === 'balanced' ? [remarkGfm, remarkCollapseStreamingBreaks] : [remarkGfm]

  // Only show the streaming-tail when there is a genuine closed portion —
  // i.e. some content has been committed to markdown rendering. When the
  // splitter falls back (closed === ''), the entire content is still
  // in-flight and we render it through ReactMarkdown directly.
  const hasCommitted = closed.length > 0

  return (
    <div className="prose prose-sm max-w-none font-sans">
      {hasCommitted ? (
        <>
          <ReactMarkdown
            remarkPlugins={remarkPlugins}
            rehypePlugins={[rehypeHighlight]}
            components={resultMessageComponents}
          >
            {closed}
          </ReactMarkdown>
          {open && (
            <pre className="streaming-tail whitespace-pre-wrap font-mono text-sm text-gray-600">
              {open}
            </pre>
          )}
        </>
      ) : (
        <ReactMarkdown
          remarkPlugins={remarkPlugins}
          rehypePlugins={[rehypeHighlight]}
          components={resultMessageComponents}
        >
          {content}
        </ReactMarkdown>
      )}
    </div>
  )
}
