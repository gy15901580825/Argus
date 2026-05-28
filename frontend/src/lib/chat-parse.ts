import type { StreamChunk } from './chat-types'

// Helper to detect code blocks in content
export function detectCodeBlocks(content: string): { isCode: boolean; language?: string } {
  const codeBlockMatch = content.match(/^```(\w+)?/)
  if (codeBlockMatch) {
    return { isCode: true, language: codeBlockMatch[1] || 'text' }
  }
  return { isCode: false }
}

// Helper to parse raw content into typed chunks
export function parseContentToChunks(content: string): StreamChunk[] {
  const chunks: StreamChunk[] = []

  // Split content by code blocks
  const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g
  let lastIndex = 0
  let match

  while ((match = codeBlockRegex.exec(content)) !== null) {
    // Add text before code block as result
    if (match.index > lastIndex) {
      const textContent = content.slice(lastIndex, match.index).trim()
      if (textContent) {
        chunks.push({ type: 'result', content: textContent })
      }
    }

    // Add code block
    chunks.push({
      type: 'code',
      content: match[2].trim(),
      language: match[1] || 'text',
    })

    lastIndex = match.index + match[0].length
  }

  // Add remaining text as result
  if (lastIndex < content.length) {
    const remainingContent = content.slice(lastIndex).trim()
    if (remainingContent) {
      chunks.push({ type: 'result', content: remainingContent })
    }
  }

  // If no chunks created, treat entire content as result
  if (chunks.length === 0 && content.trim()) {
    chunks.push({ type: 'result', content: content.trim() })
  }

  return chunks
}
