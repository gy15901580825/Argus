import { describe, it, expect } from 'vitest'
import { parseContentToChunks, detectCodeBlocks } from '@/lib/chat-parse'

describe('parseContentToChunks()', () => {
  it('returns a single result chunk for plain text', () => {
    const chunks = parseContentToChunks('Hello world')
    expect(chunks).toEqual([{ type: 'result', content: 'Hello world' }])
  })

  it('splits plain text + code fence into result + code chunks', () => {
    const chunks = parseContentToChunks('Intro text\n```python\nprint(1)\n```')
    expect(chunks).toHaveLength(2)
    expect(chunks[0]).toEqual({ type: 'result', content: 'Intro text' })
    expect(chunks[1]).toEqual({ type: 'code', content: 'print(1)', language: 'python' })
  })

  it('defaults to "text" language when fence has no language', () => {
    const chunks = parseContentToChunks('```\nbare code\n```')
    expect(chunks[0]).toEqual({ type: 'code', content: 'bare code', language: 'text' })
  })

  it('returns an empty array for empty content', () => {
    expect(parseContentToChunks('')).toEqual([])
    expect(parseContentToChunks('   \n  ')).toEqual([])
  })

  it('handles multiple code blocks interleaved with text', () => {
    const chunks = parseContentToChunks('A\n```js\n1\n```\nB\n```py\n2\n```')
    expect(chunks.map((c) => c.type)).toEqual(['result', 'code', 'result', 'code'])
    expect(chunks[1]).toMatchObject({ content: '1', language: 'js' })
    expect(chunks[3]).toMatchObject({ content: '2', language: 'py' })
  })
})

describe('detectCodeBlocks()', () => {
  it('returns false for non-code content', () => {
    expect(detectCodeBlocks('just words')).toEqual({ isCode: false })
  })

  it('detects language-tagged fences', () => {
    expect(detectCodeBlocks('```python\nprint(1)')).toEqual({ isCode: true, language: 'python' })
  })

  it('defaults language to "text" when fence has none', () => {
    expect(detectCodeBlocks('```\nraw')).toEqual({ isCode: true, language: 'text' })
  })
})
