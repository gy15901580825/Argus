import { describe, it, expect } from 'vitest'
import { remark } from 'remark'
import { remarkCollapseStreamingBreaks } from './remark-collapse-streaming-breaks'

async function process(input: string): Promise<string> {
  const file = await remark().use(remarkCollapseStreamingBreaks).process(input)
  return String(file)
}

describe('remarkCollapseStreamingBreaks', () => {
  it('collapses token-boundary blank-line runs to a single paragraph break', async () => {
    const input = 'FILE\n\n\n\n\ncon\n\n\n\nft'
    const out = await process(input)
    // The plugin removes empty paragraph nodes; remark re-serializes with
    // exactly one blank line between paragraphs.
    const paragraphCount = (out.match(/\n\n/g) || []).length
    expect(paragraphCount).toBeLessThanOrEqual(2)
  })

  it('preserves single blank lines between real paragraphs (idempotent shape)', async () => {
    const input = 'paragraph one.\n\nparagraph two.'
    const out = await process(input)
    expect(out.trim()).toContain('paragraph one.')
    expect(out.trim()).toContain('paragraph two.')
  })

  it('does not alter code blocks', async () => {
    const input = '```python\nprint(1)\n```'
    const out = await process(input)
    expect(out).toContain('```python')
    expect(out).toContain('print(1)')
  })

  it('does not touch inline formatting', async () => {
    const input = 'Some **bold** and `code`.'
    const out = await process(input)
    expect(out).toContain('**bold**')
    expect(out).toContain('`code`')
  })
})
