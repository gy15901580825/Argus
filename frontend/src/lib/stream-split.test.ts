import { describe, it, expect } from 'vitest'
import { splitClosedAndOpen, SCAN_WINDOW_BYTES } from './stream-split'

function assertInverse(closed: string, open: string, content: string) {
  expect(closed + open).toBe(content)
}

describe('splitClosedAndOpen', () => {
  it('empty string returns both empty', () => {
    const { closed, open } = splitClosedAndOpen('')
    expect(closed).toBe('')
    expect(open).toBe('')
  })

  it('returns everything as open when no boundary is found', () => {
    const content = 'hello'
    const { closed, open } = splitClosedAndOpen(content)
    expect(closed).toBe('')
    expect(open).toBe(content)
  })

  it('splits on the last paragraph break', () => {
    const content = 'paragraph one.\n\nstart of two'
    const { closed, open } = splitClosedAndOpen(content)
    expect(closed).toBe('paragraph one.\n\n')
    expect(open).toBe('start of two')
    assertInverse(closed, open, content)
  })

  it('treats a closed code fence as a safe boundary', () => {
    const content = '```python\nprint(1)\n```\n\ntrailing'
    const { closed, open } = splitClosedAndOpen(content)
    expect(closed).toBe('```python\nprint(1)\n```\n\n')
    expect(open).toBe('trailing')
    assertInverse(closed, open, content)
  })

  it('unclosed fence: everything from the opening fence is open', () => {
    const content = 'prose\n\n```python\nprint(1'
    const { closed, open } = splitClosedAndOpen(content)
    expect(closed).toBe('prose\n\n')
    expect(open).toBe('```python\nprint(1')
    assertInverse(closed, open, content)
  })

  it('unclosed fence at start: all is open', () => {
    const content = '```python\nprint(1'
    const { closed, open } = splitClosedAndOpen(content)
    expect(closed).toBe('')
    expect(open).toBe(content)
  })

  it('unclosed list item after last paragraph is kept open', () => {
    const content = 'closed.\n\n- list item not yet closed'
    const { closed, open } = splitClosedAndOpen(content)
    expect(closed).toBe('closed.\n\n')
    expect(open).toBe('- list item not yet closed')
    assertInverse(closed, open, content)
  })

  it('unclosed blockquote after last paragraph is kept open', () => {
    const content = 'closed.\n\n> quoting something'
    const { closed, open } = splitClosedAndOpen(content)
    expect(closed).toBe('closed.\n\n')
    expect(open).toBe('> quoting something')
    assertInverse(closed, open, content)
  })

  it('content longer than scan window with boundary in final window: splits correctly', () => {
    const prefix = 'x'.repeat(SCAN_WINDOW_BYTES - 100)
    const content = `${prefix}paragraph one.\n\nstart of two`
    const { closed, open } = splitClosedAndOpen(content)
    expect(open).toBe('start of two')
    expect(closed.endsWith('paragraph one.\n\n')).toBe(true)
    assertInverse(closed, open, content)
  })

  it('content where final scan window has no boundary: everything is open (pessimistic)', () => {
    const content = 'a'.repeat(SCAN_WINDOW_BYTES + 1000)
    const { closed, open } = splitClosedAndOpen(content)
    expect(closed).toBe('')
    expect(open).toBe(content)
  })
})
