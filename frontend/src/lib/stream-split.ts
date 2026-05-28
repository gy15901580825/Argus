import { streamMetrics } from './stream-metrics'

export const SCAN_WINDOW_BYTES = 4096

interface Split {
  closed: string
  open: string
}

const FENCE = '```'

function findFenceIndices(windowText: string): number[] {
  const indices: number[] = []
  let i = 0
  while (true) {
    const idx = windowText.indexOf(FENCE, i)
    if (idx === -1) break
    indices.push(idx)
    i = idx + FENCE.length
  }
  return indices
}

function isUnclosedBlockStart(tail: string): boolean {
  // Tail is the content AFTER the last \n\n boundary. It's "unclosed" if it
  // looks like a list item or blockquote that hasn't been terminated by a
  // subsequent blank line (we only enter this branch when no blank line was
  // found after it, so no extra check required).
  return /^(?:\s*(?:[-*+]\s|\d+\.\s|>\s))/.test(tail)
}

export function splitClosedAndOpen(content: string): Split {
  if (content.length === 0) return { closed: '', open: '' }

  // Only scan the last SCAN_WINDOW_BYTES characters. If the boundary we find is
  // inside the window, anchor it at the absolute offset in `content`.
  const windowStart = Math.max(0, content.length - SCAN_WINDOW_BYTES)
  const windowText = content.slice(windowStart)

  // Step 1: fence parity inside the window.
  const fences = findFenceIndices(windowText)
  if (fences.length % 2 === 1) {
    // Unclosed fence. Open starts at the last fence.
    const lastFenceAbs = windowStart + fences[fences.length - 1]
    streamMetrics.markBoundaryHit('fence', lastFenceAbs)
    return { closed: content.slice(0, lastFenceAbs), open: content.slice(lastFenceAbs) }
  }

  // Step 2: paragraph break. Only consider breaks AFTER the last closing fence
  // to avoid splitting inside a fenced block that's further back.
  const lastClosingFenceEndAbs =
    fences.length >= 2 ? windowStart + fences[fences.length - 1] + FENCE.length : windowStart

  const searchFrom = Math.max(lastClosingFenceEndAbs, windowStart)
  const searchable = content.slice(searchFrom)
  const lastBreakRel = searchable.lastIndexOf('\n\n')

  if (lastBreakRel === -1) {
    // No paragraph break in the searchable region — fallback.
    streamMetrics.markBoundaryHit('fallback', content.length)
    return { closed: '', open: content }
  }

  const boundaryAbs = searchFrom + lastBreakRel + 2 // after the \n\n

  // Step 3: if the tail after the boundary looks like an unclosed list /
  // blockquote, treat it as open.
  const tail = content.slice(boundaryAbs)
  if (isUnclosedBlockStart(tail)) {
    streamMetrics.markBoundaryHit('list', boundaryAbs)
    return { closed: content.slice(0, boundaryAbs), open: tail }
  }

  streamMetrics.markBoundaryHit('paragraph', boundaryAbs)
  return { closed: content.slice(0, boundaryAbs), open: tail }
}
