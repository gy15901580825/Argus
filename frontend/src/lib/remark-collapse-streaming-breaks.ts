import type { Plugin } from 'unified'
import type { Root, RootContent } from 'mdast'

function isEmptyParagraph(node: RootContent): boolean {
  if (node.type !== 'paragraph') return false
  if (!('children' in node) || node.children.length === 0) return true
  return node.children.every(
    (c) => c.type === 'text' && /^\s*$/.test((c as { value: string }).value)
  )
}

export const remarkCollapseStreamingBreaks: Plugin<[], Root> = () => {
  return (tree) => {
    const children = tree.children
    const kept: RootContent[] = []

    for (const node of children) {
      if (isEmptyParagraph(node)) {
        // Drop empty paragraphs entirely.
        continue
      }
      // Keep all non-empty nodes. remark serialization already inserts exactly
      // one blank line between adjacent block nodes, so no manual spacing needed.
      kept.push(node)
    }

    tree.children = kept
  }
}
