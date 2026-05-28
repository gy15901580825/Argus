export type MarkdownMode = 'balanced' | 'lenient' | 'defer' | 'off'

const VALID_MODES: ReadonlySet<string> = new Set(['balanced', 'lenient', 'defer', 'off'])

function parseCoalesce(raw: string | undefined): number {
  if (raw === undefined || raw === null) return 50
  const t = raw.trim().toLowerCase()
  if (t === '' || t === 'off' || t === '0') {
    return t === '' ? 50 : 0
  }
  const n = Number(t)
  return Number.isFinite(n) && n >= 0 ? n : 50
}

function parseMode(raw: string | undefined): MarkdownMode {
  if (!raw) return 'balanced'
  const t = raw.trim().toLowerCase()
  return (VALID_MODES.has(t) ? t : 'balanced') as MarkdownMode
}

function parseDebug(raw: string | undefined): boolean {
  return typeof raw === 'string' && raw.trim().toLowerCase() === 'true'
}

export function getCoalesceWindowMs(): number {
  if (process.env.NODE_ENV !== 'development') return 50
  return parseCoalesce(process.env.NEXT_PUBLIC_CHAT_STREAM_COALESCE_MS)
}

export function getMarkdownMode(): MarkdownMode {
  if (process.env.NODE_ENV !== 'development') return 'balanced'
  return parseMode(process.env.NEXT_PUBLIC_CHAT_STREAM_MARKDOWN_MODE)
}

export function getDebug(): boolean {
  if (process.env.NODE_ENV !== 'development') return false
  return parseDebug(process.env.NEXT_PUBLIC_CHAT_STREAM_DEBUG)
}
