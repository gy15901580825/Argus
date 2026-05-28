'use client'

import { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import {
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Play,
  Pause,
  SkipBack,
  SkipForward,
  Download,
} from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useAuthStore } from '@/store/useAuthStore'
import { API_BASE_URL } from '@/lib/api'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface BugCounts {
  critical: number
  high: number
  medium: number
  low: number
}

interface ParsedBug {
  severity: string
  category: string
  title: string
  url?: string
  steps?: string
  expected?: string
  actual?: string
  evidence?: string
  _raw?: string
}

interface BugReportBodyProps {
  bugCounts: BugCounts
  stepsDone?: number
  url?: string
  taskId?: string
  testsUrl?: string
  bugReportUrl?: string
  finalOutput?: string
  screenshotUrls?: string[]
  onRerun?: (url: string) => void
}

// ---------------------------------------------------------------------------
// Bug report parser
// ---------------------------------------------------------------------------

// State-machine field parser for a single bug block.
// Handles multi-line values for all fields correctly.
function parseBugFields(
  block: string
): Omit<ParsedBug, 'severity' | 'category' | 'title'> & { _raw: string } {
  const KNOWN = new Set(['URL', 'STEPS', 'EXPECTED', 'ACTUAL', 'EVIDENCE'])
  const acc: Record<string, string[]> = {}
  let cur: string | null = null

  for (const line of block.split('\n')) {
    const m = line.match(/^([A-Z]+):\s*(.*)$/)
    if (m && KNOWN.has(m[1])) {
      cur = m[1]
      acc[cur] = m[2] ? [m[2]] : []
    } else if (cur) {
      acc[cur].push(line)
    }
  }

  const get = (key: string) => {
    const v = acc[key]?.join('\n').trim()
    return v || undefined
  }

  return {
    url: get('URL'),
    steps: get('STEPS'),
    expected: get('EXPECTED'),
    actual: get('ACTUAL'),
    evidence: get('EVIDENCE'),
    _raw: block.trim(),
  }
}

// ---------------------------------------------------------------------------
// Structured report parser — extracts all major sections from final_output
// ---------------------------------------------------------------------------

interface ParsedExecutiveSummary {
  riskLevel?: string
  verdict?: string
  keyRisk?: string
  confidence?: string
}

interface ParsedCoverageStats {
  pagesVisited?: string
  featuresTested?: string
  checksCompleted?: string
  formsTested?: string
  inputsFuzzed?: string
  securityChecks?: string
}

interface ParsedBusinessSummary {
  appType?: string
  coreJourney?: string
  featuresTested?: string
  pagesVisited?: string
  authState?: string
}

interface ChecklistItem {
  id: string
  status: 'DONE' | 'SKIP' | 'UNKNOWN'
  skipReason?: string
  detail: string
}

interface FeatureResult {
  id: string
  name: string
  status: 'PASS' | 'FAIL' | 'PARTIAL' | 'GATED' | 'UNKNOWN'
  detail: string
}

interface ParsedReport {
  bugs: ParsedBug[]
  executive: ParsedExecutiveSummary
  coverage: ParsedCoverageStats
  business: ParsedBusinessSummary
  checklist: ChecklistItem[]
  features: FeatureResult[]
  observations: string[]
  redirects: string[]
  rawSummary: string
}

function extractSection(text: string, header: string, stopHeaders: string[]): string {
  const pattern = new RegExp(
    `${header}[:\\s]*\\n?([\\s\\S]*?)(?=\\n(?:${stopHeaders.join('|')})[:\\s]|$)`,
    'i'
  )
  return pattern.exec(text)?.[1]?.trim() ?? ''
}

// All known section headers in report order
const SECTION_HEADERS = [
  'EXECUTIVE SUMMARY[^:]*',
  'COVERAGE STATS',
  'BUSINESS SUMMARY',
  'PHASE 3 CHECKLIST',
  'REDIRECT CHECKS',
  'FEATURE TEST RESULTS',
  'OBSERVATIONS',
  'BUGS FOUND',
  'AUTO-DETECTED CONSOLE ERRORS',
  'AUTO-DETECTED NETWORK ERRORS',
]

function parseKeyValue(block: string, key: string): string | undefined {
  const m = block.match(new RegExp(`^${key}:\\s*(.+)$`, 'im'))
  return m?.[1]?.trim() || undefined
}

function parseExecutiveSummary(text: string): ParsedExecutiveSummary {
  const block = extractSection(text, 'EXECUTIVE SUMMARY[^:]*', SECTION_HEADERS)
  if (!block) return {}
  return {
    riskLevel: parseKeyValue(block, 'Risk Level'),
    verdict: parseKeyValue(block, 'One-line verdict'),
    keyRisk: parseKeyValue(block, 'Key risk'),
    confidence: parseKeyValue(block, 'Test confidence'),
  }
}

function parseCoverageStats(text: string): ParsedCoverageStats {
  const block = extractSection(text, 'COVERAGE STATS', SECTION_HEADERS)
  if (!block) return {}
  return {
    pagesVisited: parseKeyValue(block, 'Pages visited'),
    featuresTested: parseKeyValue(block, 'Features tested'),
    checksCompleted: parseKeyValue(block, 'Phase 3 checks completed'),
    formsTested: parseKeyValue(block, 'Forms tested'),
    inputsFuzzed: parseKeyValue(block, 'Inputs fuzzed'),
    securityChecks: parseKeyValue(block, 'Security checks done'),
  }
}

function parseBusinessSummary(text: string): ParsedBusinessSummary {
  const block = extractSection(text, 'BUSINESS SUMMARY', SECTION_HEADERS)
  if (!block) return {}
  return {
    appType: parseKeyValue(block, 'App type'),
    coreJourney: parseKeyValue(block, 'Core user journey'),
    featuresTested: parseKeyValue(block, 'Key features tested'),
    pagesVisited: parseKeyValue(block, 'Pages visited within[^:]*'),
    authState: parseKeyValue(block, 'Auth state'),
  }
}

function parseChecklist(text: string): ChecklistItem[] {
  const block = extractSection(text, 'PHASE 3 CHECKLIST', SECTION_HEADERS)
  if (!block) return []
  const items: ChecklistItem[] = []
  for (const line of block.split('\n')) {
    const m =
      line.match(/^([A-Z]+-(?:ERR|\d+|AUDIT)):\s*\[?(DONE|SKIP[^\]]*)\]?\s*[—-]\s*(.+)$/i) ??
      line.match(/^([A-Z]+-(?:ERR|\d+|AUDIT)):\s*(DONE|SKIP[^\s]*)\s*[—-]\s*(.+)$/i)
    if (!m) continue
    const statusRaw = m[2].trim()
    let status: ChecklistItem['status'] = 'UNKNOWN'
    let skipReason: string | undefined
    if (statusRaw === 'DONE') {
      status = 'DONE'
    } else if (statusRaw.startsWith('SKIP')) {
      status = 'SKIP'
      skipReason =
        statusRaw
          .replace(/^SKIP[-\s]*/, '')
          .replace(/[()]/g, '')
          .trim() || undefined
    }
    items.push({ id: m[1], status, skipReason, detail: m[3].trim() })
  }
  return items
}

function parseFeatureResults(text: string): FeatureResult[] {
  const block = extractSection(text, 'FEATURE TEST RESULTS', SECTION_HEADERS)
  if (!block) return []
  const results: FeatureResult[] = []
  for (const line of block.split('\n')) {
    const m = line.match(/^\[?(F-\d+)\]?\s+(.+?)\s+(PASS|FAIL|PARTIAL|GATED)\s*[—-]\s*(.+)$/i)
    if (!m) continue
    results.push({
      id: m[1],
      name: m[2].trim(),
      status: m[3].toUpperCase() as FeatureResult['status'],
      detail: m[4].trim(),
    })
  }
  return results
}

function parseObservations(text: string): string[] {
  const block = extractSection(text, 'OBSERVATIONS', SECTION_HEADERS)
  if (!block) return []
  return block
    .split('\n')
    .map((l) => l.replace(/^NOTE-\d+:\s*/, '').trim())
    .filter(Boolean)
}

function parseRedirects(text: string): string[] {
  const block = extractSection(text, 'REDIRECT CHECKS', SECTION_HEADERS)
  if (!block || /^NONE$/im.test(block.trim())) return []
  return block
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !/^NONE$/i.test(l))
}

function parseBugReport(text: string): ParsedReport {
  const empty: ParsedReport = {
    bugs: [],
    executive: {},
    coverage: {},
    business: {},
    checklist: [],
    features: [],
    observations: [],
    redirects: [],
    rawSummary: '',
  }
  if (!text) return empty

  // Extract raw BUSINESS SUMMARY for fallback
  const summaryMatch = text.match(
    /BUSINESS SUMMARY:\s*([\s\S]*?)(?=\n(?:PHASE 3 CHECKLIST|REDIRECT CHECKS|FEATURE TEST RESULTS|JOURNEY RESULTS|BUGS FOUND|---)|$)/i
  )
  const rawSummary = summaryMatch ? summaryMatch[1].trim() : ''

  // Extract the BUGS FOUND section if present; otherwise search the whole text
  const bugsSection =
    text.match(/BUGS FOUND:\s*([\s\S]*?)(?=\nNO (?:OTHER )?BUGS|AUTO-DETECTED|$)/i)?.[1] ?? text

  // Split into bug blocks by lines starting with "BUG:" or "BUG-NN:"
  const bugBlocks: string[] = []
  const allLines = bugsSection.split('\n')
  let current: string[] = []

  for (const line of allLines) {
    if (/^BUG(?:-\d+)?:/i.test(line.trim())) {
      if (current.length > 0) bugBlocks.push(current.join('\n'))
      current = [line]
    } else if (current.length > 0) {
      current.push(line)
    }
  }
  if (current.length > 0) bugBlocks.push(current.join('\n'))

  // Fallback: old --- separator format
  if (bugBlocks.length === 0) {
    for (const block of text.split(/\n---+\n/)) {
      if (/BUG(?:-\d+)?:/i.test(block)) bugBlocks.push(block)
    }
  }

  const bugs: ParsedBug[] = []
  for (const block of bugBlocks) {
    // Match both "BUG: HIGH FUNC Title" and "BUG-01: HIGH FUNC Title"
    const bugLine = block.match(/BUG(?:-\d+)?:\s*(CRITICAL|HIGH|MEDIUM|LOW)\s+(\S+)\s+(.+)/i)
    if (!bugLine) continue
    const fields = parseBugFields(block)
    bugs.push({
      severity: bugLine[1].toUpperCase(),
      category: bugLine[2],
      title: bugLine[3].trim(),
      ...fields,
    })
  }

  const ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
  bugs.sort((a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9))

  return {
    bugs,
    executive: parseExecutiveSummary(text),
    coverage: parseCoverageStats(text),
    business: parseBusinessSummary(text),
    checklist: parseChecklist(text),
    features: parseFeatureResults(text),
    observations: parseObservations(text),
    redirects: parseRedirects(text),
    rawSummary,
  }
}

// ---------------------------------------------------------------------------
// Severity config
// ---------------------------------------------------------------------------

const SEVERITY_CFG: Record<string, { badge: string; row: string }> = {
  CRITICAL: {
    badge: 'bg-red-100 text-red-800 border-red-200',
    row: 'border-red-200 bg-red-50 hover:bg-red-100',
  },
  HIGH: {
    badge: 'bg-orange-100 text-orange-800 border-orange-200',
    row: 'border-orange-200 bg-orange-50 hover:bg-orange-100',
  },
  MEDIUM: {
    badge: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    row: 'border-yellow-200 bg-yellow-50 hover:bg-yellow-100',
  },
  LOW: {
    badge: 'bg-blue-100 text-blue-800 border-blue-200',
    row: 'border-blue-200 bg-blue-50 hover:bg-blue-100',
  },
}

function SeverityBadge({
  severity,
  count,
  onClick,
  active,
}: {
  severity: string
  count: number
  onClick?: () => void
  active?: boolean
}) {
  const cfg = SEVERITY_CFG[severity.toUpperCase()] ?? {
    badge: 'bg-gray-100 text-gray-800 border-gray-200',
    row: '',
  }
  const clickable = !!onClick && count > 0
  return (
    <button
      type="button"
      onClick={clickable ? onClick : undefined}
      disabled={!clickable}
      className={[
        'flex flex-col items-center rounded-lg border px-3 py-2 w-full transition-all select-none',
        cfg.badge,
        clickable ? 'cursor-pointer hover:opacity-80 active:scale-95' : 'cursor-default',
        active ? 'ring-2 ring-inset ring-current shadow-md' : '',
      ].join(' ')}
    >
      <span className="text-xl font-bold">{count}</span>
      <span className="text-[10px] font-medium uppercase tracking-wide opacity-80">{severity}</span>
    </button>
  )
}

// ---------------------------------------------------------------------------
// Bug accordion item
// ---------------------------------------------------------------------------

function BugItem({ bug, defaultExpanded }: { bug: ParsedBug; defaultExpanded: boolean }) {
  const [open, setOpen] = useState(defaultExpanded)
  const cfg = SEVERITY_CFG[bug.severity] ?? SEVERITY_CFG.LOW

  return (
    <div className="rounded-lg border overflow-hidden mb-2">
      <button
        onClick={() => setOpen((v) => !v)}
        className={`w-full flex items-center gap-2 px-3 py-2.5 text-left cursor-pointer ${cfg.row}`}
      >
        {open ? (
          <ChevronDown className="h-3.5 w-3.5 flex-shrink-0 text-gray-500" />
        ) : (
          <ChevronRight className="h-3.5 w-3.5 flex-shrink-0 text-gray-500" />
        )}
        <span
          className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase border flex-shrink-0 ${cfg.badge}`}
        >
          {bug.severity}
        </span>
        <span className="text-xs font-medium text-gray-800 flex-1 truncate">{bug.title}</span>
        {bug.category && (
          <span className="text-[10px] text-gray-400 flex-shrink-0 font-mono">
            [{bug.category}]
          </span>
        )}
      </button>

      {open && (
        <div className="bg-white border-t border-gray-100 px-4 py-3 space-y-2 text-xs">
          {bug.url && (
            <div className="flex gap-2 items-start">
              <span className="w-16 flex-shrink-0 font-semibold text-gray-500 pt-0.5">URL</span>
              <a
                href={bug.url}
                target="_blank"
                rel="noreferrer"
                className="text-blue-600 hover:underline flex items-center gap-1 break-all"
              >
                {bug.url} <ExternalLink className="h-3 w-3 flex-shrink-0" />
              </a>
            </div>
          )}
          {bug.steps && (
            <div className="flex gap-2 items-start">
              <span className="w-16 flex-shrink-0 font-semibold text-gray-500 pt-0.5">Steps</span>
              <pre className="whitespace-pre-wrap font-sans text-gray-700 text-xs leading-relaxed">
                {bug.steps}
              </pre>
            </div>
          )}
          {bug.expected && (
            <div className="flex gap-2 items-start">
              <span className="w-16 flex-shrink-0 font-semibold text-gray-500 pt-0.5">
                Expected
              </span>
              <pre className="whitespace-pre-wrap font-sans text-green-700 text-xs leading-relaxed">
                {bug.expected}
              </pre>
            </div>
          )}
          {bug.actual && (
            <div className="flex gap-2 items-start">
              <span className="w-16 flex-shrink-0 font-semibold text-gray-500 pt-0.5">Actual</span>
              <pre className="whitespace-pre-wrap font-sans text-red-700 text-xs leading-relaxed">
                {bug.actual}
              </pre>
            </div>
          )}
          {bug.evidence && (
            <div className="flex gap-2 items-start">
              <span className="w-16 flex-shrink-0 font-semibold text-gray-500 pt-0.5">
                Evidence
              </span>
              <pre className="whitespace-pre-wrap font-sans italic text-gray-600 text-xs leading-relaxed">
                {bug.evidence}
              </pre>
            </div>
          )}
          {/* Fallback: show raw block when agent didn't use structured format */}
          {!bug.url && !bug.steps && !bug.expected && !bug.actual && !bug.evidence && bug._raw && (
            <details className="text-gray-500">
              <summary className="cursor-pointer text-purple-600 hover:underline select-none">
                View raw report text
              </summary>
              <pre className="mt-2 whitespace-pre-wrap font-mono text-[11px] text-gray-600 bg-gray-50 rounded p-2 leading-relaxed">
                {bug._raw}
              </pre>
            </details>
          )}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Screenshot slideshow player
// ---------------------------------------------------------------------------

function ScreenshotPlayer({ urls }: { urls: string[] }) {
  const [idx, setIdx] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [imgError, setImgError] = useState(false)
  const apiToken = useAuthStore((s) => s.apiToken)

  // Rewrite internal K8s URLs to public API base and append ?token= for <img> auth
  const authedUrls = useMemo(() => {
    return urls.map((u) => {
      let url = u
      // Replace internal K8s service URL with public API base URL
      const internalPattern = /^https?:\/\/argus-api-service[^/]*/
      if (internalPattern.test(url)) {
        url = url.replace(internalPattern, API_BASE_URL.replace(/\/$/, ''))
      }
      // Append auth token for API-proxied screenshot URLs
      if (apiToken && url.includes('/api/v1/web-ui-tasks/') && !url.includes('token=')) {
        const sep = url.includes('?') ? '&' : '?'
        url = `${url}${sep}token=${apiToken}`
      }
      return url
    })
  }, [urls, apiToken])

  useEffect(() => {
    if (!playing) return
    const id = setInterval(() => {
      setIdx((i) => {
        if (i >= authedUrls.length - 1) {
          setPlaying(false)
          return i
        }
        return i + 1
      })
    }, 1500)
    return () => clearInterval(id)
  }, [playing, authedUrls.length])

  // Reset error when index changes
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setImgError(false)
  }, [idx])

  if (authedUrls.length === 0)
    return (
      <div className="rounded-lg border border-gray-200 bg-gray-50 p-5 text-xs text-gray-500 space-y-2">
        <p className="font-medium text-gray-600">No recording available</p>
        <p>Screenshots were not captured during this run. Possible causes:</p>
        <ul className="list-disc list-inside space-y-1 text-gray-400">
          <li>
            Chrome was not started with{' '}
            <code className="rounded bg-gray-100 px-1 font-mono">--remote-debugging-port=9222</code>
          </li>
          <li>CDP screenshot timed out (Chrome minimized / SwiftShader rendering)</li>
          <li>The client agent version predates screenshot capture support</li>
        </ul>
        <p className="text-gray-400">
          Re-run the test with Chrome visible and the recommended startup flags to get a recording.
        </p>
      </div>
    )

  return (
    <div className="rounded-lg border border-gray-200 overflow-hidden">
      {/* header */}
      <div className="bg-gray-800 px-3 py-2 flex items-center justify-between">
        <span className="text-xs text-gray-300">🎬 Step-by-Step Recording</span>
        <span className="text-xs text-gray-400 font-mono">
          {idx + 1} / {authedUrls.length}
        </span>
      </div>

      {/* screenshot */}
      <div className="bg-black flex items-center justify-center min-h-32">
        {imgError ? (
          <div className="text-center py-6 px-4 space-y-1">
            <p className="text-xs text-gray-400">Screenshot could not be loaded</p>
            <p className="text-[11px] text-gray-500 font-mono break-all">{urls[idx]}</p>
            <p className="text-[11px] text-gray-500">
              Check that the API service is reachable and screenshots were uploaded to R2.
            </p>
          </div>
        ) : (
          <img
            src={authedUrls[idx]}
            alt={`Step ${idx + 1}`}
            className="w-full object-contain max-h-72"
            onError={() => setImgError(true)}
          />
        )}
      </div>

      {/* controls */}
      <div className="bg-gray-100 px-3 py-2 flex items-center gap-2">
        <button
          onClick={() => {
            setIdx(0)
            setPlaying(false)
          }}
          className="p-1 rounded hover:bg-gray-200 text-gray-600"
          title="Back to start"
        >
          <SkipBack className="h-3.5 w-3.5" />
        </button>
        <button
          onClick={() => setIdx((i) => Math.max(i - 1, 0))}
          className="p-1 rounded hover:bg-gray-200 text-gray-600"
        >
          <ChevronRight className="h-3.5 w-3.5 rotate-180" />
        </button>
        <button
          onClick={() => setPlaying((v) => !v)}
          className="p-1.5 rounded bg-purple-600 hover:bg-purple-700 text-white"
        >
          {playing ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
        </button>
        <button
          onClick={() => setIdx((i) => Math.min(i + 1, authedUrls.length - 1))}
          className="p-1 rounded hover:bg-gray-200 text-gray-600"
        >
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
        <input
          type="range"
          min={0}
          max={authedUrls.length - 1}
          value={idx}
          onChange={(e) => {
            setIdx(Number(e.target.value))
            setPlaying(false)
          }}
          className="flex-1 mx-1 accent-purple-600 h-1"
        />
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Summary section — structured rendering of all report sections
// ---------------------------------------------------------------------------

const RISK_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 border-red-200',
  HIGH: 'bg-orange-100 text-orange-800 border-orange-200',
  MEDIUM: 'bg-yellow-100 text-yellow-800 border-yellow-200',
  LOW: 'bg-blue-100 text-blue-800 border-blue-200',
  MINIMAL: 'bg-green-100 text-green-800 border-green-200',
}

function KeyValueRow({ label, value }: { label: string; value?: string }) {
  if (!value) return null
  return (
    <div className="flex gap-3 py-1.5 border-b border-gray-50 last:border-0">
      <span className="w-28 flex-shrink-0 text-[11px] font-semibold text-gray-400 uppercase tracking-wider pt-0.5">
        {label}
      </span>
      <span className="text-xs text-gray-700 leading-relaxed">{value}</span>
    </div>
  )
}

function SectionCard({
  title,
  icon,
  children,
}: {
  title: string
  icon: string
  children: React.ReactNode
}) {
  return (
    <div className="rounded-lg border border-gray-200 overflow-hidden">
      <div className="bg-gray-50 px-3 py-2 flex items-center gap-2 border-b border-gray-200">
        <span className="text-sm">{icon}</span>
        <span className="text-xs font-semibold text-gray-700">{title}</span>
      </div>
      <div className="px-3 py-2">{children}</div>
    </div>
  )
}

function CoverageBar({ label, value }: { label: string; value?: string }) {
  if (!value) return null
  // Try to parse "N / M" format for a progress bar
  const m = value.match(/^(\d+)\s*\/\s*(\d+)/)
  const current = m ? parseInt(m[1]) : null
  const total = m ? parseInt(m[2]) : null
  const pct = current !== null && total ? Math.round((current / total) * 100) : null

  return (
    <div className="flex items-center gap-2 py-1">
      <span className="w-28 flex-shrink-0 text-[11px] text-gray-500">{label}</span>
      {pct !== null ? (
        <>
          <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${pct >= 80 ? 'bg-green-500' : pct >= 50 ? 'bg-yellow-500' : 'bg-red-500'}`}
              style={{ width: `${pct}%` }}
            />
          </div>
          <span className="text-[11px] font-mono text-gray-500 w-16 text-right">{value}</span>
        </>
      ) : (
        <span className="text-xs text-gray-700">{value}</span>
      )}
    </div>
  )
}

const CHECKLIST_CATEGORY: Record<string, string> = {
  VAL: 'Validation',
  FUNC: 'Functional',
  SEC: 'Security',
  UX: 'UX',
  JS: 'JS Errors',
  REDIRECT: 'Redirects',
}

function ChecklistSection({ items }: { items: ChecklistItem[] }) {
  if (items.length === 0) return null
  const done = items.filter((i) => i.status === 'DONE').length
  const total = items.length

  // Group by category prefix
  const grouped: Record<string, ChecklistItem[]> = {}
  for (const item of items) {
    const prefix = item.id.replace(/-.*$/, '')
    const cat = CHECKLIST_CATEGORY[prefix] ?? prefix
    ;(grouped[cat] ??= []).push(item)
  }

  return (
    <SectionCard title={`Phase 3 Checklist (${done}/${total})`} icon="✅">
      <div className="space-y-3">
        {Object.entries(grouped).map(([cat, catItems]) => (
          <div key={cat}>
            <div className="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-1">
              {cat}
            </div>
            <div className="space-y-0.5">
              {catItems.map((item) => (
                <div key={item.id} className="flex items-start gap-2 py-0.5">
                  <span
                    className={`mt-0.5 flex-shrink-0 text-xs ${item.status === 'DONE' ? 'text-green-500' : 'text-gray-300'}`}
                  >
                    {item.status === 'DONE' ? '●' : '○'}
                  </span>
                  <span className="text-[11px] font-mono text-gray-400 w-16 flex-shrink-0">
                    {item.id}
                  </span>
                  <span className="text-xs text-gray-600 flex-1">{item.detail}</span>
                  {item.status === 'SKIP' && item.skipReason && (
                    <span className="text-[10px] text-orange-500 flex-shrink-0">
                      skip: {item.skipReason}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </SectionCard>
  )
}

const FEATURE_STATUS_STYLE: Record<string, string> = {
  PASS: 'bg-green-100 text-green-700',
  FAIL: 'bg-red-100 text-red-700',
  PARTIAL: 'bg-yellow-100 text-yellow-700',
  GATED: 'bg-gray-100 text-gray-600',
}

function FeatureResultsSection({ features }: { features: FeatureResult[] }) {
  if (features.length === 0) return null
  return (
    <SectionCard title="Feature Test Results" icon="🧪">
      <div className="space-y-1.5">
        {features.map((f) => (
          <div
            key={f.id}
            className="flex items-start gap-2 py-1 border-b border-gray-50 last:border-0"
          >
            <span
              className={`flex-shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold uppercase ${FEATURE_STATUS_STYLE[f.status] ?? 'bg-gray-100 text-gray-600'}`}
            >
              {f.status}
            </span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="text-[10px] font-mono text-gray-400">{f.id}</span>
                <span className="text-xs font-medium text-gray-800">{f.name}</span>
              </div>
              <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed">{f.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </SectionCard>
  )
}

function SummarySection({ report }: { report: ParsedReport }) {
  const {
    executive,
    coverage,
    business,
    checklist,
    features,
    observations,
    redirects,
    rawSummary,
  } = report
  const hasStructuredData =
    executive.riskLevel ||
    Object.values(coverage).some(Boolean) ||
    Object.values(business).some(Boolean) ||
    checklist.length > 0 ||
    features.length > 0

  if (!hasStructuredData && !rawSummary) {
    return (
      <div className="text-xs text-gray-400 italic py-2">
        No business summary was captured in this report.
      </div>
    )
  }

  // Fallback: if we couldn't parse structured sections, render raw as markdown
  if (!hasStructuredData) {
    return (
      <div className="prose prose-sm max-w-none text-sm">
        <ReactMarkdown remarkPlugins={[remarkGfm]}>{rawSummary}</ReactMarkdown>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {/* Executive Summary — the most important info at a glance */}
      {executive.riskLevel && (
        <div
          className={`rounded-lg border px-4 py-3 ${RISK_COLORS[executive.riskLevel.toUpperCase()] ?? 'bg-gray-50 text-gray-700 border-gray-200'}`}
        >
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-bold uppercase tracking-wide">
              Risk: {executive.riskLevel}
            </span>
            {executive.confidence && (
              <span className="text-[10px] opacity-70">· Confidence: {executive.confidence}</span>
            )}
          </div>
          {executive.verdict && (
            <p className="text-sm font-medium leading-relaxed">{executive.verdict}</p>
          )}
          {executive.keyRisk && (
            <p className="text-xs mt-1 opacity-80">Key risk: {executive.keyRisk}</p>
          )}
        </div>
      )}

      {/* Coverage Stats */}
      {Object.values(coverage).some(Boolean) && (
        <SectionCard title="Coverage" icon="📊">
          <CoverageBar label="Pages" value={coverage.pagesVisited} />
          <CoverageBar label="Features" value={coverage.featuresTested} />
          <CoverageBar label="Checks" value={coverage.checksCompleted} />
          <CoverageBar label="Forms" value={coverage.formsTested} />
          <CoverageBar label="Inputs fuzzed" value={coverage.inputsFuzzed} />
          <CoverageBar label="Security" value={coverage.securityChecks} />
        </SectionCard>
      )}

      {/* Business Summary */}
      {Object.values(business).some(Boolean) && (
        <SectionCard title="Business Summary" icon="📋">
          <KeyValueRow label="App Type" value={business.appType} />
          <KeyValueRow label="Core Journey" value={business.coreJourney} />
          <KeyValueRow label="Features" value={business.featuresTested} />
          <KeyValueRow label="Pages" value={business.pagesVisited} />
          <KeyValueRow label="Auth State" value={business.authState} />
        </SectionCard>
      )}

      {/* Feature Test Results */}
      <FeatureResultsSection features={features} />

      {/* Phase 3 Checklist */}
      <ChecklistSection items={checklist} />

      {/* Observations */}
      {observations.length > 0 && (
        <SectionCard title={`Observations (${observations.length})`} icon="💡">
          <ul className="space-y-1">
            {observations.map((obs, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-gray-600 py-0.5">
                <span className="text-gray-300 flex-shrink-0 mt-0.5">·</span>
                <span className="leading-relaxed">{obs}</span>
              </li>
            ))}
          </ul>
        </SectionCard>
      )}

      {/* Redirects */}
      {redirects.length > 0 && (
        <SectionCard title={`Redirect Checks (${redirects.length})`} icon="🔀">
          <div className="space-y-0.5">
            {redirects.map((r, i) => {
              const isPass = /PASS/i.test(r)
              const isFail = /FAIL/i.test(r)
              return (
                <div key={i} className="flex items-center gap-2 text-xs py-0.5">
                  <span
                    className={`flex-shrink-0 ${isPass ? 'text-green-500' : isFail ? 'text-red-500' : 'text-gray-400'}`}
                  >
                    {isPass ? '✓' : isFail ? '✗' : '·'}
                  </span>
                  <span className="text-gray-600">{r}</span>
                </div>
              )
            })}
          </div>
        </SectionCard>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main BugReportBody
// ---------------------------------------------------------------------------

export function BugReportBody({
  bugCounts,
  stepsDone,
  url,
  taskId,
  testsUrl,
  bugReportUrl,
  finalOutput,
  screenshotUrls,
  onRerun,
}: BugReportBodyProps) {
  const total =
    (bugCounts.critical ?? 0) +
    (bugCounts.high ?? 0) +
    (bugCounts.medium ?? 0) +
    (bugCounts.low ?? 0)
  const [expanded, setExpanded] = useState(false)
  const [activeTab, setActiveTab] = useState<'bugs' | 'summary' | 'recording'>('bugs')
  const [severityFilter, setSeverityFilter] = useState<string | null>(null)
  const [exporting, setExporting] = useState(false)
  const cardRef = useRef<HTMLDivElement>(null)

  const handleExportPDF = useCallback(async () => {
    setExporting(true)
    try {
      const html2canvas = (await import('html2canvas-pro')).default
      const { jsPDF } = await import('jspdf')

      // Build an off-screen container with ALL content (bugs + summary)
      // so the PDF captures everything regardless of tab/accordion state
      const offscreen = document.createElement('div')
      offscreen.style.cssText =
        'position:fixed;left:-9999px;top:0;width:800px;background:#fff;padding:24px;font-family:system-ui,sans-serif;'
      document.body.appendChild(offscreen)

      const report = parseBugReport(finalOutput || '')
      const {
        bugs: allBugs,
        executive,
        coverage,
        business,
        features,
        checklist,
        observations,
      } = report

      // --- Title ---
      offscreen.innerHTML = `
        <div style="margin-bottom:20px">
          <h1 style="font-size:20px;font-weight:700;margin:0 0 8px">Bug Report</h1>
          <div style="display:flex;gap:24px;font-size:13px;color:#666">
            ${url ? `<span>URL: ${url}</span>` : ''}
            <span>Date: ${new Date().toLocaleDateString()}</span>
            ${stepsDone ? `<span>Steps: ${stepsDone}</span>` : ''}
          </div>
        </div>
      `

      // --- Severity grid ---
      const sevColors: Record<string, string> = {
        critical: '#dc2626',
        high: '#ea580c',
        medium: '#ca8a04',
        low: '#2563eb',
      }
      offscreen.innerHTML += `
        <div style="display:flex;gap:12px;margin-bottom:20px">
          ${(['critical', 'high', 'medium', 'low'] as const)
            .map(
              (s) => `
            <div style="flex:1;text-align:center;padding:10px;border-radius:8px;border:1px solid ${sevColors[s]}30;background:${sevColors[s]}10">
              <div style="font-size:22px;font-weight:700;color:${sevColors[s]}">${bugCounts[s] ?? 0}</div>
              <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.5px;color:${sevColors[s]};opacity:0.8">${s}</div>
            </div>
          `
            )
            .join('')}
        </div>
      `

      // --- Executive summary ---
      if (executive.riskLevel) {
        const riskColors: Record<string, { bg: string; text: string }> = {
          CRITICAL: { bg: '#fef2f2', text: '#991b1b' },
          HIGH: { bg: '#fff7ed', text: '#9a3412' },
          MEDIUM: { bg: '#fefce8', text: '#854d0e' },
          LOW: { bg: '#eff6ff', text: '#1e40af' },
          MINIMAL: { bg: '#f0fdf4', text: '#166534' },
        }
        const rc = riskColors[executive.riskLevel.toUpperCase()] ?? {
          bg: '#f9fafb',
          text: '#374151',
        }
        offscreen.innerHTML += `
          <div style="padding:12px 16px;border-radius:8px;background:${rc.bg};color:${rc.text};margin-bottom:16px;border:1px solid ${rc.text}20">
            <div style="font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:4px">
              Risk Level: ${executive.riskLevel}
              ${executive.confidence ? `<span style="font-weight:400;opacity:0.7"> · Confidence: ${executive.confidence}</span>` : ''}
            </div>
            ${executive.verdict ? `<div style="font-size:14px;font-weight:500">${executive.verdict}</div>` : ''}
            ${executive.keyRisk ? `<div style="font-size:12px;margin-top:4px;opacity:0.8">Key risk: ${executive.keyRisk}</div>` : ''}
          </div>
        `
      }

      // Helper to build a section
      const section = (title: string, html: string) => `
        <div style="margin-bottom:16px;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">
          <div style="background:#f9fafb;padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:12px;font-weight:600;color:#374151">${title}</div>
          <div style="padding:10px 12px">${html}</div>
        </div>
      `
      const kvRow = (label: string, value?: string) =>
        value
          ? `<div style="display:flex;gap:12px;padding:4px 0;border-bottom:1px solid #f9fafb"><span style="width:100px;flex-shrink:0;font-size:11px;font-weight:600;color:#9ca3af;text-transform:uppercase">${label}</span><span style="font-size:12px;color:#374151">${value}</span></div>`
          : ''

      // --- Coverage ---
      if (Object.values(coverage).some(Boolean)) {
        const bars = [
          ['Pages', coverage.pagesVisited],
          ['Features', coverage.featuresTested],
          ['Checks', coverage.checksCompleted],
          ['Forms', coverage.formsTested],
          ['Inputs fuzzed', coverage.inputsFuzzed],
          ['Security', coverage.securityChecks],
        ]
          .filter(([, v]) => v)
          .map(([label, value]) => {
            const m = (value as string).match(/^(\d+)\s*\/\s*(\d+)/)
            const pct = m ? Math.round((parseInt(m[1]) / parseInt(m[2])) * 100) : null
            const color =
              pct !== null ? (pct >= 80 ? '#22c55e' : pct >= 50 ? '#eab308' : '#ef4444') : '#9ca3af'
            return `<div style="display:flex;align-items:center;gap:8px;padding:3px 0">
            <span style="width:100px;flex-shrink:0;font-size:11px;color:#6b7280">${label}</span>
            ${
              pct !== null
                ? `
              <div style="flex:1;height:6px;background:#f3f4f6;border-radius:3px;overflow:hidden">
                <div style="height:100%;width:${pct}%;background:${color};border-radius:3px"></div>
              </div>
              <span style="font-size:11px;font-family:monospace;color:#6b7280;width:50px;text-align:right">${value}</span>
            `
                : `<span style="font-size:12px;color:#374151">${value}</span>`
            }
          </div>`
          })
          .join('')
        offscreen.innerHTML += section('📊 Coverage', bars)
      }

      // --- Business Summary ---
      if (Object.values(business).some(Boolean)) {
        offscreen.innerHTML += section(
          '📋 Business Summary',
          kvRow('App Type', business.appType) +
            kvRow('Core Journey', business.coreJourney) +
            kvRow('Features', business.featuresTested) +
            kvRow('Pages', business.pagesVisited) +
            kvRow('Auth State', business.authState)
        )
      }

      // --- Feature Results ---
      if (features.length > 0) {
        const statusColors: Record<string, { bg: string; text: string }> = {
          PASS: { bg: '#dcfce7', text: '#15803d' },
          FAIL: { bg: '#fef2f2', text: '#b91c1c' },
          PARTIAL: { bg: '#fefce8', text: '#a16207' },
          GATED: { bg: '#f3f4f6', text: '#4b5563' },
        }
        const rows = features
          .map((f) => {
            const sc = statusColors[f.status] ?? { bg: '#f3f4f6', text: '#4b5563' }
            return `<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid #f9fafb">
            <span style="flex-shrink:0;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;background:${sc.bg};color:${sc.text}">${f.status}</span>
            <div>
              <div style="font-size:12px"><span style="font-family:monospace;color:#9ca3af;margin-right:6px">${f.id}</span><span style="font-weight:500;color:#1f2937">${f.name}</span></div>
              <div style="font-size:11px;color:#6b7280;margin-top:2px">${f.detail}</div>
            </div>
          </div>`
          })
          .join('')
        offscreen.innerHTML += section('🧪 Feature Test Results', rows)
      }

      // --- Phase 3 Checklist ---
      if (checklist.length > 0) {
        const done = checklist.filter((c) => c.status === 'DONE').length
        const rows = checklist
          .map(
            (c) =>
              `<div style="display:flex;align-items:flex-start;gap:6px;padding:2px 0">
            <span style="flex-shrink:0;color:${c.status === 'DONE' ? '#22c55e' : '#d1d5db'};font-size:12px">${c.status === 'DONE' ? '●' : '○'}</span>
            <span style="width:55px;flex-shrink:0;font-size:11px;font-family:monospace;color:#9ca3af">${c.id}</span>
            <span style="font-size:12px;color:#4b5563;flex:1">${c.detail}</span>
            ${c.status === 'SKIP' && c.skipReason ? `<span style="font-size:10px;color:#f97316;flex-shrink:0">skip: ${c.skipReason}</span>` : ''}
          </div>`
          )
          .join('')
        offscreen.innerHTML += section(`✅ Phase 3 Checklist (${done}/${checklist.length})`, rows)
      }

      // --- Observations ---
      if (observations.length > 0) {
        const rows = observations
          .map(
            (o) =>
              `<div style="display:flex;gap:8px;padding:3px 0;font-size:12px;color:#4b5563"><span style="color:#d1d5db;flex-shrink:0">·</span><span>${o}</span></div>`
          )
          .join('')
        offscreen.innerHTML += section(`💡 Observations (${observations.length})`, rows)
      }

      // --- All Bugs (expanded) ---
      if (allBugs.length > 0) {
        const sevRowColors: Record<
          string,
          { bg: string; border: string; badge: string; text: string }
        > = {
          CRITICAL: { bg: '#fef2f2', border: '#fecaca', badge: '#dc2626', text: '#991b1b' },
          HIGH: { bg: '#fff7ed', border: '#fed7aa', badge: '#ea580c', text: '#9a3412' },
          MEDIUM: { bg: '#fefce8', border: '#fde68a', badge: '#ca8a04', text: '#854d0e' },
          LOW: { bg: '#eff6ff', border: '#bfdbfe', badge: '#2563eb', text: '#1e40af' },
        }
        const bugRows = allBugs
          .map((bug) => {
            const sc = sevRowColors[bug.severity] ?? sevRowColors.LOW
            const fieldRow = (label: string, value?: string, color?: string) =>
              value
                ? `<div style="display:flex;gap:8px;padding:4px 0"><span style="width:60px;flex-shrink:0;font-size:11px;font-weight:600;color:#9ca3af">${label}</span><pre style="margin:0;white-space:pre-wrap;font-family:inherit;font-size:12px;color:${color || '#374151'};line-height:1.5">${value}</pre></div>`
                : ''
            return `<div style="border:1px solid ${sc.border};border-radius:8px;overflow:hidden;margin-bottom:8px">
            <div style="background:${sc.bg};padding:8px 12px;display:flex;align-items:center;gap:8px">
              <span style="padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;border:1px solid ${sc.border};background:${sc.bg};color:${sc.text}">${bug.severity}</span>
              <span style="font-size:12px;font-weight:500;color:#1f2937;flex:1">${bug.title}</span>
              ${bug.category ? `<span style="font-size:10px;color:#9ca3af;font-family:monospace">[${bug.category}]</span>` : ''}
            </div>
            <div style="padding:10px 12px;background:#fff">
              ${fieldRow('URL', bug.url, '#2563eb')}
              ${fieldRow('Steps', bug.steps)}
              ${fieldRow('Expected', bug.expected, '#15803d')}
              ${fieldRow('Actual', bug.actual, '#dc2626')}
              ${fieldRow('Evidence', bug.evidence, '#6b7280')}
              ${!bug.url && !bug.steps && !bug.expected && !bug.actual && !bug.evidence && bug._raw ? `<pre style="margin:0;white-space:pre-wrap;font-size:11px;color:#6b7280;background:#f9fafb;padding:8px;border-radius:4px;line-height:1.5">${bug._raw}</pre>` : ''}
            </div>
          </div>`
          })
          .join('')
        offscreen.innerHTML += section(`🐛 Bugs (${allBugs.length})`, bugRows)
      }

      const canvas = await html2canvas(offscreen, {
        scale: 2,
        useCORS: true,
        backgroundColor: '#ffffff',
        logging: false,
      })
      document.body.removeChild(offscreen)

      const imgData = canvas.toDataURL('image/png')
      const imgW = canvas.width
      const imgH = canvas.height

      const pdfW = 210
      const margin = 10
      const contentW = pdfW - margin * 2
      const contentH = (imgH * contentW) / imgW

      const pdf = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4',
      })

      const pageH = pdf.internal.pageSize.getHeight() - margin * 2

      if (contentH <= pageH) {
        pdf.addImage(imgData, 'PNG', margin, margin, contentW, contentH)
      } else {
        // Multi-page: slice the image by cropping the source canvas per page
        const pxPerPage = (pageH / contentH) * imgH
        let srcY = 0
        let page = 0
        while (srcY < imgH) {
          if (page > 0) pdf.addPage()
          const sliceH = Math.min(pxPerPage, imgH - srcY)
          const sliceCanvas = document.createElement('canvas')
          sliceCanvas.width = imgW
          sliceCanvas.height = sliceH
          const ctx = sliceCanvas.getContext('2d')!
          ctx.drawImage(canvas, 0, srcY, imgW, sliceH, 0, 0, imgW, sliceH)
          const sliceData = sliceCanvas.toDataURL('image/png')
          const sliceContentH = (sliceH * contentW) / imgW
          pdf.addImage(sliceData, 'PNG', margin, margin, contentW, sliceContentH)
          srcY += pxPerPage
          page++
        }
      }

      const timestamp = new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-')
      pdf.save(`bug-report-${timestamp}.pdf`)
    } catch (err) {
      console.error('PDF export failed:', err)
    } finally {
      setExporting(false)
    }
  }, [finalOutput, bugCounts, url, stepsDone])

  const handleSeverityClick = (severity: string) => {
    setExpanded(true)
    setActiveTab('bugs')
    setSeverityFilter((prev) => (prev === severity ? null : severity))
  }

  const report = parseBugReport(finalOutput || '')
  const { bugs } = report
  const hasScreenshots = (screenshotUrls?.length ?? 0) > 0

  const tabs: { id: 'bugs' | 'summary' | 'recording'; label: string }[] = [
    { id: 'bugs', label: `Bugs (${bugs.length || total})` },
    { id: 'summary', label: 'Summary' },
    { id: 'recording', label: `Recording${hasScreenshots ? ` (${screenshotUrls!.length})` : ''}` },
  ]

  return (
    <div
      ref={cardRef}
      className="my-3 rounded-xl border border-purple-100 bg-gradient-to-br from-purple-50 to-indigo-50 shadow-sm overflow-hidden"
    >
      {/* ── Summary header (always visible) ── */}
      <div className="p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className="text-base">🔍</span>
            <span className="font-semibold text-gray-900 text-sm">Bug Report</span>
            {total > 0 ? (
              <span className="rounded-full bg-red-100 px-2 py-0.5 text-xs font-medium text-red-700">
                {total} issue{total !== 1 ? 's' : ''}
              </span>
            ) : (
              <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
                No issues found ✓
              </span>
            )}
          </div>
          <div className="flex items-center gap-3">
            {stepsDone !== undefined && stepsDone > 0 && (
              <span className="text-xs text-gray-400">{stepsDone} steps</span>
            )}
            <button
              onClick={handleExportPDF}
              disabled={exporting}
              className="inline-flex items-center gap-1 rounded-md bg-white border border-gray-200 px-2.5 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 shadow-sm transition-colors disabled:opacity-50"
            >
              <Download className="h-3 w-3" />
              {exporting ? 'Exporting...' : 'PDF'}
            </button>
            <button
              onClick={() => setExpanded((v) => !v)}
              className="inline-flex items-center gap-1 rounded-md bg-white border border-purple-200 px-2.5 py-1 text-xs font-medium text-purple-700 hover:bg-purple-50 shadow-sm transition-colors"
            >
              {expanded ? (
                <>
                  <ChevronDown className="h-3 w-3" /> Collapse
                </>
              ) : (
                <>
                  <ChevronRight className="h-3 w-3" /> View Details
                </>
              )}
            </button>
          </div>
        </div>

        {/* Severity count grid — click to filter */}
        <div className="grid grid-cols-4 gap-2 mb-3">
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
            <SeverityBadge
              key={sev}
              severity={sev}
              count={bugCounts[sev] ?? 0}
              onClick={() => handleSeverityClick(sev.toUpperCase())}
              active={severityFilter === sev.toUpperCase()}
            />
          ))}
        </div>

        {/* Footer links */}
        {(testsUrl || bugReportUrl || (url && onRerun)) && (
          <div className="flex flex-wrap gap-2 pt-2 border-t border-purple-100">
            {testsUrl && (
              <a
                href={testsUrl}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 rounded-md bg-white border border-gray-200 px-2.5 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 shadow-sm"
              >
                ⬇️ Tests
              </a>
            )}
            {bugReportUrl && (
              <a
                href={bugReportUrl}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 rounded-md bg-white border border-gray-200 px-2.5 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 shadow-sm"
              >
                📋 Bug Report
              </a>
            )}
            {url && onRerun && (
              <button
                onClick={() => onRerun(url)}
                className="inline-flex items-center gap-1 rounded-md bg-purple-600 px-2.5 py-1 text-xs font-medium text-white hover:bg-purple-700 shadow-sm"
              >
                🔄 Re-run
              </button>
            )}
          </div>
        )}
      </div>

      {/* ── Expandable detail panel ── */}
      {expanded && (
        <div className="border-t border-purple-100 bg-white">
          {/* Tab bar */}
          <div className="flex border-b border-gray-200 bg-gray-50">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2.5 text-xs font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? 'border-purple-600 text-purple-700 bg-white'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:bg-gray-100'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="pdf-scroll-panel p-4 max-h-[480px] overflow-y-auto">
            {/* ── Bugs tab ── */}
            {activeTab === 'bugs' &&
              (() => {
                const filteredBugs = severityFilter
                  ? bugs.filter((b) => b.severity === severityFilter)
                  : bugs
                return (
                  <>
                    {severityFilter && (
                      <div className="flex items-center gap-2 mb-3">
                        <span className="text-xs text-gray-500">Filtering:</span>
                        <span
                          className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-bold uppercase border ${SEVERITY_CFG[severityFilter]?.badge}`}
                        >
                          {severityFilter}
                        </span>
                        <button
                          onClick={() => setSeverityFilter(null)}
                          className="text-xs text-gray-400 hover:text-gray-600 underline"
                        >
                          clear
                        </button>
                      </div>
                    )}
                    {bugs.length === 0 ? (
                      <div className="text-center py-6">
                        {total > 0 ? (
                          <div className="text-xs text-gray-500">
                            <p className="mb-1">
                              Bug counts detected but detailed breakdown not available.
                            </p>
                            <p className="text-gray-400">
                              The agent may not have used the structured report format.
                            </p>
                            {finalOutput && (
                              <details className="mt-3 text-left">
                                <summary className="cursor-pointer text-purple-600 hover:underline">
                                  View raw report
                                </summary>
                                <pre className="mt-2 whitespace-pre-wrap text-gray-600 bg-gray-50 rounded p-3 max-h-48 overflow-y-auto text-[11px] leading-relaxed">
                                  {finalOutput}
                                </pre>
                              </details>
                            )}
                          </div>
                        ) : (
                          <div className="text-green-600 text-sm">
                            <span className="text-2xl block mb-2">✓</span>
                            No bugs found during this exploration.
                          </div>
                        )}
                      </div>
                    ) : filteredBugs.length === 0 ? (
                      <div className="text-center py-6 text-xs text-gray-400">
                        No {severityFilter?.toLowerCase()} severity bugs found.
                      </div>
                    ) : (
                      <div>
                        {filteredBugs.map((bug, i) => (
                          <BugItem
                            key={i}
                            bug={bug}
                            defaultExpanded={bug.severity === 'CRITICAL' || bug.severity === 'HIGH'}
                          />
                        ))}
                      </div>
                    )}
                  </>
                )
              })()}

            {/* ── Summary tab ── */}
            {activeTab === 'summary' && <SummarySection report={report} />}

            {/* ── Recording tab ── */}
            {activeTab === 'recording' && <ScreenshotPlayer urls={screenshotUrls ?? []} />}
          </div>
        </div>
      )}
    </div>
  )
}
