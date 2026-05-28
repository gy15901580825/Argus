'use client'

import { useMemo, useState } from 'react'
import {
  ChevronDown,
  ChevronRight,
  Download,
  CheckCircle2,
  XCircle,
  MinusCircle,
  AlertCircle,
} from 'lucide-react'
import type { StreamChunk } from '@/lib/chat-types'
import { MessageShell } from './MessageShell'
import type { SeverityTint } from './tokens'

// ---------------------------------------------------------------------------
// Pytest output parser for API test results (inlined from legacy StreamingMessage.tsx)
// ---------------------------------------------------------------------------
type TestStatus = 'PASSED' | 'FAILED' | 'SKIPPED' | 'ERROR'
interface ParsedTest {
  name: string
  status: TestStatus
  detail?: string
}
interface ParsedTestSummary {
  passed: number
  failed: number
  skipped: number
  errors: number
  total: number
  duration?: string
}

function parsePytestOutput(stdout: string): { summary: ParsedTestSummary; tests: ParsedTest[] } {
  const tests: ParsedTest[] = []
  const testRegex = /^(\S+?::\S+?)\s+(PASSED|FAILED|SKIPPED|ERROR|XFAIL|XPASS)\b/gm
  let m: RegExpExecArray | null
  while ((m = testRegex.exec(stdout)) !== null) {
    const raw = m[2]
    const status: TestStatus =
      raw === 'PASSED' || raw === 'XPASS'
        ? 'PASSED'
        : raw === 'SKIPPED' || raw === 'XFAIL'
          ? 'SKIPPED'
          : raw === 'ERROR'
            ? 'ERROR'
            : 'FAILED'
    tests.push({ name: m[1], status })
  }

  // Collect short-summary failure/error details (after "short test summary info")
  const shortSummaryIdx = stdout.indexOf('short test summary info')
  if (shortSummaryIdx >= 0) {
    const tail = stdout.slice(shortSummaryIdx)
    const detailRegex = /^(FAILED|ERROR|SKIPPED)\s+(\S+?::\S+?)(?:\s+-\s+(.*))?$/gm
    let d: RegExpExecArray | null
    while ((d = detailRegex.exec(tail)) !== null) {
      const name = d[2]
      const detail = d[3]
      const existing = tests.find((t) => t.name === name)
      if (existing && detail) existing.detail = detail
    }
  }

  const summary: ParsedTestSummary = { passed: 0, failed: 0, skipped: 0, errors: 0, total: 0 }
  // Summary line: "===== 3 passed, 1 failed in 2.45s ====="
  const summaryMatch = stdout.match(/=+\s+([^=]+?)\s+in\s+([\d.]+s)\s+=+/)
  if (summaryMatch) {
    const s = summaryMatch[1]
    summary.duration = summaryMatch[2]
    const p = s.match(/(\d+)\s+passed/)
    if (p) summary.passed = parseInt(p[1])
    const f = s.match(/(\d+)\s+failed/)
    if (f) summary.failed = parseInt(f[1])
    const k = s.match(/(\d+)\s+skipped/)
    if (k) summary.skipped = parseInt(k[1])
    const e = s.match(/(\d+)\s+error/)
    if (e) summary.errors = parseInt(e[1])
  }
  if (
    summary.passed + summary.failed + summary.skipped + summary.errors === 0 &&
    tests.length > 0
  ) {
    for (const t of tests) {
      if (t.status === 'PASSED') summary.passed++
      else if (t.status === 'FAILED') summary.failed++
      else if (t.status === 'SKIPPED') summary.skipped++
      else if (t.status === 'ERROR') summary.errors++
    }
  }
  summary.total = summary.passed + summary.failed + summary.skipped + summary.errors
  return { summary, tests }
}

const STATUS_CFG: Record<
  TestStatus,
  { badge: string; row: string; icon: React.ComponentType<{ className?: string }> }
> = {
  PASSED: {
    badge: 'bg-green-100 text-green-800 border-green-200',
    row: 'hover:bg-green-50',
    icon: CheckCircle2,
  },
  FAILED: {
    badge: 'bg-red-100 text-red-800 border-red-200',
    row: 'hover:bg-red-50',
    icon: XCircle,
  },
  ERROR: {
    badge: 'bg-orange-100 text-orange-800 border-orange-200',
    row: 'hover:bg-orange-50',
    icon: AlertCircle,
  },
  SKIPPED: {
    badge: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    row: 'hover:bg-yellow-50',
    icon: MinusCircle,
  },
}

function StatBadge({
  label,
  count,
  color,
  active,
  onClick,
}: {
  label: string
  count: number
  color: 'blue' | 'green' | 'red' | 'yellow'
  active?: boolean
  onClick?: () => void
}) {
  const colorMap = {
    blue: 'bg-blue-50 text-blue-800 border-blue-200',
    green: 'bg-green-50 text-green-800 border-green-200',
    red: 'bg-red-50 text-red-800 border-red-200',
    yellow: 'bg-yellow-50 text-yellow-800 border-yellow-200',
  }
  const clickable = !!onClick && count > 0
  return (
    <button
      type="button"
      onClick={clickable ? onClick : undefined}
      disabled={!clickable}
      className={[
        'flex flex-col items-center rounded-lg border px-3 py-2 w-full transition-all select-none',
        colorMap[color],
        clickable ? 'cursor-pointer hover:opacity-80 active:scale-95' : 'cursor-default',
        active ? 'ring-2 ring-inset ring-current shadow-md' : '',
      ].join(' ')}
    >
      <span className="text-xl font-bold">{count}</span>
      <span className="text-[10px] font-medium uppercase tracking-wide opacity-80">{label}</span>
    </button>
  )
}

function TestRow({ test }: { test: ParsedTest }) {
  const [open, setOpen] = useState(false)
  const cfg = STATUS_CFG[test.status]
  const Icon = cfg.icon
  const canExpand = !!test.detail
  return (
    <div className="rounded border border-gray-200 overflow-hidden">
      <button
        onClick={() => canExpand && setOpen((v) => !v)}
        disabled={!canExpand}
        className={`w-full flex items-center gap-2 px-2.5 py-1.5 text-left ${cfg.row} ${canExpand ? 'cursor-pointer' : 'cursor-default'}`}
      >
        {canExpand ? (
          open ? (
            <ChevronDown className="h-3 w-3 flex-shrink-0 text-gray-400" />
          ) : (
            <ChevronRight className="h-3 w-3 flex-shrink-0 text-gray-400" />
          )
        ) : (
          <span className="h-3 w-3 flex-shrink-0" />
        )}
        <Icon
          className={`h-3.5 w-3.5 flex-shrink-0 ${
            test.status === 'PASSED'
              ? 'text-green-600'
              : test.status === 'FAILED'
                ? 'text-red-600'
                : test.status === 'ERROR'
                  ? 'text-orange-600'
                  : 'text-yellow-600'
          }`}
        />
        <span
          className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-bold uppercase border flex-shrink-0 ${cfg.badge}`}
        >
          {test.status}
        </span>
        <span className="text-xs font-mono text-gray-700 flex-1 truncate">{test.name}</span>
      </button>
      {open && test.detail && (
        <div className="bg-white border-t border-gray-100 px-3 py-2">
          <pre className="whitespace-pre-wrap text-xs font-mono text-red-700 leading-relaxed">
            {test.detail}
          </pre>
        </div>
      )}
    </div>
  )
}

// API Test execution result card (pytest-aware) — private helper for TestResultArtifact.
function SSHResultBody({ chunk }: { chunk: StreamChunk }) {
  const [showStdout, setShowStdout] = useState(false)
  const [showStderr, setShowStderr] = useState(false)
  const [filter, setFilter] = useState<TestStatus | 'ALL'>('ALL')
  const r = chunk.sshResult

  const { summary, tests } = useMemo(() => parsePytestOutput(r?.stdout || ''), [r?.stdout])

  if (!r) return null

  const visibleTests =
    filter === 'ALL'
      ? tests
      : tests.filter((t) => {
          if (filter === 'FAILED') return t.status === 'FAILED' || t.status === 'ERROR'
          return t.status === filter
        })

  const setF = (s: TestStatus | 'ALL') => setFilter((cur) => (cur === s ? 'ALL' : s))

  return (
    <div
      className={`my-2 rounded-lg border overflow-hidden ${r.success ? 'border-green-200' : 'border-red-200'}`}
    >
      {/* Header */}
      <div className={`px-4 py-3 ${r.success ? 'bg-green-50' : 'bg-red-50'}`}>
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <div
              className={`h-2.5 w-2.5 rounded-full ${r.success ? 'bg-green-500' : 'bg-red-500'}`}
            />
            <h3
              className={`text-sm font-semibold ${r.success ? 'text-green-800' : 'text-red-800'}`}
            >
              API Test Execution {r.success ? 'Succeeded' : 'Failed'}
            </h3>
          </div>
          <div className="flex items-center gap-2">
            {summary.duration && (
              <span className="text-xs text-gray-600 font-mono">⏱ {summary.duration}</span>
            )}
            <span
              className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${r.success ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700'}`}
            >
              Exit Code: {r.exit_code}
            </span>
          </div>
        </div>
      </div>

      {/* Summary badges (4-column grid) */}
      {summary.total > 0 && (
        <div className="grid grid-cols-4 gap-2 p-3 bg-white border-t border-gray-100">
          <StatBadge
            label="TOTAL"
            count={summary.total}
            color="blue"
            active={filter === 'ALL'}
            onClick={() => setFilter('ALL')}
          />
          <StatBadge
            label="PASSED"
            count={summary.passed}
            color="green"
            active={filter === 'PASSED'}
            onClick={() => setF('PASSED')}
          />
          <StatBadge
            label="FAILED"
            count={summary.failed + summary.errors}
            color="red"
            active={filter === 'FAILED'}
            onClick={() => setF('FAILED')}
          />
          <StatBadge
            label="SKIPPED"
            count={summary.skipped}
            color="yellow"
            active={filter === 'SKIPPED'}
            onClick={() => setF('SKIPPED')}
          />
        </div>
      )}

      {/* Test list */}
      {visibleTests.length > 0 && (
        <div className="border-t border-gray-100 px-3 py-2.5 bg-white">
          <div className="text-[11px] font-semibold text-gray-500 mb-1.5 uppercase tracking-wide">
            Test Results ({visibleTests.length}
            {filter !== 'ALL' ? ` of ${tests.length}` : ''})
          </div>
          <div className="space-y-1 max-h-72 overflow-y-auto">
            {visibleTests.map((t, i) => (
              <TestRow key={i} test={t} />
            ))}
          </div>
        </div>
      )}

      {/* stdout / stderr / allure */}
      <div className="border-t border-gray-100 px-3 py-2.5 bg-gray-50 space-y-2">
        {r.stdout && (
          <div>
            <button
              onClick={() => setShowStdout(!showStdout)}
              className="flex items-center gap-1 text-xs font-medium text-gray-600 hover:text-gray-800"
            >
              {showStdout ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
              Raw stdout
            </button>
            {showStdout && (
              <pre className="mt-1 max-h-64 overflow-auto rounded bg-gray-900 p-3 text-xs text-green-300 font-mono">
                {r.stdout}
              </pre>
            )}
          </div>
        )}
        {r.stderr && (
          <div>
            <button
              onClick={() => setShowStderr(!showStderr)}
              className="flex items-center gap-1 text-xs font-medium text-gray-600 hover:text-gray-800"
            >
              {showStderr ? (
                <ChevronDown className="h-3 w-3" />
              ) : (
                <ChevronRight className="h-3 w-3" />
              )}
              Raw stderr
            </button>
            {showStderr && (
              <pre className="mt-1 max-h-40 overflow-auto rounded bg-gray-900 p-3 text-xs text-red-300 font-mono">
                {r.stderr}
              </pre>
            )}
          </div>
        )}
        {r.allure_results_url && (
          <a
            href={r.allure_results_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1.5 text-xs text-blue-600 hover:text-blue-800 font-medium"
          >
            <Download className="h-3 w-3" /> Download Allure Results
          </a>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Public artifact component
// ---------------------------------------------------------------------------

interface Props {
  chunks: StreamChunk[]
}

function parsePytestCounts(stdout: string) {
  const extract = (label: string) => {
    const m = stdout.match(new RegExp(`(\\d+)\\s+${label}`, 'i'))
    return m ? parseInt(m[1], 10) : 0
  }
  const durationMatch = stdout.match(/in\s+([0-9.]+)s/i)
  if (!durationMatch) return null

  const passed = extract('passed')
  const failed = extract('failed')
  const skipped = extract('skipped')
  if (passed + failed + skipped === 0) return null

  return { passed, failed, skipped, durationS: parseFloat(durationMatch[1]) }
}

export function TestResultArtifact({ chunks }: Props) {
  const chunk = chunks[0]
  if (!chunk) return null
  const stdout = chunk.sshResult?.stdout ?? ''
  const counts = parsePytestCounts(stdout)

  let summary = 'Test run complete'
  let tint: SeverityTint = null
  if (counts) {
    const parts: string[] = [`${counts.passed} passed`]
    if (counts.failed) parts.push(`${counts.failed} failed`)
    if (counts.skipped) parts.push(`${counts.skipped} skipped`)
    summary = `${parts.join(', ')} in ${counts.durationS}s`
    tint = counts.failed > 0 ? 'critical' : 'success'
  }

  return (
    <MessageShell category="testResult" summary={summary} severityTint={tint}>
      <SSHResultBody chunk={chunk} />
    </MessageShell>
  )
}
