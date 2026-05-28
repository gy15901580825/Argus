'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/useAuthStore'
import {
  streamStrategy,
  TypedStreamChunk,
  getWebUITasks,
  getWebUITask,
  deleteWebUITask,
  cancelWebUITest,
  WebUITask,
} from '@/lib/api'
import { QuotaBadge } from '@/components/QuotaBadge'
import { PlannerTimeline, PlannerStepEntry } from '@/components/PlannerTimeline'

// ─── Types ────────────────────────────────────────────────────────────────────

interface BugCounts {
  critical: number
  high: number
  medium: number
  low: number
}

interface TestResult {
  task_id?: string
  bug_counts: BugCounts
  steps_done: number
  has_tests: boolean
  test_script?: string
}

interface LogEntry {
  type: 'log' | 'result' | 'error'
  content: string
  isThinking?: boolean
}

const PERSONA_OPTIONS = [
  { value: 'new_user', label: 'New User' },
  { value: 'experienced_user', label: 'Experienced User' },
  { value: 'admin', label: 'Admin' },
  { value: 'power_user', label: 'Power User' },
]

// ─── Severity Badge ────────────────────────────────────────────────────────────

function SeverityBadge({ severity, count }: { severity: string; count: number }) {
  const styles: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 border-red-200',
    high: 'bg-orange-100 text-orange-800 border-orange-200',
    medium: 'bg-yellow-100 text-yellow-800 border-yellow-200',
    low: 'bg-blue-100 text-blue-800 border-blue-200',
  }
  const style = styles[severity] || 'bg-gray-100 text-gray-800 border-gray-200'
  return (
    <div className={`flex flex-col items-center rounded-lg border px-4 py-3 ${style}`}>
      <span className="text-2xl font-bold">{count}</span>
      <span className="text-xs font-medium uppercase tracking-wide">{severity}</span>
    </div>
  )
}

// ─── Main Page ─────────────────────────────────────────────────────────────────

export default function WebUITestPage() {
  const router = useRouter()
  const { user, apiToken, _hasHydrated } = useAuthStore()

  // Config state
  const [targetUrl, setTargetUrl] = useState('')
  const [cdpUrl, setCdpUrl] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [businessContext, setBusinessContext] = useState('')
  const [userPersona, setUserPersona] = useState('new_user')
  const [maxSteps, setMaxSteps] = useState(100)
  const [headless, setHeadless] = useState(true)
  const [showAdvanced, setShowAdvanced] = useState(false)

  // Run state
  const [isRunning, setIsRunning] = useState(false)
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [plannerSteps, setPlannerSteps] = useState<PlannerStepEntry[]>([])
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testScript, setTestScript] = useState<string>('')
  const [error, setError] = useState('')

  // Resumable task (persisted across page refresh)
  const [resumeTaskId, setResumeTaskId] = useState<string | null>(null)
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // History
  const [history, setHistory] = useState<WebUITask[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)

  const logEndRef = useRef<HTMLDivElement>(null)
  const abortControllerRef = useRef<AbortController | null>(null)

  const handleStop = useCallback(() => {
    cancelWebUITest().catch(() => {})
    abortControllerRef.current?.abort()
    setIsRunning(false)
    localStorage.removeItem('webui_running_task')
    if (pollTimerRef.current) clearInterval(pollTimerRef.current)
  }, [])

  // Poll DB for a task that is still running (used after page refresh)
  const startPollingTask = useCallback((taskId: string) => {
    if (pollTimerRef.current) clearInterval(pollTimerRef.current)
    setIsRunning(true)
    appendLog({ type: 'log', content: `[Reconnected] Polling task ${taskId} for completion...` })

    pollTimerRef.current = setInterval(async () => {
      try {
        const task = await getWebUITask(taskId)
        appendLog({
          type: 'log',
          content: `[Poll] Status: ${task.status} | Steps: ${task.steps_done}`,
          isThinking: true,
        })

        if (task.status === 'completed') {
          clearInterval(pollTimerRef.current!)
          setIsRunning(false)
          localStorage.removeItem('webui_running_task')
          setResumeTaskId(null)
          if (task.bug_counts) {
            setTestResult({
              task_id: task.id,
              bug_counts: task.bug_counts as BugCounts,
              steps_done: task.steps_done,
              has_tests: !!task.tests_url,
            })
          }
          appendLog({
            type: 'result',
            content: `Task completed. Bugs: ${JSON.stringify(task.bug_counts)}`,
          })
        } else if (task.status === 'failed' || task.status === 'cancelled') {
          clearInterval(pollTimerRef.current!)
          setIsRunning(false)
          localStorage.removeItem('webui_running_task')
          setResumeTaskId(null)
          appendLog({ type: 'error', content: `Task ${task.status}: ${task.error_message || ''}` })
        }
      } catch (err) {
        appendLog({ type: 'error', content: `Poll error: ${err}` })
      }
    }, 5000)
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // On mount: restore running task from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('webui_running_task')
    if (!saved) return
    try {
      const { task_id, url: savedUrl } = JSON.parse(saved)
      if (task_id) {
        setResumeTaskId(task_id)
        if (savedUrl && !targetUrl) setTargetUrl(savedUrl)
      }
    } catch {}
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Cleanup poll timer on unmount
  useEffect(
    () => () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current)
    },
    []
  )

  useEffect(() => {
    if (_hasHydrated && !user) {
      router.push('/login')
    }
  }, [user, _hasHydrated, router])

  useEffect(() => {
    if (user) {
      setHistoryLoading(true)
      getWebUITasks(20)
        .then(setHistory)
        .catch(() => {})
        .finally(() => setHistoryLoading(false))
    }
  }, [user])

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const appendLog = (entry: LogEntry) => {
    setLogs((prev) => [...prev, entry])
  }

  const handleRun = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required.')
      return
    }
    setError('')
    setIsRunning(true)
    setLogs([])
    setPlannerSteps([])
    setTestResult(null)
    setTestScript('')
    const abortController = new AbortController()
    abortControllerRef.current = abortController

    // Build context for web UI testing
    const context: Record<string, any> = {
      max_steps: maxSteps,
      user_persona: userPersona,
      business_context: businessContext || undefined,
      headless: cdpUrl ? true : headless,
    }
    if (username && password) {
      context.credentials = { username, password }
    }

    try {
      await streamStrategy(
        {
          content: targetUrl,
          context,
          userId: user?.id,
          cdpUrl: cdpUrl || undefined,
          localTestEnabled: !!cdpUrl,
          signal: abortController.signal,
        },
        // onChunk — raw text (ignored, we use onTypedChunk)
        () => {},
        // onError
        (err) => {
          appendLog({ type: 'error', content: err.message })
          setError(err.message)
        },
        // onComplete
        () => {
          setIsRunning(false)
          localStorage.removeItem('webui_running_task')
        },
        // onTypedChunk
        (chunk: TypedStreamChunk) => {
          if (chunk.type === 'planner_step' && chunk.plannerStep) {
            setPlannerSteps((prev) => [...prev, chunk.plannerStep!])
            return
          }
          if (chunk.type === 'log') {
            appendLog({ type: 'log', content: chunk.content, isThinking: chunk.isThinking })

            // Try to extract nested web-UI result/artifact from log content
            try {
              const inner = JSON.parse(chunk.content)
              if (inner.type === 'result' && inner.bug_counts) {
                const tid = inner.task_id
                if (tid)
                  localStorage.setItem(
                    'webui_running_task',
                    JSON.stringify({ task_id: tid, url: targetUrl })
                  )
                setResumeTaskId(tid || null)
                setTestResult({
                  task_id: tid,
                  bug_counts: inner.bug_counts,
                  steps_done: inner.steps_done || 0,
                  has_tests: inner.has_tests || false,
                })
                localStorage.removeItem('webui_running_task')
              }
              if (inner.task_id && !testResult) {
                // task has started — persist task_id immediately
                localStorage.setItem(
                  'webui_running_task',
                  JSON.stringify({ task_id: inner.task_id, url: targetUrl })
                )
                setResumeTaskId(inner.task_id)
              }
              if (
                inner.type === 'artifact' &&
                inner.artifact_type === 'web_ui_tests' &&
                inner.content
              ) {
                setTestScript(inner.content)
              }
            } catch {
              // not JSON — normal log line
            }
          } else if (chunk.type === 'result') {
            appendLog({ type: 'result', content: chunk.content })

            // Parse result for bug counts / test script
            try {
              const inner = JSON.parse(chunk.content)
              if (inner.type === 'result' && inner.bug_counts) {
                setTestResult({
                  task_id: inner.task_id,
                  bug_counts: inner.bug_counts,
                  steps_done: inner.steps_done || 0,
                  has_tests: inner.has_tests || false,
                })
              }
              if (inner.type === 'artifact' && inner.content) {
                setTestScript(inner.content)
              }
            } catch {
              // plain text result
            }
          } else if (chunk.type === 'web_ui_bug' && chunk.webUiBugData) {
            const d = chunk.webUiBugData
            if (d.task_id)
              localStorage.setItem(
                'webui_running_task',
                JSON.stringify({ task_id: d.task_id, url: targetUrl })
              )
            setResumeTaskId(d.task_id || null)
            setTestResult({
              task_id: d.task_id,
              bug_counts: {
                critical: d.bug_counts.critical ?? 0,
                high: d.bug_counts.high ?? 0,
                medium: d.bug_counts.medium ?? 0,
                low: d.bug_counts.low ?? 0,
              },
              steps_done: d.steps_done ?? 0,
              has_tests: !!d.tests_url,
            })
            localStorage.removeItem('webui_running_task')
          } else if (chunk.type === 'web_ui_artifact' && chunk.webUiArtifactData) {
            setTestScript(chunk.webUiArtifactData.script)
          } else if (chunk.type === 'error') {
            appendLog({ type: 'error', content: chunk.content })
            setError(chunk.content)
          }
        }
      )
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      setError(msg)
      appendLog({ type: 'error', content: msg })
    } finally {
      setIsRunning(false)
    }
  }

  const handleDownloadScript = () => {
    if (!testScript) return
    const blob = new Blob([testScript], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `web_ui_test_${Date.now()}.py`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleDeleteHistory = async (id: string) => {
    try {
      await deleteWebUITask(id)
      setHistory((prev) => prev.filter((t) => t.id !== id))
    } catch {
      // ignore
    }
  }

  const totalBugs = testResult
    ? testResult.bug_counts.critical +
      testResult.bug_counts.high +
      testResult.bug_counts.medium +
      testResult.bug_counts.low
    : 0

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b">
        <div className="container flex h-16 items-center px-4">
          <div className="font-bold text-xl text-primary">Web UI Testing</div>
        </div>
      </header>

      <main className="container mx-auto py-8 px-4">
        <div className="grid gap-6 lg:grid-cols-5">
          {/* ── Config Panel ───────────────────────────────── */}
          <div className="lg:col-span-2 space-y-4">
            <div className="rounded-xl border bg-card shadow p-6 space-y-4">
              <h2 className="text-lg font-semibold">Test Configuration</h2>

              {/* Target URL */}
              <div>
                <label className="block text-sm font-medium mb-1">
                  Target URL <span className="text-destructive">*</span>
                </label>
                <input
                  type="url"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  disabled={isRunning}
                />
              </div>

              {/* CDP URL */}
              <div>
                <label className="block text-sm font-medium mb-1">CDP URL (local Chrome)</label>
                <input
                  type="text"
                  value={cdpUrl}
                  onChange={(e) => setCdpUrl(e.target.value)}
                  placeholder="http://localhost:9222"
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  disabled={isRunning}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Start Chrome with{' '}
                  <code className="bg-muted px-1 rounded">--remote-debugging-port=9222</code>
                </p>
              </div>

              {/* User Persona */}
              <div>
                <label className="block text-sm font-medium mb-1">User Persona</label>
                <select
                  value={userPersona}
                  onChange={(e) => setUserPersona(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  disabled={isRunning}
                >
                  {PERSONA_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Max Steps */}
              <div>
                <label className="block text-sm font-medium mb-1">
                  Max Steps: <span className="font-normal text-muted-foreground">{maxSteps}</span>
                </label>
                <input
                  type="range"
                  min={20}
                  max={500}
                  step={10}
                  value={maxSteps}
                  onChange={(e) => setMaxSteps(Number(e.target.value))}
                  className="w-full"
                  disabled={isRunning}
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>20</span>
                  <span>500</span>
                </div>
              </div>

              {/* Advanced toggle */}
              <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                className="text-sm text-primary hover:underline"
              >
                {showAdvanced ? '▾ Hide advanced' : '▸ Show advanced'}
              </button>

              {showAdvanced && (
                <div className="space-y-4 pt-2 border-t">
                  {/* Credentials */}
                  <div>
                    <label className="block text-sm font-medium mb-1">Username</label>
                    <input
                      type="text"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="Optional login username"
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                      disabled={isRunning}
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Password</label>
                    <input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="Optional login password"
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                      disabled={isRunning}
                    />
                  </div>
                  {/* Business Context */}
                  <div>
                    <label className="block text-sm font-medium mb-1">Business Context</label>
                    <textarea
                      value={businessContext}
                      onChange={(e) => setBusinessContext(e.target.value)}
                      placeholder="Describe the application's purpose, key workflows, target users..."
                      rows={3}
                      className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm resize-none"
                      disabled={isRunning}
                    />
                  </div>
                  {/* Headless toggle (only relevant when no CDP URL) */}
                  {!cdpUrl && (
                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        role="switch"
                        aria-checked={headless}
                        onClick={() => setHeadless((v) => !v)}
                        disabled={isRunning}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          headless ? 'bg-primary' : 'bg-muted'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            headless ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                      <span className="text-sm">Headless mode</span>
                    </div>
                  )}
                </div>
              )}

              {/* Resume banner — shown after page refresh when a task was running */}
              {resumeTaskId && !isRunning && (
                <div className="rounded-md bg-amber-50 border border-amber-200 px-3 py-2 text-sm">
                  <p className="text-amber-800 font-medium mb-1">
                    ⚡ Task was running before refresh
                  </p>
                  <p className="text-amber-700 text-xs mb-2">
                    Task ID: {resumeTaskId.slice(0, 8)}…
                  </p>
                  <div className="flex gap-2">
                    <button
                      onClick={() => startPollingTask(resumeTaskId)}
                      className="rounded bg-amber-500 text-white px-3 py-1 text-xs font-medium hover:bg-amber-600"
                    >
                      Resume monitoring
                    </button>
                    <button
                      onClick={() => {
                        setResumeTaskId(null)
                        localStorage.removeItem('webui_running_task')
                      }}
                      className="rounded border border-amber-300 text-amber-700 px-3 py-1 text-xs hover:bg-amber-100"
                    >
                      Dismiss
                    </button>
                  </div>
                </div>
              )}

              {/* Subscription quota */}
              <QuotaBadge />

              {error && (
                <p className="text-sm text-destructive rounded-md bg-destructive/10 px-3 py-2">
                  {error}
                </p>
              )}

              {isRunning ? (
                <button
                  onClick={handleStop}
                  className="w-full rounded-md bg-red-500 text-white px-4 py-2 text-sm font-medium hover:bg-red-600 transition-colors flex items-center justify-center gap-2"
                >
                  <span className="inline-block h-3.5 w-3.5 rounded-sm bg-white" />
                  Stop
                </button>
              ) : (
                <button
                  onClick={handleRun}
                  disabled={!targetUrl.trim()}
                  className="w-full rounded-md bg-primary text-primary-foreground px-4 py-2 text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
                >
                  Start Web UI Test
                </button>
              )}
            </div>

            {/* ── Bug Summary ────────────────────────────────── */}
            {testResult && (
              <div className="rounded-xl border bg-card shadow p-6">
                <h2 className="text-lg font-semibold mb-3">Bug Report</h2>
                <p className="text-sm text-muted-foreground mb-4">
                  {totalBugs} issue{totalBugs !== 1 ? 's' : ''} found
                  {testResult.steps_done > 0 && ` · ${testResult.steps_done} steps`}
                </p>
                <div className="grid grid-cols-2 gap-3">
                  <SeverityBadge severity="critical" count={testResult.bug_counts.critical} />
                  <SeverityBadge severity="high" count={testResult.bug_counts.high} />
                  <SeverityBadge severity="medium" count={testResult.bug_counts.medium} />
                  <SeverityBadge severity="low" count={testResult.bug_counts.low} />
                </div>
                {testResult.has_tests && (
                  <p className="text-xs text-muted-foreground mt-3">
                    Test script generated — see panel on the right
                  </p>
                )}
              </div>
            )}
          </div>

          {/* ── Output Panel ───────────────────────────────────── */}
          <div className="lg:col-span-3 space-y-4">
            {plannerSteps.length > 0 && <PlannerTimeline steps={plannerSteps} />}
            {/* Live Log */}
            <div className="rounded-xl border bg-card shadow overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b bg-muted/40">
                <span className="text-sm font-medium">Live Output</span>
                {isRunning && (
                  <span className="flex items-center gap-2 text-xs text-muted-foreground">
                    <span className="animate-pulse inline-block h-2 w-2 rounded-full bg-green-500" />
                    Running
                  </span>
                )}
              </div>
              <div className="h-80 overflow-y-auto bg-slate-950 p-4 font-mono text-xs">
                {logs.length === 0 && !isRunning && (
                  <span className="text-slate-500">
                    Output will appear here when the test runs...
                  </span>
                )}
                {logs.map((entry, i) => (
                  <div
                    key={i}
                    className={`mb-1 leading-relaxed ${
                      entry.type === 'error'
                        ? 'text-red-400'
                        : entry.isThinking
                          ? 'text-slate-400'
                          : 'text-slate-100'
                    }`}
                  >
                    {entry.content}
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
            </div>

            {/* Test Script Preview */}
            {testScript && (
              <div className="rounded-xl border bg-card shadow overflow-hidden">
                <div className="flex items-center justify-between px-4 py-3 border-b bg-muted/40">
                  <span className="text-sm font-medium">Generated Test Script</span>
                  <button
                    onClick={handleDownloadScript}
                    className="text-xs rounded-md border bg-background px-3 py-1 hover:bg-accent transition-colors"
                  >
                    Download .py
                  </button>
                </div>
                <pre className="h-96 overflow-auto bg-slate-950 text-slate-100 p-4 text-xs font-mono whitespace-pre">
                  {testScript}
                </pre>
              </div>
            )}
          </div>
        </div>

        {/* ── Task History ─────────────────────────────────────────── */}
        {(history.length > 0 || historyLoading) && (
          <div className="mt-8">
            <h2 className="text-lg font-semibold mb-4">Task History</h2>
            <div className="rounded-xl border bg-card shadow overflow-hidden">
              <table className="w-full text-sm">
                <thead className="border-b bg-muted/40">
                  <tr>
                    <th className="text-left px-4 py-3 font-medium">URL</th>
                    <th className="text-left px-4 py-3 font-medium">Status</th>
                    <th className="text-left px-4 py-3 font-medium">Bugs</th>
                    <th className="text-left px-4 py-3 font-medium">Steps</th>
                    <th className="text-left px-4 py-3 font-medium">Date</th>
                    <th className="px-4 py-3" />
                  </tr>
                </thead>
                <tbody>
                  {historyLoading && (
                    <tr>
                      <td
                        colSpan={6}
                        className="px-4 py-6 text-center text-muted-foreground text-xs"
                      >
                        Loading...
                      </td>
                    </tr>
                  )}
                  {history.map((task) => {
                    const totalB = task.bug_counts
                      ? task.bug_counts.critical +
                        task.bug_counts.high +
                        task.bug_counts.medium +
                        task.bug_counts.low
                      : null
                    const statusColor =
                      task.status === 'completed'
                        ? 'text-green-600'
                        : task.status === 'failed'
                          ? 'text-red-500'
                          : task.status === 'running'
                            ? 'text-blue-500'
                            : 'text-muted-foreground'
                    return (
                      <tr key={task.id} className="border-b last:border-0 hover:bg-muted/20">
                        <td className="px-4 py-3 max-w-xs truncate">
                          <a
                            href={task.target_url}
                            target="_blank"
                            rel="noreferrer"
                            className="hover:underline text-primary"
                          >
                            {task.target_url}
                          </a>
                        </td>
                        <td className={`px-4 py-3 font-medium ${statusColor}`}>{task.status}</td>
                        <td className="px-4 py-3">
                          {totalB !== null ? (
                            <span
                              className={
                                totalB > 0 ? 'text-orange-600 font-medium' : 'text-muted-foreground'
                              }
                            >
                              {totalB}
                            </span>
                          ) : (
                            '—'
                          )}
                        </td>
                        <td className="px-4 py-3 text-muted-foreground">{task.steps_done}</td>
                        <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                          {new Date(task.created_at).toLocaleDateString()}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {task.tests_url && (
                              <a
                                href={task.tests_url}
                                className="text-xs rounded-md border bg-background px-2 py-1 hover:bg-accent"
                              >
                                Tests
                              </a>
                            )}
                            {task.bug_report_url && (
                              <a
                                href={task.bug_report_url}
                                className="text-xs rounded-md border bg-background px-2 py-1 hover:bg-accent"
                              >
                                Bugs
                              </a>
                            )}
                            <button
                              onClick={() => handleDeleteHistory(task.id)}
                              className="text-xs text-destructive hover:underline px-1"
                            >
                              Delete
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
