'use client'

import { useState, useRef, useEffect, useCallback, Suspense } from 'react'
import { useRouter, useSearchParams, usePathname } from 'next/navigation'
import {
  streamStrategy,
  streamStrategyTrial,
  validateTrialToken,
  getUserAgents,
  uploadScript,
  createScript,
  bulkDeleteChatSessions,
  getChatSessions,
  createChatSession,
  deleteChatSession,
  getChatMessages,
  createChatMessage,
  cancelWebUITest,
  ChatSession,
  SSHConfig,
} from '@/lib/api'
import { useAuthStore } from '@/store/useAuthStore'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Icons } from '@/components/ui/icons'
import { OAuthTokenDialog } from '@/components/OAuthTokenDialog'
import {
  AlertCircle,
  Check,
  CheckSquare,
  ChevronDown,
  ChevronRight,
  Download,
  Menu,
  MessageSquare,
  Plus,
  Square,
  Trash2,
  X,
} from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import rehypeHighlight from 'rehype-highlight'
import 'highlight.js/styles/github-dark.css'
import Editor from 'react-simple-code-editor'
import { highlight, languages } from 'prismjs'
import 'prismjs/components/prism-json'
import 'prismjs/themes/prism.css'
import { BulkDeleteDialog } from '@/components/chat/BulkDeleteDialog'
import { pLimitFetch } from '@/lib/p-limit-fetch'
import { CodeBlock } from '@/components/chat/CodeBlock'
import type { StreamChunk } from '@/lib/chat-types'
import { ChatMessage, groupChunks } from '@/components/chat/messages'
import { PlannerTimeline, PlannerStepEntry } from '@/components/PlannerTimeline'
import { useWebUITest } from '@/hooks/useWebUITest'
import { WebUIConfigPanel } from '@/components/WebUIConfigPanel'
import { CDPConfigDialog } from '@/components/CDPConfigDialog'
import { PhaseProgressBar } from '@/components/PhaseProgressBar'
import { Globe } from 'lucide-react'
import { getWebUITasks } from '@/lib/api'
import type { WebUITask } from '@/lib/api'
import { QuotaBadge } from '@/components/QuotaBadge'
import { track } from '@/lib/analytics'
import { useCoalescedStreamBuffer } from '@/hooks/useCoalescedStreamBuffer'
import { getCoalesceWindowMs } from '@/lib/stream-config'
import { streamMetrics } from '@/lib/stream-metrics'
import { WizardRoundMessage, WizardGuideMessage } from '@/components/chat/messages'
import type {
  WizardRoundMessageData,
  WizardGuideMessageData,
  WizardInputKind,
} from '@/lib/wizard-types'
import { getChatSession } from '@/lib/api'

interface Message {
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
  chunks?: StreamChunk[] // typed chunks for proper rendering of assistant messages
}

type WizardEntry =
  | { kind: 'wizard_round'; data: WizardRoundMessageData }
  | { kind: 'wizard_guide'; data: WizardGuideMessageData }
  | { kind: 'wizard_aborted'; atLabel: string; rounds: number }

// Helper: save assistant message chunks to localStorage for a session
function saveSessionChunks(sessionId: string, messageIndex: number, chunks: StreamChunk[]) {
  try {
    const key = `chatChunks_${sessionId}`
    const existing = JSON.parse(localStorage.getItem(key) || '{}')
    existing[messageIndex] = chunks
    localStorage.setItem(key, JSON.stringify(existing))
  } catch (e) {
    // localStorage full or unavailable — silently ignore
  }
}

// Helper: load all cached chunks for a session from localStorage
function loadSessionChunks(sessionId: string): Record<number, StreamChunk[]> {
  try {
    const key = `chatChunks_${sessionId}`
    return JSON.parse(localStorage.getItem(key) || '{}')
  } catch {
    return {}
  }
}

// Collapsible JSON component
function CollapsibleJSON({ data, title = 'JSON' }: { data: any; title?: string }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const jsonString = JSON.stringify(data, null, 2)

  return (
    <div className="border border-gray-200 rounded-md overflow-hidden">
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full flex items-center justify-between px-3 py-1.5 bg-gray-50 hover:bg-gray-100 transition-colors text-left"
      >
        <div className="flex items-center gap-2">
          {isExpanded ? (
            <ChevronDown className="h-3 w-3 text-gray-500" />
          ) : (
            <ChevronRight className="h-3 w-3 text-gray-500" />
          )}
          <span className="text-xs font-mono text-gray-600">{title}</span>
        </div>
        <span className="text-xs text-gray-400">{jsonString.length} chars</span>
      </button>
      {isExpanded && (
        <pre className="text-xs bg-gray-50 p-3 overflow-x-auto max-h-96 overflow-y-auto font-mono text-gray-700">
          {jsonString}
        </pre>
      )}
    </div>
  )
}

// Render details and summary in a beautified way
function BeautifiedDetails({ details, summary }: { details?: any; summary?: any }) {
  return (
    <div className="space-y-3 mb-4">
      {summary && (
        <div className="rounded-lg bg-blue-50 border border-blue-200 p-4">
          <div className="flex items-start gap-2">
            <div className="mt-0.5">
              <svg
                className="h-4 w-4 text-blue-600"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-xs font-semibold text-blue-900 mb-1">Summary</p>
              <p className="text-sm text-blue-800 leading-relaxed">
                {typeof summary === 'string' ? summary : JSON.stringify(summary, null, 2)}
              </p>
            </div>
          </div>
        </div>
      )}
      {details && (
        <div className="rounded-lg bg-green-50 border border-green-200 p-4">
          <div className="flex items-start gap-2">
            <div className="mt-0.5">
              <svg
                className="h-4 w-4 text-green-600"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                />
              </svg>
            </div>
            <div className="flex-1">
              <p className="text-xs font-semibold text-green-900 mb-1">Details</p>
              <div className="text-sm text-green-800 leading-relaxed">
                {typeof details === 'string' ? (
                  <p>{details}</p>
                ) : Array.isArray(details) ? (
                  <ul className="list-disc list-inside space-y-1">
                    {details.map((item, i) => (
                      <li key={i}>{typeof item === 'string' ? item : JSON.stringify(item)}</li>
                    ))}
                  </ul>
                ) : (
                  <pre className="text-xs bg-green-100 p-2 rounded overflow-x-auto">
                    {JSON.stringify(details, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Helper function to find the end of a JSON object
function findJsonEnd(str: string, startIndex: number): number {
  let depth = 0
  let inString = false
  let escapeNext = false

  for (let i = startIndex; i < str.length; i++) {
    const char = str[i]

    if (escapeNext) {
      escapeNext = false
      continue
    }

    if (char === '\\') {
      escapeNext = true
      continue
    }

    if (char === '"') {
      inString = !inString
      continue
    }

    if (inString) continue

    if (char === '{' || char === '[') {
      depth++
    } else if (char === '}' || char === ']') {
      depth--
      if (depth === 0) {
        return i + 1
      }
    }
  }

  return -1
}

function FormattedMessage({ content }: { content: string }) {
  const trimmed = content.trim()

  // Helper function to handle JSON data rendering
  const renderJsonData = (data: any, markdownContent?: string) => {
    // Handle Service Menu
    if (data.response_type === 'service_menu') {
      return (
        <div className="space-y-4">
          <p className="text-sm leading-relaxed">{data.message}</p>
          {data.capabilities && Array.isArray(data.capabilities) && (
            <div className="rounded-lg bg-blue-50 p-4">
              <p className="mb-2 font-semibold text-blue-900">Capabilities:</p>
              <ul className="space-y-2">
                {data.capabilities.map((cap: string, i: number) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-blue-800">
                    <span className="mt-1 block h-1.5 w-1.5 flex-shrink-0 rounded-full bg-blue-500" />
                    <span>{cap}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )
    }

    // Handle Clarification Needed
    if (data.response_type === 'clarification_needed') {
      return (
        <div className="space-y-4">
          <p className="text-sm leading-relaxed">{data.message}</p>
          {data.suggested_actions && Array.isArray(data.suggested_actions) && (
            <div className="rounded-lg bg-yellow-50 p-4 border border-yellow-100">
              <p className="mb-2 font-semibold text-yellow-900">Suggested Actions:</p>
              <ul className="space-y-2">
                {data.suggested_actions.map((action: string, i: number) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-yellow-800">
                    <span className="mt-1 block h-1.5 w-1.5 flex-shrink-0 rounded-full bg-yellow-500" />
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )
    }

    // Handle Auth Required
    if (data.response_type === 'auth_required') {
      return (
        <div className="space-y-4">
          <div className="rounded-lg bg-red-50 p-4 border border-red-100">
            <div className="flex items-start gap-3">
              <AlertCircle className="h-5 w-5 text-red-600 mt-0.5" />
              <div className="space-y-2">
                <p className="text-sm font-medium text-red-900">Authentication Required</p>
                <p className="text-sm text-red-800">{data.message}</p>
                {data.target_url && (
                  <p className="text-xs text-red-700 bg-red-100 px-2 py-1 rounded w-fit font-mono">
                    Target: {data.target_url}
                  </p>
                )}
                {data.suggested_action && (
                  <p className="text-sm font-medium text-red-800 mt-2">
                    Action: {data.suggested_action}
                  </p>
                )}
              </div>
            </div>
          </div>
        </div>
      )
    }

    // Handle mixed JSON + Markdown content
    // Extract details and summary for beautified display
    const { details, summary } = data

    return (
      <div className="space-y-4">
        {/* 1. Beautified details and summary */}
        {(details || summary) && <BeautifiedDetails details={details} summary={summary} />}

        {/* 2. Markdown content */}
        {markdownContent && (
          <div className="prose prose-sm max-w-none font-sans">
            <ReactMarkdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeHighlight]}>
              {markdownContent}
            </ReactMarkdown>
          </div>
        )}
      </div>
    )
  }

  // Try to detect mixed content (JSON + Markdown)
  // Check if content starts with JSON
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      // Find the end of the JSON object
      const jsonEnd = findJsonEnd(trimmed, 0)

      if (jsonEnd > 0) {
        const jsonContent = trimmed.substring(0, jsonEnd)
        const markdownContent = trimmed.substring(jsonEnd).trim()

        try {
          const data = JSON.parse(jsonContent)
          return renderJsonData(data, markdownContent)
        } catch (parseError) {
          // JSON parse failed, try parsing the whole content as JSON
        }
      }
    } catch (e) {
      // Not valid JSON structure, continue to other parsing methods
    }

    // Try to parse as pure JSON (fallback)
    try {
      const data = JSON.parse(trimmed)
      return renderJsonData(data)
    } catch (e) {
      // Not JSON, continue to markdown/text rendering
    }
  }

  // Check if content contains markdown patterns
  const hasMarkdown = /```|^#{1,6}\s|^\*\s|^-\s|^\d+\.\s|^\|.*\|/m.test(content)

  if (hasMarkdown) {
    return (
      <div className="prose prose-sm max-w-none font-sans">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          rehypePlugins={[rehypeHighlight]}
          components={{
            // Override code blocks to use our CodeBlock component with copy button
            pre: ({ children }) => {
              // Extract the code and language from the child using safe type checking
              const child = children as React.ReactElement<{
                className?: string
                children?: React.ReactNode
              }>
              const className = child?.props?.className
              if (className && typeof className === 'string' && className.includes('language-')) {
                const language = className.replace('language-', '')
                const code = String(child.props.children || '').replace(/\n$/, '')
                return <CodeBlock code={code} language={language} />
              }
              return (
                <pre className="my-2 overflow-x-auto rounded-lg bg-gray-900 p-4 text-sm font-mono">
                  {children}
                </pre>
              )
            },
            code: ({ className, children, ...props }) => {
              const isInline = !className
              return isInline ? (
                <code
                  className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-sm text-gray-800"
                  {...props}
                >
                  {children}
                </code>
              ) : (
                <code className={`font-mono text-sm text-gray-100 ${className || ''}`} {...props}>
                  {children}
                </code>
              )
            },
            p: ({ children }) => <p className="my-1.5 font-sans">{children}</p>,
            li: ({ children }) => <li className="font-sans">{children}</li>,
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
    )
  }

  // Plain text fallback
  return (
    <div className="whitespace-pre-wrap break-words text-sm leading-relaxed font-sans">
      {content}
    </div>
  )
}

function ChatPageContent() {
  const user = useAuthStore((state) => state.user)
  const _hasHydrated = useAuthStore((state) => state._hasHydrated)
  const router = useRouter()
  const searchParams = useSearchParams()
  const pathname = usePathname()
  const urlSessionId = searchParams.get('session')

  const [messages, setMessages] = useState<Message[]>([])
  const [content, setContent] = useState('')
  const [context, setContext] = useState('{\n  "cookie": "",\n  "token": ""\n}')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const abortControllerRef = useRef<AbortController | null>(null)
  const streamBuffer = useCoalescedStreamBuffer<StreamChunk>({
    coalesceMs: getCoalesceWindowMs(),
  })
  const streamingChunks = streamBuffer.items
  const [plannerSteps, setPlannerSteps] = useState<PlannerStepEntry[]>([])
  // Test environment: 'cloud' (default, zero-config) or 'local' (requires Client Agent)
  const [testEnv, setTestEnv] = useState<'cloud' | 'local'>('cloud')
  const [showTestEnvInfo, setShowTestEnvInfo] = useState(false)
  const [isLoaded, setIsLoaded] = useState(false)
  const [showSaveButton, setShowSaveButton] = useState(false)
  const [lastGeneratedScript, setLastGeneratedScript] = useState<string>('')
  const [lastGeneratedScriptUrl, setLastGeneratedScriptUrl] = useState<string | null>(null)

  // Web UI Test hook
  const {
    webUiTestEnabled,
    setWebUiTestEnabled,
    showWebUIPanel,
    setShowWebUIPanel,
    showCDPDialog,
    setShowCDPDialog,
    webUiConfig,
    setWebUiConfig,
    currentResult: webUiCurrentResult,
    setCurrentResult: setWebUiCurrentResult,
    currentScript: webUiCurrentScript,
    setCurrentScript: setWebUiCurrentScript,
    webUiPhases,
    isLocalMode,
    setIsLocalMode,
    buildStreamContext,
    resetForNewTest,
    updatePhaseFromLog,
  } = useWebUITest(isLoaded)

  // Recent web UI tasks for sidebar and welcome screen
  const [recentWebUITasks, setRecentWebUITasks] = useState<WebUITask[]>([])

  // SSH remote execution state (advanced option for cloud env)
  const [showSSHDialog, setShowSSHDialog] = useState(false)
  const [sshConfig, setSSHConfig] = useState<SSHConfig | null>(null)
  const [sshFormIP, setSSHFormIP] = useState('')
  const [sshFormUsername, setSSHFormUsername] = useState('')
  const [sshFormPemBase64, setSSHFormPemBase64] = useState('')
  const [sshFormPytestArgs, setSSHFormPytestArgs] = useState('--alluredir=./allure-results -v')

  // Detect trial mode synchronously from URL params (before any useEffect runs)
  const urlTrialToken = searchParams.get('token')
  const urlTrialUrl = searchParams.get('trialUrl')
  const isTrialFromUrl = !!(urlTrialToken && urlTrialUrl)

  const [trialMode, setTrialMode] = useState(isTrialFromUrl)
  const [trialToken, setTrialToken] = useState<string | null>(urlTrialToken || null)
  const [trialUrl, setTrialUrl] = useState<string | null>(
    urlTrialUrl ? decodeURIComponent(urlTrialUrl) : null
  )
  const [trialUsed, setTrialUsed] = useState(false)
  const [trialError, setTrialError] = useState<string | null>(null)

  // New state for chat history
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [currentSessionId, setCurrentSessionId] = useState<string | null>(null)
  const [isSidebarOpen, setIsSidebarOpen] = useState(true)

  // Manage mode (bulk actions) state
  const [isManageMode, setIsManageMode] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [isBulkDeleting, setIsBulkDeleting] = useState(false)
  const [isExporting, setIsExporting] = useState(false)
  const [exportProgress, setExportProgress] = useState<{ done: number; total: number }>({
    done: 0,
    total: 0,
  })
  const [showBulkDeleteDialog, setShowBulkDeleteDialog] = useState(false)
  const [bulkActionBanner, setBulkActionBanner] = useState<string | null>(null)

  // Wizard state — parallel to messages, holds wizard round/guide/aborted entries
  const [wizardEntries, setWizardEntries] = useState<WizardEntry[]>([])

  // Close sidebar in trial mode
  useEffect(() => {
    if (trialMode) {
      setIsSidebarOpen(false)
    }
  }, [trialMode])

  // Authentication check - redirect to login if not authenticated (skip in trial mode)
  useEffect(() => {
    if (_hasHydrated && !user && !trialMode) {
      router.push('/login')
    }
  }, [user, _hasHydrated, router, trialMode])

  useEffect(() => {
    const savedEnv = localStorage.getItem('testEnv')
    if (savedEnv === 'local' || savedEnv === 'cloud') {
      setTestEnv(savedEnv)
    }

    // Restore last session if no URL param
    const params = new URLSearchParams(window.location.search)
    if (!params.get('session')) {
      const lastSessionId = localStorage.getItem('lastChatSessionId')
      if (lastSessionId) {
        const newParams = new URLSearchParams(window.location.search)
        newParams.set('session', lastSessionId)
        router.replace(`${pathname}?${newParams.toString()}`)
      }
    }

    setIsLoaded(true)
  }, [])

  // Handle prompt from URL (e.g., from Hero page redirect)
  const urlPrompt = searchParams.get('prompt')
  const formRef = useRef<HTMLFormElement>(null)
  const hasAutoSubmitted = useRef(false)

  useEffect(() => {
    if (urlPrompt && !hasAutoSubmitted.current && _hasHydrated && user) {
      // Decode and set the content
      const decodedPrompt = decodeURIComponent(urlPrompt)
      setContent(decodedPrompt)

      // Clear the prompt from URL to prevent re-submission on refresh
      const params = new URLSearchParams(searchParams.toString())
      params.delete('prompt')
      const newUrl = params.toString() ? `${pathname}?${params.toString()}` : pathname
      router.replace(newUrl)

      // Mark as auto-submitted to prevent re-runs
      hasAutoSubmitted.current = true

      // Auto-submit after a short delay to ensure state is set
      setTimeout(() => {
        formRef.current?.requestSubmit()
      }, 100)
    }
  }, [urlPrompt, _hasHydrated, user, searchParams, pathname, router])

  // Trial mode: validate token and auto-trigger test
  const hasTrialStarted = useRef(false)
  useEffect(() => {
    if (!trialMode || !trialToken || !trialUrl || hasTrialStarted.current) return
    hasTrialStarted.current = true

    const runTrial = async () => {
      // Validate the token first
      try {
        const validation = await validateTrialToken(trialToken)
        if (!validation.valid) {
          const reasonMsg =
            validation.reason === 'consumed'
              ? 'This trial link has already been used. Sign up to continue testing.'
              : validation.reason === 'expired'
                ? 'This trial link has expired. Sign up to continue testing.'
                : 'Invalid trial link. Please request a new one.'
          setTrialError(reasonMsg)
          return
        }
      } catch (err) {
        setTrialError('Failed to validate trial token. Please try again later.')
        return
      }

      // Token is valid — start the test
      setLoading(true)
      streamMetrics.startSession()
      streamBuffer.clear()
      setPlannerSteps([])
      setMessages([
        {
          role: 'user',
          content: `Testing API: ${trialUrl}`,
          timestamp: new Date(),
        },
      ])

      let fullContent = ''
      const trialChunks: StreamChunk[] = []

      try {
        await streamStrategyTrial(
          trialUrl,
          trialToken,
          (chunk) => {
            // onChunk — not used for fullContent accumulation in trial mode either
          },
          (error) => {
            console.error('Trial streaming error:', error)
            setError(error.message)
            streamBuffer.flushSync()
            streamMetrics.endSession()
            streamBuffer.clear()
            setPlannerSteps([])
            setLoading(false)
            setTrialUsed(true)
          },
          () => {
            streamBuffer.flushSync()
            streamMetrics.endSession()
            setMessages((prev) => [
              ...prev,
              {
                role: 'assistant',
                content: fullContent,
                timestamp: new Date(),
                chunks: [...trialChunks],
              },
            ])
            streamBuffer.clear()
            setPlannerSteps([])
            setLoading(false)
            setTrialUsed(true)
          },
          (typedChunk) => {
            if (typedChunk.type === 'planner_step' && typedChunk.plannerStep) {
              setPlannerSteps((prev) => [...prev, typedChunk.plannerStep!])
              return // do not push to streamingChunks / not a regular StreamChunk
            }
            const chunk: StreamChunk = {
              type: typedChunk.type as StreamChunk['type'],
              content: typedChunk.content,
              isThinking: typedChunk.isThinking,
              author: typedChunk.author,
              stage: typedChunk.stage,
              sshResult: typedChunk.sshResult,
            }
            trialChunks.push(chunk)
            streamBuffer.push(chunk)
            if (typedChunk.type === 'result') {
              fullContent += typedChunk.content
            } else if (typedChunk.type === 'error') {
              fullContent += '\n**Error:** ' + typedChunk.content + '\n'
            } else if (typedChunk.type === 'ssh_result' && typedChunk.sshResult) {
              const r = typedChunk.sshResult
              fullContent +=
                '\n**Remote Test Execution ' +
                (r.success ? 'Succeeded' : 'Failed') +
                '** (Exit Code: ' +
                r.exit_code +
                ')\n'
              if (r.stdout) fullContent += '\n```\n' + r.stdout + '\n```\n'
              if (r.stderr) fullContent += '\n**stderr:**\n```\n' + r.stderr + '\n```\n'
              if (r.allure_results_url)
                fullContent += '\n[Download Allure Results](' + r.allure_results_url + ')\n'
            } else if (typedChunk.type === 'log') {
              fullContent += typedChunk.content + '\n'
            }
          }
        )
      } catch (err: any) {
        const errorMsg = err.message || String(err)
        // Check for consumed/expired errors from the backend
        if (errorMsg.includes('already been used') || errorMsg.includes('expired')) {
          setTrialError(errorMsg)
        } else {
          setError(errorMsg)
        }
        streamBuffer.flushSync()
        streamMetrics.endSession()
        streamBuffer.clear()
        setPlannerSteps([])
        setLoading(false)
        setTrialUsed(true)
      }
    }

    runTrial()
  }, [trialMode, trialToken, trialUrl])

  // Save current session to local storage
  useEffect(() => {
    if (currentSessionId) {
      localStorage.setItem('lastChatSessionId', currentSessionId)
    }
  }, [currentSessionId])

  const [showTokenDialog, setShowTokenDialog] = useState(false)
  const [agentOnline, setAgentOnline] = useState(false)
  const [checkingAgent, setCheckingAgent] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const scrollContainerRef = useRef<HTMLDivElement>(null)
  // true = user has manually scrolled up; suppress auto-scroll until they return to bottom
  const userScrolledUpRef = useRef(false)

  // Detect manual scroll: if user scrolls up (not at bottom), suppress auto-scroll
  useEffect(() => {
    const container = scrollContainerRef.current
    if (!container) return
    const onScroll = () => {
      const distanceFromBottom =
        container.scrollHeight - container.scrollTop - container.clientHeight
      // Consider "at bottom" if within 80px (accounts for rounding / padding)
      userScrolledUpRef.current = distanceFromBottom > 80
    }
    container.addEventListener('scroll', onScroll, { passive: true })
    return () => container.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    // Only auto-scroll when streaming AND user hasn't manually scrolled up
    if (streamingChunks.length > 0 && !userScrolledUpRef.current) {
      const container = scrollContainerRef.current
      if (container) {
        container.scrollTop = container.scrollHeight
      }
    }
  }, [streamingChunks])

  // Save testEnv to localStorage and sync isLocalMode
  useEffect(() => {
    if (isLoaded) {
      localStorage.setItem('testEnv', testEnv)
    }
    setIsLocalMode(testEnv === 'local')
  }, [testEnv, isLoaded, setIsLocalMode])

  // Load/save SSH config from localStorage
  useEffect(() => {
    const saved = localStorage.getItem('sshConfig')
    if (saved) {
      try {
        const parsed = JSON.parse(saved)
        setSSHConfig(parsed)
        setSSHFormIP(parsed.remote_ip || '')
        setSSHFormUsername(parsed.username || '')
        setSSHFormPemBase64(parsed.pem_key_base64 || '')
        setSSHFormPytestArgs(parsed.pytest_args || '--alluredir=./allure-results -v')
      } catch (e) {
        /* ignore */
      }
    }
  }, [])

  // Check agent status when local env is selected
  const checkAgentStatus = async () => {
    if (testEnv !== 'local' || !user) {
      setAgentOnline(false)
      return
    }

    setCheckingAgent(true)
    try {
      const response = await getUserAgents()
      // Check if user has at least one active agent
      const hasActiveAgent =
        response.agents.length > 0 && response.agents.some((agent) => agent.status === 'active')
      setAgentOnline(hasActiveAgent)
    } catch (error) {
      console.error('Failed to check agent status:', error)
      setAgentOnline(false)
    } finally {
      setCheckingAgent(false)
    }
  }

  // Poll agent status when local env is selected
  useEffect(() => {
    if (testEnv === 'local' && user) {
      // Check immediately
      checkAgentStatus()

      // Then check every 10 seconds
      const interval = setInterval(checkAgentStatus, 10000)

      return () => clearInterval(interval)
    } else {
      setAgentOnline(false)
    }
  }, [testEnv, user])

  const handleNewChat = useCallback(
    (updateUrl = true) => {
      if (updateUrl) {
        const params = new URLSearchParams(searchParams.toString())
        if (params.get('session')) {
          params.delete('session')
          router.push(`${pathname}?${params.toString()}`)
          return
        }
      }

      setCurrentSessionId(null)
      localStorage.removeItem('lastChatSessionId')
      setMessages([])
      setWizardEntries([])
      setContent('')
      setContext('{\n  "cookie": "",\n  "token": ""\n}')
      setError(null)
      streamBuffer.clear()
      setShowSaveButton(false)
      setLastGeneratedScript('')
      resetForNewTest()

      // On mobile, close sidebar
      if (typeof window !== 'undefined' && window.innerWidth < 768) {
        setIsSidebarOpen(false)
      }
    },
    [searchParams, pathname, router]
  )

  const loadSessions = useCallback(async () => {
    try {
      const data = await getChatSessions()
      setSessions(data)
    } catch (err) {
      console.error('Failed to load sessions:', err)
    }
  }, [])

  const loadSessionMessages = useCallback(
    async (sessionId: string) => {
      try {
        setLoading(true)
        setCurrentSessionId(sessionId)
        setError(null)
        setMessages([])

        const msgs = await getChatMessages(sessionId)
        // Prefer DB-persisted chunks (server-side, cross-browser durable). Fall
        // back to localStorage cache for legacy rows persisted before V15, then
        // to the flat content blob as the last resort.
        const cachedChunks = loadSessionChunks(sessionId)
        setMessages(
          msgs.map((m, index) => {
            const dbChunks = Array.isArray(m.chunks) && m.chunks.length > 0 ? m.chunks : null
            const lsChunks =
              m.role === 'assistant' && cachedChunks[index] ? cachedChunks[index] : undefined
            return {
              role: m.role as 'user' | 'assistant',
              content: m.content,
              timestamp: new Date(m.created_at),
              chunks: dbChunks ?? lsChunks,
            }
          })
        )

        setLoading(false)
        // On mobile, close sidebar
        if (typeof window !== 'undefined' && window.innerWidth < 768) {
          setIsSidebarOpen(false)
        }
      } catch (err: any) {
        console.error('Failed to load messages:', err)
        // If session not found, clear it completely
        const errorMessage = typeof err === 'string' ? err : err.message || JSON.stringify(err)
        if (errorMessage.toLowerCase().includes('not found') || errorMessage.includes('404')) {
          console.log('Session not found, clearing stale session:', sessionId)
          // Clear the stale session from localStorage
          const storedSessionId = localStorage.getItem('lastChatSessionId')
          if (storedSessionId === sessionId) {
            localStorage.removeItem('lastChatSessionId')
          }
          // Clear URL and reset state
          setCurrentSessionId(null)
          setMessages([])
          setError('Chat session no longer exists. Starting a new chat.')
          const params = new URLSearchParams(window.location.search)
          params.delete('session')
          router.replace(`${pathname}?${params.toString()}`)
        } else {
          setError('Failed to load chat history: ' + errorMessage)
        }
        setLoading(false)
      }
    },
    [pathname, router]
  )

  // Load sessions
  useEffect(() => {
    if (user) {
      loadSessions()
    }
  }, [user, loadSessions])

  // Load recent Web UI tasks
  useEffect(() => {
    if (user) {
      getWebUITasks(10)
        .then(setRecentWebUITasks)
        .catch(() => {})
    }
  }, [user])

  // Handle URL session changes
  useEffect(() => {
    if (urlSessionId) {
      if (urlSessionId !== currentSessionId) {
        loadSessionMessages(urlSessionId)
      }
    } else {
      // Only clear if we have a session ID but URL is empty (user clicked New Chat or navigated back)
      if (currentSessionId) {
        handleNewChat(false)
      }
    }
  }, [urlSessionId, currentSessionId, loadSessionMessages, handleNewChat])

  // Hydrate wizard entries from session.wizard_state on session load
  useEffect(() => {
    if (!urlSessionId) return
    getChatSession(urlSessionId)
      .then((session) => {
        const ws = session.wizard_state
        if (!ws?.active) return
        const hydrated: WizardEntry[] = (ws.rounds || []).map((r: any) => ({
          kind: 'wizard_round' as const,
          data: {
            kind: 'wizard_round' as const,
            roundN: r.n,
            roundLabel: r.round_label,
            question: r.question,
            options: r.options || [],
            allowFreeText: r.allow_free_text,
            allowBack: false,
            status: r.answer ? ('answered' as const) : ('pending' as const),
            selectedAnswer: r.answer ?? undefined,
          },
        }))
        setWizardEntries(hydrated)
      })
      .catch(() => {
        // Non-fatal — wizard_state hydration failing shouldn't break message loading
      })
  }, [urlSessionId])

  // ESC key exits manage mode
  useEffect(() => {
    if (!isManageMode) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsManageMode(false)
        setSelectedIds(new Set())
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [isManageMode])

  useEffect(() => {
    if (!bulkActionBanner) return
    const t = window.setTimeout(() => setBulkActionBanner(null), 5000)
    return () => window.clearTimeout(t)
  }, [bulkActionBanner])

  if (!_hasHydrated) {
    return null
  }

  const handleSelectSession = (sessionId: string) => {
    if (isManageMode) {
      handleToggleSelected(sessionId)
      return
    }
    const params = new URLSearchParams(searchParams.toString())
    params.set('session', sessionId)
    router.push(`${pathname}?${params.toString()}`)
  }

  const handleDeleteSession = async (e: React.MouseEvent, sessionId: string) => {
    e.stopPropagation()
    if (confirm('Are you sure you want to delete this chat?')) {
      try {
        await deleteChatSession(sessionId)
        setSessions((prev) => prev.filter((s) => s.id !== sessionId))
        if (currentSessionId === sessionId) {
          handleNewChat()
        }
      } catch (err) {
        console.error('Failed to delete session:', err)
      }
    }
  }

  const handleEnterManageMode = () => {
    setIsManageMode(true)
    setSelectedIds(new Set())
  }

  const handleExitManageMode = () => {
    setIsManageMode(false)
    setSelectedIds(new Set())
  }

  const handleToggleSelected = (sessionId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(sessionId)) next.delete(sessionId)
      else next.add(sessionId)
      return next
    })
  }

  const handleToggleSelectAll = () => {
    setSelectedIds((prev) =>
      prev.size === sessions.length ? new Set() : new Set(sessions.map((s) => s.id))
    )
  }

  const handleOpenBulkDelete = () => setShowBulkDeleteDialog(true)

  const handleConfirmBulkDelete = async () => {
    const ids = Array.from(selectedIds)
    if (ids.length === 0) {
      setShowBulkDeleteDialog(false)
      return
    }
    setIsBulkDeleting(true)
    try {
      const result = await bulkDeleteChatSessions(ids)
      const deletedSet = new Set(result.deleted_ids)
      setSessions((prev) => prev.filter((s) => !deletedSet.has(s.id)))

      if (currentSessionId && deletedSet.has(currentSessionId)) {
        handleNewChat()
      }

      if (result.deleted_count < ids.length) {
        const missing = ids.length - result.deleted_count
        setBulkActionBanner(
          `Deleted ${result.deleted_count} of ${ids.length} sessions (${missing} not found or already removed)`
        )
      } else {
        setBulkActionBanner(`Deleted ${result.deleted_count} sessions`)
      }
      setShowBulkDeleteDialog(false)
      handleExitManageMode()
    } catch (err) {
      console.error('Bulk delete failed:', err)
      setBulkActionBanner('Failed to delete sessions. Please try again.')
      setShowBulkDeleteDialog(false)
    } finally {
      setIsBulkDeleting(false)
    }
  }

  const handleBulkExport = async () => {
    const ids = Array.from(selectedIds)
    if (ids.length === 0) return

    setIsExporting(true)
    setExportProgress({ done: 0, total: ids.length })

    type ExportItem = {
      session: ChatSession
      messages: Awaited<ReturnType<typeof getChatMessages>>
      error: Error | null
    }

    const sessionData = await pLimitFetch<string, ExportItem>(ids, 6, async (id) => {
      const session = sessions.find((s) => s.id === id)
      if (!session) {
        setExportProgress((p) => ({ ...p, done: p.done + 1 }))
        return {
          session: { id, title: '(unknown)', created_at: '', updated_at: '' } as ChatSession,
          messages: [],
          error: new Error('Session not found in local state'),
        }
      }
      try {
        const messages = await getChatMessages(id)
        setExportProgress((p) => ({ ...p, done: p.done + 1 }))
        return { session, messages, error: null }
      } catch (err) {
        setExportProgress((p) => ({ ...p, done: p.done + 1 }))
        return { session, messages: [], error: err as Error }
      }
    })

    const md = sessionData
      .map(({ session, messages, error }) => {
        const header = `# ${session.title}\n\n_Created: ${session.created_at}_\n\n---\n\n`
        if (error) return header + `> [Failed to load messages: ${error.message}]\n\n`
        return (
          header +
          messages
            .map((m) => `**${m.role}** _(${m.created_at})_:\n\n${m.content}\n`)
            .join('\n---\n\n')
        )
      })
      .join('\n\n===\n\n')

    const blob = new Blob([md], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `chat-export-${new Date().toISOString().slice(0, 10)}.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)

    const errorCount = sessionData.filter((d) => d.error).length
    if (errorCount > 0) {
      setBulkActionBanner(`Exported ${ids.length} sessions (${errorCount} with errors)`)
    } else {
      setBulkActionBanner(`Exported ${ids.length} sessions`)
    }
    setIsExporting(false)
    setExportProgress({ done: 0, total: 0 })
  }

  const postWizardInput = async (roundN: number, kind: WizardInputKind, value?: string) => {
    if (!currentSessionId || !user) return
    const abortController = new AbortController()
    abortControllerRef.current = abortController

    setLoading(true)
    streamMetrics.startSession()
    setError(null)
    streamBuffer.clear()
    setPlannerSteps([])

    // Collected chunks for this wizard postback turn
    const collectedChunks: StreamChunk[] = []
    let fullContent = ''

    await streamStrategy(
      {
        content: '',
        sessionId: currentSessionId,
        userId: user.id,
        wizardInput: { roundN, kind, value },
        signal: abortController.signal,
      },
      (_chunk) => {},
      (error) => {
        if (error.name === 'AbortError' || error.message?.includes('aborted')) {
          streamBuffer.flushSync()
          streamMetrics.endSession()
          streamBuffer.clear()
          setPlannerSteps([])
          setLoading(false)
          return
        }
        console.error('Wizard postback streaming error:', error)
        setError(typeof error.message === 'string' ? error.message : JSON.stringify(error))
        streamBuffer.flushSync()
        streamMetrics.endSession()
        streamBuffer.clear()
        setPlannerSteps([])
        setLoading(false)
      },
      async () => {
        streamBuffer.flushSync()
        streamMetrics.endSession()
        const assistantChunks = [...collectedChunks]
        if (assistantChunks.length > 0) {
          setMessages((prev) => {
            const newMessages = [
              ...prev,
              {
                role: 'assistant' as const,
                content: fullContent,
                timestamp: new Date(),
                chunks: assistantChunks,
              },
            ]
            if (currentSessionId) {
              const assistantIndex = newMessages.length - 1
              saveSessionChunks(currentSessionId, assistantIndex, assistantChunks)
            }
            return newMessages
          })
        }
        streamBuffer.clear()
        setPlannerSteps([])
        setLoading(false)
        if (fullContent && currentSessionId) {
          await createChatMessage(
            currentSessionId,
            'assistant',
            fullContent,
            assistantChunks.length > 0 ? assistantChunks : null
          )
        }
      },
      (typedChunk) => {
        if (typedChunk.type === 'planner_step' && typedChunk.plannerStep) {
          setPlannerSteps((prev) => [...prev, typedChunk.plannerStep!])
          return
        }
        if (typedChunk.type === 'wizard_round' && typedChunk.wizardRound) {
          const p = typedChunk.wizardRound
          setWizardEntries((prev) => {
            const marked = prev.map((e) =>
              e.kind === 'wizard_round' && e.data.status === 'pending'
                ? { ...e, data: { ...e.data, status: 'stale' as const } }
                : e
            )
            return [
              ...marked,
              {
                kind: 'wizard_round' as const,
                data: {
                  kind: 'wizard_round' as const,
                  roundN: p.round_n,
                  roundLabel: p.round_label,
                  question: p.question,
                  options: p.options,
                  allowFreeText: p.allow_free_text,
                  allowBack: p.allow_back,
                  status: 'pending' as const,
                },
              },
            ]
          })
          return
        }
        if (typedChunk.type === 'wizard_guide' && typedChunk.wizardGuide) {
          const p = typedChunk.wizardGuide
          setWizardEntries((prev) => [
            ...prev,
            {
              kind: 'wizard_guide' as const,
              data: {
                kind: 'wizard_guide' as const,
                guideKind: p.kind,
                markdown: p.markdown,
              },
            },
          ])
          return
        }
        if (typedChunk.type === 'wizard_aborted' && typedChunk.wizardAborted) {
          const p = typedChunk.wizardAborted
          setWizardEntries((prev) => {
            const marked = prev.map((e) =>
              e.kind === 'wizard_round' && e.data.status === 'pending'
                ? { ...e, data: { ...e.data, status: 'stale' as const } }
                : e
            )
            return [
              ...marked,
              {
                kind: 'wizard_aborted' as const,
                atLabel: p.at_round_label,
                rounds: p.rounds_used,
              },
            ]
          })
          return
        }
        const chunk: StreamChunk = {
          type: typedChunk.type as StreamChunk['type'],
          content: typedChunk.content,
          isThinking: typedChunk.isThinking,
          author: typedChunk.author,
          stage: typedChunk.stage,
          sshResult: typedChunk.sshResult,
        }
        collectedChunks.push(chunk)
        streamBuffer.push(chunk)
        if (typedChunk.type === 'result') {
          fullContent += typedChunk.content
        } else if (typedChunk.type === 'error') {
          fullContent += '\n**Error:** ' + typedChunk.content + '\n'
        } else if (typedChunk.type === 'log') {
          fullContent += typedChunk.content + '\n'
        }
      }
    )
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!content.trim()) {
      setError('Please enter some content')
      return
    }

    // Check client agent status if local env is selected
    if (testEnv === 'local' && !agentOnline) {
      setError(
        'Client Agent is offline. Please start the Client Agent or switch to Cloud environment.'
      )
      return
    }

    track('chat_submit', {
      mode: webUiTestEnabled ? 'web_ui_test' : 'chat',
      session_new: !currentSessionId,
      test_env: testEnv,
      prompt_len: content.trim().length,
      authenticated: Boolean(user),
    })

    const abortController = new AbortController()
    abortControllerRef.current = abortController

    setLoading(true)
    streamMetrics.startSession()
    setError(null)
    streamBuffer.clear()
    setPlannerSteps([])

    // Add user message
    const userContent = content.trim()
    const userMessage: Message = {
      role: 'user',
      content: userContent,
      timestamp: new Date(),
    }
    setMessages((prev) => [...prev, userMessage])

    // Clear input
    setContent('')

    // Parse context if provided
    let contextObj: Record<string, any> | undefined
    if (context.trim()) {
      try {
        contextObj = JSON.parse(context)
      } catch (e) {
        console.warn('Invalid JSON context, ignoring:', e)
      }
    }

    let sessionId = currentSessionId

    try {
      // Create session if not exists
      if (!sessionId) {
        // Generate a title from the first message (truncate to 50 chars)
        const title = userContent.length > 50 ? userContent.substring(0, 50) + '...' : userContent
        const newSession = await createChatSession(title)
        sessionId = newSession.id
        setCurrentSessionId(sessionId)
        setSessions((prev) => [newSession, ...prev])

        // Update URL without reloading
        const params = new URLSearchParams(searchParams.toString())
        params.set('session', sessionId)
        router.replace(`${pathname}?${params.toString()}`)
      }

      // Save user message
      await createChatMessage(sessionId, 'user', userContent)

      // Track streaming content locally — all chunks go into fullContent (for DB persistence)
      let fullContent = ''
      // Collect all typed chunks for proper rendering after completion
      const collectedChunks: StreamChunk[] = []

      if (webUiTestEnabled) {
        resetForNewTest()
        setShowWebUIPanel(false) // hide config panel during run to keep Stop button visible
      }

      await streamStrategy(
        {
          content: userContent,
          context: webUiTestEnabled ? buildStreamContext(contextObj) : contextObj,
          sessionId,
          userId: user?.id,
          localTestEnabled: testEnv === 'local',
          remoteTestEnabled: testEnv === 'cloud',
          sshConfig: testEnv === 'cloud' && sshConfig ? sshConfig : undefined,
          cdpUrl: testEnv === 'local' && webUiConfig.cdpUrl ? webUiConfig.cdpUrl : undefined,
          signal: abortController.signal,
        },
        (_chunk) => {
          // Raw chunks no longer accumulated — typed chunks handle rendering and DB content
        },
        (error) => {
          // AbortError = user clicked Stop — not an error to show
          if (error.name === 'AbortError' || error.message?.includes('aborted')) {
            streamBuffer.flushSync()
            streamMetrics.endSession()
            streamBuffer.clear()
            setPlannerSteps([])
            setLoading(false)
            if (webUiTestEnabled) setShowWebUIPanel(true)
            return
          }
          console.error('Streaming error:', error)
          setError(typeof error.message === 'string' ? error.message : JSON.stringify(error))
          streamBuffer.flushSync()
          streamMetrics.endSession()
          streamBuffer.clear()
          setPlannerSteps([])
          setLoading(false)
          if (webUiTestEnabled) setShowWebUIPanel(true)
        },
        async (scriptUrl?: string) => {
          console.log('[ChatPage] onComplete callback received scriptUrl:', scriptUrl)

          streamBuffer.flushSync()
          streamMetrics.endSession()

          // On complete, add assistant message with typed chunks for proper rendering
          const assistantChunks = [...collectedChunks]
          setMessages((prev) => {
            const newMessages = [
              ...prev,
              {
                role: 'assistant' as const,
                content: fullContent,
                timestamp: new Date(),
                chunks: assistantChunks,
              },
            ]
            // Cache chunks to localStorage so they survive page refresh
            if (sessionId) {
              const assistantIndex = newMessages.length - 1
              saveSessionChunks(sessionId, assistantIndex, assistantChunks)
            }
            return newMessages
          })
          streamBuffer.clear()
          setPlannerSteps([])
          setLoading(false)
          if (webUiTestEnabled) setShowWebUIPanel(true) // restore config panel after run

          // Save assistant message content to DB along with structured chunks
          // so reload renders proper artifact cards instead of flat text.
          if (sessionId) {
            await createChatMessage(
              sessionId,
              'assistant',
              fullContent,
              assistantChunks.length > 0 ? assistantChunks : null
            )
          }

          // Check if response contains script generation (for saving)
          if (
            fullContent.includes('test_') ||
            fullContent.includes('conftest') ||
            fullContent.includes('```python')
          ) {
            console.log('[ChatPage] Detected script content, showing save button')
            setShowSaveButton(true)
            setLastGeneratedScript(fullContent)
            if (scriptUrl) {
              console.log('[ChatPage] Setting lastGeneratedScriptUrl to:', scriptUrl)
              setLastGeneratedScriptUrl(scriptUrl)
            } else {
              console.log('[ChatPage] No scriptUrl provided, will use fallback')
            }
          }
        },
        (typedChunk) => {
          if (typedChunk.type === 'planner_step' && typedChunk.plannerStep) {
            setPlannerSteps((prev) => [...prev, typedChunk.plannerStep!])
            return // do not push to streamingChunks / not a regular StreamChunk
          }
          if (typedChunk.type === 'wizard_round' && typedChunk.wizardRound) {
            const p = typedChunk.wizardRound
            setWizardEntries((prev) => {
              const marked = prev.map((e) =>
                e.kind === 'wizard_round' && e.data.status === 'pending'
                  ? { ...e, data: { ...e.data, status: 'stale' as const } }
                  : e
              )
              return [
                ...marked,
                {
                  kind: 'wizard_round' as const,
                  data: {
                    kind: 'wizard_round' as const,
                    roundN: p.round_n,
                    roundLabel: p.round_label,
                    question: p.question,
                    options: p.options,
                    allowFreeText: p.allow_free_text,
                    allowBack: p.allow_back,
                    status: 'pending' as const,
                  },
                },
              ]
            })
            return
          }
          if (typedChunk.type === 'wizard_guide' && typedChunk.wizardGuide) {
            const p = typedChunk.wizardGuide
            setWizardEntries((prev) => [
              ...prev,
              {
                kind: 'wizard_guide' as const,
                data: {
                  kind: 'wizard_guide' as const,
                  guideKind: p.kind,
                  markdown: p.markdown,
                },
              },
            ])
            return
          }
          if (typedChunk.type === 'wizard_aborted' && typedChunk.wizardAborted) {
            const p = typedChunk.wizardAborted
            setWizardEntries((prev) => {
              const marked = prev.map((e) =>
                e.kind === 'wizard_round' && e.data.status === 'pending'
                  ? { ...e, data: { ...e.data, status: 'stale' as const } }
                  : e
              )
              return [
                ...marked,
                {
                  kind: 'wizard_aborted' as const,
                  atLabel: p.at_round_label,
                  rounds: p.rounds_used,
                },
              ]
            })
            return
          }
          const chunk: StreamChunk = {
            type: typedChunk.type as StreamChunk['type'],
            content: typedChunk.content,
            isThinking: typedChunk.isThinking,
            author: typedChunk.author,
            stage: typedChunk.stage,
            sshResult: typedChunk.sshResult,
            webUiBugData: typedChunk.webUiBugData,
            webUiArtifactData: typedChunk.webUiArtifactData,
          }
          collectedChunks.push(chunk)
          streamBuffer.push(chunk)

          // Mirror typed web_ui_bug / web_ui_artifact into the page-level
          // result/script state so the WebUI side panel keeps working.
          if (typedChunk.type === 'web_ui_bug' && typedChunk.webUiBugData) {
            const d = typedChunk.webUiBugData
            setWebUiCurrentResult({
              task_id: d.task_id,
              bug_counts: {
                critical: d.bug_counts?.critical ?? 0,
                high: d.bug_counts?.high ?? 0,
                medium: d.bug_counts?.medium ?? 0,
                low: d.bug_counts?.low ?? 0,
              },
              steps_done: d.steps_done ?? 0,
              has_tests: !!d.tests_url,
            })
          } else if (typedChunk.type === 'web_ui_artifact' && typedChunk.webUiArtifactData) {
            setWebUiCurrentScript(typedChunk.webUiArtifactData.script)
            setShowSaveButton(true)
            setLastGeneratedScript(typedChunk.webUiArtifactData.script)
          }

          // Detect Web UI nested result/artifact
          if (webUiTestEnabled && (typedChunk.type === 'log' || typedChunk.type === 'result')) {
            try {
              const inner = JSON.parse(typedChunk.content)
              if (inner.type === 'result' && inner.bug_counts) {
                setWebUiCurrentResult(inner)
                const bugChunk: StreamChunk = {
                  type: 'web_ui_bug',
                  content: '',
                  webUiBugData: {
                    bug_counts: inner.bug_counts,
                    steps_done: inner.steps_done,
                    url: inner.url,
                    task_id: inner.task_id,
                    tests_url: inner.tests_url,
                    bug_report_url: inner.bug_report_url,
                    final_output: inner.final_output,
                    screenshot_urls: inner.screenshot_urls,
                  },
                }
                collectedChunks.push(bugChunk)
                streamBuffer.push(bugChunk)
              }
              if (
                (inner.type === 'artifact' || inner.type === 'web_ui_artifact') &&
                inner.artifact_type === 'web_ui_tests' &&
                inner.content
              ) {
                setWebUiCurrentScript(inner.content)
                const artifactChunk: StreamChunk = {
                  type: 'web_ui_artifact',
                  content: '',
                  webUiArtifactData: {
                    script: inner.content,
                    name: inner.name,
                    task_id: inner.task_id,
                  },
                }
                collectedChunks.push(artifactChunk)
                streamBuffer.push(artifactChunk)
                setShowSaveButton(true)
                setLastGeneratedScript(inner.content)
              }
            } catch {}
            // Update phase progress from log text
            if (typedChunk.type === 'log') {
              updatePhaseFromLog(typedChunk.content)
            }
          }

          // Accumulate all content into fullContent for DB persistence
          if (typedChunk.type === 'result') {
            fullContent += typedChunk.content
          } else if (typedChunk.type === 'error') {
            fullContent += '\n**Error:** ' + typedChunk.content + '\n'
          } else if (typedChunk.type === 'ssh_result' && typedChunk.sshResult) {
            const r = typedChunk.sshResult
            fullContent +=
              '\n**Remote Test Execution ' +
              (r.success ? 'Succeeded' : 'Failed') +
              '** (Exit Code: ' +
              r.exit_code +
              ')\n'
            if (r.stdout) fullContent += '\n```\n' + r.stdout + '\n```\n'
            if (r.stderr) fullContent += '\n**stderr:**\n```\n' + r.stderr + '\n```\n'
            if (r.allure_results_url)
              fullContent += '\n[Download Allure Results](' + r.allure_results_url + ')\n'
          } else if (typedChunk.type === 'log') {
            fullContent += typedChunk.content + '\n'
          }
        }
      )
    } catch (err: any) {
      console.error('Error:', err)
      setError(typeof err.message === 'string' ? err.message : JSON.stringify(err))
      streamBuffer.flushSync()
      streamMetrics.endSession()
      setLoading(false)
      streamBuffer.clear()
      setPlannerSteps([])
      if (webUiTestEnabled) setShowWebUIPanel(true)
    }
  }

  const handleSaveScript = async () => {
    try {
      const scriptName = `Test Script - ${new Date().toISOString().split('T')[0]}`

      console.log(
        '[ChatPage] handleSaveScript called, lastGeneratedScriptUrl:',
        lastGeneratedScriptUrl
      )

      if (lastGeneratedScriptUrl) {
        // Use the R2 URL if available
        console.log('[ChatPage] Using R2 URL path, saving:', lastGeneratedScriptUrl)
        await createScript({
          name: scriptName,
          script_address: lastGeneratedScriptUrl,
          description: `Generated from chat on ${new Date().toISOString().split('T')[0]}`,
          version: '1.0.0',
        })
      } else {
        console.log('[ChatPage] No R2 URL, using fallback path with uploadScript')
        // Fallback: Extract Python script content from the full response
        let scriptContent = lastGeneratedScript

        // Try to extract Python code from markdown code blocks
        const pythonCodeMatch = scriptContent.match(/```python\n([\s\S]*?)```/)
        if (pythonCodeMatch && pythonCodeMatch[1]) {
          scriptContent = pythonCodeMatch[1].trim()
        } else {
          // If no markdown code block, try to extract code between ``` markers
          const codeMatch = scriptContent.match(/```\n([\s\S]*?)```/)
          if (codeMatch && codeMatch[1]) {
            scriptContent = codeMatch[1].trim()
          }
        }

        // Use the existing save-script endpoint
        await uploadScript({
          name: scriptName,
          content: scriptContent,
          description: `Generated from chat on ${new Date().toISOString().split('T')[0]}`,
          version: '1.0.0',
        })
      }

      setShowSaveButton(false)

      // Show success message with option to view scripts
      if (window.confirm('Script saved successfully! Would you like to view your scripts now?')) {
        router.push('/scripts')
      }
    } catch (err: any) {
      console.error('Failed to save script:', err)
      alert('Failed to save script: ' + (err.message || 'Unknown error'))
    }
  }

  return (
    <div className="flex h-[calc(100vh-4rem)] overflow-hidden">
      {/* Sidebar - hidden in trial mode */}
      {!trialMode && (
        <div
          className={`${
            isSidebarOpen ? 'w-64' : 'w-0'
          } bg-gray-50 border-r border-gray-200 flex flex-col transition-all duration-300 ease-in-out overflow-hidden flex-shrink-0`}
        >
          <div className="p-4 border-b border-gray-200">
            {!isManageMode ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleNewChat(true)}
                  className="flex items-center gap-2 flex-1 rounded-md bg-blue-600 px-3 py-2 text-sm font-medium text-white hover:bg-blue-700 transition-colors"
                >
                  <Plus className="h-4 w-4" />
                  New Chat
                </button>
                <button
                  onClick={handleEnterManageMode}
                  disabled={sessions.length === 0}
                  className="flex items-center gap-1 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-40"
                  title="Bulk select sessions"
                >
                  <Check className="h-4 w-4" />
                  Manage
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm font-medium text-gray-700">
                  <span>
                    Selected: {selectedIds.size}/{sessions.length}
                  </span>
                  <button
                    onClick={handleExitManageMode}
                    className="flex items-center gap-1 rounded-md p-1 text-gray-500 hover:bg-gray-200"
                    title="Cancel (Esc)"
                  >
                    <X className="h-4 w-4" />
                    Cancel
                  </button>
                </div>
                <div className="flex items-center gap-1">
                  <button
                    onClick={handleToggleSelectAll}
                    className="flex items-center gap-1 rounded-md border border-gray-300 bg-white px-2 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50"
                  >
                    {selectedIds.size === sessions.length && sessions.length > 0 ? (
                      <CheckSquare className="h-3.5 w-3.5" />
                    ) : (
                      <Square className="h-3.5 w-3.5" />
                    )}
                    {selectedIds.size === sessions.length && sessions.length > 0 ? 'None' : 'All'}
                  </button>
                  <button
                    onClick={handleOpenBulkDelete}
                    disabled={selectedIds.size === 0 || isBulkDeleting || isExporting}
                    className="flex items-center gap-1 rounded-md bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-40"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete
                  </button>
                  <button
                    onClick={handleBulkExport}
                    disabled={selectedIds.size === 0 || isBulkDeleting || isExporting}
                    className="flex items-center gap-1 rounded-md border border-gray-300 bg-white px-2 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-40"
                  >
                    <Download className="h-3.5 w-3.5" />
                    {isExporting
                      ? `Exporting (${exportProgress.done}/${exportProgress.total})…`
                      : 'Export'}
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="flex-1 overflow-y-auto p-2 space-y-1">
            {sessions.map((session) => {
              const isSelected = selectedIds.has(session.id)
              return (
                <div
                  key={session.id}
                  onClick={() => handleSelectSession(session.id)}
                  className={`group flex items-center gap-3 rounded-md px-3 py-2 text-sm cursor-pointer transition-colors ${
                    !isManageMode && currentSessionId === session.id
                      ? 'bg-blue-100 text-blue-900'
                      : isManageMode && isSelected
                        ? 'bg-blue-50 text-blue-900'
                        : 'text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  {isManageMode ? (
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => handleToggleSelected(session.id)}
                      onClick={(e) => e.stopPropagation()}
                      className="h-4 w-4 flex-shrink-0 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                      aria-label={`Select ${session.title}`}
                    />
                  ) : (
                    <MessageSquare className="h-4 w-4 flex-shrink-0 opacity-50" />
                  )}
                  <span className="flex-1 truncate">{session.title}</span>
                  {!isManageMode && (
                    <button
                      onClick={(e) => handleDeleteSession(e, session.id)}
                      className="opacity-0 group-hover:opacity-100 p-1 hover:bg-red-100 hover:text-red-600 rounded transition-all"
                    >
                      <Trash2 className="h-3 w-3" />
                    </button>
                  )}
                </div>
              )
            })}

            {sessions.length === 0 && (
              <div className="text-center py-8 text-gray-500 text-sm">No chat history</div>
            )}
          </div>
          {bulkActionBanner && (
            <div className="m-2 rounded-md border border-blue-200 bg-blue-50 px-3 py-2 text-xs text-blue-800">
              {bulkActionBanner}
            </div>
          )}
          <div className="p-3 border-t border-gray-200">
            <QuotaBadge />
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header */}
        <div className="h-14 border-b border-gray-200 flex items-center px-4 justify-between bg-white">
          <div className="flex items-center gap-3">
            {!trialMode && (
              <button
                onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                className="p-2 rounded-md hover:bg-gray-100 text-gray-600"
              >
                {isSidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
              </button>
            )}
            <h1 className="text-lg font-semibold truncate">
              {trialMode
                ? 'API Test Trial'
                : currentSessionId
                  ? sessions.find((s) => s.id === currentSessionId)?.title || 'Chat'
                  : 'New Chat'}
            </h1>
            {trialMode && (
              <span className="rounded-full bg-amber-100 px-2.5 py-0.5 text-xs font-medium text-amber-800">
                Trial Mode
              </span>
            )}
          </div>

          <div className="flex items-center gap-4">
            {!trialMode && showSaveButton && (
              <button
                onClick={handleSaveScript}
                className="rounded-md bg-green-600 px-4 py-2 text-sm font-medium text-white hover:bg-green-700"
              >
                Save Script
              </button>
            )}

            {!trialMode && (
              <div className="flex items-center gap-2">
                <Globe className="h-4 w-4 text-purple-500 hidden md:block" />
                <span className="text-sm text-muted-foreground hidden md:inline">Web UI</span>
                <button
                  type="button"
                  aria-pressed={webUiTestEnabled}
                  onClick={() => setWebUiTestEnabled((prev) => !prev)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors duration-200 ${webUiTestEnabled ? 'bg-purple-500' : 'bg-gray-200'}`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform duration-200 ${webUiTestEnabled ? 'translate-x-5' : 'translate-x-1'}`}
                  />
                </button>
                {webUiTestEnabled && isLocalMode && (
                  <button
                    onClick={() => setShowCDPDialog(true)}
                    className="rounded bg-indigo-100 px-2 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-200 transition-colors"
                  >
                    CDP ⚙️
                  </button>
                )}
              </div>
            )}

            {/* Test Environment Segmented Control */}
            {!trialMode && (
              <div className="flex items-center gap-2">
                <div className="relative">
                  <button
                    type="button"
                    className="text-muted-foreground hover:text-foreground transition-colors"
                    aria-label="Test environment info"
                    onClick={() => setShowTestEnvInfo((prev) => !prev)}
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      viewBox="0 0 20 20"
                      fill="currentColor"
                      className="w-4 h-4"
                    >
                      <path
                        fillRule="evenodd"
                        d="M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0ZM8.94 6.94a.75.75 0 1 1-1.061-1.061 3 3 0 1 1 2.871 5.026v.345a.75.75 0 0 1-1.5 0v-.5c0-.72.57-1.172 1.081-1.287A1.5 1.5 0 1 0 8.94 6.94ZM10 15a1 1 0 1 0 0-2 1 1 0 0 0 0 2Z"
                        clipRule="evenodd"
                      />
                    </svg>
                  </button>
                  {showTestEnvInfo && (
                    <>
                      <div
                        className="fixed inset-0 z-40"
                        onClick={() => setShowTestEnvInfo(false)}
                      />
                      <div className="absolute top-full right-0 mt-2 w-80 p-3 bg-popover text-popover-foreground text-xs rounded-lg shadow-lg border z-50">
                        <p className="font-semibold mb-2">Test Environment</p>
                        <div className="space-y-2">
                          <div>
                            <p className="font-medium">Cloud</p>
                            <p className="text-muted-foreground">
                              Tests run on Argus cloud infrastructure. No setup required.
                              Supports API testing and browser automation via Playwright.
                            </p>
                          </div>
                          <div className="border-t pt-2">
                            <p className="font-medium">My Machine</p>
                            <p className="text-muted-foreground">
                              Tests run on your local machine via the Client Agent. Best for
                              intranet URLs or reusing your own browser session. Requires the Client
                              Agent to be running.
                            </p>
                          </div>
                          <div className="border-t pt-2">
                            <p className="font-medium text-muted-foreground">
                              Custom SSH Host (Advanced)
                            </p>
                            <p className="text-muted-foreground">
                              When using Cloud, you can optionally configure a custom SSH host to
                              run tests on your own server instead of Argus infrastructure.
                            </p>
                          </div>
                        </div>
                      </div>
                    </>
                  )}
                </div>
                <div className="inline-flex rounded-lg border border-gray-200 bg-gray-100 p-0.5">
                  <button
                    type="button"
                    onClick={() => setTestEnv('cloud')}
                    className={`rounded-md px-3 py-1 text-xs font-medium transition-all duration-200 ${
                      testEnv === 'cloud'
                        ? 'bg-white text-blue-700 shadow-sm'
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    <span className="hidden sm:inline">Cloud</span>
                    <span className="sm:hidden">Cloud</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setTestEnv('local')
                      if (!agentOnline) {
                        setShowTokenDialog(true)
                      }
                    }}
                    className={`rounded-md px-3 py-1 text-xs font-medium transition-all duration-200 ${
                      testEnv === 'local'
                        ? 'bg-white text-blue-700 shadow-sm'
                        : 'text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    <span className="hidden sm:inline">My Machine</span>
                    <span className="sm:hidden">Local</span>
                  </button>
                </div>
                {/* SSH shortcut for cloud env */}
                {testEnv === 'cloud' && (
                  <button
                    type="button"
                    onClick={() => setShowSSHDialog(true)}
                    className={`rounded px-2 py-1 text-xs font-medium transition-colors ${
                      sshConfig
                        ? 'bg-blue-100 text-blue-700 hover:bg-blue-200'
                        : 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                    }`}
                    title="Optional: Use your own server instead of Argus cloud"
                  >
                    {sshConfig ? `SSH: ${sshConfig.username}@${sshConfig.remote_ip}` : 'SSH'}
                  </button>
                )}
              </div>
            )}

            {/* Local env: Client Agent status */}
            {!trialMode && testEnv === 'local' && (
              <div className="flex items-center gap-2 rounded-md border border-gray-200 bg-white px-2.5 py-1 shadow-sm">
                <button
                  type="button"
                  onClick={() => setShowTokenDialog(true)}
                  className="rounded bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 hover:bg-blue-200 transition-colors"
                  title="Configure Client Agent"
                >
                  Agent
                </button>
                <div className="h-3 w-px bg-gray-300"></div>
                <div className="relative flex items-center">
                  <div
                    className={`h-2 w-2 rounded-full transition-colors duration-300 ${agentOnline ? 'bg-green-500' : 'bg-gray-400'}`}
                  >
                    {agentOnline && (
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75"></span>
                    )}
                  </div>
                </div>
                <span
                  className={`text-xs font-medium ${agentOnline ? 'text-green-700' : 'text-gray-500'}`}
                >
                  {checkingAgent ? 'Checking...' : agentOnline ? 'Online' : 'Offline'}
                </span>
                <button
                  onClick={checkAgentStatus}
                  disabled={checkingAgent}
                  className="rounded p-0.5 hover:bg-gray-100 disabled:opacity-50"
                  title="Refresh status"
                >
                  <Icons.spinner className={`h-3 w-3 ${checkingAgent ? 'animate-spin' : ''}`} />
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="flex flex-1 gap-6 overflow-hidden p-6">
          {/* Chat Display Area */}
          <div className="flex flex-1 flex-col overflow-hidden rounded-lg border bg-white shadow-sm">
            <div ref={scrollContainerRef} className="flex-1 overflow-y-auto p-6">
              {/* Trial error/expired message */}
              {trialError && (
                <div className="flex h-full items-center justify-center text-center">
                  <div className="max-w-md space-y-4">
                    <AlertCircle className="mx-auto h-12 w-12 text-amber-500" />
                    <h2 className="text-xl font-semibold text-gray-900">{trialError}</h2>
                    <a
                      href="/login"
                      className="inline-block rounded-md bg-blue-600 px-6 py-2 text-sm font-medium text-white hover:bg-blue-700"
                    >
                      Sign Up Free
                    </a>
                  </div>
                </div>
              )}

              {messages.length === 0 && streamingChunks.length === 0 && !trialError && (
                <div className="flex h-full items-center justify-center p-6">
                  {trialMode ? (
                    <div className="max-w-md text-center">
                      <Icons.sparkles className="mx-auto mb-4 h-12 w-12 text-blue-500" />
                      <h2 className="mb-2 text-xl font-semibold">Running Your Free API Test...</h2>
                      <p className="text-gray-600">{`Testing: ${trialUrl}`}</p>
                      {loading && (
                        <Icons.spinner className="mx-auto mt-4 h-6 w-6 animate-spin text-blue-500" />
                      )}
                    </div>
                  ) : (
                    <div className="max-w-2xl w-full space-y-6">
                      <div className="text-center">
                        <Icons.sparkles className="mx-auto mb-3 h-10 w-10 text-blue-500" />
                        <h2 className="text-xl font-semibold text-gray-900">
                          What do you want to test?
                        </h2>
                        <p className="text-sm text-gray-500 mt-1">
                          Enter a URL or describe your testing goal
                        </p>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <button
                          onClick={() => {
                            setContent('https://')
                          }}
                          className="group rounded-xl border-2 border-blue-100 bg-blue-50 p-4 text-left hover:border-blue-300 hover:bg-blue-100 transition-all"
                        >
                          <div className="text-2xl mb-2">🔌</div>
                          <div className="font-semibold text-blue-900 text-sm">API Testing</div>
                          <div className="text-xs text-blue-700 mt-1 opacity-80">
                            Paste Swagger/OpenAPI URL to auto-generate comprehensive test suites
                          </div>
                        </button>
                        <button
                          onClick={() => {
                            setWebUiTestEnabled(true)
                            setContent('https://')
                          }}
                          className="group rounded-xl border-2 border-purple-100 bg-purple-50 p-4 text-left hover:border-purple-300 hover:bg-purple-100 transition-all"
                        >
                          <div className="text-2xl mb-2">🌐</div>
                          <div className="font-semibold text-purple-900 text-sm">
                            Web UI Testing
                          </div>
                          <div className="text-xs text-purple-700 mt-1 opacity-80">
                            AI browser automation explores your app, finds bugs, generates
                            Playwright tests
                          </div>
                        </button>
                      </div>
                      {recentWebUITasks.length > 0 && (
                        <div>
                          <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
                            Recent Web UI Tests
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {recentWebUITasks.slice(0, 5).map((task) => {
                              const total = task.bug_counts
                                ? task.bug_counts.critical +
                                  task.bug_counts.high +
                                  task.bug_counts.medium +
                                  task.bug_counts.low
                                : null
                              return (
                                <button
                                  key={task.id}
                                  onClick={() => {
                                    setWebUiTestEnabled(true)
                                    setContent(task.target_url)
                                  }}
                                  className="flex items-center gap-2 rounded-lg border bg-white px-3 py-2 text-xs hover:bg-gray-50 shadow-sm"
                                >
                                  <Globe className="h-3 w-3 text-purple-500" />
                                  <span className="text-gray-700 max-w-[140px] truncate">
                                    {new URL(task.target_url).hostname}
                                  </span>
                                  {total !== null && (
                                    <span
                                      className={`rounded-full px-1.5 py-0.5 ${total > 0 ? 'bg-red-100 text-red-600' : 'bg-green-100 text-green-600'}`}
                                    >
                                      {total > 0 ? `${total} bugs` : '✓'}
                                    </span>
                                  )}
                                </button>
                              )
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              <div className="space-y-4">
                {messages.map((message, index) => (
                  <div
                    key={index}
                    className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    {message.role === 'user' ? (
                      <div className="max-w-[80%] rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 text-gray-900">
                        <div className="mb-1 text-xs text-gray-500">You</div>
                        <FormattedMessage content={message.content} />
                        <div className="mt-1 text-xs text-gray-500">
                          {message.timestamp.toLocaleTimeString()}
                        </div>
                      </div>
                    ) : (
                      <div className="w-full max-w-3xl">
                        {message.chunks && message.chunks.length > 0 ? (
                          groupChunks(message.chunks).map((group, i) => (
                            <ChatMessage
                              key={i}
                              group={group}
                              onRerunWebUI={(url) => {
                                setWebUiTestEnabled(true)
                                setContent(url)
                              }}
                              onSaveScript={(script) => {
                                setLastGeneratedScript(script)
                                setShowSaveButton(true)
                              }}
                            />
                          ))
                        ) : (
                          <FormattedMessage content={message.content} />
                        )}
                        <div className="mt-1 text-xs text-gray-400">
                          {message.timestamp.toLocaleTimeString()}
                        </div>
                      </div>
                    )}
                  </div>
                ))}

                {wizardEntries.length > 0 && (
                  <div className="space-y-3">
                    {wizardEntries.map((e, i) => {
                      if (e.kind === 'wizard_round') {
                        return (
                          <WizardRoundMessage
                            key={`wiz-${i}`}
                            {...e.data}
                            onSelect={(v) => {
                              setWizardEntries((prev) =>
                                prev.map((x, xi) =>
                                  xi === i
                                    ? ({
                                        kind: 'wizard_round' as const,
                                        data: {
                                          ...e.data,
                                          status: 'answered' as const,
                                          selectedAnswer: v,
                                        },
                                      } satisfies WizardEntry)
                                    : x
                                )
                              )
                              postWizardInput(
                                e.data.roundN,
                                e.data.allowFreeText ? 'free_text' : 'option_click',
                                v
                              )
                            }}
                            onBack={() => postWizardInput(e.data.roundN, 'back')}
                            onAbort={() => postWizardInput(e.data.roundN, 'abort')}
                          />
                        )
                      }
                      if (e.kind === 'wizard_guide') {
                        return <WizardGuideMessage key={`wiz-${i}`} {...e.data} />
                      }
                      if (e.kind === 'wizard_aborted') {
                        return (
                          <div key={`wiz-${i}`} className="text-sm text-muted-foreground py-2">
                            Wizard aborted at {e.atLabel} ({e.rounds} round(s) used).
                          </div>
                        )
                      }
                      return null
                    })}
                  </div>
                )}

                {(streamingChunks.length > 0 || plannerSteps.length > 0) && (
                  <div className="flex justify-start">
                    <div className="w-full max-w-3xl">
                      {webUiTestEnabled && <PhaseProgressBar phases={webUiPhases} />}
                      {plannerSteps.length > 0 && <PlannerTimeline steps={plannerSteps} />}
                      {groupChunks(streamingChunks).map((group, i) => (
                        <ChatMessage
                          key={i}
                          group={group}
                          isStreaming={loading}
                          onRerunWebUI={(url) => {
                            setWebUiTestEnabled(true)
                            setContent(url)
                          }}
                          onSaveScript={(script) => {
                            setLastGeneratedScript(script)
                            setShowSaveButton(true)
                          }}
                        />
                      ))}
                      <div className="mt-2">
                        <Icons.spinner className="h-4 w-4 animate-spin" />
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div ref={messagesEndRef} />
            </div>

            {error && (
              <div className="border-t bg-red-50 px-6 py-3">
                <div className="flex items-start gap-2">
                  <span className="text-red-600">Error:</span>
                  <span className="flex-1 text-sm text-red-600">{error}</span>
                  <button
                    onClick={() => setError(null)}
                    className="text-red-600 hover:text-red-800"
                  >
                    ×
                  </button>
                </div>
              </div>
            )}

            {/* Input Form or Trial Sign-Up Wall */}
            {trialMode && trialUsed ? (
              <div className="border-t bg-amber-50 p-6">
                <div className="flex flex-col items-center gap-3 text-center">
                  <p className="text-sm font-medium text-amber-800">
                    Your free trial has been used. Sign up to continue testing.
                  </p>
                  <a
                    href="/login"
                    className="inline-block rounded-md bg-blue-600 px-6 py-2 text-sm font-medium text-white hover:bg-blue-700"
                  >
                    Sign Up Free
                  </a>
                </div>
              </div>
            ) : trialMode ? (
              <div className="border-t bg-gray-50 px-6 py-3">
                <p className="text-xs text-center text-gray-500">
                  This is a one-time trial test. Sign up for unlimited access.
                </p>
              </div>
            ) : (
              <>
                {webUiTestEnabled && showWebUIPanel && (
                  <WebUIConfigPanel
                    config={webUiConfig}
                    onChange={setWebUiConfig}
                    onClose={() => setShowWebUIPanel(false)}
                    isLocalMode={isLocalMode}
                    onOpenCDPDialog={() => setShowCDPDialog(true)}
                  />
                )}
                <form ref={formRef} onSubmit={handleSubmit} className="border-t bg-gray-50 p-6">
                  <div className="space-y-3">
                    <div>
                      <textarea
                        value={content}
                        onChange={(e) => setContent(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
                            e.preventDefault()
                            e.currentTarget.form?.requestSubmit()
                          }
                        }}
                        placeholder={
                          webUiTestEnabled
                            ? '🌐 Enter web app URL to explore with AI browser (e.g. https://app.example.com)'
                            : 'Enter a URL, project description, or requirements to generate tests...'
                        }
                        className="w-full resize-none rounded-md border p-3 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                        rows={3}
                        disabled={loading}
                      />
                      <p className="mt-1 text-xs text-gray-500">
                        Tip: Press{' '}
                        <kbd className="px-1.5 py-0.5 text-xs font-semibold text-gray-800 bg-gray-100 border border-gray-300 rounded">
                          Ctrl
                        </kbd>{' '}
                        +{' '}
                        <kbd className="px-1.5 py-0.5 text-xs font-semibold text-gray-800 bg-gray-100 border border-gray-300 rounded">
                          Enter
                        </kbd>{' '}
                        to submit
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      {/* Config summary badge */}
                      {!loading && (
                        <span className="hidden sm:inline-flex items-center gap-1.5 rounded-full bg-gray-100 px-3 py-1 text-xs text-gray-600">
                          {webUiTestEnabled ? 'Browser Test' : 'API Test'}
                          <span className="text-gray-400">on</span>
                          {testEnv === 'cloud'
                            ? sshConfig
                              ? `SSH (${sshConfig.remote_ip})`
                              : 'Cloud (Test Runner)'
                            : 'Local'}
                        </span>
                      )}
                      {loading ? (
                        <button
                          type="button"
                          onClick={() => {
                            cancelWebUITest().catch(() => {})
                            abortControllerRef.current?.abort()
                            setLoading(false)
                          }}
                          className="flex items-center gap-2 rounded-md bg-red-500 px-6 py-2 font-medium text-white transition-colors hover:bg-red-600"
                        >
                          <X className="h-4 w-4" />
                          Stop
                        </button>
                      ) : (
                        <button
                          type="submit"
                          disabled={loading || !content.trim()}
                          className={`flex items-center gap-2 rounded-md px-6 py-2 font-medium text-white disabled:opacity-50 transition-colors ${webUiTestEnabled ? 'bg-purple-600 hover:bg-purple-700' : 'bg-blue-600 hover:bg-blue-700'}`}
                        >
                          {webUiTestEnabled ? (
                            <Globe className="h-4 w-4" />
                          ) : (
                            <Icons.send className="h-4 w-4" />
                          )}
                          {webUiTestEnabled ? 'Start Web UI Test' : 'Execute'}
                        </button>
                      )}
                    </div>
                  </div>
                </form>
              </>
            )}
          </div>

          {/* Context Panel - hidden in trial mode */}
          {!trialMode && (
            <Card className="w-80 flex-shrink-0 hidden xl:block">
              <CardHeader>
                <CardTitle className="text-lg">Context (Optional)</CardTitle>
                <CardDescription>Additional information in JSON format</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="min-h-[400px] w-full rounded-md border border-gray-200 font-mono text-sm shadow-sm overflow-hidden bg-gray-50">
                  <Editor
                    value={context}
                    onValueChange={(code) => setContext(code)}
                    highlight={(code) => highlight(code, languages.json, 'json')}
                    padding={12}
                    style={{
                      fontFamily: '"Fira code", "Fira Mono", monospace',
                      fontSize: 14,
                      minHeight: '400px',
                    }}
                    textareaClassName="focus:outline-none"
                    placeholder='{
                    "project_type": "web",
                    "cookie": "",
                    "token": ""
                  }'
                    disabled={loading}
                  />
                </div>
                <div className="mt-4 space-y-2 text-xs text-gray-600">
                  <p className="font-semibold">Examples:</p>
                  <ul className="space-y-1 pl-4">
                    <li>• project_type: web, mobile, api</li>
                    <li>• cookie: {'{ "name": "value" }'} (bi-pass auth)</li>
                    <li>• token: "eyJhbG..." (Authorization header)</li>
                    <li>• tech_stack: [frameworks, languages]</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* CDP Config Dialog */}
      <CDPConfigDialog
        isOpen={showCDPDialog}
        onClose={() => setShowCDPDialog(false)}
        config={webUiConfig.cdpUrl ? { cdp_url: webUiConfig.cdpUrl } : null}
        onSave={(cdpConfig) => {
          setWebUiConfig((prev) => ({ ...prev, cdpUrl: cdpConfig.cdp_url }))
        }}
        onDisable={() => {
          setWebUiConfig((prev) => ({ ...prev, cdpUrl: '' }))
        }}
      />

      {/* SSH Config Dialog */}
      {showSSHDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-2xl">
            <h2 className="mb-4 text-lg font-semibold text-gray-900">SSH Configuration</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Remote IP Address
                </label>
                <input
                  type="text"
                  value={sshFormIP}
                  onChange={(e) => setSSHFormIP(e.target.value)}
                  placeholder="e.g. 192.168.1.100"
                  className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Username</label>
                <input
                  type="text"
                  value={sshFormUsername}
                  onChange={(e) => setSSHFormUsername(e.target.value)}
                  placeholder="e.g. ubuntu"
                  className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  PEM Private Key
                </label>
                <input
                  type="file"
                  accept=".pem,.key"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) {
                      const reader = new FileReader()
                      reader.onload = () => {
                        const base64 = btoa(reader.result as string)
                        setSSHFormPemBase64(base64)
                      }
                      reader.readAsText(file)
                    }
                  }}
                  className="w-full text-sm text-gray-500 file:mr-4 file:rounded-md file:border-0 file:bg-blue-50 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-blue-700 hover:file:bg-blue-100"
                />
                {sshFormPemBase64 && <p className="mt-1 text-xs text-green-600">PEM key loaded</p>}
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Pytest Arguments
                </label>
                <input
                  type="text"
                  value={sshFormPytestArgs}
                  onChange={(e) => setSSHFormPytestArgs(e.target.value)}
                  placeholder="--alluredir=./allure-results -v"
                  className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>
            <div className="mt-6 flex justify-between">
              {sshConfig ? (
                <button
                  onClick={() => {
                    setSSHConfig(null)
                    setSSHFormIP('')
                    setSSHFormUsername('')
                    setSSHFormPemBase64('')
                    setSSHFormPytestArgs('--alluredir=./allure-results -v')
                    localStorage.removeItem('sshConfig')
                    setShowSSHDialog(false)
                  }}
                  className="rounded-md px-4 py-2 text-sm font-medium text-red-600 hover:bg-red-50"
                >
                  Clear
                </button>
              ) : (
                <div />
              )}
              <div className="flex gap-3">
                <button
                  onClick={() => {
                    setShowSSHDialog(false)
                  }}
                  className="rounded-md px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    if (!sshFormIP || !sshFormUsername || !sshFormPemBase64) {
                      alert('Please fill in all required fields (IP, Username, PEM key)')
                      return
                    }
                    const config: SSHConfig = {
                      remote_ip: sshFormIP,
                      username: sshFormUsername,
                      pem_key_base64: sshFormPemBase64,
                      pytest_args: sshFormPytestArgs,
                    }
                    setSSHConfig(config)
                    localStorage.setItem('sshConfig', JSON.stringify(config))
                    setShowSSHDialog(false)
                  }}
                  className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700"
                >
                  Save
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* OAuth Token Dialog */}
      <OAuthTokenDialog
        isOpen={showTokenDialog}
        onClose={() => {
          setShowTokenDialog(false)
        }}
        localTestEnabled={testEnv === 'local'}
        onLocalTestEnabledChange={(enabled) => setTestEnv(enabled ? 'local' : 'cloud')}
      />

      {/* Bulk Delete Dialog */}
      <BulkDeleteDialog
        isOpen={showBulkDeleteDialog}
        onClose={() => setShowBulkDeleteDialog(false)}
        onConfirm={handleConfirmBulkDelete}
        sessionTitles={sessions.filter((s) => selectedIds.has(s.id)).map((s) => s.title)}
        isDeleting={isBulkDeleting}
      />
    </div>
  )
}

export default function ChatPage() {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen w-screen items-center justify-center">
          <Icons.spinner className="h-8 w-8 animate-spin" />
        </div>
      }
    >
      <ChatPageContent />
    </Suspense>
  )
}
