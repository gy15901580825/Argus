export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'https://www.example.com'

// Helper to access auth store imperatively
import { useAuthStore } from '@/store/useAuthStore'
import type {
  WizardInput,
  WizardRoundEvent,
  WizardAbortedEvent,
  WizardGuideEvent,
} from './wizard-types'

type FetchOptions = RequestInit & {
  params?: Record<string, string>
}

export async function fetchClient<T>(endpoint: string, options: FetchOptions = {}): Promise<T> {
  const { params, ...init } = options

  const url = new URL(`${API_BASE_URL}${endpoint}`)

  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.append(key, value)
    })
  }

  // Inject API Token if available
  const apiToken = useAuthStore.getState().apiToken
  const headers = new Headers(init.headers)

  if (apiToken) {
    headers.set('x-api-token', apiToken)
  }

  // Set default content type if not present
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(url.toString(), {
    ...init,
    headers,
  })

  if (!response.ok) {
    let errorMessage = `API request failed: ${response.status} ${response.statusText}`
    try {
      const errorData = await response.json()
      // Try to extract a meaningful message from common error formats
      const detail = errorData.detail || errorData.message || errorData.error
      if (detail) {
        errorMessage = typeof detail === 'string' ? detail : JSON.stringify(detail)
      } else {
        errorMessage = JSON.stringify(errorData)
      }
    } catch {
      // If JSON parsing fails, try to get text body
      const errorText = await response.text().catch(() => '')
      if (errorText) {
        errorMessage = `${errorMessage} - ${errorText.slice(0, 100)}`
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

// Blog Types
export interface BlogResponse {
  id: string
  title: string
  content: string
  slug?: string
  summary?: string
  author_id: string
  author_name?: string
  is_published: boolean
  published_at?: string
  created_at: string
  updated_at: string
  category_id?: string
  category_name?: string
  category_slug?: string
  cover_image_url?: string
  meta_title?: string
  meta_description?: string
  og_image_url?: string
  canonical_url?: string
  reading_time_min?: number
  view_count: number
  content_format: string
  featured: boolean
  status: string
  tags?: { id: string; name: string; slug: string }[]
}

export interface BlogListItem {
  id: string
  title: string
  slug?: string
  summary?: string
  author_id: string
  author_name?: string
  is_published: boolean
  published_at?: string
  created_at: string
  category_id?: string
  category_name?: string
  category_slug?: string
  cover_image_url?: string
  reading_time_min?: number
  view_count: number
  featured: boolean
  status: string
  tags?: { id: string; name: string; slug: string }[]
}

export interface CategoryResponse {
  id: string
  name: string
  slug: string
  description?: string
  parent_id?: string
  sort_order: number
  created_at: string
  post_count: number
}

export interface TagResponse {
  id: string
  name: string
  slug: string
  created_at: string
  post_count: number
}

export interface CommentResponse {
  id: string
  content: string
  user_id: string
  user_name?: string
  blog_id: string
  parent_comment_id?: string
  created_at: string
  updated_at: string
  status: string
  likes_count: number
}

// Blog Admin API Functions
export interface BlogCreateRequest {
  title: string
  content: string
  slug?: string
  summary?: string
  category_id?: string
  tag_ids?: string[]
  cover_image_url?: string
  meta_title?: string
  meta_description?: string
  og_image_url?: string
  canonical_url?: string
  content_format?: string
  featured?: boolean
  status?: string
  scheduled_at?: string
}

export interface BlogUpdateRequest {
  title?: string
  content?: string
  slug?: string
  summary?: string
  category_id?: string
  tag_ids?: string[]
  cover_image_url?: string
  meta_title?: string
  meta_description?: string
  og_image_url?: string
  canonical_url?: string
  content_format?: string
  featured?: boolean
  status?: string
  is_published?: boolean
  scheduled_at?: string
}

export interface MediaAsset {
  id: string
  filename: string
  r2_key: string
  r2_url: string
  mime_type: string
  file_size_bytes: number
  width?: number
  height?: number
  alt_text?: string
  uploaded_by: string
  created_at: string
}

export async function createBlog(data: BlogCreateRequest): Promise<BlogResponse> {
  return fetchClient<BlogResponse>('/api/v1/blogs', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export async function updateBlog(id: string, data: BlogUpdateRequest): Promise<BlogResponse> {
  return fetchClient<BlogResponse>(`/api/v1/blogs/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  })
}

export async function deleteBlog(id: string): Promise<void> {
  return fetchClient<void>(`/api/v1/blogs/${id}`, { method: 'DELETE' })
}

export async function getAdminBlogs(
  params: BlogListParams & { include_unpublished?: boolean; status?: string } = {}
): Promise<BlogListItem[]> {
  const p: Record<string, string> = {
    limit: (params.limit ?? 50).toString(),
    offset: (params.offset ?? 0).toString(),
    include_unpublished: 'true',
  }
  if (params.status) p.status = params.status
  if (params.q) p.q = params.q
  return fetchClient<BlogListItem[]>('/api/v1/blogs', { params: p })
}

export async function createCategory(data: {
  name: string
  slug?: string
  description?: string
  parent_id?: string
  sort_order?: number
}): Promise<CategoryResponse> {
  return fetchClient<CategoryResponse>('/api/v1/blog/categories', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export async function deleteCategory(id: string): Promise<void> {
  return fetchClient<void>(`/api/v1/blog/categories/${id}`, { method: 'DELETE' })
}

export async function createTag(data: { name: string; slug?: string }): Promise<TagResponse> {
  return fetchClient<TagResponse>('/api/v1/blog/tags', {
    method: 'POST',
    body: JSON.stringify(data),
  })
}

export async function deleteTag(id: string): Promise<void> {
  return fetchClient<void>(`/api/v1/blog/tags/${id}`, { method: 'DELETE' })
}

export async function getMediaAssets(limit = 50, offset = 0): Promise<MediaAsset[]> {
  return fetchClient<MediaAsset[]>('/api/v1/blog/media', {
    params: { limit: limit.toString(), offset: offset.toString() },
  })
}

export async function uploadMedia(file: File): Promise<MediaAsset> {
  const formData = new FormData()
  formData.append('file', file)
  const apiToken = useAuthStore.getState().apiToken
  const headers: Record<string, string> = {}
  if (apiToken) headers['x-api-token'] = apiToken
  const res = await fetch(`${API_BASE_URL}/api/v1/blog/media`, {
    method: 'POST',
    headers,
    body: formData,
  })
  if (!res.ok) throw new Error('Upload failed')
  return res.json()
}

export async function deleteMedia(id: string): Promise<void> {
  return fetchClient<void>(`/api/v1/blog/media/${id}`, { method: 'DELETE' })
}

// Document Types
export interface DocumentResponse {
  id: string
  title: string
  description?: string
  content?: string
  owner_id: string
  owner_name?: string
  is_published: boolean
  published_at?: string
  created_at: string
  updated_at: string
}

// Orchestrator Types
export interface AgentCommandResponse {
  status: string
  result: any
}

// Script Types
export interface ScriptResponse {
  id: string
  name: string
  script_address: string
  description?: string
  owner_id: string
  owner_name?: string
  version?: string
  created_at: string
  updated_at: string
}

// Blog API Functions
export interface BlogListParams {
  limit?: number
  offset?: number
  category?: string
  tag?: string
  q?: string
  featured?: boolean
}

export async function getBlogs(params: BlogListParams = {}): Promise<BlogListItem[]> {
  const p: Record<string, string> = {
    limit: (params.limit ?? 20).toString(),
    offset: (params.offset ?? 0).toString(),
  }
  if (params.category) p.category = params.category
  if (params.tag) p.tag = params.tag
  if (params.q) p.q = params.q
  if (params.featured !== undefined) p.featured = params.featured.toString()
  return fetchClient<BlogListItem[]>('/api/v1/blogs', { params: p })
}

export async function getBlog(id: string): Promise<BlogResponse> {
  return fetchClient<BlogResponse>(`/api/v1/blogs/${id}`)
}

export async function getBlogBySlug(slug: string): Promise<BlogResponse> {
  return fetchClient<BlogResponse>(`/api/v1/blogs/by-slug/${slug}`)
}

export async function getBlogComments(id: string): Promise<CommentResponse[]> {
  return fetchClient<CommentResponse[]>(`/api/v1/blogs/${id}/comments`)
}

export async function getCategories(): Promise<CategoryResponse[]> {
  return fetchClient<CategoryResponse[]>('/api/v1/blog/categories')
}

export async function getTags(): Promise<TagResponse[]> {
  return fetchClient<TagResponse[]>('/api/v1/blog/tags')
}

/**
 * Server-side blog fetch (no auth needed, uses direct fetch).
 * Used in generateMetadata and server components.
 */
export async function fetchBlogBySlugServer(slugOrId: string): Promise<BlogResponse | null> {
  // Try slug first
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/blogs/by-slug/${slugOrId}`, {
      next: { revalidate: 60 },
    })
    if (res.ok) return res.json()
  } catch {
    /* fall through */
  }

  // If it looks like a UUID, try by ID (backward compat)
  const isUUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(slugOrId)
  if (isUUID) {
    try {
      const res = await fetch(`${API_BASE_URL}/api/v1/blogs/${slugOrId}`, {
        next: { revalidate: 60 },
      })
      if (res.ok) return res.json()
    } catch {
      /* ignore */
    }
  }

  return null
}

export async function fetchBlogsServer(params: BlogListParams = {}): Promise<BlogListItem[]> {
  try {
    const url = new URL(`${API_BASE_URL}/api/v1/blogs`)
    url.searchParams.set('limit', (params.limit ?? 20).toString())
    url.searchParams.set('offset', (params.offset ?? 0).toString())
    if (params.category) url.searchParams.set('category', params.category)
    if (params.tag) url.searchParams.set('tag', params.tag)
    if (params.q) url.searchParams.set('q', params.q)
    const res = await fetch(url.toString(), { next: { revalidate: 60 } })
    if (!res.ok) return []
    return res.json()
  } catch {
    return []
  }
}

// Document API Functions
export async function getDocuments(limit = 10, offset = 0): Promise<DocumentResponse[]> {
  return fetchClient<DocumentResponse[]>('/api/v1/documents', {
    params: {
      limit: limit.toString(),
      offset: offset.toString(),
    },
  })
}

export async function getDocument(id: string): Promise<DocumentResponse> {
  return fetchClient<DocumentResponse>(`/api/v1/documents/${id}`)
}

// Agent Types
export interface AgentInfo {
  agent_id: string
  agent_name: string
  agent_type: string
  status: string
  description?: string
  created_at?: string
}

export interface AgentListResponse {
  agents: AgentInfo[]
}

// Orchestrator API Functions
export async function runAgentCommand(
  agentId: string,
  toolName: string,
  args: any
): Promise<AgentCommandResponse> {
  return fetchClient<AgentCommandResponse>('/api/v1/orchestrator/run_command', {
    method: 'POST',
    body: JSON.stringify({
      agent_id: agentId,
      tool_name: toolName,
      arguments: args,
    }),
  })
}

export async function getUserAgents(): Promise<AgentListResponse> {
  return fetchClient<AgentListResponse>('/api/v1/agent/list', {
    method: 'GET',
  })
}

// SSH Configuration for remote test execution
export interface SSHConfig {
  remote_ip: string
  username: string
  pem_key_base64: string // PEM key encoded as base64
  pytest_args?: string
}

export interface StreamStrategyOptions {
  content: string
  context?: Record<string, any>
  sessionId?: string
  userId?: string
  localTestEnabled?: boolean
  remoteTestEnabled?: boolean
  sshConfig?: SSHConfig
  cdpUrl?: string
  signal?: AbortSignal
  wizardInput?: WizardInput
}

// Typed chunk for classified streaming display
export interface TypedStreamChunk {
  type:
    | 'log'
    | 'result'
    | 'error'
    | 'ssh_result'
    | 'web_ui_artifact'
    | 'web_ui_bug'
    | 'planner_step'
    | 'wizard_round'
    | 'wizard_aborted'
    | 'wizard_guide'
  content: string
  isThinking?: boolean
  author?: string
  stage?: string
  sshResult?: {
    success: boolean
    stdout: string
    stderr: string
    exit_code: number
    allure_results_url?: string
  }
  webUiArtifactData?: {
    script: string
    name?: string
    task_id?: string
  }
  webUiBugData?: {
    bug_counts: { critical?: number; high?: number; medium?: number; low?: number; total?: number }
    steps_done?: number
    url?: string
    task_id?: string
    tests_url?: string
    bug_report_url?: string
    final_output?: string
    screenshot_urls?: string[]
  }
  plannerStep?: {
    type:
      | 'thinking'
      | 'tool_use_start'
      | 'tool_use_end'
      | 'tool_error'
      | 'fallback'
      | 'malformed'
      | 'max_steps_hit'
      | 'done'
    step_index: number
    timestamp: number
    text?: string
    tool_name?: string
    tool_input?: Record<string, unknown>
    tool_summary?: string
    error?: string
    reason?: string
    to?: string
  }
  wizardRound?: WizardRoundEvent
  wizardAborted?: WizardAbortedEvent
  wizardGuide?: WizardGuideEvent
}

function tryParsePlannerStep(raw: unknown): TypedStreamChunk['plannerStep'] | null {
  if (!raw || typeof raw !== 'object') return null
  const obj = raw as Record<string, unknown>
  // Orchestrator events.py emits {event_type: "planner_step", payload: "<json>"}
  if (obj.event_type === 'planner_step') {
    const payload =
      typeof obj.payload === 'string'
        ? (() => {
            try {
              return JSON.parse(obj.payload)
            } catch {
              return null
            }
          })()
        : obj.payload
    if (payload && typeof payload === 'object') {
      return payload as TypedStreamChunk['plannerStep']
    }
  }
  // Direct planner_step payload (no event_type wrapper)
  if (obj.type && typeof obj.step_index === 'number') {
    return obj as TypedStreamChunk['plannerStep']
  }
  return null
}

export async function streamStrategy(
  options: StreamStrategyOptions,
  onChunk: (chunk: string) => void,
  onError?: (error: Error) => void,
  onComplete?: (scriptUrl?: string) => void,
  onTypedChunk?: (chunk: TypedStreamChunk) => void
): Promise<void> {
  const {
    content,
    context,
    sessionId,
    userId,
    localTestEnabled,
    remoteTestEnabled,
    sshConfig,
    cdpUrl,
    signal,
  } = options

  const url = new URL(`${API_BASE_URL}/api/v1/orchestrator/strategy/stream`)

  // Inject API Token if available
  const apiToken = useAuthStore.getState().apiToken
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  }

  if (apiToken) {
    headers['x-api-token'] = apiToken
    headers['Authorization'] = `Bearer ${apiToken}`
  }

  let capturedScriptUrl: string | undefined

  try {
    const body: Record<string, any> = {
      content,
      context,
      session_id: sessionId,
      user_id: userId,
      local_test_enabled: localTestEnabled,
      remote_test_enabled: remoteTestEnabled,
    }

    // Include SSH config for remote test execution (optional)
    if (sshConfig) {
      body.ssh_config = sshConfig
    }

    // Include CDP URL for local browser testing
    if (cdpUrl) {
      body.cdp_url = cdpUrl
    }

    // Include wizard input for option-picker wizard flow
    if (options.wizardInput) {
      body.wizardInput = options.wizardInput
    }

    const response = await fetch(url.toString(), {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal,
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Stream request failed' }))
      throw new Error(JSON.stringify(error))
    }

    if (!response.body) {
      throw new Error('Response body is null')
    }

    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''

    while (true) {
      if (signal?.aborted) {
        reader.cancel()
        if (onComplete) onComplete(capturedScriptUrl)
        break
      }

      const { done, value } = await reader.read()

      if (done) {
        console.log('[StreamStrategy] Stream complete, final capturedScriptUrl:', capturedScriptUrl)
        if (onComplete) onComplete(capturedScriptUrl)
        break
      }

      buffer += decoder.decode(value, { stream: true })

      // Process complete SSE messages
      const lines = buffer.split('\n')
      buffer = lines.pop() || '' // Keep incomplete line in buffer

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6) // Remove 'data: ' prefix

          if (data.trim()) {
            try {
              const parsed = JSON.parse(data)

              // Debug: Log all events
              console.log('[StreamStrategy] Received event:', {
                type: parsed.type,
                hasScriptUrl: !!parsed.script_url,
                hasContent: !!parsed.content,
                hasParts: !!parsed.content?.parts,
              })

              // Capture script URL if present (from direct event or artifact event)
              if (parsed.script_url) {
                console.log(
                  '[StreamStrategy] Captured script_url from direct event:',
                  parsed.script_url
                )
                capturedScriptUrl = parsed.script_url
              }

              // Check for nested artifact in content.parts (for RemoteAgent compatibility)
              if (parsed.content?.parts?.[0]?.text) {
                try {
                  const innerData = JSON.parse(parsed.content.parts[0].text)
                  console.log('[StreamStrategy] Parsed nested content:', { type: innerData.type })
                  if (innerData.type === 'artifacts' && innerData.files?.[0]?.download_url) {
                    console.log(
                      '[StreamStrategy] Captured script_url from nested artifact:',
                      innerData.files[0].download_url
                    )
                    capturedScriptUrl = innerData.files[0].download_url
                  }
                } catch (e) {
                  // Not JSON or not the structure we expect, ignore
                }
              }

              // Handle different event types
              if (parsed.type === 'artifact') {
                // Artifact event - don't display to user, just capture URL
                // URL was already captured above via parsed.script_url
                console.log('[StreamStrategy] Artifact event received, skipping display')
                continue
              } else if (parsed.type === 'log' || parsed.type === 'discovery_progress') {
                // Log events - display in "thinking" style with smaller font
                // These come from api_discover.py progress updates
                const stage = parsed.stage || ''
                const message = parsed.message || parsed.text || parsed.content || ''
                const formattedText = stage ? `[${stage}] ${message}` : message
                if (formattedText) {
                  onChunk(formattedText + '\n')
                  // Emit typed chunk for thinking-style display
                  if (onTypedChunk) {
                    onTypedChunk({
                      type: 'log',
                      content: formattedText,
                      isThinking: true,
                      author: parsed.author,
                      stage: parsed.stage,
                    })
                  }
                }
              } else if (parsed.type === 'progress') {
                // Progress events are "thinking" logs - display in smaller font.
                // PlannerAgent wraps planner_step events inside ADK Event content,
                // which surfaces here as text = JSON-encoded {event_type, payload}.
                // Unwrap and route to the planner_step handler.
                const text = parsed.text || parsed.content || ''
                let routedAsPlannerStep = false
                if (text && text.startsWith('{')) {
                  try {
                    const inner = JSON.parse(text)
                    const step = tryParsePlannerStep(inner)
                    if (step) {
                      if (onTypedChunk) {
                        onTypedChunk({
                          type: 'planner_step',
                          content: step.text || step.tool_summary || '',
                          plannerStep: step,
                          author: parsed.author,
                        })
                      }
                      routedAsPlannerStep = true
                    }
                  } catch {
                    // Not JSON, fall through to thinking display
                  }
                }
                if (!routedAsPlannerStep && text) {
                  onChunk(text)
                  // Emit typed chunk for log/thinking display
                  if (onTypedChunk) {
                    onTypedChunk({
                      type: 'log',
                      content: text,
                      isThinking: true,
                      author: parsed.author,
                      stage: parsed.stage,
                    })
                  }
                }
              } else if (parsed.type === 'result') {
                // Result events are the main output - normal display
                const text = parsed.text || parsed.content || ''
                if (text) {
                  onChunk(text)
                  // Emit typed chunk for result display
                  if (onTypedChunk) {
                    onTypedChunk({ type: 'result', content: text })
                  }
                }
              } else if (parsed.type === 'planner_step' || parsed.event_type === 'planner_step') {
                // Direct planner_step event (dict yield path)
                const step = tryParsePlannerStep(parsed)
                if (step && onTypedChunk) {
                  onTypedChunk({
                    type: 'planner_step',
                    content: step.text || step.tool_summary || '',
                    plannerStep: step,
                  })
                }
              } else if (
                parsed.event_type === 'wizard_round' &&
                typeof parsed.payload === 'string'
              ) {
                // Wizard events — orchestrator emits {event_type: "wizard_round", payload: "<json>"}
                try {
                  const payload = JSON.parse(parsed.payload) as WizardRoundEvent
                  if (onTypedChunk) {
                    onTypedChunk({ type: 'wizard_round', content: '', wizardRound: payload })
                  }
                } catch {
                  // malformed wizard_round payload — ignore
                }
              } else if (
                parsed.event_type === 'wizard_aborted' &&
                typeof parsed.payload === 'string'
              ) {
                try {
                  const payload = JSON.parse(parsed.payload) as WizardAbortedEvent
                  if (onTypedChunk) {
                    onTypedChunk({ type: 'wizard_aborted', content: '', wizardAborted: payload })
                  }
                } catch {}
              } else if (
                parsed.event_type === 'wizard_guide' &&
                typeof parsed.payload === 'string'
              ) {
                try {
                  const payload = JSON.parse(parsed.payload) as WizardGuideEvent
                  if (onTypedChunk) {
                    onTypedChunk({ type: 'wizard_guide', content: '', wizardGuide: payload })
                  }
                } catch {}
              } else if (
                typeof parsed === 'object' &&
                parsed !== null &&
                typeof parsed.at_round_label === 'string' &&
                typeof parsed.rounds_used === 'number' &&
                !parsed.event_type
              ) {
                // api_service emits wizard_aborted as a bare payload (no event_type wrapper)
                if (onTypedChunk) {
                  onTypedChunk({
                    type: 'wizard_aborted',
                    content: '',
                    wizardAborted: parsed as WizardAbortedEvent,
                  })
                }
              } else if (parsed.type === 'web_ui_artifact') {
                // Test script artifact (cloud Web UI test or client agent).
                // Orchestrator unwraps {event_type, payload} → flat dict with type=web_ui_artifact
                // and the pytest source in `content`. Route to TestScriptArtifact for syntax-
                // highlighted, collapsible rendering instead of letting it fall through to
                // ResultMessage (which strips fenced code → flat paragraph).
                const script = parsed.content || ''
                if (script && onTypedChunk) {
                  onTypedChunk({
                    type: 'web_ui_artifact',
                    content: '',
                    webUiArtifactData: {
                      script,
                      name: parsed.name || 'test_script.py',
                      task_id: parsed.task_id,
                    },
                  })
                }
              } else if (parsed.type === 'web_ui_bug') {
                // Bug report payload (client agent path; cloud path delivers bug_counts
                // inside the `result` event instead). Route to BugReportArtifact.
                if (onTypedChunk) {
                  onTypedChunk({
                    type: 'web_ui_bug',
                    content: '',
                    webUiBugData: {
                      bug_counts: parsed.bug_counts || {},
                      steps_done: parsed.steps_done,
                      url: parsed.url,
                      task_id: parsed.task_id,
                      tests_url: parsed.tests_url,
                      bug_report_url: parsed.bug_report_url,
                      final_output: parsed.final_output,
                      screenshot_urls: parsed.screenshot_urls,
                    },
                  })
                }
              } else if (parsed.type === 'ssh_result') {
                // SSH remote execution result
                const sshData = parsed.ssh_result || parsed
                const statusText = sshData.success ? 'PASSED' : 'FAILED'
                const summaryText = `\n--- Remote Test Execution ${statusText} (exit code: ${sshData.exit_code}) ---\n`
                onChunk(summaryText)
                if (onTypedChunk) {
                  onTypedChunk({
                    type: 'ssh_result',
                    content: summaryText,
                    sshResult: sshData,
                  })
                }
              } else if (parsed.type === 'error' || parsed.error) {
                // Display error message to user instead of throwing
                const errorMsg = parsed.error || parsed.message || 'Unknown error occurred'
                onChunk(`\n❌ Error: ${errorMsg}\n`)
                // Emit typed chunk for error display
                if (onTypedChunk) {
                  onTypedChunk({ type: 'error', content: errorMsg })
                }
                if (onError) {
                  onError(new Error(errorMsg))
                }
                // Break loop on error to stop processing further chunks
                reader.cancel()
                return
              } else if (parsed.type) {
                // Other types with content - treat as result
                const text = parsed.text || parsed.content || parsed.message || ''
                if (text) {
                  onChunk(text)
                  if (onTypedChunk) {
                    onTypedChunk({ type: 'result', content: text })
                  }
                }
              }
            } catch (parseError) {
              // If not JSON, treat as plain text
              if (data !== '{}') {
                onChunk(data)
              }
            }
          }
        } else if (line.startsWith('event: ')) {
          const eventType = line.slice(7).trim()
          if (eventType === 'done') {
            console.log(
              '[StreamStrategy] Event done received, final capturedScriptUrl:',
              capturedScriptUrl
            )
            if (onComplete) onComplete(capturedScriptUrl)
            return
          } else if (eventType === 'error') {
            // Error data will be in the next 'data:' line
            continue
          }
        }
      }
    }
  } catch (error) {
    // AbortError means the user deliberately stopped — treat as clean completion
    if (error instanceof DOMException && error.name === 'AbortError') {
      if (onComplete) onComplete(capturedScriptUrl)
      return
    }
    if (onError) {
      onError(error instanceof Error ? error : new Error(String(error)))
    } else {
      throw error
    }
  }
}

// --- Profile APIs ---

export interface ProfileResponse {
  id: string
  username: string
  email: string
  display_name: string | null
  avatar: string | null
  role: string
  created_at: string
  updated_at: string
}

export interface ProfileUpdate {
  username?: string
  email?: string
  display_name?: string
  avatar?: string
}

export async function getProfile(): Promise<ProfileResponse> {
  return fetchClient<ProfileResponse>('/api/v1/profile')
}

export async function updateProfile(data: ProfileUpdate): Promise<ProfileResponse> {
  return fetchClient<ProfileResponse>('/api/v1/profile', {
    method: 'PATCH',
    body: JSON.stringify(data),
  })
}

// Cancel Web UI Test
// --- Subscription APIs ---

export interface SubscriptionPlan {
  id: string
  name: string
  description: string
  price_cents: number
  test_cases_limit: number
  features: string | Record<string, unknown>
}

export interface SubscriptionStatus {
  plan: string
  status: string
  test_cases_used: number
  test_cases_limit: number
  current_period_end: string | null
  cancel_at_period_end: boolean
}

export interface UsageDetails {
  test_cases_used: number
  test_cases_limit: number
  period_start: string | null
  period_end: string | null
  llm_cost_usd: number
}

export async function getSubscriptionPlans(): Promise<SubscriptionPlan[]> {
  return fetchClient<SubscriptionPlan[]>('/api/v1/subscription/plans')
}

export async function getSubscriptionStatus(): Promise<SubscriptionStatus> {
  return fetchClient<SubscriptionStatus>('/api/v1/subscription/status')
}

export async function getSubscriptionUsage(): Promise<UsageDetails> {
  return fetchClient<UsageDetails>('/api/v1/subscription/usage')
}

export async function createCheckoutSession(plan: string): Promise<{ checkout_url: string }> {
  return fetchClient<{ checkout_url: string }>('/api/v1/subscription/create-checkout', {
    method: 'POST',
    body: JSON.stringify({ plan }),
  })
}

export async function createPortalSession(): Promise<{ portal_url: string }> {
  return fetchClient<{ portal_url: string }>('/api/v1/subscription/create-portal', {
    method: 'POST',
    body: JSON.stringify({}),
  })
}

export async function cancelWebUITest(): Promise<{ status: string; task_id: string }> {
  return fetchClient<{ status: string; task_id: string }>(
    '/api/v1/orchestrator/cancel-web-ui-test',
    {
      method: 'POST',
      body: JSON.stringify({}),
    }
  )
}

// Script API Functions
export async function getScripts(): Promise<ScriptResponse[]> {
  return fetchClient<ScriptResponse[]>('/api/v1/scripts')
}

export async function getScript(scriptId: string): Promise<ScriptResponse> {
  return fetchClient<ScriptResponse>(`/api/v1/scripts/${scriptId}`)
}

export async function createScript(script: {
  name: string
  script_address: string
  description?: string
  version?: string
}): Promise<ScriptResponse> {
  return fetchClient<ScriptResponse>('/api/v1/scripts', {
    method: 'POST',
    body: JSON.stringify(script),
  })
}

export async function updateScript(
  scriptId: string,
  script: {
    name?: string
    script_address?: string
    description?: string
    version?: string
  }
): Promise<ScriptResponse> {
  return fetchClient<ScriptResponse>(`/api/v1/scripts/${scriptId}`, {
    method: 'PUT',
    body: JSON.stringify(script),
  })
}

export async function deleteScript(scriptId: string): Promise<{ message: string; id: string }> {
  return fetchClient<{ message: string; id: string }>(`/api/v1/scripts/${scriptId}`, {
    method: 'DELETE',
  })
}

export async function saveGeneratedScript(script: {
  name: string
  script_address: string
  description?: string
  version?: string
}): Promise<ScriptResponse> {
  return fetchClient<ScriptResponse>('/api/v1/orchestrator/strategy/save-script', {
    method: 'POST',
    body: JSON.stringify(script),
  })
}

export async function uploadScript(script: {
  name: string
  content: string
  description?: string
  version?: string
}): Promise<ScriptResponse> {
  // Use the new upload-script endpoint that handles R2 upload
  return fetchClient<ScriptResponse>('/api/v1/orchestrator/strategy/upload-script', {
    method: 'POST',
    body: JSON.stringify(script),
  })
}

// Chat Types
export interface ChatSession {
  id: string
  user_id: string
  title: string
  created_at: string
  updated_at: string
  wizard_state?: any
}

export interface ChatMessage {
  id: string
  session_id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  // Optional structured StreamChunk[] persisted alongside the flat content.
  // When present, frontend hydrates from this (proper artifact cards) instead
  // of falling back to the flat text blob (which collapses code into the log).
  chunks?: any[] | null
  created_at: string
}

// Chat API
export async function getChatSessions(limit = 50, offset = 0): Promise<ChatSession[]> {
  return fetchClient<ChatSession[]>('/api/v1/chat/sessions', {
    params: { limit: limit.toString(), offset: offset.toString() },
  })
}

export async function createChatSession(title: string): Promise<ChatSession> {
  return fetchClient<ChatSession>('/api/v1/chat/sessions', {
    method: 'POST',
    body: JSON.stringify({ title }),
  })
}

export async function getChatSession(id: string): Promise<ChatSession> {
  return fetchClient<ChatSession>(`/api/v1/chat/sessions/${id}`)
}

export async function updateChatSession(id: string, title: string): Promise<ChatSession> {
  return fetchClient<ChatSession>(`/api/v1/chat/sessions/${id}`, {
    method: 'PUT',
    body: JSON.stringify({ title }),
  })
}

export async function deleteChatSession(id: string): Promise<void> {
  return fetchClient<void>(`/api/v1/chat/sessions/${id}`, {
    method: 'DELETE',
  })
}

export interface BulkDeleteResult {
  deleted_count: number
  deleted_ids: string[]
}

export async function bulkDeleteChatSessions(ids: string[]): Promise<BulkDeleteResult> {
  return fetchClient<BulkDeleteResult>('/api/v1/chat/sessions/bulk-delete', {
    method: 'POST',
    body: JSON.stringify({ ids }),
  })
}

export async function getChatMessages(sessionId: string): Promise<ChatMessage[]> {
  return fetchClient<ChatMessage[]>(`/api/v1/chat/sessions/${sessionId}/messages`)
}

export async function createChatMessage(
  sessionId: string,
  role: string,
  content: string,
  chunks?: any[] | null
): Promise<ChatMessage> {
  return fetchClient<ChatMessage>(`/api/v1/chat/sessions/${sessionId}/messages`, {
    method: 'POST',
    body: JSON.stringify({ role, content, chunks: chunks ?? null }),
  })
}

// Web UI Task Types
export interface WebUITask {
  id: string
  owner_id: string
  target_url: string
  status: string
  user_persona?: string
  max_steps?: number
  created_at: string
  started_at?: string
  finished_at?: string
  steps_done: number
  tests_url?: string
  bug_report_url?: string
  features_url?: string
  bug_counts?: {
    critical: number
    high: number
    medium: number
    low: number
  }
  test_summary?: {
    total: number
    passed: number
    failed: number
  }
  error_message?: string
}

// Web UI Task API
export async function getWebUITasks(limit = 50, offset = 0): Promise<WebUITask[]> {
  return fetchClient<WebUITask[]>('/api/v1/web-ui-tasks', {
    params: { limit: limit.toString(), offset: offset.toString() },
  })
}

export async function getWebUITask(id: string): Promise<WebUITask> {
  return fetchClient<WebUITask>(`/api/v1/web-ui-tasks/${id}`)
}

export async function deleteWebUITask(id: string): Promise<{ message: string; id: string }> {
  return fetchClient<{ message: string; id: string }>(`/api/v1/web-ui-tasks/${id}`, {
    method: 'DELETE',
  })
}

// Trial Token API

export interface TrialValidateResponse {
  valid: boolean
  target_url?: string
  email?: string
  reason?: string
}

export interface TrialCreateResponse {
  trial_url: string
  token: string
  expires_at: string
}

export async function createTrialToken(
  email: string,
  targetUrl: string,
  expiresHours: number = 168
): Promise<TrialCreateResponse> {
  return fetchClient<TrialCreateResponse>('/api/v1/trial/create', {
    method: 'POST',
    body: JSON.stringify({
      email,
      target_url: targetUrl,
      expires_hours: expiresHours,
    }),
  })
}

export async function validateTrialToken(token: string): Promise<TrialValidateResponse> {
  const url = new URL(`${API_BASE_URL}/api/v1/trial/validate`)
  const response = await fetch(url.toString(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
  })
  return response.json()
}

export async function streamStrategyTrial(
  targetUrl: string,
  trialToken: string,
  onChunk: (chunk: string) => void,
  onError?: (error: Error) => void,
  onComplete?: (scriptUrl?: string) => void,
  onTypedChunk?: (chunk: TypedStreamChunk) => void
): Promise<void> {
  const url = new URL(`${API_BASE_URL}/api/v1/orchestrator/strategy/stream`)

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'x-trial-token': trialToken,
  }

  try {
    const response = await fetch(url.toString(), {
      method: 'POST',
      headers,
      body: JSON.stringify({
        content: targetUrl,
      }),
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Stream request failed' }))
      throw new Error(error.detail || JSON.stringify(error))
    }

    if (!response.body) {
      throw new Error('Response body is null')
    }

    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    let capturedScriptUrl: string | undefined

    while (true) {
      const { done, value } = await reader.read()

      if (done) {
        if (onComplete) onComplete(capturedScriptUrl)
        break
      }

      buffer += decoder.decode(value, { stream: true })

      const lines = buffer.split('\n')
      buffer = lines.pop() || ''

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          const data = line.slice(6)

          if (data.trim()) {
            try {
              const parsed = JSON.parse(data)

              if (parsed.script_url) {
                capturedScriptUrl = parsed.script_url
              }

              if (parsed.type === 'artifact') {
                continue
              } else if (parsed.type === 'log' || parsed.type === 'discovery_progress') {
                const stage = parsed.stage || ''
                const message = parsed.message || parsed.text || parsed.content || ''
                const formattedText = stage ? `[${stage}] ${message}` : message
                if (formattedText) {
                  onChunk(formattedText + '\n')
                  if (onTypedChunk) {
                    onTypedChunk({
                      type: 'log',
                      content: formattedText,
                      isThinking: true,
                      author: parsed.author,
                      stage: parsed.stage,
                    })
                  }
                }
              } else if (parsed.type === 'progress') {
                const text = parsed.text || parsed.content || ''
                if (text) {
                  onChunk(text)
                  if (onTypedChunk) {
                    onTypedChunk({
                      type: 'log',
                      content: text,
                      isThinking: true,
                      author: parsed.author,
                      stage: parsed.stage,
                    })
                  }
                }
              } else if (parsed.type === 'result') {
                const text = parsed.text || parsed.content || ''
                if (text) {
                  onChunk(text)
                  if (onTypedChunk) {
                    onTypedChunk({ type: 'result', content: text })
                  }
                }
              } else if (parsed.type === 'error' || parsed.error) {
                const errorMsg = parsed.error || parsed.message || 'Unknown error occurred'
                onChunk(`\n Error: ${errorMsg}\n`)
                if (onTypedChunk) {
                  onTypedChunk({ type: 'error', content: errorMsg })
                }
                if (onError) {
                  onError(new Error(errorMsg))
                }
                reader.cancel()
                return
              } else if (parsed.type) {
                const text = parsed.text || parsed.content || parsed.message || ''
                if (text) {
                  onChunk(text)
                  if (onTypedChunk) {
                    onTypedChunk({ type: 'result', content: text })
                  }
                }
              }
            } catch (parseError) {
              if (data !== '{}') {
                onChunk(data)
              }
            }
          }
        } else if (line.startsWith('event: ')) {
          const eventType = line.slice(7).trim()
          if (eventType === 'done') {
            if (onComplete) onComplete(capturedScriptUrl)
            return
          }
        }
      }
    }
  } catch (error) {
    if (onError) {
      onError(error instanceof Error ? error : new Error(String(error)))
    } else {
      throw error
    }
  }
}
