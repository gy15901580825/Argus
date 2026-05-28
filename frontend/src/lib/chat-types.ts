// Streaming-chat domain types.
// Pure type module (no runtime imports) — safe to import from any chat primitive.

export type StreamChunkType =
  | 'log'
  | 'discovery_progress'
  | 'planner_step'
  | 'progress'
  | 'result'
  | 'code'
  | 'ssh_result'
  | 'web_ui_bug'
  | 'web_ui_artifact'
  | 'error'
  | 'system'

export interface StreamChunk {
  type: StreamChunkType
  content: string
  language?: string
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
  webUiArtifactData?: {
    script: string
    name?: string
    task_id?: string
  }
}
