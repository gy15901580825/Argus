'use client'

import type { StreamChunk } from '@/lib/chat-types'
import { BugReportBody } from './_BugReportBody'

interface Props {
  chunks: StreamChunk[]
  onRerunWebUI?: (url: string) => void
}

// BugReportBody is already a self-contained card with its own "View Details"
// expand toggle. Wrapping it in MessageShell created a confusing
// double-collapse — clicking the outer chevron hid the entire card instead
// of expanding the tabs the user actually wanted to see.
export function BugReportArtifact({ chunks, onRerunWebUI }: Props) {
  const data = chunks[0]?.webUiBugData
  if (!data) return null
  const counts = data.bug_counts

  return (
    <BugReportBody
      bugCounts={{
        critical: counts.critical ?? 0,
        high: counts.high ?? 0,
        medium: counts.medium ?? 0,
        low: counts.low ?? 0,
      }}
      stepsDone={data.steps_done}
      url={data.url ?? ''}
      taskId={data.task_id}
      testsUrl={data.tests_url}
      bugReportUrl={data.bug_report_url}
      finalOutput={data.final_output}
      screenshotUrls={data.screenshot_urls ?? []}
      onRerun={onRerunWebUI}
    />
  )
}
