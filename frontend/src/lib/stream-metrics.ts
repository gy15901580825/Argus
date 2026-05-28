import { getDebug } from './stream-config'

type BoundaryKind = 'fence' | 'paragraph' | 'list' | 'fallback'

interface SessionSummary {
  flushRateHz: number
  batchSizeP95: number
  boundaryDistribution: Record<BoundaryKind, number>
}

const EMPTY_DISTRIBUTION: Record<BoundaryKind, number> = {
  fence: 0,
  paragraph: 0,
  list: 0,
  fallback: 0,
}

interface SessionState {
  flushTimestamps: number[]
  batchSizes: number[]
  boundaries: Record<BoundaryKind, number>
  startedAt: number
  reportTimer: ReturnType<typeof setInterval> | null
  lastRollingRateHz: number
}

let session: SessionState | null = null

function newSessionState(): SessionState {
  return {
    flushTimestamps: [],
    batchSizes: [],
    boundaries: { ...EMPTY_DISTRIBUTION },
    startedAt: Date.now(),
    reportTimer: null,
    lastRollingRateHz: 0,
  }
}

function rollingRateHz(stamps: number[]): number {
  const now = Date.now()
  const windowStart = now - 1000
  return stamps.filter((t) => t >= windowStart).length
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))
  return sorted[idx]
}

function report() {
  if (!session) return
  const hz = rollingRateHz(session.flushTimestamps)
  session.lastRollingRateHz = hz
  const avgBatch = session.batchSizes.length
    ? session.batchSizes.reduce((a, b) => a + b, 0) / session.batchSizes.length
    : 0
  const { fence, paragraph, list, fallback } = session.boundaries
  console.log(
    `[stream] ${hz} flushes/s, avg batch=${avgBatch.toFixed(1)}, boundary: fence=${fence} paragraph=${paragraph} list=${list} fallback=${fallback}`
  )
}

export const streamMetrics = {
  startSession(): void {
    if (!getDebug()) return
    if (session?.reportTimer) clearInterval(session.reportTimer)
    session = newSessionState()
    session.reportTimer = setInterval(report, 1000)
  },

  markFlush(batchSize: number): void {
    if (!getDebug() || !session) return
    session.flushTimestamps.push(Date.now())
    session.batchSizes.push(batchSize)
  },

  markBoundaryHit(kind: BoundaryKind, _position: number): void {
    if (!getDebug() || !session) return
    session.boundaries[kind]++
  },

  endSession(): SessionSummary {
    if (!session) {
      return { flushRateHz: 0, batchSizeP95: 0, boundaryDistribution: { ...EMPTY_DISTRIBUTION } }
    }
    if (session.reportTimer) clearInterval(session.reportTimer)
    const summary: SessionSummary = {
      flushRateHz: session.lastRollingRateHz,
      batchSizeP95: percentile(session.batchSizes, 95),
      boundaryDistribution: { ...session.boundaries },
    }
    if (getDebug()) {
      console.log(
        `[stream] session end: p95 batch=${summary.batchSizeP95}, total flushes=${session.flushTimestamps.length}`
      )
    }
    session = null
    return summary
  },
}
