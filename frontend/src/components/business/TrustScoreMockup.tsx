import { TrendingDown } from 'lucide-react'

type Metric = {
  name: string
  value: number
  state: 'good' | 'warn'
}

const METRICS: Metric[] = [
  { name: 'Task Success Rate', value: 94, state: 'good' },
  { name: 'Tool-Call Accuracy', value: 91, state: 'good' },
  { name: 'Recovery', value: 88, state: 'good' },
  { name: 'Efficiency', value: 76, state: 'warn' },
  { name: 'Security', value: 92, state: 'good' },
  { name: 'Compliance', value: 100, state: 'good' },
]

const TRUST_SCORE = 87
const RADIUS = 42
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

export function TrustScoreMockup() {
  const dashOffset = CIRCUMFERENCE * (1 - TRUST_SCORE / 100)

  return (
    <div className="relative max-w-5xl mx-auto">
      {/* Outer glow */}
      <div className="absolute -inset-4 bg-gradient-to-br from-cyan-500/20 via-transparent to-violet-500/20 blur-2xl rounded-3xl" />

      <div className="relative rounded-2xl border border-slate-800 bg-slate-950 shadow-2xl overflow-hidden">
        {/* Browser chrome */}
        <div className="flex items-center gap-3 px-4 py-3 bg-slate-900/80 border-b border-slate-800">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 rounded-full bg-red-500" />
            <div className="w-3 h-3 rounded-full bg-yellow-500" />
            <div className="w-3 h-3 rounded-full bg-green-500" />
          </div>
          <div className="flex-1 flex justify-center">
            <span className="text-xs text-slate-400 font-mono px-3 py-1 rounded-md bg-slate-800/60 border border-slate-700/50">
              example.com / agents / agent-prod-v3.2
            </span>
          </div>
          <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-cyan-400/10 border border-cyan-400/30">
            <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-[10px] font-bold text-cyan-300 tracking-widest">LIVE</span>
          </div>
        </div>

        {/* Body */}
        <div className="p-6 md:p-8 grid grid-cols-1 md:grid-cols-5 gap-6 md:gap-8 items-center">
          {/* Left — gauge */}
          <div className="md:col-span-2 flex flex-col items-center">
            <div className="relative w-44 h-44 md:w-48 md:h-48">
              <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                <defs>
                  <linearGradient id="trustGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stopColor="#22d3ee" />
                    <stop offset="100%" stopColor="#0891b2" />
                  </linearGradient>
                </defs>
                <circle
                  cx="50"
                  cy="50"
                  r={RADIUS}
                  stroke="rgba(148,163,184,0.12)"
                  strokeWidth="6"
                  fill="none"
                />
                <circle
                  cx="50"
                  cy="50"
                  r={RADIUS}
                  stroke="url(#trustGradient)"
                  strokeWidth="6"
                  fill="none"
                  strokeLinecap="round"
                  strokeDasharray={CIRCUMFERENCE}
                  strokeDashoffset={dashOffset}
                  style={{ filter: 'drop-shadow(0 0 6px rgba(34,211,238,0.4))' }}
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <div className="text-[10px] uppercase tracking-[0.2em] text-slate-500 mb-1">
                  Trust Score
                </div>
                <div className="text-6xl font-extrabold bg-clip-text text-transparent bg-gradient-to-br from-white to-slate-300 leading-none">
                  {TRUST_SCORE}
                </div>
                <div className="text-xs text-slate-500 mt-1">/ 100</div>
              </div>
            </div>
            <div className="mt-4 inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30">
              <div className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-bold text-emerald-300 tracking-widest">PASSING</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-2 font-mono">build #1284 · 2 min ago</div>
          </div>

          {/* Right — metrics grid */}
          <div className="md:col-span-3 grid grid-cols-1 sm:grid-cols-2 gap-3">
            {METRICS.map((m) => {
              const isWarn = m.state === 'warn'
              return (
                <div
                  key={m.name}
                  className={`rounded-lg border p-3 transition-colors ${
                    isWarn
                      ? 'border-amber-500/30 bg-amber-500/[0.04]'
                      : 'border-slate-800 bg-slate-900/40 hover:border-cyan-400/30'
                  }`}
                >
                  <div className="flex items-baseline justify-between mb-2">
                    <span className="text-xs text-slate-400 font-medium">{m.name}</span>
                    <span
                      className={`text-base font-bold tabular-nums ${
                        isWarn ? 'text-amber-300' : 'text-white'
                      }`}
                    >
                      {m.value}
                      <span className="text-xs text-slate-500 font-normal">%</span>
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        isWarn
                          ? 'bg-gradient-to-r from-amber-500 to-amber-300'
                          : 'bg-gradient-to-r from-cyan-500 to-cyan-300'
                      }`}
                      style={{ width: `${m.value}%` }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Footer — regression alert */}
        <div className="px-6 py-4 bg-amber-500/[0.06] border-t border-amber-500/20 flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <div className="shrink-0 w-9 h-9 rounded-full bg-amber-500/15 border border-amber-500/30 flex items-center justify-center">
              <TrendingDown className="h-4 w-4 text-amber-400" />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-amber-200">
                Regression detected vs. last deploy
              </div>
              <div className="text-xs text-amber-200/60 truncate">
                Efficiency dropped 84% → 76% on prod build #1284 ·{' '}
                <span className="font-mono">tool_call_loop</span> in 12 / 47 traces
              </div>
            </div>
          </div>
          <button
            type="button"
            className="shrink-0 inline-flex items-center gap-1 text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            View Diff
            <span aria-hidden>→</span>
          </button>
        </div>
      </div>
    </div>
  )
}
