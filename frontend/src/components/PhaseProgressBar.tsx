'use client'

interface PhaseInfo {
  name: string
  icon: string
  status: 'pending' | 'running' | 'done'
}

interface PhaseProgressBarProps {
  phases: PhaseInfo[]
  currentStep?: number
  maxSteps?: number
}

export function PhaseProgressBar({ phases, currentStep, maxSteps }: PhaseProgressBarProps) {
  const hasActivity = phases.some((p) => p.status !== 'pending')
  if (!hasActivity) return null

  return (
    <div className="my-2 rounded-lg border border-purple-100 bg-purple-50 p-3">
      <div className="flex items-center justify-between mb-2.5">
        <span className="text-xs font-semibold text-purple-800">🌐 Web UI Exploration</span>
        {currentStep !== undefined && maxSteps !== undefined && (
          <span className="text-xs text-purple-500">
            Step {currentStep}/{maxSteps}
          </span>
        )}
      </div>
      <div className="space-y-2">
        {phases.map((phase, i) => (
          <div key={i} className="flex items-center gap-2.5">
            <span className="text-sm w-5 flex-shrink-0">{phase.icon}</span>
            <div className="flex-1 min-w-0">
              <div className="flex items-center justify-between text-xs mb-1">
                <span
                  className={`font-medium truncate ${
                    phase.status === 'done'
                      ? 'text-green-700'
                      : phase.status === 'running'
                        ? 'text-purple-700'
                        : 'text-gray-400'
                  }`}
                >
                  {phase.name}
                </span>
                <span
                  className={`flex-shrink-0 ml-2 text-[10px] px-1.5 py-0.5 rounded-full font-medium ${
                    phase.status === 'done'
                      ? 'bg-green-100 text-green-700'
                      : phase.status === 'running'
                        ? 'bg-purple-100 text-purple-700'
                        : 'bg-gray-100 text-gray-400'
                  }`}
                >
                  {phase.status === 'done'
                    ? '✓ Done'
                    : phase.status === 'running'
                      ? '⏳ Running'
                      : 'Pending'}
                </span>
              </div>
              <div className="h-1 w-full rounded-full bg-gray-200 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ${
                    phase.status === 'done'
                      ? 'w-full bg-green-500'
                      : phase.status === 'running'
                        ? 'w-1/2 bg-purple-500'
                        : 'w-0'
                  }`}
                />
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
