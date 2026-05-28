'use client'
import { useState } from 'react'
import { ChevronDown, ChevronRight, X } from 'lucide-react'
import type { WebUIConfig } from '@/hooks/useWebUITest'

interface WebUIConfigPanelProps {
  config: WebUIConfig
  onChange: (config: WebUIConfig) => void
  onClose: () => void
  isLocalMode: boolean
  onOpenCDPDialog: () => void
}

const PERSONAS = [
  { value: 'new_user', label: '👤 New User' },
  { value: 'experienced_user', label: '🧑‍💻 Experienced User' },
  { value: 'admin', label: '⚙️ Admin' },
  { value: 'power_user', label: '🚀 Power User' },
]

export function WebUIConfigPanel({
  config,
  onChange,
  onClose,
  isLocalMode,
  onOpenCDPDialog,
}: WebUIConfigPanelProps) {
  const [showAdvanced, setShowAdvanced] = useState(false)
  const update = (partial: Partial<WebUIConfig>) => onChange({ ...config, ...partial })

  return (
    <div className="border-t border-purple-100 bg-gradient-to-r from-purple-50/80 to-indigo-50/80 px-4 py-3">
      <div className="flex items-center justify-between mb-2.5">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-purple-800">🌐 Web UI Testing</span>
          {isLocalMode ? (
            <button
              onClick={onOpenCDPDialog}
              className="text-xs rounded-full bg-indigo-100 text-indigo-700 px-2.5 py-0.5 hover:bg-indigo-200 transition-colors font-medium"
            >
              CDP: {config.cdpUrl.replace('http://', '') || 'localhost:9222'}
            </button>
          ) : (
            <button
              onClick={onOpenCDPDialog}
              className="text-xs rounded-full bg-gray-100 text-gray-500 px-2.5 py-0.5 hover:bg-indigo-100 hover:text-indigo-700 transition-colors"
            >
              + Use local Chrome
            </button>
          )}
        </div>
        <button onClick={onClose} className="rounded p-1 hover:bg-purple-100 transition-colors">
          <X className="h-3.5 w-3.5 text-purple-500" />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">User Persona</label>
          <select
            value={config.userPersona}
            onChange={(e) => update({ userPersona: e.target.value as WebUIConfig['userPersona'] })}
            className="w-full rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs focus:border-purple-400 focus:outline-none focus:ring-1 focus:ring-purple-300"
          >
            {PERSONAS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">
            Max Steps: <span className="text-purple-600 font-semibold">{config.maxSteps}</span>
          </label>
          <input
            type="range"
            min={20}
            max={500}
            step={10}
            value={config.maxSteps}
            onChange={(e) => update({ maxSteps: Number(e.target.value) })}
            className="w-full h-1.5 accent-purple-500 cursor-pointer"
          />
          <div className="flex justify-between text-[10px] text-gray-400 mt-0.5">
            <span>20</span>
            <span>500</span>
          </div>
        </div>
      </div>

      <button
        onClick={() => setShowAdvanced((v) => !v)}
        className="mt-2 flex items-center gap-1 text-xs text-purple-600 hover:text-purple-800 transition-colors"
      >
        {showAdvanced ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        Advanced options (CDP, credentials, context)
      </button>

      {showAdvanced && (
        <div className="mt-2 space-y-2 border-t border-purple-100 pt-2">
          {/* CDP URL — only shown in My Machine (local) mode */}
          {isLocalMode && (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                Chrome CDP URL
                <span className="ml-1 text-gray-400 font-normal">
                  (leave empty to use client agent default)
                </span>
              </label>
              <input
                type="text"
                value={config.cdpUrl}
                onChange={(e) => update({ cdpUrl: e.target.value })}
                placeholder="http://localhost:9222"
                className="w-full rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs font-mono focus:border-purple-400 focus:outline-none"
              />
              <p className="mt-0.5 text-[10px] text-gray-400">
                Start Chrome with:{' '}
                <code className="bg-gray-100 px-1 rounded">
                  google-chrome --remote-debugging-port=9222
                  --disable-backgrounding-occluded-windows --disable-renderer-backgrounding
                </code>
              </p>
            </div>
          )}

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Login Username</label>
              <input
                type="text"
                value={config.username}
                onChange={(e) => update({ username: e.target.value })}
                placeholder="Optional"
                className="w-full rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs focus:border-purple-400 focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Login Password</label>
              <input
                type="password"
                value={config.password}
                onChange={(e) => update({ password: e.target.value })}
                placeholder="Optional"
                className="w-full rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs focus:border-purple-400 focus:outline-none"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Business Context</label>
            <textarea
              value={config.businessContext}
              onChange={(e) => update({ businessContext: e.target.value })}
              placeholder="Describe the app's purpose, key workflows, target users..."
              rows={2}
              className="w-full rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs resize-none focus:border-purple-400 focus:outline-none"
            />
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              role="switch"
              aria-checked={config.headless}
              onClick={() => update({ headless: !config.headless })}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${config.headless ? 'bg-purple-500' : 'bg-gray-300'}`}
            >
              <span
                className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${config.headless ? 'translate-x-4' : 'translate-x-0.5'}`}
              />
            </button>
            <span className="text-xs text-gray-600">Headless mode</span>
          </div>
        </div>
      )}
    </div>
  )
}
