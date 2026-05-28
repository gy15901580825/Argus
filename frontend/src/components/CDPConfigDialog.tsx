'use client'
import { useState } from 'react'
import { X } from 'lucide-react'

export interface CDPConfig {
  cdp_url: string
}

interface CDPConfigDialogProps {
  isOpen: boolean
  onClose: () => void
  config: CDPConfig | null
  onSave: (config: CDPConfig) => void
  onDisable: () => void
}

export function CDPConfigDialog({
  isOpen,
  onClose,
  config,
  onSave,
  onDisable,
}: CDPConfigDialogProps) {
  const [cdpUrl, setCdpUrl] = useState(config?.cdp_url || 'http://localhost:9222')
  const [copied, setCopied] = useState(false)

  if (!isOpen) return null

  const chromeCmd = 'google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-test'

  const copyCmd = () => {
    navigator.clipboard.writeText(chromeCmd)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-lg rounded-xl bg-white shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b">
          <h2 className="text-base font-semibold text-gray-900">
            🌐 Local Chrome CDP Configuration
          </h2>
          <button onClick={onClose} className="rounded p-1 hover:bg-gray-100">
            <X className="h-4 w-4 text-gray-500" />
          </button>
        </div>

        <div className="px-6 py-4 space-y-4">
          <div className="rounded-lg bg-indigo-50 border border-indigo-100 p-3 text-xs text-indigo-800">
            <p className="font-semibold mb-1">📖 How to use local mode:</p>
            <p>
              Start Chrome with remote debugging, then browser-use AI will connect to your existing
              browser — no new window. Perfect for testing intranet or localhost apps.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">CDP URL</label>
            <input
              type="text"
              value={cdpUrl}
              onChange={(e) => setCdpUrl(e.target.value)}
              className="w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-mono focus:border-purple-500 focus:outline-none focus:ring-1 focus:ring-purple-500"
              placeholder="http://localhost:9222"
            />
            <p className="mt-1 text-xs text-gray-500">
              Default: <code>http://localhost:9222</code> (or use{' '}
              <code>host.docker.internal:9222</code> in Docker)
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Start Chrome with CDP
            </label>
            <div className="relative rounded-md bg-gray-900 p-3 pr-16">
              <code className="text-xs text-green-300 font-mono break-all">{chromeCmd}</code>
              <button
                onClick={copyCmd}
                className="absolute right-2 top-2 rounded bg-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-600 hover:text-white"
              >
                {copied ? '✓' : 'Copy'}
              </button>
            </div>
          </div>
        </div>

        <div className="flex items-center justify-between px-6 py-4 border-t bg-gray-50 rounded-b-xl">
          <button
            onClick={() => {
              onDisable()
              onClose()
            }}
            className="text-sm font-medium text-red-600 hover:text-red-800 hover:underline"
          >
            Disable Local Mode
          </button>
          <div className="flex gap-3">
            <button
              onClick={onClose}
              className="rounded-md px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-200"
            >
              Cancel
            </button>
            <button
              onClick={() => {
                onSave({ cdp_url: cdpUrl })
                onClose()
              }}
              className="rounded-md bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-700"
            >
              Save
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
