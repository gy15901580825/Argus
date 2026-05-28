'use client'

import { useState } from 'react'
import { Dialog } from '@/components/ui/dialog'
import { Icons } from '@/components/ui/icons'
import { useAuthStore } from '@/store/useAuthStore'

interface OAuthTokenDialogProps {
  isOpen: boolean
  onClose: () => void
  localTestEnabled: boolean
  onLocalTestEnabledChange: (enabled: boolean) => void
}

export function OAuthTokenDialog({
  isOpen,
  onClose,
  localTestEnabled,
  onLocalTestEnabledChange,
}: OAuthTokenDialogProps) {
  const apiToken = useAuthStore((state) => state.apiToken)
  const [error, setError] = useState<string | null>(null)
  const [copiedField, setCopiedField] = useState<string | null>(null)

  const copyToClipboard = async (text: string, fieldName: string) => {
    try {
      // Try modern clipboard API first
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text)
        setCopiedField(fieldName)
        setTimeout(() => setCopiedField(null), 2000)
      } else {
        // Fallback to older method
        const textArea = document.createElement('textarea')
        textArea.value = text
        textArea.style.position = 'fixed'
        textArea.style.left = '-999999px'
        textArea.style.top = '-999999px'
        document.body.appendChild(textArea)
        textArea.focus()
        textArea.select()

        try {
          const successful = document.execCommand('copy')
          if (successful) {
            setCopiedField(fieldName)
            setTimeout(() => setCopiedField(null), 2000)
          } else {
            throw new Error('Copy command failed')
          }
        } finally {
          document.body.removeChild(textArea)
        }
      }
    } catch (err) {
      console.error('Failed to copy:', err)
      setError('Failed to copy to clipboard. Please try again or copy manually.')
    }
  }

  const dockerCommandMac = apiToken
    ? `docker run \\\n  -e API_TOKEN=${apiToken} \\\n  -e CDP_URL=http://host.docker.internal:9222 \\\n  <your-gh-user>/client_agent:latest`
    : ''
  const dockerCommandLinux = apiToken
    ? `docker run \\\n  --network=host \\\n  -e API_TOKEN=${apiToken} \\\n  <your-gh-user>/client_agent:latest`
    : ''

  const chromeCommandMac = `/Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome \\\n  --remote-debugging-port=9222 \\\n  --remote-debugging-address=0.0.0.0 \\\n  --user-data-dir=/tmp/chrome-cdp \\\n  --no-first-run \\\n  --disable-backgrounding-occluded-windows \\\n  --disable-renderer-backgrounding \\\n  --disable-background-timer-throttling &`
  const chromeCommandLinux = `google-chrome \\\n  --remote-debugging-port=9222 \\\n  --user-data-dir=/tmp/chrome-cdp \\\n  --no-first-run \\\n  --disable-backgrounding-occluded-windows \\\n  --disable-renderer-backgrounding \\\n  --disable-background-timer-throttling &`

  return (
    <Dialog isOpen={isOpen} onClose={onClose} title="Run Client Agent" className="max-w-3xl">
      {error && (
        <div className="rounded-md bg-red-50 p-4 mb-4">
          <div className="text-sm text-red-700">{error}</div>
        </div>
      )}

      <div>
        <div className="mb-4 rounded-md bg-yellow-50 p-4">
          <div className="flex items-center justify-between">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-yellow-400" viewBox="0 0 20 20" fill="currentColor">
                  <path
                    fillRule="evenodd"
                    d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                    clipRule="evenodd"
                  />
                </svg>
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-yellow-800">Development/Testing Only</h3>
                <div className="mt-2 text-sm text-yellow-700">
                  Enable local testing mode for development
                </div>
              </div>
            </div>
            <label className="flex items-center cursor-pointer">
              <div className="relative">
                <input
                  type="checkbox"
                  className="sr-only"
                  checked={localTestEnabled}
                  onChange={(e) => onLocalTestEnabledChange(e.target.checked)}
                />
                <div
                  className={`block w-14 h-8 rounded-full transition ${localTestEnabled ? 'bg-blue-600' : 'bg-gray-400'}`}
                ></div>
                <div
                  className={`dot absolute left-1 top-1 bg-white w-6 h-6 rounded-full transition transform ${localTestEnabled ? 'translate-x-6' : ''}`}
                ></div>
              </div>
            </label>
          </div>
        </div>

        <div className="space-y-4">
          <hr className="my-6" />

          <div className="rounded-md bg-blue-50 p-4">
            <div className="flex">
              <div className="flex-shrink-0">
                <svg className="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
                  <path
                    fillRule="evenodd"
                    d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
                    clipRule="evenodd"
                  />
                </svg>
              </div>
              <div className="ml-3 flex-1">
                <h3 className="text-sm font-medium text-blue-900">Docker Client Setup</h3>
                <div className="mt-2 text-sm text-blue-800">
                  <p className="mb-2">Step 1 — Pull the client agent Docker image:</p>
                  <div className="relative">
                    <pre className="overflow-x-auto rounded bg-blue-100 p-3 pr-20 font-mono text-xs text-blue-900">
                      docker pull <your-gh-user>/client_agent:latest
                    </pre>
                    <button
                      onClick={(e) => {
                        e.preventDefault()
                        e.stopPropagation()
                        copyToClipboard(
                          'docker pull <your-gh-user>/client_agent:latest',
                          'docker-pull'
                        )
                      }}
                      className="absolute right-2 top-2 z-10 flex items-center gap-1 rounded bg-blue-200 px-2 py-1 text-xs text-blue-800 hover:bg-blue-300 cursor-pointer"
                      type="button"
                    >
                      {copiedField === 'docker-pull' ? (
                        <>
                          <Icons.check className="h-3 w-3" />
                          Copied
                        </>
                      ) : (
                        <>
                          <Icons.copy className="h-3 w-3" />
                          Copy
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <hr className="my-6" />

          {apiToken && (
            <>
              <div className="rounded-md bg-green-50 p-4">
                <div className="flex">
                  <div className="flex-shrink-0">
                    <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                      <path
                        fillRule="evenodd"
                        d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                        clipRule="evenodd"
                      />
                    </svg>
                  </div>
                  <div className="ml-3 flex-1">
                    <h3 className="text-sm font-medium text-green-900">
                      Step 2 — Run the client agent
                    </h3>
                    <div className="mt-2 text-sm text-green-800">
                      <p className="mb-2">Copy and run the command for your platform:</p>

                      <p className="mb-1 text-xs font-medium text-green-900">macOS</p>
                      <div className="relative mb-3">
                        <pre className="rounded bg-green-100 p-3 pr-20 font-mono text-xs text-green-900 whitespace-pre-wrap break-all">
                          {dockerCommandMac}
                        </pre>
                        <button
                          onClick={(e) => {
                            e.preventDefault()
                            e.stopPropagation()
                            copyToClipboard(dockerCommandMac, 'docker-run-mac')
                          }}
                          className="absolute right-2 top-2 z-10 flex items-center gap-1 rounded bg-green-200 px-2 py-1 text-xs text-green-800 hover:bg-green-300 cursor-pointer"
                          type="button"
                        >
                          {copiedField === 'docker-run-mac' ? (
                            <>
                              <Icons.check className="h-3 w-3" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Icons.copy className="h-3 w-3" />
                              Copy
                            </>
                          )}
                        </button>
                      </div>

                      <p className="mb-1 text-xs font-medium text-green-900">Linux</p>
                      <div className="relative">
                        <pre className="rounded bg-green-100 p-3 pr-20 font-mono text-xs text-green-900 whitespace-pre-wrap break-all">
                          {dockerCommandLinux}
                        </pre>
                        <button
                          onClick={(e) => {
                            e.preventDefault()
                            e.stopPropagation()
                            copyToClipboard(dockerCommandLinux, 'docker-run-linux')
                          }}
                          className="absolute right-2 top-2 z-10 flex items-center gap-1 rounded bg-green-200 px-2 py-1 text-xs text-green-800 hover:bg-green-300 cursor-pointer"
                          type="button"
                        >
                          {copiedField === 'docker-run-linux' ? (
                            <>
                              <Icons.check className="h-3 w-3" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Icons.copy className="h-3 w-3" />
                              Copy
                            </>
                          )}
                        </button>
                      </div>

                      <ul className="mt-3 space-y-1 text-xs text-green-700">
                        <li>
                          <strong>macOS</strong>: uses{' '}
                          <code className="rounded bg-green-100 px-1 font-mono">
                            host.docker.internal
                          </code>{' '}
                          to reach Chrome on the host —{' '}
                          <code className="rounded bg-green-100 px-1 font-mono">
                            --network=host
                          </code>{' '}
                          does not work on macOS (Docker runs in a VM)
                        </li>
                        <li>
                          <strong>Linux</strong>:{' '}
                          <code className="rounded bg-green-100 px-1 font-mono">
                            --network=host
                          </code>{' '}
                          shares the host network stack so the container can reach{' '}
                          <code className="rounded bg-green-100 px-1 font-mono">localhost</code>{' '}
                          directly
                        </li>
                      </ul>
                    </div>
                  </div>
                </div>
              </div>

              <div className="mt-4 rounded-md bg-purple-50 p-4">
                <h4 className="mb-2 text-sm font-medium text-purple-900">
                  Optional: Web UI Testing with local Chrome
                </h4>
                <p className="mb-2 text-xs text-purple-800">
                  To enable AI-driven browser testing on intranet sites, start Chrome with remote
                  debugging before running the container:
                </p>

                <p className="mb-1 text-xs font-medium text-purple-900">macOS</p>
                <div className="relative mb-3">
                  <pre className="overflow-x-auto rounded bg-purple-100 p-3 pr-20 font-mono text-xs text-purple-900 whitespace-pre">
                    {chromeCommandMac}
                  </pre>
                  <button
                    onClick={(e) => {
                      e.preventDefault()
                      e.stopPropagation()
                      copyToClipboard(chromeCommandMac, 'chrome-cdp-mac')
                    }}
                    className="absolute right-2 top-2 z-10 flex items-center gap-1 rounded bg-purple-200 px-2 py-1 text-xs text-purple-800 hover:bg-purple-300 cursor-pointer"
                    type="button"
                  >
                    {copiedField === 'chrome-cdp-mac' ? (
                      <>
                        <Icons.check className="h-3 w-3" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Icons.copy className="h-3 w-3" />
                        Copy
                      </>
                    )}
                  </button>
                </div>

                <p className="mb-1 text-xs font-medium text-purple-900">Linux</p>
                <div className="relative">
                  <pre className="overflow-x-auto rounded bg-purple-100 p-3 pr-20 font-mono text-xs text-purple-900 whitespace-pre">
                    {chromeCommandLinux}
                  </pre>
                  <button
                    onClick={(e) => {
                      e.preventDefault()
                      e.stopPropagation()
                      copyToClipboard(chromeCommandLinux, 'chrome-cdp-linux')
                    }}
                    className="absolute right-2 top-2 z-10 flex items-center gap-1 rounded bg-purple-200 px-2 py-1 text-xs text-purple-800 hover:bg-purple-300 cursor-pointer"
                    type="button"
                  >
                    {copiedField === 'chrome-cdp-linux' ? (
                      <>
                        <Icons.check className="h-3 w-3" />
                        Copied
                      </>
                    ) : (
                      <>
                        <Icons.copy className="h-3 w-3" />
                        Copy
                      </>
                    )}
                  </button>
                </div>
                <p className="mt-2 text-xs text-purple-700">
                  Then verify Chrome is ready:{' '}
                  <code className="rounded bg-purple-100 px-1 font-mono">
                    curl http://localhost:9222/json/version
                  </code>{' '}
                  — should return JSON. Then in the chat page, enable <strong>Web UI</strong> mode
                  and set CDP URL to{' '}
                  <code className="rounded bg-purple-100 px-1 font-mono">
                    http://localhost:9222
                  </code>
                  .
                </p>
                <ul className="mt-1 space-y-0.5 text-xs text-purple-600">
                  <li>
                    <code className="rounded bg-purple-100 px-1 font-mono">
                      --remote-debugging-address=0.0.0.0
                    </code>
                    : (macOS only) listen on all interfaces — required so Docker can reach Chrome
                    via{' '}
                    <code className="rounded bg-purple-100 px-1 font-mono">
                      host.docker.internal
                    </code>
                  </li>
                  <li>
                    <code className="rounded bg-purple-100 px-1 font-mono">
                      --user-data-dir=/tmp/chrome-cdp
                    </code>
                    : isolated profile — avoids conflicts with your existing Chrome session
                  </li>
                  <li>
                    <code className="rounded bg-purple-100 px-1 font-mono">&</code>: run in
                    background so the terminal stays free (Linux/macOS)
                  </li>
                  <li>
                    <code className="rounded bg-purple-100 px-1 font-mono">
                      --disable-backgrounding-*
                    </code>
                    : prevents rendering throttle → avoids CDP screenshot timeouts
                  </li>
                </ul>
              </div>
            </>
          )}
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="rounded-md bg-gray-200 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-300"
          >
            Close
          </button>
        </div>
      </div>
    </Dialog>
  )
}
