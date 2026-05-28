'use client'

import { useState } from 'react'
import { runAgentCommand } from '@/lib/api'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

export default function AgentPage() {
  const [agentId, setAgentId] = useState('')
  const [toolName, setToolName] = useState('ping')
  const [argsJson, setArgsJson] = useState('{}')
  const [result, setResult] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleExecute = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      // Validate JSON arguments
      let parsedArgs = {}
      try {
        parsedArgs = JSON.parse(argsJson)
      } catch (e) {
        throw new Error('Invalid JSON arguments')
      }

      if (!agentId) {
        throw new Error('Agent ID is required')
      }

      const response = await runAgentCommand(agentId, toolName, parsedArgs)
      setResult(JSON.stringify(response, null, 2))
    } catch (err: any) {
      console.error('Execution error:', err)
      setError(typeof err.message === 'string' ? err.message : JSON.stringify(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container mx-auto py-10">
      <h1 className="mb-8 text-3xl font-bold">Agent Interaction</h1>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Send Command</CardTitle>
            <CardDescription>Execute a tool on a connected agent</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleExecute} className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="agentId" className="text-sm font-medium">
                  Agent ID
                </label>
                <input
                  id="agentId"
                  value={agentId}
                  onChange={(e) => setAgentId(e.target.value)}
                  placeholder="e.g. agent-123"
                  className="w-full rounded-md border p-2"
                  required
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="toolName" className="text-sm font-medium">
                  Tool Name
                </label>
                <input
                  id="toolName"
                  value={toolName}
                  onChange={(e) => setToolName(e.target.value)}
                  placeholder="e.g. ping"
                  className="w-full rounded-md border p-2"
                  required
                />
              </div>

              <div className="space-y-2">
                <label htmlFor="args" className="text-sm font-medium">
                  Arguments (JSON)
                </label>
                <textarea
                  id="args"
                  value={argsJson}
                  onChange={(e) => setArgsJson(e.target.value)}
                  placeholder="{}"
                  className="min-h-[150px] w-full rounded-md border p-2 font-mono text-sm"
                  required
                />
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full rounded-md bg-blue-600 px-4 py-2 text-white hover:bg-blue-700 disabled:opacity-50"
              >
                {loading ? 'Executing...' : 'Execute Command'}
              </button>
            </form>
          </CardContent>
        </Card>

        <Card className="h-full">
          <CardHeader>
            <CardTitle>Result</CardTitle>
            <CardDescription>Output from the agent</CardDescription>
          </CardHeader>
          <CardContent className="h-[calc(100%-5rem)]">
            <div className="h-full w-full rounded-md bg-slate-950 p-4 font-mono text-sm text-slate-50 overflow-auto">
              {error ? (
                <span className="text-red-400">Error: {error}</span>
              ) : result ? (
                <pre>{result}</pre>
              ) : (
                <span className="text-slate-500">Waiting for command execution...</span>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
