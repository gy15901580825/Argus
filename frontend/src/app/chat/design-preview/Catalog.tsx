'use client'

import {
  ThinkingMessage,
  ProgressMessage,
  ResultMessage,
  CodeArtifact,
  TestResultArtifact,
  TestScriptArtifact,
  BugReportArtifact,
  ErrorMessage,
  SystemMessage,
} from '@/components/chat/messages'
import type { StreamChunk } from '@/lib/chat-types'

const fixtures = {
  thinking: [
    { type: 'log' as const, content: 'Parsing request', author: 'planner', stage: 'parse' },
    { type: 'log' as const, content: 'Choosing strategy', author: 'planner', stage: 'decide' },
    { type: 'log' as const, content: 'Dispatching to agent', author: 'planner', stage: 'dispatch' },
  ],
  progress: [
    { type: 'progress' as const, content: 'Step 1 of 3 — preparing environment' },
    { type: 'progress' as const, content: 'Step 2 of 3 — running tests' },
  ],
  result: [
    {
      type: 'result' as const,
      content:
        '# Summary\n\nAll tests completed successfully. See below for details.\n\n- Test A passed\n- Test B passed',
    },
  ],
  code: [
    {
      type: 'code' as const,
      content: 'def hello():\n    print("hi")\n\nhello()',
      language: 'python',
    },
  ],
  testResult: [
    {
      type: 'ssh_result' as const,
      content: '',
      sshResult: {
        success: false,
        stdout: '============= 3 passed, 1 failed in 12.4s =============',
        stderr: '',
        exit_code: 1,
      },
    },
  ],
  testScript: [
    {
      type: 'web_ui_artifact' as const,
      content: '',
      webUiArtifactData: {
        script: 'import pytest\n\ndef test_login():\n    pass\n',
        name: 'test_login.py',
      },
    },
  ],
  bugReport: [
    {
      type: 'web_ui_bug' as const,
      content: '',
      webUiBugData: {
        bug_counts: { critical: 1, high: 1, total: 2 },
        url: 'https://example.com',
        task_id: 'demo',
        screenshot_urls: [],
      },
    },
  ],
  error: [
    { type: 'error' as const, content: 'Connection refused\nbackend unreachable on port 8081' },
  ],
  system: [{ type: 'system' as const, content: 'Session started' }],
} satisfies Record<string, StreamChunk[]>

export function Catalog() {
  return (
    <div className="mx-auto max-w-3xl p-8">
      <h1 className="mb-8 text-2xl font-semibold">Chat Message Primitive Catalog</h1>
      <p className="mb-8 text-sm text-gray-500">
        Dev-only. Every primitive rendered with fixture data.
      </p>

      <Section title="ThinkingMessage (collapsed default)">
        <ThinkingMessage chunks={fixtures.thinking} />
      </Section>

      <Section title="ProgressMessage (collapsed default)">
        <ProgressMessage chunks={fixtures.progress} />
      </Section>

      <Section title="ResultMessage (isStreaming=false)">
        <ResultMessage chunks={fixtures.result} isStreaming={false} />
      </Section>

      <Section title="ResultMessage (isStreaming=true)">
        <ResultMessage chunks={fixtures.result} isStreaming={true} />
      </Section>

      <Section title="CodeArtifact">
        <CodeArtifact chunks={fixtures.code} />
      </Section>

      <Section title="TestResultArtifact (has failures — critical tint)">
        <TestResultArtifact chunks={fixtures.testResult} />
      </Section>

      <Section title="TestScriptArtifact">
        <TestScriptArtifact chunks={fixtures.testScript} />
      </Section>

      <Section title="BugReportArtifact">
        <BugReportArtifact chunks={fixtures.bugReport} />
      </Section>

      <Section title="ErrorMessage">
        <ErrorMessage chunks={fixtures.error} />
      </Section>

      <Section title="SystemMessage">
        <SystemMessage chunks={fixtures.system} />
      </Section>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-10">
      <h2 className="mb-3 text-xs font-medium uppercase tracking-wider text-gray-400">{title}</h2>
      <div className="rounded-lg border border-gray-200 p-6">{children}</div>
    </section>
  )
}
