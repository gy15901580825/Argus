import type { LucideIcon } from 'lucide-react'
import {
  Brain,
  TrendingUp,
  MessageSquare,
  FileCode,
  FlaskConical,
  FileText,
  Bug,
  AlertCircle,
  Info,
} from 'lucide-react'

export type MessageCategory =
  | 'thinking'
  | 'progress'
  | 'result'
  | 'code'
  | 'testResult'
  | 'testScript'
  | 'bugReport'
  | 'error'
  | 'system'

export type SeverityTint = 'critical' | 'high' | 'medium' | 'low' | 'success' | null

export const messageTokens = {
  gap: 'gap-4',
  padX: 'px-4',
  padY: 'py-3',
  iconSize: 14,
  labelClass: 'text-xs uppercase tracking-wider text-gray-500',
  summaryClass: 'text-sm text-gray-900',
  dividerClass: 'border-t border-gray-100 pt-3',
  bodyIndentPx: 22, // icon(14) + gap-2(8)
} as const

export const collapseDefault: Record<MessageCategory, boolean> = {
  thinking: true,
  progress: true,
  result: false,
  code: true,
  testResult: false,
  testScript: true,
  bugReport: false,
  error: false,
  system: false,
}

export const categoryMeta: Record<MessageCategory, { icon: LucideIcon; label: string }> = {
  thinking: { icon: Brain, label: 'Thinking' },
  progress: { icon: TrendingUp, label: 'Progress' },
  result: { icon: MessageSquare, label: 'Response' },
  code: { icon: FileCode, label: 'Code' },
  testResult: { icon: FlaskConical, label: 'Test results' },
  testScript: { icon: FileText, label: 'Test script' },
  bugReport: { icon: Bug, label: 'Bug report' },
  error: { icon: AlertCircle, label: 'Error' },
  system: { icon: Info, label: 'System' },
}

export const severityClass: Record<Exclude<SeverityTint, null>, string> = {
  critical: 'text-red-700 font-semibold',
  high: 'text-red-600 font-semibold',
  medium: 'text-amber-700',
  low: 'text-gray-700',
  success: 'text-green-700 font-semibold',
}
