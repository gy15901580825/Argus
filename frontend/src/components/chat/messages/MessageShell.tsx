'use client'

import { useState, useId, type ReactNode } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import {
  type MessageCategory,
  type SeverityTint,
  categoryMeta,
  collapseDefault,
  messageTokens,
  severityClass,
} from './tokens'

interface MessageShellProps {
  category: MessageCategory
  summary: ReactNode
  children?: ReactNode
  defaultCollapsed?: boolean
  severityTint?: SeverityTint
  bodyAlwaysVisible?: boolean
}

export function MessageShell({
  category,
  summary,
  children,
  defaultCollapsed,
  severityTint = null,
  bodyAlwaysVisible = false,
}: MessageShellProps) {
  const bodyId = useId()
  const [collapsed, setCollapsed] = useState(defaultCollapsed ?? collapseDefault[category])

  if (category === 'result') {
    return <>{children}</>
  }

  const { icon: Icon, label } = categoryMeta[category]
  const summaryClassName = [
    messageTokens.summaryClass,
    severityTint ? severityClass[severityTint] : '',
  ]
    .filter(Boolean)
    .join(' ')

  const hasBody = Boolean(children)
  const showBody = bodyAlwaysVisible || !collapsed

  return (
    <div className={`${messageTokens.dividerClass}`}>
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        disabled={!hasBody || bodyAlwaysVisible}
        aria-expanded={!collapsed}
        aria-controls={hasBody ? bodyId : undefined}
        className="flex w-full items-start gap-2 rounded text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-gray-300"
      >
        <Icon className="mt-0.5 h-[14px] w-[14px] shrink-0 text-gray-500" />
        <span className="flex-1">
          <span className={`block ${messageTokens.labelClass}`}>{label}</span>
          <span data-message-summary className={`block ${summaryClassName}`}>
            {summary}
          </span>
        </span>
        {hasBody &&
          !bodyAlwaysVisible &&
          (collapsed ? (
            <ChevronRight className="mt-0.5 h-4 w-4 shrink-0 text-gray-400" />
          ) : (
            <ChevronDown className="mt-0.5 h-4 w-4 shrink-0 text-gray-400" />
          ))}
      </button>
      {hasBody && showBody && (
        <div id={bodyId} className="mt-2" style={{ paddingLeft: messageTokens.bodyIndentPx }}>
          {children}
        </div>
      )}
    </div>
  )
}
