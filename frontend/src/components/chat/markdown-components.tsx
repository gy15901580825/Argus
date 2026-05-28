'use client'

// Shared ReactMarkdown component overrides used by both the legacy StreamingResultMessage and the new ResultMessage primitive.

import type { Components } from 'react-markdown'
import { CodeBlock } from './CodeBlock'

export const resultMessageComponents: Components = {
  pre: ({ children }) => {
    const child = children as React.ReactElement<{
      className?: string
      children?: React.ReactNode
    }>
    const className = child?.props?.className
    if (className && typeof className === 'string' && className.includes('language-')) {
      const language = className.replace('language-', '')
      const code = String(child.props.children || '').replace(/\n$/, '')
      return <CodeBlock code={code} language={language} />
    }
    return (
      <pre className="my-2 overflow-x-auto rounded-lg bg-gray-900 p-4 text-sm font-mono">
        {children}
      </pre>
    )
  },
  code: ({ className, children, ...props }) => {
    const isInline = !className
    return isInline ? (
      <code
        className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-sm text-gray-800"
        {...props}
      >
        {children}
      </code>
    ) : (
      <code className={`font-mono text-sm text-gray-100 ${className || ''}`} {...props}>
        {children}
      </code>
    )
  },
  p: ({ children }) => <p className="my-1.5 font-sans">{children}</p>,
  li: ({ children }) => <li className="font-sans">{children}</li>,
  h1: ({ children }) => <h1 className="font-sans">{children}</h1>,
  h2: ({ children }) => <h2 className="font-sans">{children}</h2>,
  h3: ({ children }) => <h3 className="font-sans">{children}</h3>,
  h4: ({ children }) => <h4 className="font-sans">{children}</h4>,
}
