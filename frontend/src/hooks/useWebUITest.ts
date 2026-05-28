'use client'
import { useState, useEffect } from 'react'

export interface WebUIConfig {
  cdpUrl: string
  username: string
  password: string
  maxSteps: number
  userPersona: 'new_user' | 'experienced_user' | 'admin' | 'power_user'
  businessContext: string
  headless: boolean
}

export interface WebUIResultData {
  task_id?: string
  bug_counts: { critical: number; high: number; medium: number; low: number }
  steps_done: number
  has_tests: boolean
  url?: string
  tests_url?: string
  bug_report_url?: string
}

const DEFAULT_CONFIG: WebUIConfig = {
  cdpUrl: '',
  username: '',
  password: '',
  maxSteps: 100,
  userPersona: 'new_user',
  businessContext: '',
  headless: true,
}

export function useWebUITest(isLoaded: boolean) {
  const [webUiTestEnabled, setWebUiTestEnabled] = useState(false)
  const [showWebUIPanel, setShowWebUIPanel] = useState(false)
  const [showCDPDialog, setShowCDPDialog] = useState(false)
  const [webUiConfig, setWebUiConfig] = useState<WebUIConfig>(DEFAULT_CONFIG)
  const [currentResult, setCurrentResult] = useState<WebUIResultData | null>(null)
  const [currentScript, setCurrentScript] = useState('')
  const [webUiPhases, setWebUiPhases] = useState<
    Array<{ name: string; icon: string; status: 'pending' | 'running' | 'done' }>
  >([
    { name: 'Business Intelligence', icon: '🔎', status: 'pending' },
    { name: 'Core User Journeys', icon: '🗺️', status: 'pending' },
    { name: 'Bug Hunting', icon: '🐛', status: 'pending' },
  ])

  useEffect(() => {
    const savedConfig = localStorage.getItem('webUiConfig')
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (savedConfig) {
      try {
        setWebUiConfig(JSON.parse(savedConfig))
      } catch {}
    }
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (localStorage.getItem('webUiTestEnabled') === 'true') setWebUiTestEnabled(true)
  }, [])

  useEffect(() => {
    if (isLoaded) {
      localStorage.setItem('webUiConfig', JSON.stringify(webUiConfig))
      localStorage.setItem('webUiTestEnabled', String(webUiTestEnabled))
    }
  }, [webUiConfig, webUiTestEnabled, isLoaded])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setShowWebUIPanel(webUiTestEnabled)
  }, [webUiTestEnabled])

  // isLocalMode is now driven by the parent (testEnv === 'local'),
  // not by whether cdpUrl is set. This avoids circular dependency.
  const [isLocalMode, setIsLocalMode] = useState(false)

  const buildStreamContext = (baseContext?: Record<string, any>) => {
    if (!webUiTestEnabled) return baseContext
    return {
      ...baseContext,
      max_steps: webUiConfig.maxSteps,
      user_persona: webUiConfig.userPersona,
      ...(webUiConfig.businessContext && { business_context: webUiConfig.businessContext }),
      headless: webUiConfig.headless,
      ...(webUiConfig.username &&
        webUiConfig.password && {
          credentials: { username: webUiConfig.username, password: webUiConfig.password },
        }),
    }
  }

  const resetForNewTest = () => {
    setCurrentResult(null)
    setCurrentScript('')
    setWebUiPhases([
      { name: 'Business Intelligence', icon: '🔎', status: 'pending' },
      { name: 'Core User Journeys', icon: '🗺️', status: 'pending' },
      { name: 'Bug Hunting', icon: '🐛', status: 'pending' },
    ])
  }

  const updatePhaseFromLog = (logText: string) => {
    const lower = logText.toLowerCase()
    setWebUiPhases((prev) => {
      const next = [...prev]
      if (lower.includes('phase 1') || lower.includes('business intelligence')) {
        next[0] = {
          ...next[0],
          status: lower.includes('complete') || lower.includes('done') ? 'done' : 'running',
        }
      } else if (lower.includes('phase 2') || lower.includes('user journey')) {
        if (next[0].status !== 'done') next[0] = { ...next[0], status: 'done' }
        next[1] = {
          ...next[1],
          status: lower.includes('complete') || lower.includes('done') ? 'done' : 'running',
        }
      } else if (lower.includes('phase 3') || lower.includes('bug hunt')) {
        if (next[0].status !== 'done') next[0] = { ...next[0], status: 'done' }
        if (next[1].status !== 'done') next[1] = { ...next[1], status: 'done' }
        next[2] = {
          ...next[2],
          status: lower.includes('complete') || lower.includes('done') ? 'done' : 'running',
        }
      }
      return next
    })
  }

  return {
    webUiTestEnabled,
    setWebUiTestEnabled,
    showWebUIPanel,
    setShowWebUIPanel,
    showCDPDialog,
    setShowCDPDialog,
    webUiConfig,
    setWebUiConfig,
    currentResult,
    setCurrentResult,
    currentScript,
    setCurrentScript,
    webUiPhases,
    setWebUiPhases,
    isLocalMode,
    setIsLocalMode,
    buildStreamContext,
    resetForNewTest,
    updatePhaseFromLog,
  }
}
