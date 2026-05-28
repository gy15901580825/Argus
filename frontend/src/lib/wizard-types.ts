// frontend/src/lib/wizard-types.ts
export type WizardRoundLabel =
  | 'intent'
  | 'run_where'
  | 'credentials'
  | 'persona'
  | 'target_url'
  | 'local_setup_check'
  | 'confirm'
  | 'other'

export type WizardAnswerKind =
  | 'option_click'
  | 'free_text'
  | 'bound_context_skip'
  | 'parsed_from_text'

export type WizardInputKind = 'option_click' | 'free_text' | 'back' | 'abort'

export interface WizardRoundEvent {
  round_n: number
  question: string
  options: string[]
  allow_free_text: boolean
  allow_back: boolean
  round_label: WizardRoundLabel
}

export interface WizardGuideEvent {
  kind: 'client_agent_install' | 'cdp_browser_launch'
  markdown: string
}

export interface WizardAbortedEvent {
  at_round_label: WizardRoundLabel
  rounds_used: number
}

export interface WizardInput {
  roundN: number
  kind: WizardInputKind
  value?: string
}

export interface WizardRoundMessageData {
  kind: 'wizard_round'
  roundN: number
  roundLabel: WizardRoundLabel
  question: string
  options: string[]
  allowFreeText: boolean
  allowBack: boolean
  status: 'pending' | 'answered' | 'stale'
  selectedAnswer?: string
}

export interface WizardGuideMessageData {
  kind: 'wizard_guide'
  guideKind: WizardGuideEvent['kind']
  markdown: string
}
