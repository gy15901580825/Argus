import { describe, it, expect, afterEach, vi } from 'vitest'
import { getCoalesceWindowMs, getMarkdownMode, getDebug } from './stream-config'

describe('stream-config', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
  })

  it('returns hard-coded defaults in production regardless of env', () => {
    vi.stubEnv('NODE_ENV', 'production')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_COALESCE_MS', '200')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_MARKDOWN_MODE', 'defer')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_DEBUG', 'true')
    expect(getCoalesceWindowMs()).toBe(50)
    expect(getMarkdownMode()).toBe('balanced')
    expect(getDebug()).toBe(false)
  })

  it('honors env overrides in development', () => {
    vi.stubEnv('NODE_ENV', 'development')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_COALESCE_MS', '20')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_MARKDOWN_MODE', 'defer')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_DEBUG', 'true')
    expect(getCoalesceWindowMs()).toBe(20)
    expect(getMarkdownMode()).toBe('defer')
    expect(getDebug()).toBe(true)
  })

  it('treats coalesce "off" and "0" as zero (disables gate)', () => {
    vi.stubEnv('NODE_ENV', 'development')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_COALESCE_MS', 'off')
    expect(getCoalesceWindowMs()).toBe(0)
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_COALESCE_MS', '0')
    expect(getCoalesceWindowMs()).toBe(0)
  })

  it('invalid markdown mode falls back to balanced in dev', () => {
    vi.stubEnv('NODE_ENV', 'development')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_MARKDOWN_MODE', 'banana')
    expect(getMarkdownMode()).toBe('balanced')
  })

  it('missing env vars yield defaults in dev', () => {
    vi.stubEnv('NODE_ENV', 'development')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_COALESCE_MS', '')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_MARKDOWN_MODE', '')
    vi.stubEnv('NEXT_PUBLIC_CHAT_STREAM_DEBUG', '')
    expect(getCoalesceWindowMs()).toBe(50)
    expect(getMarkdownMode()).toBe('balanced')
    expect(getDebug()).toBe(false)
  })
})
