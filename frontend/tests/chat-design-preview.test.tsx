import { describe, it, expect, vi, afterEach } from 'vitest'

describe('/chat/design-preview', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    vi.doUnmock('next/navigation')
    vi.resetModules()
  })

  it('calls notFound() in production', async () => {
    vi.resetModules()
    vi.stubEnv('NODE_ENV', 'production')
    const notFoundMock = vi.fn(() => {
      throw new Error('NEXT_NOT_FOUND')
    })
    vi.doMock('next/navigation', () => ({ notFound: notFoundMock }))
    const Page = (await import('@/app/chat/design-preview/page')).default
    expect(() => Page()).toThrow('NEXT_NOT_FOUND')
    expect(notFoundMock).toHaveBeenCalled()
  })
})
