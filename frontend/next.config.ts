import type { NextConfig } from 'next'

// Suppress deprecation warning for util._extend
const originalEmitWarning = process.emitWarning
process.emitWarning = (warning: string | Error, ...args: any[]) => {
  if (typeof warning === 'string' && warning.includes('The `util._extend` API is deprecated')) {
    return
  }
  if (
    warning &&
    typeof warning === 'object' &&
    'message' in warning &&
    warning.message &&
    warning.message.includes('The `util._extend` API is deprecated')
  ) {
    return
  }
  return (originalEmitWarning as any).apply(process, [warning, ...args])
}

if (process.env.NODE_ENV === 'development') {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
}

const nextConfig: NextConfig = {
  output: 'standalone',
  allowedDevOrigins: ['192.168.1.121', '192.168.1.161'],
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'images.unsplash.com' },
      { protocol: 'https', hostname: '*.r2.cloudflarestorage.com' },
      { protocol: 'https', hostname: 'scripts.example.com' },
      { protocol: 'https', hostname: 'media.example.com' },
    ],
  },
}

export default nextConfig
