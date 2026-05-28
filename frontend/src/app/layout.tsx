import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { GoogleAnalytics } from '@next/third-parties/google'
import './globals.css'
import { Header } from '@/components/layout/Header'
import { Footer } from '@/components/layout/Footer'
import { Providers } from '@/components/providers'
import { HashRedirect } from '@/components/HashRedirect'
import { ClickTracker } from '@/components/analytics/ClickTracker'
import { AnalyticsIdentify } from '@/components/analytics/AnalyticsIdentify'
import { PageViewTracker } from '@/components/analytics/PageViewTracker'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  metadataBase: new URL('https://www.example.com'),
  title: {
    default: 'Argus — Test AI Agents for Reliability, Security & Compliance',
    template: '%s | Argus',
  },
  description:
    'Argus proves your AI agent is reliable, secure, and audit-ready — before you ship, and on every deploy. Reliability scoring, adversarial probes, and EU AI Act / NIST AI RMF evidence in one workflow.',
  alternates: {
    canonical: '/',
    types: {
      'application/rss+xml': '/feed',
    },
  },
  openGraph: {
    type: 'website',
    siteName: 'Argus',
    url: 'https://www.example.com',
    title: 'Test AI Agents for Reliability, Security & Compliance',
    description:
      'Reliability scoring, adversarial probes, and EU AI Act / NIST AI RMF evidence — in one CI run.',
    images: [
      {
        url: '/og-home.png',
        width: 1200,
        height: 630,
        alt: 'Argus — Test AI Agents for Reliability, Security & Compliance',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Test AI Agents for Reliability, Security & Compliance',
    description: 'Reliability scoring, adversarial probes, and EU AI Act evidence — in one CI run.',
    images: ['/og-home.png'],
  },
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className="scroll-smooth">
      <body
        className={`${inter.className} antialiased min-h-screen flex flex-col bg-background text-foreground`}
      >
        <Providers>
          <HashRedirect />
          <Header />
          <main className="flex-grow pt-16">{children}</main>
          <Footer />
          {process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID && (
            <>
              <ClickTracker />
              <AnalyticsIdentify />
              <PageViewTracker />
            </>
          )}
        </Providers>
      </body>
      {process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID && (
        <GoogleAnalytics gaId={process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID} />
      )}
    </html>
  )
}
