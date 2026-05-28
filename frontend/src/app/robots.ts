import type { MetadataRoute } from 'next'

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: '*',
        allow: '/',
        disallow: ['/admin/', '/dashboard/', '/api/', '/callback', '/probe-content/'],
      },
    ],
    sitemap: 'https://www.example.com/sitemap.xml',
  }
}
