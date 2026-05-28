import type { MetadataRoute } from 'next'
import { API_BASE_URL } from '@/lib/api'

const SITE_URL = 'https://www.example.com'

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const staticPages: MetadataRoute.Sitemap = [
    { url: SITE_URL, lastModified: new Date(), changeFrequency: 'weekly', priority: 1.0 },
    { url: `${SITE_URL}/blog`, lastModified: new Date(), changeFrequency: 'daily', priority: 0.9 },
    {
      url: `${SITE_URL}/pricing`,
      lastModified: new Date(),
      changeFrequency: 'monthly',
      priority: 0.8,
    },
    { url: `${SITE_URL}/docs`, lastModified: new Date(), changeFrequency: 'weekly', priority: 0.7 },
  ]

  // Fetch published blog slugs
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/blogs?limit=500`, {
      next: { revalidate: 3600 },
    })
    if (res.ok) {
      const blogs = await res.json()
      const blogPages: MetadataRoute.Sitemap = blogs.map((b: any) => ({
        url: `${SITE_URL}/blog/${b.slug || b.id}`,
        lastModified: new Date(b.published_at || b.created_at),
        changeFrequency: 'weekly' as const,
        priority: 0.7,
      }))
      return [...staticPages, ...blogPages]
    }
  } catch {
    /* ignore */
  }

  // Fetch categories
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/blog/categories`, {
      next: { revalidate: 3600 },
    })
    if (res.ok) {
      const cats = await res.json()
      const catPages: MetadataRoute.Sitemap = cats.map((c: any) => ({
        url: `${SITE_URL}/blog?category=${c.slug}`,
        lastModified: new Date(),
        changeFrequency: 'weekly' as const,
        priority: 0.6,
      }))
      return [...staticPages, ...catPages]
    }
  } catch {
    /* ignore */
  }

  return staticPages
}
