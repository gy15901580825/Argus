import { API_BASE_URL } from '@/lib/api'

const SITE_URL = 'https://www.example.com'

export async function GET() {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/blogs?limit=50`, {
      next: { revalidate: 3600 },
    })
    const blogs = res.ok ? await res.json() : []

    const items = blogs
      .map(
        (b: any) => `
    <item>
      <title><![CDATA[${b.title}]]></title>
      <link>${SITE_URL}/blog/${b.slug || b.id}</link>
      <guid isPermaLink="true">${SITE_URL}/blog/${b.slug || b.id}</guid>
      <description><![CDATA[${b.summary || ''}]]></description>
      <pubDate>${new Date(b.published_at || b.created_at).toUTCString()}</pubDate>
      ${b.category_name ? `<category>${b.category_name}</category>` : ''}
      ${b.author_name ? `<dc:creator><![CDATA[${b.author_name}]]></dc:creator>` : ''}
    </item>`
      )
      .join('')

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>Argus Blog</title>
    <link>${SITE_URL}/blog</link>
    <description>Insights on AI-powered testing, automation, and product updates</description>
    <language>en</language>
    <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
    <atom:link href="${SITE_URL}/feed" rel="self" type="application/rss+xml"/>
    ${items}
  </channel>
</rss>`

    return new Response(xml, {
      headers: {
        'Content-Type': 'application/xml; charset=utf-8',
        'Cache-Control': 'public, max-age=3600, s-maxage=3600',
      },
    })
  } catch {
    return new Response(
      '<rss version="2.0"><channel><title>Argus Blog</title></channel></rss>',
      {
        headers: { 'Content-Type': 'application/xml' },
      }
    )
  }
}
