import type { Metadata } from 'next'
import { notFound } from 'next/navigation'
import { fetchBlogBySlugServer, API_BASE_URL } from '@/lib/api'
import { BlogPostClient } from './BlogPostClient'

interface Props {
  params: Promise<{ slug: string }>
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params
  const blog = await fetchBlogBySlugServer(slug)
  if (!blog) return { title: 'Blog Post Not Found' }

  const title = blog.meta_title || blog.title
  const description = blog.meta_description || blog.summary || `${blog.title} - Argus Blog`
  const ogImage = blog.og_image_url || blog.cover_image_url

  return {
    title: `${title} | Argus Blog`,
    description,
    openGraph: {
      title,
      description,
      type: 'article',
      publishedTime: blog.published_at || undefined,
      authors: blog.author_name ? [blog.author_name] : undefined,
      ...(ogImage && { images: [{ url: ogImage, width: 1200, height: 630 }] }),
    },
    twitter: {
      card: 'summary_large_image',
      title,
      description,
      ...(ogImage && { images: [ogImage] }),
    },
    ...(blog.canonical_url && { alternates: { canonical: blog.canonical_url } }),
  }
}

export default async function BlogPostPage({ params }: Props) {
  const { slug } = await params
  const blog = await fetchBlogBySlugServer(slug)
  if (!blog) notFound()

  // JSON-LD structured data for Google Rich Results
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'BlogPosting',
    headline: blog.title,
    description: blog.summary || '',
    image: blog.og_image_url || blog.cover_image_url || undefined,
    datePublished: blog.published_at,
    dateModified: blog.updated_at,
    author: {
      '@type': 'Person',
      name: blog.author_name || 'Argus Team',
    },
    publisher: {
      '@type': 'Organization',
      name: 'Argus',
      url: 'https://www.example.com',
    },
    mainEntityOfPage: {
      '@type': 'WebPage',
      '@id': `https://www.example.com/blog/${slug}`,
    },
    wordCount: blog.content ? blog.content.replace(/<[^>]*>/g, '').split(/\s+/).length : undefined,
    ...(blog.category_name && { articleSection: blog.category_name }),
  }

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <BlogPostClient blog={blog} />
    </>
  )
}
