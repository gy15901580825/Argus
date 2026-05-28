'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { useRouter } from 'next/navigation'
import { Calendar, User, ArrowLeft, MessageCircle, Clock, Eye, Tag, Share2 } from 'lucide-react'
import { getBlogComments, type BlogResponse, type CommentResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { track } from '@/lib/analytics'

interface Props {
  blog: BlogResponse
}

export function BlogPostClient({ blog }: Props) {
  const router = useRouter()
  const [comments, setComments] = useState<CommentResponse[]>([])

  useEffect(() => {
    getBlogComments(blog.id)
      .then(setComments)
      .catch(() => {})
  }, [blog.id])

  useEffect(() => {
    track('blog_article_view', {
      blog_id: blog.id,
      blog_slug: blog.slug || undefined,
      blog_category: blog.category_slug || undefined,
      blog_tag_count: blog.tags?.length || 0,
      reading_time_min: blog.reading_time_min || undefined,
    })
  }, [blog.id, blog.slug, blog.category_slug, blog.tags, blog.reading_time_min])

  const formatDate = (dateString: string) =>
    new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })

  return (
    <div className="min-h-screen pt-24 pb-20 px-4">
      <div className="container mx-auto max-w-3xl">
        <Button variant="ghost" onClick={() => router.push('/blog')} className="mb-8">
          <ArrowLeft className="mr-2 w-4 h-4" />
          Back to Blog
        </Button>

        <article>
          {/* Category + Tags */}
          {(blog.category_name || (blog.tags && blog.tags.length > 0)) && (
            <div className="flex flex-wrap gap-2 mb-4">
              {blog.category_name && (
                <Link
                  href={`/blog?category=${blog.category_slug}`}
                  className="text-xs font-medium text-primary bg-primary/10 px-2.5 py-1 rounded-full"
                >
                  {blog.category_name}
                </Link>
              )}
              {blog.tags?.map((t) => (
                <Link
                  key={t.id}
                  href={`/blog?tag=${t.slug}`}
                  className="text-xs text-muted-foreground bg-muted px-2.5 py-1 rounded-full"
                >
                  {t.name}
                </Link>
              ))}
            </div>
          )}

          <h1 className="text-4xl font-bold mb-4 leading-tight">{blog.title}</h1>

          {/* Meta row */}
          <div className="flex flex-wrap items-center gap-4 text-sm text-muted-foreground mb-8">
            {blog.author_name && (
              <span className="flex items-center gap-1.5">
                <User className="w-4 h-4" />
                {blog.author_name}
              </span>
            )}
            {blog.published_at && (
              <span className="flex items-center gap-1.5">
                <Calendar className="w-4 h-4" />
                {formatDate(blog.published_at)}
              </span>
            )}
            {blog.reading_time_min && (
              <span className="flex items-center gap-1.5">
                <Clock className="w-4 h-4" />
                {blog.reading_time_min} min read
              </span>
            )}
            <span className="flex items-center gap-1.5">
              <Eye className="w-4 h-4" />
              {blog.view_count} views
            </span>
          </div>

          {/* Cover image */}
          {blog.cover_image_url && (
            <div className="relative aspect-video rounded-xl overflow-hidden mb-8">
              {blog.cover_image_url.startsWith('data:') ? (
                // eslint-disable-next-line @next/next/no-img-element
                <img
                  src={blog.cover_image_url}
                  alt={blog.title}
                  className="w-full h-full object-cover"
                />
              ) : (
                <Image
                  src={blog.cover_image_url}
                  alt={blog.title}
                  fill
                  className="object-cover"
                  priority
                  sizes="(max-width: 768px) 100vw, 768px"
                />
              )}
            </div>
          )}

          {/* Summary */}
          {blog.summary && (
            <p className="text-xl text-muted-foreground mb-8 italic border-l-4 border-primary/30 pl-4">
              {blog.summary}
            </p>
          )}

          {/* Content */}
          <div
            className="prose prose-lg dark:prose-invert max-w-none mb-12"
            dangerouslySetInnerHTML={{ __html: blog.content }}
          />

          {/* Social Sharing */}
          <div className="flex items-center gap-3 py-6 border-t border-b mb-12">
            <Share2 className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-muted-foreground mr-2">Share:</span>
            {(() => {
              const url = typeof window !== 'undefined' ? window.location.href : ''
              const text = encodeURIComponent(blog.title)
              const encodedUrl = encodeURIComponent(url)
              const onShare = (platform: string) =>
                track('blog_social_share', { platform, blog_slug: blog.slug || undefined })
              return (
                <>
                  <a
                    href={`https://twitter.com/intent/tweet?text=${text}&url=${encodedUrl}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={() => onShare('twitter')}
                    className="px-3 py-1.5 text-xs font-medium rounded-full border hover:bg-muted transition-colors"
                  >
                    X / Twitter
                  </a>
                  <a
                    href={`https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={() => onShare('linkedin')}
                    className="px-3 py-1.5 text-xs font-medium rounded-full border hover:bg-muted transition-colors"
                  >
                    LinkedIn
                  </a>
                  <a
                    href={`https://news.ycombinator.com/submitlink?u=${encodedUrl}&t=${text}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={() => onShare('hackernews')}
                    className="px-3 py-1.5 text-xs font-medium rounded-full border hover:bg-muted transition-colors"
                  >
                    Hacker News
                  </a>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(url)
                      onShare('copy_link')
                    }}
                    className="px-3 py-1.5 text-xs font-medium rounded-full border hover:bg-muted transition-colors"
                  >
                    Copy Link
                  </button>
                </>
              )
            })()}
          </div>

          {/* Comments */}
          <div className="border-t pt-8 mt-12">
            <div className="flex items-center gap-2 mb-6">
              <MessageCircle className="w-5 h-5" />
              <h2 className="text-2xl font-bold">Comments ({comments.length})</h2>
            </div>

            {comments.length === 0 ? (
              <p className="text-muted-foreground">No comments yet. Be the first to comment!</p>
            ) : (
              <div className="space-y-6">
                {comments.map((comment) => (
                  <div key={comment.id} className="border rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="font-semibold">{comment.user_name || 'Anonymous'}</span>
                      <span className="text-sm text-muted-foreground">
                        {formatDate(comment.created_at)}
                      </span>
                    </div>
                    <p className="text-foreground">{comment.content}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </article>
      </div>
    </div>
  )
}
