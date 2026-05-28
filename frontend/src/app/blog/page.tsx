'use client'

import { Suspense, useEffect, useState, useCallback } from 'react'
import Link from 'next/link'
import Image from 'next/image'
import { useSearchParams, useRouter } from 'next/navigation'
import { Calendar, User, ArrowRight, Clock, Search, Tag, FolderOpen } from 'lucide-react'
import {
  getBlogs,
  getCategories,
  getTags,
  type BlogListItem,
  type CategoryResponse,
  type TagResponse,
} from '@/lib/api'
import { Button } from '@/components/ui/button'
import { track } from '@/lib/analytics'

export default function BlogPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen pt-32 text-center text-muted-foreground">Loading...</div>
      }
    >
      <BlogPageContent />
    </Suspense>
  )
}

function BlogPageContent() {
  const searchParams = useSearchParams()
  const router = useRouter()

  const [blogs, setBlogs] = useState<BlogListItem[]>([])
  const [categories, setCategories] = useState<CategoryResponse[]>([])
  const [tags, setTags] = useState<TagResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [hasMore, setHasMore] = useState(true)

  const category = searchParams.get('category') || undefined
  const tag = searchParams.get('tag') || undefined
  const q = searchParams.get('q') || undefined
  const [searchInput, setSearchInput] = useState(q || '')
  const limit = 12

  const fetchBlogs = useCallback(
    async (offset = 0, append = false) => {
      setLoading(true)
      try {
        const data = await getBlogs({ limit, offset, category, tag, q })
        if (append) {
          setBlogs((prev) => [...prev, ...data])
        } else {
          setBlogs(data)
        }
        setHasMore(data.length === limit)
      } catch {
        // ignore
      } finally {
        setLoading(false)
      }
    },
    [category, tag, q]
  )

  useEffect(() => {
    fetchBlogs(0)
  }, [fetchBlogs])

  useEffect(() => {
    track('blog_list_view', {
      has_filter: Boolean(category || tag || q),
      category: category || undefined,
      tag: tag || undefined,
      search_len: q ? q.length : 0,
    })
  }, [category, tag, q])

  useEffect(() => {
    Promise.all([getCategories(), getTags()])
      .then(([cats, ts]) => {
        setCategories(cats)
        setTags(ts)
      })
      .catch(() => {})
  }, [])

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = searchInput.trim()
    track('blog_search', {
      query_len: trimmed.length,
      has_category: Boolean(category),
      has_tag: Boolean(tag),
    })
    const params = new URLSearchParams()
    if (trimmed) params.set('q', trimmed)
    if (category) params.set('category', category)
    if (tag) params.set('tag', tag)
    router.push(`/blog${params.toString() ? '?' + params.toString() : ''}`)
  }

  const setFilter = (key: string, value: string | null) => {
    track('blog_filter', { filter_type: key, filter_value: value || 'clear' })
    const params = new URLSearchParams(searchParams.toString())
    if (value) params.set(key, value)
    else params.delete(key)
    params.delete('offset')
    router.push(`/blog${params.toString() ? '?' + params.toString() : ''}`)
  }

  const formatDate = (dateString: string) =>
    new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })

  const activeFilters = [category, tag, q].filter(Boolean).length > 0

  return (
    <div className="min-h-screen pt-24 pb-20 px-4">
      <div className="container mx-auto max-w-6xl">
        {/* Header */}
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">Blog</h1>
          <p className="text-muted-foreground text-lg max-w-2xl mx-auto">
            Insights on AI-powered testing, automation best practices, and product updates
          </p>
        </div>

        {/* Search + Filters */}
        <div className="mb-10 space-y-4">
          <form onSubmit={handleSearch} className="flex gap-2 max-w-lg mx-auto">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Search articles..."
                className="w-full pl-10 pr-4 py-2 border rounded-lg bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <Button type="submit" size="sm">
              Search
            </Button>
          </form>

          {/* Category pills */}
          {categories.length > 0 && (
            <div className="flex flex-wrap justify-center gap-2">
              <button
                onClick={() => setFilter('category', null)}
                className={`px-3 py-1 rounded-full text-sm border transition-colors ${
                  !category ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
                }`}
              >
                All
              </button>
              {categories.map((cat) => (
                <button
                  key={cat.id}
                  onClick={() => setFilter('category', cat.slug === category ? null : cat.slug)}
                  className={`px-3 py-1 rounded-full text-sm border transition-colors ${
                    category === cat.slug ? 'bg-primary text-primary-foreground' : 'hover:bg-muted'
                  }`}
                >
                  {cat.name} ({cat.post_count})
                </button>
              ))}
            </div>
          )}

          {activeFilters && (
            <div className="text-center">
              <button
                onClick={() => router.push('/blog')}
                className="text-sm text-muted-foreground hover:text-foreground underline"
              >
                Clear all filters
              </button>
            </div>
          )}
        </div>

        {/* Blog grid */}
        {loading && blogs.length === 0 ? (
          <div className="text-center text-muted-foreground py-12">Loading...</div>
        ) : blogs.length === 0 ? (
          <div className="text-center py-20">
            <p className="text-muted-foreground">No articles found.</p>
          </div>
        ) : (
          <>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-8">
              {blogs.map((blog) => (
                <article
                  key={blog.id}
                  className="border rounded-xl overflow-hidden hover:shadow-lg transition-shadow flex flex-col"
                >
                  {blog.cover_image_url && (
                    <Link href={`/blog/${blog.slug || blog.id}`}>
                      <div className="relative aspect-video bg-muted">
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
                            sizes="(max-width: 768px) 100vw, (max-width: 1200px) 50vw, 33vw"
                          />
                        )}
                      </div>
                    </Link>
                  )}
                  <div className="p-5 flex flex-col flex-1">
                    {(blog.category_name || (blog.tags && blog.tags.length > 0)) && (
                      <div className="flex flex-wrap gap-2 mb-3">
                        {blog.category_name && (
                          <button
                            onClick={() => setFilter('category', blog.category_slug || null)}
                            className="text-xs font-medium text-primary bg-primary/10 px-2 py-0.5 rounded"
                          >
                            {blog.category_name}
                          </button>
                        )}
                        {blog.tags?.slice(0, 2).map((t) => (
                          <button
                            key={t.id}
                            onClick={() => setFilter('tag', t.slug)}
                            className="text-xs text-muted-foreground bg-muted px-2 py-0.5 rounded"
                          >
                            {t.name}
                          </button>
                        ))}
                      </div>
                    )}

                    <Link href={`/blog/${blog.slug || blog.id}`}>
                      <h2 className="text-lg font-bold mb-2 hover:text-primary transition-colors line-clamp-2">
                        {blog.title}
                      </h2>
                    </Link>

                    {blog.summary && (
                      <p className="text-muted-foreground text-sm mb-4 line-clamp-2 flex-1">
                        {blog.summary}
                      </p>
                    )}

                    <div className="flex items-center justify-between text-xs text-muted-foreground mt-auto pt-3 border-t">
                      <div className="flex items-center gap-3">
                        {blog.author_name && (
                          <span className="flex items-center gap-1">
                            <User className="w-3 h-3" />
                            {blog.author_name}
                          </span>
                        )}
                        {blog.published_at && (
                          <span className="flex items-center gap-1">
                            <Calendar className="w-3 h-3" />
                            {formatDate(blog.published_at)}
                          </span>
                        )}
                      </div>
                      {blog.reading_time_min && (
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {blog.reading_time_min} min
                        </span>
                      )}
                    </div>
                  </div>
                </article>
              ))}
            </div>

            {hasMore && (
              <div className="text-center pt-10">
                <Button
                  variant="outline"
                  onClick={() => fetchBlogs(blogs.length, true)}
                  disabled={loading}
                >
                  {loading ? 'Loading...' : 'Load More'}
                </Button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
