'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { Plus, Pencil, Trash2, Eye, Search, Filter } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useAuthStore } from '@/store/useAuthStore'
import {
  getAdminBlogs,
  deleteBlog,
  getCategories,
  getTags,
  type BlogListItem,
  type CategoryResponse,
  type TagResponse,
} from '@/lib/api'

const STATUS_COLORS: Record<string, string> = {
  published: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400',
  draft: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400',
  scheduled: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400',
  archived: 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-400',
}

export default function AdminBlogPage() {
  const user = useAuthStore((s) => s.user)
  const router = useRouter()
  const [blogs, setBlogs] = useState<BlogListItem[]>([])
  const [categories, setCategories] = useState<CategoryResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [searchQ, setSearchQ] = useState('')
  const [deleting, setDeleting] = useState<string | null>(null)

  const loadData = async () => {
    setLoading(true)
    try {
      const [b, c] = await Promise.all([
        getAdminBlogs({ status: statusFilter || undefined, q: searchQ || undefined }),
        getCategories(),
      ])
      setBlogs(b)
      setCategories(c)
    } catch {
      /* ignore */
    }
    setLoading(false)
  }

  useEffect(() => {
    if (!user) {
      router.push('/login')
      return
    }
    if (!user.role || !['SUPER_ADMIN', 'CONTENT_ADMIN'].includes(user.role)) {
      router.push('/')
      return
    }
    loadData()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user])

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (user) loadData()
  }, [statusFilter])

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    loadData()
  }

  const handleDelete = async (id: string, title: string) => {
    if (!confirm(`Delete "${title}"? This cannot be undone.`)) return
    setDeleting(id)
    try {
      await deleteBlog(id)
      setBlogs((prev) => prev.filter((b) => b.id !== id))
    } catch (err) {
      alert('Delete failed')
    }
    setDeleting(null)
  }

  const formatDate = (d: string) =>
    new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })

  if (!user || !user.role || !['SUPER_ADMIN', 'CONTENT_ADMIN'].includes(user.role)) return null

  return (
    <div className="min-h-screen pt-24 pb-16 px-4">
      <div className="container mx-auto max-w-6xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold">Blog Management</h1>
            <p className="text-muted-foreground mt-1">{blogs.length} posts</p>
          </div>
          <Button onClick={() => router.push('/admin/blog/new')}>
            <Plus className="w-4 h-4 mr-2" />
            New Post
          </Button>
        </div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3 mb-6">
          <form onSubmit={handleSearch} className="flex gap-2 flex-1">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <input
                type="text"
                value={searchQ}
                onChange={(e) => setSearchQ(e.target.value)}
                placeholder="Search posts..."
                className="w-full pl-10 pr-4 py-2 border rounded-lg bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <Button type="submit" variant="outline" size="sm">
              Search
            </Button>
          </form>
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="border rounded-lg px-3 py-2 text-sm bg-background"
          >
            <option value="">All Status</option>
            <option value="draft">Draft</option>
            <option value="published">Published</option>
            <option value="scheduled">Scheduled</option>
            <option value="archived">Archived</option>
          </select>
        </div>

        {/* Table */}
        {loading ? (
          <div className="text-center py-12 text-muted-foreground">Loading...</div>
        ) : blogs.length === 0 ? (
          <div className="text-center py-20 text-muted-foreground">
            No posts found. Create your first post!
          </div>
        ) : (
          <div className="border rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left p-3 font-medium">Title</th>
                  <th className="text-left p-3 font-medium hidden md:table-cell">Category</th>
                  <th className="text-left p-3 font-medium">Status</th>
                  <th className="text-left p-3 font-medium hidden sm:table-cell">Views</th>
                  <th className="text-left p-3 font-medium hidden sm:table-cell">Date</th>
                  <th className="text-right p-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y">
                {blogs.map((blog) => (
                  <tr key={blog.id} className="hover:bg-muted/30 transition-colors">
                    <td className="p-3">
                      <div className="font-medium line-clamp-1">{blog.title}</div>
                      {blog.author_name && (
                        <div className="text-xs text-muted-foreground">by {blog.author_name}</div>
                      )}
                    </td>
                    <td className="p-3 hidden md:table-cell text-muted-foreground">
                      {blog.category_name || '—'}
                    </td>
                    <td className="p-3">
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full font-medium ${STATUS_COLORS[blog.status] || STATUS_COLORS.draft}`}
                      >
                        {blog.status}
                      </span>
                      {blog.featured && (
                        <span className="ml-1 text-xs px-1.5 py-0.5 rounded bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400">
                          Featured
                        </span>
                      )}
                    </td>
                    <td className="p-3 hidden sm:table-cell text-muted-foreground">
                      {blog.view_count}
                    </td>
                    <td className="p-3 hidden sm:table-cell text-muted-foreground">
                      {blog.published_at
                        ? formatDate(blog.published_at)
                        : formatDate(blog.created_at)}
                    </td>
                    <td className="p-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        {blog.slug && (
                          <Button variant="ghost" size="icon" asChild className="h-8 w-8">
                            <Link href={`/blog/${blog.slug}`} target="_blank">
                              <Eye className="w-4 h-4" />
                            </Link>
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          onClick={() => router.push(`/admin/blog/${blog.id}/edit`)}
                        >
                          <Pencil className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8 text-destructive"
                          disabled={deleting === blog.id}
                          onClick={() => handleDelete(blog.id, blog.title)}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
