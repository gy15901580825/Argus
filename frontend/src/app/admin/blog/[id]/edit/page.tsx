'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/useAuthStore'
import { getBlog, type BlogResponse } from '@/lib/api'
import { BlogEditorForm } from '@/components/blog/BlogEditorForm'

export default function EditBlogPage() {
  const user = useAuthStore((s) => s.user)
  const router = useRouter()
  const params = useParams()
  const id = params.id as string
  const [blog, setBlog] = useState<BlogResponse | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!user) {
      router.push('/login')
      return
    }
    if (!user.role || !['SUPER_ADMIN', 'CONTENT_ADMIN'].includes(user.role)) {
      router.push('/')
      return
    }

    getBlog(id)
      .then(setBlog)
      .catch(() => router.push('/admin/blog'))
      .finally(() => setLoading(false))
  }, [user, id, router])

  if (!user || !user.role || !['SUPER_ADMIN', 'CONTENT_ADMIN'].includes(user.role)) return null
  if (loading)
    return <div className="min-h-screen pt-32 text-center text-muted-foreground">Loading...</div>
  if (!blog) return null

  return <BlogEditorForm blog={blog} />
}
