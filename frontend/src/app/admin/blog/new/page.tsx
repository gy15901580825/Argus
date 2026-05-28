'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/useAuthStore'
import { BlogEditorForm } from '@/components/blog/BlogEditorForm'

export default function NewBlogPage() {
  const user = useAuthStore((s) => s.user)
  const router = useRouter()

  useEffect(() => {
    if (!user) router.push('/login')
    else if (!user.role || !['SUPER_ADMIN', 'CONTENT_ADMIN'].includes(user.role)) router.push('/')
  }, [user, router])

  if (!user || !user.role || !['SUPER_ADMIN', 'CONTENT_ADMIN'].includes(user.role)) return null

  return <BlogEditorForm />
}
