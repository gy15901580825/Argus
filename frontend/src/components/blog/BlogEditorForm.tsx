'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { ArrowLeft, Save, Eye } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { TiptapEditor } from './TiptapEditor'
import {
  createBlog,
  updateBlog,
  getCategories,
  getTags,
  type BlogResponse,
  type BlogCreateRequest,
  type BlogUpdateRequest,
  type CategoryResponse,
  type TagResponse,
} from '@/lib/api'

interface Props {
  blog?: BlogResponse | null
}

export function BlogEditorForm({ blog }: Props) {
  const router = useRouter()
  const isEdit = !!blog

  const [title, setTitle] = useState(blog?.title || '')
  const [slug, setSlug] = useState(blog?.slug || '')
  const [summary, setSummary] = useState(blog?.summary || '')
  const [content, setContent] = useState(blog?.content || '')
  const [categoryId, setCategoryId] = useState(blog?.category_id || '')
  const [selectedTags, setSelectedTags] = useState<string[]>(blog?.tags?.map((t) => t.id) || [])
  const [coverImageUrl, setCoverImageUrl] = useState(blog?.cover_image_url || '')
  const [metaTitle, setMetaTitle] = useState(blog?.meta_title || '')
  const [metaDescription, setMetaDescription] = useState(blog?.meta_description || '')
  const [ogImageUrl, setOgImageUrl] = useState(blog?.og_image_url || '')
  const [canonicalUrl, setCanonicalUrl] = useState(blog?.canonical_url || '')
  const [featured, setFeatured] = useState(blog?.featured || false)
  const [status, setStatus] = useState(blog?.status || 'draft')

  const [categories, setCategories] = useState<CategoryResponse[]>([])
  const [tags, setTags] = useState<TagResponse[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')
  const [showSEO, setShowSEO] = useState(false)

  useEffect(() => {
    Promise.all([getCategories(), getTags()])
      .then(([c, t]) => {
        setCategories(c)
        setTags(t)
      })
      .catch(() => {})
  }, [])

  const handleSave = async (saveStatus?: string) => {
    if (!title.trim()) {
      setError('Title is required')
      return
    }
    if (!content.trim()) {
      setError('Content is required')
      return
    }

    setSaving(true)
    setError('')

    try {
      const data: BlogCreateRequest & BlogUpdateRequest = {
        title,
        content,
        slug: slug || undefined,
        summary: summary || undefined,
        category_id: categoryId || undefined,
        tag_ids: selectedTags.length > 0 ? selectedTags : undefined,
        cover_image_url: coverImageUrl || undefined,
        meta_title: metaTitle || undefined,
        meta_description: metaDescription || undefined,
        og_image_url: ogImageUrl || undefined,
        canonical_url: canonicalUrl || undefined,
        featured,
        status: saveStatus || status,
      }

      if (isEdit) {
        await updateBlog(blog!.id, data)
      } else {
        await createBlog(data)
      }

      router.push('/admin/blog')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Save failed')
    }
    setSaving(false)
  }

  const toggleTag = (id: string) => {
    setSelectedTags((prev) => (prev.includes(id) ? prev.filter((t) => t !== id) : [...prev, id]))
  }

  return (
    <div className="min-h-screen pt-24 pb-16 px-4 lg:px-8">
      <div className="mx-auto max-w-screen-2xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <Button variant="ghost" onClick={() => router.push('/admin/blog')}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back
          </Button>
          <div className="flex items-center gap-2">
            <Button variant="outline" onClick={() => handleSave('draft')} disabled={saving}>
              Save Draft
            </Button>
            <Button onClick={() => handleSave('published')} disabled={saving}>
              <Save className="w-4 h-4 mr-2" />
              {saving ? 'Saving...' : isEdit ? 'Update & Publish' : 'Publish'}
            </Button>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-destructive/10 text-destructive rounded-lg text-sm">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-[1fr_320px] gap-6">
          {/* Main editor */}
          <div className="space-y-4 min-w-0">
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Post title"
              className="w-full text-3xl font-bold bg-transparent border-none focus:outline-none placeholder:text-muted-foreground/40"
            />

            <input
              type="text"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="URL slug (auto-generated from title)"
              className="w-full text-sm text-muted-foreground bg-transparent border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary/50"
            />

            <textarea
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder="Write a brief summary..."
              rows={2}
              className="w-full text-sm bg-transparent border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
            />

            <TiptapEditor content={content} onChange={setContent} />
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Status */}
            <div className="border rounded-lg p-4">
              <h3 className="font-semibold mb-3">Status</h3>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="w-full border rounded-lg px-3 py-2 text-sm bg-background"
              >
                <option value="draft">Draft</option>
                <option value="published">Published</option>
                <option value="scheduled">Scheduled</option>
                <option value="archived">Archived</option>
              </select>
              <label className="flex items-center gap-2 mt-3 text-sm">
                <input
                  type="checkbox"
                  checked={featured}
                  onChange={(e) => setFeatured(e.target.checked)}
                  className="rounded"
                />
                Featured post
              </label>
            </div>

            {/* Category */}
            <div className="border rounded-lg p-4">
              <h3 className="font-semibold mb-3">Category</h3>
              <select
                value={categoryId}
                onChange={(e) => setCategoryId(e.target.value)}
                className="w-full border rounded-lg px-3 py-2 text-sm bg-background"
              >
                <option value="">No category</option>
                {categories.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>

            {/* Tags */}
            <div className="border rounded-lg p-4">
              <h3 className="font-semibold mb-3">Tags</h3>
              <div className="flex flex-wrap gap-2">
                {tags.map((t) => (
                  <button
                    key={t.id}
                    type="button"
                    onClick={() => toggleTag(t.id)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                      selectedTags.includes(t.id)
                        ? 'bg-primary text-primary-foreground border-primary'
                        : 'hover:bg-muted'
                    }`}
                  >
                    {t.name}
                  </button>
                ))}
                {tags.length === 0 && <p className="text-xs text-muted-foreground">No tags yet</p>}
              </div>
            </div>

            {/* Cover Image */}
            <div className="border rounded-lg p-4">
              <h3 className="font-semibold mb-3">Cover Image</h3>
              <input
                type="text"
                value={coverImageUrl}
                onChange={(e) => setCoverImageUrl(e.target.value)}
                placeholder="Image URL"
                className="w-full border rounded-lg px-3 py-2 text-sm bg-background focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
              {coverImageUrl && (
                <img
                  src={coverImageUrl}
                  alt="Cover"
                  className="mt-2 rounded-lg w-full h-32 object-cover"
                />
              )}
            </div>

            {/* SEO */}
            <div className="border rounded-lg p-4">
              <button
                type="button"
                onClick={() => setShowSEO(!showSEO)}
                className="font-semibold w-full text-left flex justify-between items-center"
              >
                SEO Settings
                <span className="text-xs text-muted-foreground">{showSEO ? 'Hide' : 'Show'}</span>
              </button>
              {showSEO && (
                <div className="mt-3 space-y-3">
                  <input
                    type="text"
                    value={metaTitle}
                    onChange={(e) => setMetaTitle(e.target.value)}
                    placeholder="Meta title"
                    className="w-full border rounded-lg px-3 py-2 text-sm bg-background"
                  />
                  <textarea
                    value={metaDescription}
                    onChange={(e) => setMetaDescription(e.target.value)}
                    placeholder="Meta description"
                    rows={2}
                    className="w-full border rounded-lg px-3 py-2 text-sm bg-background resize-none"
                  />
                  <input
                    type="text"
                    value={ogImageUrl}
                    onChange={(e) => setOgImageUrl(e.target.value)}
                    placeholder="OG image URL"
                    className="w-full border rounded-lg px-3 py-2 text-sm bg-background"
                  />
                  <input
                    type="text"
                    value={canonicalUrl}
                    onChange={(e) => setCanonicalUrl(e.target.value)}
                    placeholder="Canonical URL"
                    className="w-full border rounded-lg px-3 py-2 text-sm bg-background"
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
