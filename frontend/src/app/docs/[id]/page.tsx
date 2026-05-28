'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import Link from 'next/link'
import { Calendar, User, ArrowLeft, FileText } from 'lucide-react'
import { getDocument, type DocumentResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'

export default function DocumentPage() {
  const params = useParams()
  const router = useRouter()
  const id = params.id as string
  const [document, setDocument] = useState<DocumentResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchDocumentData() {
      try {
        setLoading(true)
        const docData = await getDocument(id)
        setDocument(docData)
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load document')
      } finally {
        setLoading(false)
      }
    }

    if (id) {
      fetchDocumentData()
    }
  }, [id])

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })
  }

  if (loading) {
    return (
      <div className="min-h-screen pt-32 pb-20 px-4">
        <div className="container mx-auto max-w-4xl">
          <div className="text-center">
            <p className="text-muted-foreground">Loading...</p>
          </div>
        </div>
      </div>
    )
  }

  if (error || !document) {
    return (
      <div className="min-h-screen pt-32 pb-20 px-4">
        <div className="container mx-auto max-w-4xl">
          <div className="text-center">
            <h1 className="text-2xl font-bold mb-4">Document Not Found</h1>
            <p className="text-muted-foreground mb-6">
              {error || 'The document you are looking for does not exist.'}
            </p>
            <Button asChild>
              <Link href="/docs">Back to Documentation</Link>
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen pt-32 pb-20 px-4">
      <div className="container mx-auto max-w-4xl">
        <Button variant="ghost" onClick={() => router.back()} className="mb-8">
          <ArrowLeft className="mr-2 w-4 h-4" />
          Back
        </Button>

        <article>
          <div className="flex items-center gap-3 mb-6">
            <div className="p-3 bg-primary/10 rounded-lg">
              <FileText className="w-6 h-6 text-primary" />
            </div>
            <h1 className="text-4xl font-bold">{document.title}</h1>
          </div>

          <div className="flex items-center gap-4 text-sm text-muted-foreground mb-8">
            {document.owner_name && (
              <div className="flex items-center gap-2">
                <User className="w-4 h-4" />
                <span>{document.owner_name}</span>
              </div>
            )}
            {document.published_at && (
              <div className="flex items-center gap-2">
                <Calendar className="w-4 h-4" />
                <span>{formatDate(document.published_at)}</span>
              </div>
            )}
          </div>

          {document.description && (
            <p className="text-xl text-muted-foreground mb-8 italic border-l-4 border-primary pl-4">
              {document.description}
            </p>
          )}

          {document.content ? (
            <div
              className="document-content text-foreground leading-relaxed"
              dangerouslySetInnerHTML={{ __html: document.content }}
              style={{
                lineHeight: '1.75',
              }}
            />
          ) : (
            <div>
              <p className="text-muted-foreground">No content available for this document.</p>
            </div>
          )}
        </article>
      </div>
    </div>
  )
}
