'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { Calendar, User, ArrowRight, FileText } from 'lucide-react'
import { getDocuments, type DocumentResponse } from '@/lib/api'
import { Button } from '@/components/ui/button'

export default function DocsPage() {
  const [documents, setDocuments] = useState<DocumentResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(0)
  const limit = 10

  useEffect(() => {
    async function fetchDocuments() {
      try {
        setLoading(true)
        const data = await getDocuments(limit, page * limit)
        if (page === 0) {
          setDocuments(data)
        } else {
          setDocuments((prev) => [...prev, ...data])
        }
        setError(null)
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load documents')
      } finally {
        setLoading(false)
      }
    }

    fetchDocuments()
  }, [page])

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    })
  }

  if (loading && documents.length === 0) {
    return (
      <div className="min-h-screen pt-32 pb-20 px-4">
        <div className="container mx-auto max-w-4xl">
          <div className="text-center">
            <h1 className="text-4xl font-bold mb-4">Documentation</h1>
            <p className="text-muted-foreground">Loading...</p>
          </div>
        </div>
      </div>
    )
  }

  if (error && documents.length === 0) {
    return (
      <div className="min-h-screen pt-32 pb-20 px-4">
        <div className="container mx-auto max-w-4xl">
          <div className="text-center">
            <h1 className="text-4xl font-bold mb-4">Documentation</h1>
            <p className="text-destructive">{error}</p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen pt-32 pb-20 px-4">
      <div className="container mx-auto max-w-4xl">
        <div className="text-center mb-12">
          <h1 className="text-4xl font-bold mb-4">Documentation</h1>
          <p className="text-muted-foreground text-lg">
            Guides, tutorials, and reference materials
          </p>
        </div>

        {documents.length === 0 ? (
          <div className="text-center py-20">
            <p className="text-muted-foreground">No documents available yet.</p>
          </div>
        ) : (
          <div className="space-y-6">
            {documents.map((doc) => (
              <article
                key={doc.id}
                className="border rounded-lg p-6 hover:shadow-lg transition-shadow"
              >
                <div className="flex items-start gap-4">
                  <div className="p-3 bg-primary/10 rounded-lg">
                    <FileText className="w-6 h-6 text-primary" />
                  </div>
                  <div className="flex-1">
                    <Link href={`/docs/${doc.id}`}>
                      <h2 className="text-2xl font-bold mb-2 hover:text-primary transition-colors">
                        {doc.title}
                      </h2>
                    </Link>
                    {doc.description && (
                      <p className="text-muted-foreground mb-4">{doc.description}</p>
                    )}
                    <div className="flex items-center gap-4 text-sm text-muted-foreground mb-4">
                      {doc.owner_name && (
                        <div className="flex items-center gap-2">
                          <User className="w-4 h-4" />
                          <span>{doc.owner_name}</span>
                        </div>
                      )}
                      {doc.published_at && (
                        <div className="flex items-center gap-2">
                          <Calendar className="w-4 h-4" />
                          <span>{formatDate(doc.published_at)}</span>
                        </div>
                      )}
                    </div>
                    <Link href={`/docs/${doc.id}`}>
                      <Button variant="outline" className="group">
                        Read more
                        <ArrowRight className="ml-2 w-4 h-4 group-hover:translate-x-1 transition-transform" />
                      </Button>
                    </Link>
                  </div>
                </div>
              </article>
            ))}

            {documents.length > 0 && documents.length % limit === 0 && (
              <div className="text-center pt-8">
                <Button onClick={() => setPage((p) => p + 1)} disabled={loading} variant="outline">
                  {loading ? 'Loading...' : 'Load More'}
                </Button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
