'use client'

import { useEffect, useState, useRef } from 'react'
import { useRouter } from 'next/navigation'
import Image from 'next/image'
import { Upload, Trash2, Copy, Check, Image as ImageIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useAuthStore } from '@/store/useAuthStore'
import { getMediaAssets, uploadMedia, deleteMedia, type MediaAsset } from '@/lib/api'

function formatBytes(bytes: number) {
  if (bytes < 1024) return bytes + ' B'
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB'
}

export default function AdminMediaPage() {
  const user = useAuthStore((s) => s.user)
  const router = useRouter()
  const fileInput = useRef<HTMLInputElement>(null)

  const [assets, setAssets] = useState<MediaAsset[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const loadAssets = async () => {
    setLoading(true)
    try {
      setAssets(await getMediaAssets())
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
    loadAssets()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user])

  const handleUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files
    if (!files || files.length === 0) return
    setUploading(true)
    try {
      for (const file of Array.from(files)) {
        const asset = await uploadMedia(file)
        setAssets((prev) => [asset, ...prev])
      }
    } catch (err) {
      alert('Upload failed')
    }
    setUploading(false)
    if (fileInput.current) fileInput.current.value = ''
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this file?')) return
    try {
      await deleteMedia(id)
      setAssets((prev) => prev.filter((a) => a.id !== id))
    } catch {
      alert('Delete failed')
    }
  }

  const copyUrl = (url: string, id: string) => {
    navigator.clipboard.writeText(url)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  if (!user || !user.role || !['SUPER_ADMIN', 'CONTENT_ADMIN'].includes(user.role)) return null

  return (
    <div className="min-h-screen pt-24 pb-16 px-4">
      <div className="container mx-auto max-w-6xl">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-3xl font-bold">Media Library</h1>
            <p className="text-muted-foreground mt-1">{assets.length} files</p>
          </div>
          <div>
            <input
              ref={fileInput}
              type="file"
              accept="image/*,video/mp4,application/pdf"
              multiple
              onChange={handleUpload}
              className="hidden"
            />
            <Button onClick={() => fileInput.current?.click()} disabled={uploading}>
              <Upload className="w-4 h-4 mr-2" />
              {uploading ? 'Uploading...' : 'Upload'}
            </Button>
          </div>
        </div>

        {loading ? (
          <div className="text-center py-12 text-muted-foreground">Loading...</div>
        ) : assets.length === 0 ? (
          <div className="text-center py-20">
            <ImageIcon className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
            <p className="text-muted-foreground">No media files yet. Upload your first file!</p>
          </div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 gap-4">
            {assets.map((asset) => (
              <div
                key={asset.id}
                className="group border rounded-xl overflow-hidden hover:shadow-md transition-shadow"
              >
                <div className="relative aspect-square bg-muted">
                  {asset.mime_type.startsWith('image/') ? (
                    <Image
                      src={asset.r2_url}
                      alt={asset.alt_text || asset.filename}
                      fill
                      className="object-cover"
                      sizes="(max-width: 640px) 50vw, (max-width: 1024px) 25vw, 20vw"
                    />
                  ) : (
                    <div className="flex items-center justify-center h-full">
                      <span className="text-xs text-muted-foreground uppercase font-medium">
                        {asset.mime_type.split('/')[1]}
                      </span>
                    </div>
                  )}
                  {/* Overlay actions */}
                  <div className="absolute inset-0 bg-black/0 group-hover:bg-black/40 transition-colors flex items-center justify-center gap-2 opacity-0 group-hover:opacity-100">
                    <button
                      onClick={() => copyUrl(asset.r2_url, asset.id)}
                      className="p-2 bg-white rounded-full text-gray-800 hover:bg-gray-100"
                      title="Copy URL"
                    >
                      {copiedId === asset.id ? (
                        <Check className="w-4 h-4" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                    <button
                      onClick={() => handleDelete(asset.id)}
                      className="p-2 bg-white rounded-full text-red-600 hover:bg-red-50"
                      title="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
                <div className="p-2">
                  <p className="text-xs font-medium truncate" title={asset.filename}>
                    {asset.filename}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {formatBytes(asset.file_size_bytes)}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
