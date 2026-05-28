'use client'

import { Loader2 } from 'lucide-react'
import { Dialog } from '@/components/ui/dialog'

interface BulkDeleteDialogProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
  sessionTitles: string[]
  isDeleting: boolean
}

const PREVIEW_LIMIT = 5

export function BulkDeleteDialog({
  isOpen,
  onClose,
  onConfirm,
  sessionTitles,
  isDeleting,
}: BulkDeleteDialogProps) {
  const count = sessionTitles.length
  const previewTitles = sessionTitles.slice(0, PREVIEW_LIMIT)
  const overflow = Math.max(0, count - PREVIEW_LIMIT)
  const noun = count === 1 ? 'session' : 'sessions'
  const possessive = count === 1 ? 'its' : 'their'

  return (
    <Dialog isOpen={isOpen} onClose={onClose} title={`Delete ${count} ${noun}?`}>
      <div className="space-y-4">
        <p className="text-sm text-gray-700">
          This will permanently delete {count} chat {noun} and all {possessive} messages. This
          cannot be undone.
        </p>

        {count > 0 && (
          <div>
            <p className="text-sm font-medium text-gray-900 mb-2">Preview:</p>
            <ul className="text-sm text-gray-600 space-y-1 list-disc pl-5">
              {previewTitles.map((title, i) => (
                <li key={i} className="truncate">
                  {title}
                </li>
              ))}
              {overflow > 0 && <li className="italic text-gray-500">…and {overflow} more</li>}
            </ul>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <button
            type="button"
            onClick={onClose}
            disabled={isDeleting}
            className="rounded-md border border-gray-300 bg-white px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={isDeleting}
            aria-busy={isDeleting}
            className="inline-flex items-center gap-2 rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
          >
            {isDeleting && (
              <>
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                <span className="sr-only">Deleting…</span>
              </>
            )}
            Delete ({count})
          </button>
        </div>
      </div>
    </Dialog>
  )
}
