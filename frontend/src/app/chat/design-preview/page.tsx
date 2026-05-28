import { notFound } from 'next/navigation'
import { Catalog } from './Catalog'

export default function DesignPreviewPage() {
  if (process.env.NODE_ENV === 'production') {
    notFound()
  }
  return <Catalog />
}
