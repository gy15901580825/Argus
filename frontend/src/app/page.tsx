import { Hero } from '@/components/business/Hero'
import { Features } from '@/components/business/Features'
import { Customers } from '@/components/business/Customers'
import { FAQ } from '@/components/business/FAQ'
import { CTA } from '@/components/business/CTA'

export default function Home() {
  return (
    <>
      <Hero />
      <Features />
      <Customers />
      <FAQ />
      <CTA />
    </>
  )
}
