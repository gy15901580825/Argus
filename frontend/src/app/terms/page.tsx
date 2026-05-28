'use client'

import { useRouter } from 'next/navigation'
import { Button } from '@/components/ui/button'

export default function TermsPage() {
  const router = useRouter()

  return (
    <div className="min-h-screen bg-background pt-20 pb-12">
      <div className="container mx-auto max-w-3xl px-4">
        <h1 className="text-3xl font-bold mb-2">Terms of Service</h1>
        <p className="text-sm text-muted-foreground mb-8">Last updated: March 28, 2026</p>

        <TermsContent />

        <div className="mt-8">
          <Button variant="outline" onClick={() => router.back()}>
            Back
          </Button>
        </div>
      </div>
    </div>
  )
}

export function TermsContent() {
  return (
    <div className="prose prose-sm dark:prose-invert max-w-none space-y-6">
      <section>
        <h2 className="text-xl font-semibold">1. Acceptance of Terms</h2>
        <p>
          By creating an account and using Argus (&quot;the Platform&quot;), operated by Argus
          (&quot;the Company&quot;, &quot;we&quot;, &quot;us&quot;, or &quot;our&quot;), you
          (&quot;the User&quot;, &quot;you&quot;, or &quot;your&quot;) agree to be bound by these
          Terms of Service (&quot;Terms&quot;). If you do not agree to these Terms, you must not use
          the Platform.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">2. Description of Service</h2>
        <p>
          Argus is an AI-powered automated testing platform that enables users to submit target
          URLs for automated web UI exploration, bug detection, and test script generation. The
          Platform uses artificial intelligence agents, browser automation, and related technologies
          to analyze web applications and generate testing artifacts.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">3. User Responsibilities and Obligations</h2>
        <p>By using the Platform, you represent and warrant that:</p>
        <ul className="list-disc pl-6 space-y-2">
          <li>
            <strong>Authorization:</strong> You have proper authorization to test any target URL or
            web application submitted to the Platform. You shall only test websites, applications,
            and systems for which you have explicit written permission from the owner or authorized
            representative.
          </li>
          <li>
            <strong>Lawful Use:</strong> You will use the Platform only for lawful purposes and in
            compliance with all applicable local, state, national, and international laws and
            regulations, including but not limited to computer fraud, data protection, and privacy
            laws.
          </li>
          <li>
            <strong>No Unauthorized Access:</strong> You will not use the Platform to gain
            unauthorized access to any computer system, network, or data. You will not use the
            Platform for penetration testing, vulnerability scanning, or security testing of any
            system without explicit written authorization from the system owner.
          </li>
          <li>
            <strong>No Malicious Use:</strong> You will not use the Platform to: (a) disrupt or
            damage any third-party system or service; (b) conduct denial-of-service attacks; (c)
            distribute malware or malicious code; (d) harvest or collect personal data without
            consent; or (e) engage in any activity that violates the rights of any third party.
          </li>
          <li>
            <strong>Data Responsibility:</strong> You are solely responsible for the data you submit
            to the Platform and any data generated through your use of the Platform. You must ensure
            that your use does not violate any data protection or privacy regulations, including
            GDPR, CCPA, or similar legislation.
          </li>
          <li>
            <strong>Account Security:</strong> You are responsible for maintaining the
            confidentiality of your account credentials, API tokens, and any access keys. You are
            responsible for all activities that occur under your account.
          </li>
          <li>
            <strong>Generated Content:</strong> You acknowledge that AI-generated test scripts, bug
            reports, and other outputs are provided as-is. You are responsible for reviewing,
            validating, and ensuring the appropriateness of any generated content before use in
            production or other environments.
          </li>
        </ul>
      </section>

      <section>
        <h2 className="text-xl font-semibold">4. Limitation of Liability</h2>
        <p>TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW:</p>
        <ul className="list-disc pl-6 space-y-2">
          <li>
            The Platform is provided on an &quot;AS IS&quot; and &quot;AS AVAILABLE&quot; basis
            without warranties of any kind, whether express, implied, statutory, or otherwise,
            including but not limited to implied warranties of merchantability, fitness for a
            particular purpose, title, and non-infringement.
          </li>
          <li>
            The Company shall not be liable for any direct, indirect, incidental, special,
            consequential, or exemplary damages, including but not limited to damages for loss of
            profits, goodwill, data, or other intangible losses, arising out of or in connection
            with your use of the Platform.
          </li>
          <li>
            The Company shall not be liable for any damages, losses, or legal consequences arising
            from: (a) your testing of third-party systems or websites; (b) unauthorized or unlawful
            use of the Platform; (c) any actions taken based on AI-generated outputs; (d) any
            disruption or damage caused to third-party systems through use of the Platform; or (e)
            any violation of applicable laws or regulations through your use of the Platform.
          </li>
          <li>
            You agree to bear full legal responsibility for all consequences arising from your use
            of the Platform, including any claims, damages, or liabilities resulting from testing
            activities conducted through the Platform.
          </li>
        </ul>
      </section>

      <section>
        <h2 className="text-xl font-semibold">5. Indemnification</h2>
        <p>
          You agree to indemnify, defend, and hold harmless the Company, its officers, directors,
          employees, agents, licensors, and suppliers from and against all claims, losses, expenses,
          damages, and costs, including reasonable attorneys&apos; fees, arising out of or relating
          to: (a) your use or misuse of the Platform; (b) your violation of these Terms; (c) your
          violation of any applicable law or regulation; (d) your testing of any third-party system
          or application; or (e) any claim that your use of the Platform caused damage to a third
          party.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">6. Intellectual Property</h2>
        <p>
          The Platform, including its software, design, and documentation, is the intellectual
          property of the Company. Test scripts and reports generated for you through the Platform
          are licensed to you for your use, but the underlying AI models, algorithms, and Platform
          technology remain the exclusive property of the Company.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">7. Data Collection and Privacy</h2>
        <p>
          We collect and process data necessary to provide the Platform services, including account
          information, target URLs, testing results, and usage analytics. By using the Platform, you
          consent to such data collection. We do not sell your personal data to third parties. For
          detailed information, please refer to our Privacy Policy.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">8. Service Availability and Modifications</h2>
        <p>
          We reserve the right to modify, suspend, or discontinue the Platform (or any part thereof)
          at any time with or without notice. We shall not be liable to you or any third party for
          any modification, suspension, or discontinuation of the Platform.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">9. Termination</h2>
        <p>
          We may terminate or suspend your account and access to the Platform at our sole
          discretion, without prior notice or liability, for any reason, including but not limited
          to breach of these Terms. Upon termination, your right to use the Platform will
          immediately cease. Sections 4, 5, 6, and 10 shall survive any termination.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">10. Governing Law and Dispute Resolution</h2>
        <p>
          These Terms shall be governed by and construed in accordance with the laws of the
          jurisdiction in which the Company is incorporated, without regard to its conflict of law
          provisions. Any disputes arising from these Terms or your use of the Platform shall be
          resolved through binding arbitration in accordance with applicable arbitration rules.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">11. Changes to Terms</h2>
        <p>
          We reserve the right to update or modify these Terms at any time. Changes will be
          effective upon posting to the Platform. Your continued use of the Platform after any
          changes constitutes acceptance of the modified Terms. We encourage you to review these
          Terms periodically.
        </p>
      </section>

      <section>
        <h2 className="text-xl font-semibold">12. Contact Information</h2>
        <p>
          If you have any questions about these Terms, please contact us at{' '}
          <a href="mailto:support@example.com" className="text-primary hover:underline">
            support@example.com
          </a>
          .
        </p>
      </section>
    </div>
  )
}
