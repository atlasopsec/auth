// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import Link from "next/link";

import { VerifyEmailForm } from "@/components/auth/link-forms";

export default function VerifyEmailPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Confirm your email</h1>
      <p>Enter your password to confirm your address and log in.</p>
      <VerifyEmailForm />
      <p className="text-sm">
        Link expired?{" "}
        <Link href="/sign-up/check-email" className="underline">
          Send a new one
        </Link>
      </p>
    </>
  );
}
