// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import Link from "next/link";

import { ResetPasswordForm } from "@/components/auth/link-forms";

export default function ResetPasswordPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Set a new password</h1>
      <ResetPasswordForm />
      <p className="text-sm">
        Link expired?{" "}
        <Link href="/forgot-password" className="underline">
          Send a new one
        </Link>
      </p>
    </>
  );
}
