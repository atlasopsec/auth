// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { ForgotPasswordForm } from "@/components/auth/link-forms";

export default function ForgotPasswordPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Reset your password</h1>
      <p>We&apos;ll email you a link to set a new password.</p>
      <ForgotPasswordForm />
    </>
  );
}
