// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { ResendVerificationForm } from "@/components/auth/link-forms";

export default function CheckEmailPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Check your email</h1>
      <p>
        We sent you a link to confirm your email address. Open it to finish
        signing up and log in.
      </p>
      <h2 className="text-lg font-semibold">Didn&apos;t get it?</h2>
      <ResendVerificationForm />
    </>
  );
}
