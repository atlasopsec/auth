// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { ConfirmEmailChangeForm } from "@/components/auth/link-forms";

export default function ConfirmEmailChangePage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Confirm your new email</h1>
      <p>
        Your account will use this address from now on. You&apos;ll be logged
        out everywhere, and can log in again with the new address.
      </p>
      <ConfirmEmailChangeForm />
    </>
  );
}
