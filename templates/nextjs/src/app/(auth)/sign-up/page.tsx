// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import Link from "next/link";

import { SignUpForm } from "@/components/auth/sign-up-form";

export default function SignUpPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Sign up</h1>
      <SignUpForm />
      <p className="text-sm">
        Have an account?{" "}
        <Link href="/login" className="underline">
          Log in
        </Link>
      </p>
    </>
  );
}
