// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import Link from "next/link";
import { Suspense } from "react";

import { LoginForm } from "@/components/auth/login-form";
import { safeNext } from "@/lib/auth/safe-next";

export default function LoginPage({ searchParams }: PageProps<"/login">) {
  return (
    <>
      <h1 className="text-2xl font-semibold">Log in</h1>
      {/* The form needs "next" from the URL, which is only known at request
          time, so it streams in behind this boundary. */}
      <Suspense>
        <Form searchParams={searchParams} />
      </Suspense>
      <p className="text-sm">
        No account?{" "}
        <Link href="/sign-up" className="underline">
          Sign up
        </Link>
      </p>
    </>
  );
}

async function Form({
  searchParams,
}: Pick<PageProps<"/login">, "searchParams">) {
  const next = safeNext((await searchParams).next) ?? undefined;
  return <LoginForm next={next} />;
}
