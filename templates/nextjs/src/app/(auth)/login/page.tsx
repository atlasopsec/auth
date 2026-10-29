// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import Link from "next/link";
import { Suspense } from "react";

import { LoginForm } from "@/components/auth/login-form";
import { OAuthButtons } from "@/components/auth/oauth-buttons";
import { PROVIDER_NAMES, enabledProviders } from "@/lib/auth/oauth";
import { noticeText } from "@/lib/auth/notices";
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
        <Link href="/forgot-password" className="underline">
          Forgot your password?
        </Link>
      </p>
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
  const params = await searchParams;
  const next = safeNext(params.next) ?? undefined;
  const notice = noticeText(params.notice);
  return (
    <>
      {notice && <p role="status">{notice}</p>}
      <LoginForm next={next} />
      <OAuthButtons
        next={next}
        providers={enabledProviders().map((id) => ({
          id,
          name: PROVIDER_NAMES[id],
        }))}
      />
    </>
  );
}
