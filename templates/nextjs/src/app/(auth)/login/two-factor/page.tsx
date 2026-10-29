// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import Link from "next/link";
import { Suspense } from "react";

import { TwoFactorForm } from "@/components/auth/two-factor-form";
import { safeNext } from "@/lib/auth/safe-next";

export default function TwoFactorPage({
  searchParams,
}: PageProps<"/login/two-factor">) {
  return (
    <>
      <h1 className="text-2xl font-semibold">Two-factor authentication</h1>
      <Suspense>
        <Form searchParams={searchParams} />
      </Suspense>
      <p className="text-sm">
        <Link href="/login" className="underline">
          Start over
        </Link>
      </p>
    </>
  );
}

async function Form({
  searchParams,
}: Pick<PageProps<"/login/two-factor">, "searchParams">) {
  const next = safeNext((await searchParams).next) ?? undefined;
  return <TwoFactorForm next={next} />;
}
