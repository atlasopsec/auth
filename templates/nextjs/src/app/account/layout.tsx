// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import Link from "next/link";
import type { ReactNode } from "react";

export default function AccountLayout({ children }: { children: ReactNode }) {
  return (
    <main className="mx-auto grid w-full max-w-lg gap-10 px-4 py-16">
      <nav className="flex gap-4 text-sm underline">
        <Link href="/dashboard">Dashboard</Link>
        <Link href="/account">Account</Link>
        <Link href="/account/two-factor">Two-factor authentication</Link>
      </nav>
      {children}
    </main>
  );
}
