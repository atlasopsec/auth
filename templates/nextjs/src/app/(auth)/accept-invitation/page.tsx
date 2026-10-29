// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { cookies } from "next/headers";
import Link from "next/link";
import { Suspense } from "react";

import {
  AcceptInvitationForm,
  HoldInvitation,
} from "@/components/auth/invitation";
import { INVITATION_COOKIE } from "@/lib/auth/cookies";
import { getSession } from "@/lib/auth/session";

export default function AcceptInvitationPage() {
  return (
    <>
      <h1 className="text-2xl font-semibold">Join an organization</h1>
      <HoldInvitation />
      {/* Reads the invitation cookie and the session at request time. */}
      <Suspense fallback={<p>Loading…</p>}>
        <Invitation />
      </Suspense>
    </>
  );
}

async function Invitation() {
  const held = (await cookies()).has(INVITATION_COOKIE);
  if (!held) {
    // The link's token is moved into the cookie as soon as the page loads,
    // so this shows only for a page opened without one.
    return <p>Open the invitation link from your email to join.</p>;
  }
  if (!(await getSession())) {
    const next = encodeURIComponent("/accept-invitation");
    return (
      <p>
        <Link href={`/login?next=${next}`} className="underline">
          Log in
        </Link>{" "}
        or{" "}
        <Link href="/sign-up" className="underline">
          sign up
        </Link>{" "}
        with the address the invitation was sent to, and you&apos;ll come back
        here to accept it.
      </p>
    );
  }
  return <AcceptInvitationForm />;
}
