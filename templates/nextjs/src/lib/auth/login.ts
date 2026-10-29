// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import type { z } from "zod";

import type { Challenge, Login } from "@/lib/api/schemas";
import {
  INVITATION_COOKIE,
  SESSION_COOKIE,
  TWO_FACTOR_COOKIE,
  cookieOptions,
} from "@/lib/auth/cookies";
import { DEFAULT_AFTER_LOGIN } from "@/lib/auth/safe-next";

// Helpers for the server actions in actions.ts and link-actions.ts.

export function fieldErrors(error: z.ZodError): Record<string, string> {
  const out: Record<string, string> = {};
  for (const issue of error.issues) {
    const field = String(issue.path[0] ?? "");
    out[field] ??= issue.message;
  }
  return out;
}

// startSession sets the session cookie for a new login.
export async function startSession(login: Login): Promise<void> {
  (await cookies()).set(
    SESSION_COOKIE,
    login.token,
    // Until the latest the session can last: it's extended each time it's
    // used, and the Go API ends it sooner if it sits unused.
    cookieOptions(login.absolute_expires_at),
  );
}

// finishLogin starts the session, or holds the 2FA challenge and goes to
// the code page, then goes to next.
export async function finishLogin(
  result: Login | Challenge,
  next: string | null,
): Promise<never> {
  if ("two_factor_required" in result) {
    (await cookies()).set(
      TWO_FACTOR_COOKIE,
      result.challenge_token,
      cookieOptions(result.expires_at),
    );
    const query = next ? `?next=${encodeURIComponent(next)}` : "";
    redirect(`/login/two-factor${query}`);
  }
  await startSession(result);
  redirect(next ?? DEFAULT_AFTER_LOGIN);
}

// afterLogin is where a login with no "next" goes: back to an invitation
// the user opened before logging in, or the default page.
export async function afterLogin(): Promise<string> {
  const store = await cookies();
  return store.has(INVITATION_COOKIE)
    ? "/accept-invitation"
    : DEFAULT_AFTER_LOGIN;
}
