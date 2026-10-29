// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";

import { ApiError, callApi } from "@/lib/api/client";
import { meSchema, type Me } from "@/lib/api/schemas";
import { SESSION_COOKIE } from "@/lib/auth/cookies";
import { loginPath } from "@/lib/auth/safe-next";

// getSession returns the logged-in user, checked with the Go API, or null.
// It's cached for one request only, never longer, so a session ended
// elsewhere stops working on the next request.
export const getSession = cache(async (): Promise<Me | null> => {
  const token = await getSessionToken();
  if (!token) {
    return null;
  }
  try {
    return await callApi("/v1/users/me", meSchema, { token });
  } catch (e) {
    // The session expired or was ended.
    if (e instanceof ApiError && e.status === 401) {
      return null;
    }
    throw e;
  }
});

// requireSession is the real check for protected pages and server actions:
// proxy.ts only looks for the cookie. Without a session, it redirects to
// the login page, which comes back to path afterwards.
export async function requireSession(path: string): Promise<Me> {
  const session = await getSession();
  if (!session) {
    redirect(loginPath(path));
  }
  return session;
}

// getSessionToken returns the session token from the cookie, for calling
// the Go API as the user.
export async function getSessionToken(): Promise<string | undefined> {
  return (await cookies()).get(SESSION_COOKIE)?.value;
}
