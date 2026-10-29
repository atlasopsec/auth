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

// The page where users who must have 2FA set it up.
export const TWO_FACTOR_SETUP_PATH = "/account/two-factor";

type RequireOptions = {
  // For the 2FA setup page itself, which users who must set up 2FA are
  // allowed to see.
  duringTwoFactorSetup?: boolean;
};

// requireSession is the real check for protected pages and server actions:
// proxy.ts only looks for the cookie. Without a session, it redirects to
// the login page, which comes back to path afterwards. A user who must set
// up 2FA is sent to do that first: the Go API refuses everything else for
// them until they do.
export async function requireSession(
  path: string,
  options: RequireOptions = {},
): Promise<Me> {
  const session = await getSession();
  if (!session) {
    redirect(loginPath(path));
  }
  if (
    session.two_factor_required &&
    !session.two_factor_enabled &&
    !options.duringTwoFactorSetup
  ) {
    redirect(TWO_FACTOR_SETUP_PATH);
  }
  return session;
}

// getSessionToken returns the session token from the cookie, for calling
// the Go API as the user.
export async function getSessionToken(): Promise<string | undefined> {
  return (await cookies()).get(SESSION_COOKIE)?.value;
}
