// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import type { NextRequest } from "next/server";
import { z } from "zod";

import { ApiError, callApi } from "@/lib/api/client";
import { loginOrChallengeSchema } from "@/lib/api/schemas";
import { clearedCookie } from "@/lib/auth/cookies";
import { afterLogin, finishLogin } from "@/lib/auth/login";
import type { Notice } from "@/lib/auth/notices";
import { OAUTH_COOKIE, decodeFlow } from "@/lib/auth/oauth";
import { getSessionToken } from "@/lib/auth/session";

// Google and GitHub send the browser back here with code and state.
//
// The auth standard asks route handlers that change data to check the
// Origin header. This one can't: the provider's redirect is a plain
// navigation, which sends none. The __Host-oauth cookie protects it
// instead. Only the browser that started the sign-in has its verifier, and
// the Go API refuses to finish the flow without it, so nobody can finish
// their own sign-in in someone else's browser (login CSRF).
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const store = await cookies();
  const flow = decodeFlow(store.get(OAUTH_COOKIE)?.value);
  // Used once, whatever happens next.
  store.set(OAUTH_COOKIE, "", clearedCookie);

  const code = params.get("code");
  const state = params.get("state");
  if (!flow) {
    redirect(notice("/login", "oauth-expired"));
  }
  const back = flow.purpose === "link" ? "/account" : "/login";
  if (!code || !state) {
    // The user said no at the provider, or the provider had an error.
    redirect(notice(back, "oauth-failed"));
  }

  const body = { state, code, client_verifier: flow.verifier };
  if (flow.purpose === "link") {
    redirect(notice("/account", await link(body)));
  }

  let result;
  try {
    result = await callApi("/v1/oauth-flows/complete", loginOrChallengeSchema, {
      method: "POST",
      body,
    });
  } catch (e) {
    redirect(notice("/login", failure(e)));
  }
  return finishLogin(result, flow.next ?? (await afterLogin()));
}

async function link(body: Record<string, string>): Promise<Notice> {
  const token = await getSessionToken();
  if (!token) {
    return "oauth-failed";
  }
  try {
    await callApi("/v1/oauth-flows/complete", z.object({ id: z.string() }), {
      method: "POST",
      body,
      token,
    });
    return "oauth-linked";
  } catch (e) {
    return failure(e);
  }
}

// failure picks the notice for an error. Only fixed messages are shown.
function failure(e: unknown): Notice {
  if (e instanceof ApiError) {
    switch (e.code) {
      case "oauth_email_not_verified":
        return "oauth-email-not-verified";
      case "oauth_account_in_use":
        return "oauth-account-in-use";
      case "oauth_already_linked":
        return "oauth-already-linked";
    }
  } else {
    console.error(e);
  }
  return "oauth-failed";
}

function notice(path: string, n: Notice): string {
  return `${path}?notice=${n}`;
}
