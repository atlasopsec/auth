// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import type { NextRequest } from "next/server";

import { env } from "@/lib/env";

// Google and GitHub send the browser here when the mobile app started the
// sign-in. This passes code and state on to the app's deep link, which
// finishes the sign-in with its own verifier. It doesn't change anything
// itself.
export function GET(request: NextRequest) {
  const deepLink = env().MOBILE_OAUTH_REDIRECT_URL;
  if (!deepLink) {
    return new Response("Not found", { status: 404 });
  }
  const to = new URL(deepLink);
  for (const name of ["code", "state", "error"]) {
    const value = request.nextUrl.searchParams.get(name);
    if (value !== null) {
      to.searchParams.set(name, value);
    }
  }
  return Response.redirect(to, 303);
}
