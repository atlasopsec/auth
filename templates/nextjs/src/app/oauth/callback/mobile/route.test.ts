import { NextRequest } from "next/server";
import { describe, expect, it, vi } from "vitest";

async function call(query: string) {
  const { GET } = await import("@/app/oauth/callback/mobile/route");
  return GET(
    new NextRequest(`http://localhost/oauth/callback/mobile?${query}`),
  );
}

describe("GET /oauth/callback/mobile", () => {
  it("passes code and state, and nothing else, to the app", async () => {
    const res = await call("code=c&state=s&extra=x");
    expect(res.status).toBe(303);
    expect(res.headers.get("location")).toBe(
      "exampleapp://oauth?code=c&state=s",
    );
  });

  it("passes on the provider's error", async () => {
    const res = await call("error=access_denied&state=s");
    expect(res.headers.get("location")).toBe(
      "exampleapp://oauth?state=s&error=access_denied",
    );
  });

  it("is a 404 without a mobile app", async () => {
    vi.resetModules();
    vi.stubEnv("MOBILE_OAUTH_REDIRECT_URL", undefined);
    try {
      expect((await call("code=c&state=s")).status).toBe(404);
    } finally {
      vi.unstubAllEnvs();
      vi.resetModules();
    }
  });
});
