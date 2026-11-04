import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { SESSION_COOKIE } from "@/lib/auth/cookies";
import { proxy } from "@/proxy";

function request(path: string, loggedIn = false): NextRequest {
  const req = new NextRequest(new URL(path, "http://localhost"));
  if (loggedIn) {
    req.cookies.set(SESSION_COOKIE, "session-token");
  }
  return req;
}

function nonceOf(policy: string | null): string | undefined {
  return policy?.match(/'nonce-([^']+)'/)?.[1];
}

describe("proxy", () => {
  it.each(["/dashboard", "/account/two-factor"])(
    "sends logged-out visitors from %s to log in",
    (path) => {
      const res = proxy(request(path + "?tab=1"));
      expect(res.headers.get("location")).toBe(
        `http://localhost/login?next=${encodeURIComponent(path + "?tab=1")}`,
      );
    },
  );

  it.each(["/login", "/dashboards", "/"])(
    "lets logged-out visitors see %s",
    (path) => {
      expect(proxy(request(path)).headers.get("location")).toBeNull();
    },
  );

  it("sets the policy with a new nonce for each response", () => {
    const a = proxy(request("/dashboard", true));
    const b = proxy(request("/login"));
    const nonceA = nonceOf(a.headers.get("content-security-policy"));
    const nonceB = nonceOf(b.headers.get("content-security-policy"));
    expect(nonceA).toBeTruthy();
    expect(nonceB).toBeTruthy();
    expect(nonceA).not.toBe(nonceB);
  });

  it("passes the policy on to the page, so Next.js uses the same nonce", () => {
    const res = proxy(request("/login"));
    const policy = res.headers.get("content-security-policy");
    // NextResponse.next({ request: { headers } }) forwards them this way.
    expect(
      res.headers.get("x-middleware-request-content-security-policy"),
    ).toBe(policy);
  });
});
