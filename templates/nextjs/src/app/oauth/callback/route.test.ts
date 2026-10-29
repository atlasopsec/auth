import { NextRequest } from "next/server";
import { HttpResponse, http } from "msw/http";
import { describe, expect, it, vi } from "vitest";

import { GET } from "@/app/oauth/callback/route";
import { SESSION_COOKIE, TWO_FACTOR_COOKIE } from "@/lib/auth/cookies";
import { OAUTH_COOKIE, encodeFlow, type Flow } from "@/lib/auth/oauth";
import { API, apiError, apiServer } from "@/test/api";
import { testLogin } from "@/test/fixtures";
import { fakeRequest, redirectOf } from "@/test/next";

const verifier = "v".repeat(43);

function started(flow: Partial<Flow> = {}) {
  fakeRequest.cookies.set(
    OAUTH_COOKIE,
    encodeFlow({ verifier, purpose: "login", next: null, ...flow }),
  );
}

function callback(query = "code=the-code&state=the-state") {
  return redirectOf(() =>
    GET(new NextRequest(`http://localhost/oauth/callback?${query}`)),
  );
}

function completes(reply: () => Response) {
  const seen: { body: unknown; auth: string | null }[] = [];
  apiServer.use(
    http.post(`${API}/v1/oauth-flows/complete`, async ({ request }) => {
      seen.push({
        body: await request.json(),
        auth: request.headers.get("authorization"),
      });
      return reply();
    }),
  );
  return seen;
}

describe("GET /oauth/callback", () => {
  it("finishes the sign-in with this browser's verifier", async () => {
    const seen = completes(() =>
      HttpResponse.json(testLogin("new-token"), { status: 201 }),
    );
    started({ next: "/account" });

    expect(await callback()).toBe("/account");
    expect(seen[0].body).toEqual({
      state: "the-state",
      code: "the-code",
      client_verifier: verifier,
    });
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)?.value).toBe("new-token");
    expect(fakeRequest.setCookies.get(OAUTH_COOKIE)?.options?.maxAge).toBe(0);
  });

  it("asks for the 2FA code when the user has 2FA", async () => {
    completes(() =>
      HttpResponse.json({
        two_factor_required: true,
        challenge_token: "challenge-token",
        expires_at: new Date(Date.now() + 300_000).toISOString(),
      }),
    );
    started();
    expect(await callback()).toBe("/login/two-factor?next=%2Fdashboard");
    expect(fakeRequest.setCookies.get(TWO_FACTOR_COOKIE)?.value).toBe(
      "challenge-token",
    );
  });

  it("refuses a browser that didn't start the sign-in", async () => {
    const seen = completes(() =>
      HttpResponse.json(testLogin(), { status: 201 }),
    );
    expect(await callback()).toBe("/login?notice=oauth-expired");
    expect(seen).toHaveLength(0);
    expect(fakeRequest.setCookies.has(SESSION_COOKIE)).toBe(false);
  });

  it("handles the user saying no at the provider", async () => {
    const seen = completes(() =>
      HttpResponse.json(testLogin(), { status: 201 }),
    );
    started();
    expect(await callback("error=access_denied&state=the-state")).toBe(
      "/login?notice=oauth-failed",
    );
    expect(seen).toHaveLength(0);
    expect(fakeRequest.setCookies.get(OAUTH_COOKIE)?.options?.maxAge).toBe(0);
  });

  it.each([
    ["oauth_email_not_verified", "oauth-email-not-verified"],
    ["oauth_failed", "oauth-failed"],
    ["something_new", "oauth-failed"],
  ])("shows a fixed notice for %s", async (code, notice) => {
    completes(() =>
      HttpResponse.json(apiError(code, "Text from the API."), { status: 403 }),
    );
    started();
    expect(await callback()).toBe(`/login?notice=${notice}`);
  });

  it("logs unexpected failures without showing them", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    completes(() => HttpResponse.json({ not: "a login" }, { status: 201 }));
    started();
    expect(await callback()).toBe("/login?notice=oauth-failed");
    expect(log).toHaveBeenCalled();
  });

  describe("linking", () => {
    it("links the provider as the logged-in user", async () => {
      const seen = completes(() =>
        HttpResponse.json(
          { id: "acct-1", provider: "google", email: "", created_at: "" },
          { status: 201 },
        ),
      );
      started({ purpose: "link" });
      fakeRequest.cookies.set(SESSION_COOKIE, "session-token");

      expect(await callback()).toBe("/account?notice=oauth-linked");
      expect(seen[0].auth).toBe("Bearer session-token");
      expect(fakeRequest.setCookies.has(SESSION_COOKIE)).toBe(false);
    });

    it.each([
      ["oauth_account_in_use", "oauth-account-in-use"],
      ["oauth_already_linked", "oauth-already-linked"],
    ])("explains %s on the account page", async (code, notice) => {
      completes(() =>
        HttpResponse.json(apiError(code, "Text."), { status: 409 }),
      );
      started({ purpose: "link" });
      fakeRequest.cookies.set(SESSION_COOKIE, "session-token");
      expect(await callback()).toBe(`/account?notice=${notice}`);
    });

    it("fails without a session", async () => {
      const seen = completes(() =>
        HttpResponse.json({ id: "x" }, { status: 201 }),
      );
      started({ purpose: "link" });
      expect(await callback()).toBe("/account?notice=oauth-failed");
      expect(seen).toHaveLength(0);
    });
  });
});
