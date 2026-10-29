import { HttpResponse, http } from "msw/http";
import { describe, expect, it } from "vitest";

import { SESSION_COOKIE } from "@/lib/auth/cookies";
import { OAUTH_COOKIE, challengeOf, decodeFlow } from "@/lib/auth/oauth";
import {
  startOAuthLink,
  startOAuthLogin,
  unlinkOAuth,
} from "@/lib/auth/oauth-actions";
import { API, apiError, apiServer } from "@/test/api";
import { fakeRequest, redirectOf } from "@/test/next";

function form(fields: Record<string, string>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(fields)) {
    f.set(k, v);
  }
  return f;
}

function flowStarts(path: string) {
  const seen: { body: Record<string, string>; auth: string | null }[] = [];
  apiServer.use(
    http.post(`${API}${path}`, async ({ request }) => {
      seen.push({
        body: (await request.json()) as Record<string, string>,
        auth: request.headers.get("authorization"),
      });
      return HttpResponse.json(
        {
          authorization_url: "https://accounts.google.example/auth?x=1",
          expires_at: new Date(Date.now() + 600_000).toISOString(),
        },
        { status: 201 },
      );
    }),
  );
  return seen;
}

describe("startOAuthLogin", () => {
  it("keeps the verifier in a cookie and sends the browser to the provider", async () => {
    const seen = flowStarts("/v1/oauth-flows");

    const to = await redirectOf(() =>
      startOAuthLogin({}, form({ provider: "google", next: "/account" })),
    );

    expect(to).toBe("https://accounts.google.example/auth?x=1");
    const cookie = fakeRequest.setCookies.get(OAUTH_COOKIE)!;
    expect(cookie.options).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    });
    // As long as the flow: 10 minutes.
    expect(cookie.options?.maxAge).toBeGreaterThan(590);
    expect(cookie.options?.maxAge).toBeLessThanOrEqual(600);
    const flow = decodeFlow(cookie.value)!;
    expect(flow).toMatchObject({ purpose: "login", next: "/account" });
    // Only the challenge goes to the API; the verifier stays here.
    expect(seen[0].body).toEqual({
      provider: "google",
      client: "web",
      client_challenge: challengeOf(flow.verifier),
    });
  });

  it("refuses a provider that isn't turned on", async () => {
    const state = await startOAuthLogin({}, form({ provider: "github" }));
    expect(state.message).toMatch(/isn't available/);
    expect(fakeRequest.setCookies.size).toBe(0);
  });

  it("drops a next that leaves the site", async () => {
    flowStarts("/v1/oauth-flows");
    await redirectOf(() =>
      startOAuthLogin({}, form({ provider: "google", next: "//evil.example" })),
    );
    expect(
      decodeFlow(fakeRequest.setCookies.get(OAUTH_COOKIE)!.value)?.next,
    ).toBeNull();
  });

  it("shows the API's error and sets no cookie", async () => {
    apiServer.use(
      http.post(`${API}/v1/oauth-flows`, () =>
        HttpResponse.json(apiError("rate_limited", "Too many requests."), {
          status: 429,
        }),
      ),
    );
    const state = await startOAuthLogin({}, form({ provider: "google" }));
    expect(state.message).toBe("Too many requests.");
    expect(fakeRequest.setCookies.size).toBe(0);
  });
});

describe("startOAuthLink", () => {
  it("starts a link as the user, with the current password", async () => {
    const seen = flowStarts("/v1/users/me/oauth-accounts");
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");

    await redirectOf(() =>
      startOAuthLink({}, form({ provider: "google", current_password: "pw" })),
    );

    expect(seen[0].auth).toBe("Bearer session-token");
    expect(seen[0].body).toMatchObject({
      provider: "google",
      current_password: "pw",
    });
    expect(
      decodeFlow(fakeRequest.setCookies.get(OAUTH_COOKIE)!.value)?.purpose,
    ).toBe("link");
  });
});

describe("unlinkOAuth", () => {
  const id = "01920000-0000-7000-8000-000000000007";

  it("unlinks with the current password", async () => {
    let body: unknown;
    apiServer.use(
      http.delete(
        `${API}/v1/users/me/oauth-accounts/${id}`,
        async ({ request }) => {
          body = await request.json();
          return new HttpResponse(null, { status: 204 });
        },
      ),
    );
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");
    expect(await unlinkOAuth({}, form({ id, current_password: "pw" }))).toEqual(
      {
        done: true,
      },
    );
    expect(body).toEqual({ current_password: "pw" });
  });

  it("refuses anything that isn't an account ID", async () => {
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");
    const state = await unlinkOAuth({}, form({ id: "../../sessions" }));
    expect(state.fieldErrors?.id).toMatch(/wasn't found/);
  });
});
