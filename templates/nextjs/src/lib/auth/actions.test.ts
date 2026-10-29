import { HttpResponse, http } from "msw/http";
import { describe, expect, it } from "vitest";

import { logIn, logOut, signUp, verifyTwoFactor } from "@/lib/auth/actions";
import { SESSION_COOKIE, TWO_FACTOR_COOKIE } from "@/lib/auth/cookies";
import { API, apiError, apiServer } from "@/test/api";
import { testLogin } from "@/test/fixtures";
import { fakeRequest, redirectOf } from "@/test/next";

function form(fields: Record<string, string>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(fields)) {
    f.set(k, v);
  }
  return f;
}

const credentials = { email: "ada@example.com", password: "a fake passphrase" };

describe("logIn", () => {
  it("sets the session cookie until the session's latest expiry, then goes to next", async () => {
    let body: unknown;
    apiServer.use(
      http.post(`${API}/v1/sessions`, async ({ request }) => {
        body = await request.json();
        return HttpResponse.json(testLogin("new-token"), { status: 201 });
      }),
    );

    const to = await redirectOf(() =>
      logIn({}, form({ ...credentials, next: "/account" })),
    );

    expect(to).toBe("/account");
    expect(body).toEqual({ ...credentials, client: "web" });
    const cookie = fakeRequest.setCookies.get(SESSION_COOKIE);
    expect(cookie?.value).toBe("new-token");
    expect(cookie?.options).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    });
    expect(cookie?.options?.maxAge).toBeGreaterThan(3590);
    expect(cookie?.options?.maxAge).toBeLessThanOrEqual(3600);
  });

  it("never sends people to another site", async () => {
    apiServer.use(
      http.post(`${API}/v1/sessions`, () =>
        HttpResponse.json(testLogin(), { status: 201 }),
      ),
    );
    expect(
      await redirectOf(() =>
        logIn({}, form({ ...credentials, next: "//evil.example" })),
      ),
    ).toBe("/dashboard");
  });

  it("keeps a 2FA challenge in its own cookie, not the URL", async () => {
    const expires = new Date(Date.now() + 5 * 60 * 1000).toISOString();
    apiServer.use(
      http.post(`${API}/v1/sessions`, () =>
        HttpResponse.json({
          two_factor_required: true,
          challenge_token: "challenge-token",
          expires_at: expires,
        }),
      ),
    );

    const to = await redirectOf(() =>
      logIn({}, form({ ...credentials, next: "/account" })),
    );

    expect(to).toBe("/login/two-factor?next=%2Faccount");
    expect(to).not.toContain("challenge-token");
    expect(fakeRequest.setCookies.get(TWO_FACTOR_COOKIE)?.value).toBe(
      "challenge-token",
    );
    expect(fakeRequest.setCookies.has(SESSION_COOKIE)).toBe(false);
  });

  it("shows the API's message, keeps the email, and never the password", async () => {
    apiServer.use(
      http.post(`${API}/v1/sessions`, () =>
        HttpResponse.json(
          apiError(
            "invalid_credentials",
            "The email or password is incorrect.",
          ),
          { status: 401 },
        ),
      ),
    );

    const state = await logIn({}, form(credentials));

    expect(state).toEqual({
      message: "The email or password is incorrect.",
      values: { email: "ada@example.com" },
    });
    expect(fakeRequest.setCookies.size).toBe(0);
  });

  it("checks its input before calling the API", async () => {
    const state = await logIn({}, form({ email: " ", password: "" }));
    expect(state.fieldErrors).toEqual({
      email: "Enter your email address.",
      password: "Enter your password.",
    });
  });
});

describe("verifyTwoFactor", () => {
  it("swaps the challenge cookie for a session", async () => {
    let body: unknown;
    apiServer.use(
      http.post(
        `${API}/v1/two-factor-challenges/verify`,
        async ({ request }) => {
          body = await request.json();
          return HttpResponse.json(testLogin("new-token"), { status: 201 });
        },
      ),
    );
    fakeRequest.cookies.set(TWO_FACTOR_COOKIE, "challenge-token");

    const to = await redirectOf(() =>
      verifyTwoFactor({}, form({ code: " 123456 ", next: "/account" })),
    );

    expect(to).toBe("/account");
    expect(body).toEqual({
      challenge_token: "challenge-token",
      code: "123456",
    });
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)?.value).toBe("new-token");
    expect(fakeRequest.setCookies.get(TWO_FACTOR_COOKIE)?.options?.maxAge).toBe(
      0,
    );
  });

  it("shows a wrong code next to the field, and keeps the challenge", async () => {
    apiServer.use(
      http.post(`${API}/v1/two-factor-challenges/verify`, () =>
        HttpResponse.json(
          apiError("invalid_two_factor_code", "That code isn't right."),
          {
            status: 401,
          },
        ),
      ),
    );
    fakeRequest.cookies.set(TWO_FACTOR_COOKIE, "challenge-token");

    const state = await verifyTwoFactor({}, form({ code: "000000" }));

    expect(state).toEqual({ fieldErrors: { code: "That code isn't right." } });
    expect(fakeRequest.setCookies.size).toBe(0);
  });

  it("clears a challenge that's used up", async () => {
    apiServer.use(
      http.post(`${API}/v1/two-factor-challenges/verify`, () =>
        HttpResponse.json(
          apiError("two_factor_challenge_invalid", "This login has expired."),
          { status: 401 },
        ),
      ),
    );
    fakeRequest.cookies.set(TWO_FACTOR_COOKIE, "challenge-token");

    const state = await verifyTwoFactor({}, form({ code: "000000" }));

    expect(state.message).toBe("This login has expired.");
    expect(fakeRequest.setCookies.get(TWO_FACTOR_COOKIE)?.options?.maxAge).toBe(
      0,
    );
  });

  it("asks to log in again without a challenge", async () => {
    const state = await verifyTwoFactor({}, form({ code: "123456" }));
    expect(state.message).toMatch(/log in with your password again/i);
  });
});

describe("signUp", () => {
  it("goes to 'check your email' when the email must be verified first", async () => {
    apiServer.use(
      http.post(`${API}/v1/users`, () =>
        HttpResponse.json({ verification_required: true }, { status: 202 }),
      ),
    );
    expect(await redirectOf(() => signUp({}, form(credentials)))).toBe(
      "/sign-up/check-email",
    );
    expect(fakeRequest.setCookies.size).toBe(0);
  });

  it("logs in when the project allows unverified logins", async () => {
    apiServer.use(
      http.post(`${API}/v1/users`, () =>
        HttpResponse.json(testLogin("new-token"), { status: 201 }),
      ),
    );
    expect(await redirectOf(() => signUp({}, form(credentials)))).toBe(
      "/dashboard",
    );
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)?.value).toBe("new-token");
  });

  it("shows field errors from the API", async () => {
    apiServer.use(
      http.post(`${API}/v1/users`, () =>
        HttpResponse.json(
          apiError("validation_failed", "Check the form.", [
            {
              field: "password",
              code: "too_short",
              message: "Use at least 12 characters.",
            },
          ]),
          { status: 422 },
        ),
      ),
    );
    const state = await signUp({}, form(credentials));
    expect(state.fieldErrors).toEqual({
      password: "Use at least 12 characters.",
    });
  });
});

describe("logOut", () => {
  function deleteAnswers(status: number) {
    let calls = 0;
    apiServer.use(
      http.delete(`${API}/v1/sessions/current`, ({ request }) => {
        calls++;
        expect(request.headers.get("authorization")).toBe(
          "Bearer session-token",
        );
        return status === 204
          ? new HttpResponse(null, { status })
          : HttpResponse.json(apiError("x", "y"), { status });
      }),
    );
    return () => calls;
  }

  it("ends the session in the Go API, then clears the cookie", async () => {
    const calls = deleteAnswers(204);
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");

    expect(await redirectOf(() => logOut({}))).toBe("/login");
    expect(calls()).toBe(1);
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)).toMatchObject({
      value: "",
      options: { maxAge: 0, secure: true, path: "/" },
    });
  });

  it("clears the cookie of a session that had already ended", async () => {
    deleteAnswers(401);
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");
    expect(await redirectOf(() => logOut({}))).toBe("/login");
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)?.options?.maxAge).toBe(0);
  });

  it("keeps the cookie when the session couldn't be ended", async () => {
    deleteAnswers(500);
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");

    const state = await logOut({});

    expect(state.message).toMatch(/something went wrong/i);
    expect(fakeRequest.setCookies.size).toBe(0);
  });
});
