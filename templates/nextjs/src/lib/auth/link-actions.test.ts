import { HttpResponse, http } from "msw/http";
import { describe, expect, it } from "vitest";

import {
  INVITATION_COOKIE,
  SESSION_COOKIE,
  TWO_FACTOR_COOKIE,
} from "@/lib/auth/cookies";
import {
  acceptInvitation,
  confirmEmailChange,
  holdInvitation,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
} from "@/lib/auth/link-actions";
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

function capture(method: "post", path: string, reply: () => Response) {
  const bodies: unknown[] = [];
  apiServer.use(
    http[method](`${API}${path}`, async ({ request }) => {
      bodies.push(await request.json());
      return reply();
    }),
  );
  return bodies;
}

const invalidLink = () =>
  HttpResponse.json(
    apiError(
      "token_invalid_or_expired",
      "This link is invalid or has expired.",
    ),
    { status: 422 },
  );

describe("verifyEmail", () => {
  it("sends the token and password, then logs in", async () => {
    const bodies = capture("post", "/v1/email-verifications/confirm", () =>
      HttpResponse.json(testLogin("new-token"), { status: 201 }),
    );

    const to = await redirectOf(() =>
      verifyEmail(
        {},
        form({ token: "link-token", password: "a fake passphrase" }),
      ),
    );

    expect(to).toBe("/dashboard");
    expect(bodies).toEqual([
      { token: "link-token", password: "a fake passphrase", client: "web" },
    ]);
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)?.value).toBe("new-token");
  });

  it("goes back to a held invitation after logging in", async () => {
    capture("post", "/v1/email-verifications/confirm", () =>
      HttpResponse.json(testLogin(), { status: 201 }),
    );
    fakeRequest.cookies.set(INVITATION_COOKIE, "invitation-token");

    const to = await redirectOf(() =>
      verifyEmail({}, form({ token: "t", password: "p" })),
    );

    expect(to).toBe("/accept-invitation");
  });

  it("asks for the 2FA code when the user has 2FA", async () => {
    capture("post", "/v1/email-verifications/confirm", () =>
      HttpResponse.json({
        two_factor_required: true,
        challenge_token: "challenge-token",
        expires_at: new Date(Date.now() + 300_000).toISOString(),
      }),
    );

    const to = await redirectOf(() =>
      verifyEmail({}, form({ token: "t", password: "p" })),
    );

    expect(to).toBe("/login/two-factor?next=%2Fdashboard");
    expect(fakeRequest.setCookies.get(TWO_FACTOR_COOKIE)?.value).toBe(
      "challenge-token",
    );
  });

  it("says when the link is incomplete", async () => {
    const state = await verifyEmail({}, form({ token: "", password: "p" }));
    expect(state.message).toMatch(/link is incomplete/);
  });

  it("shows an expired link's message", async () => {
    capture("post", "/v1/email-verifications/confirm", invalidLink);
    const state = await verifyEmail({}, form({ token: "t", password: "p" }));
    expect(state.message).toBe("This link is invalid or has expired.");
    expect(fakeRequest.setCookies.size).toBe(0);
  });
});

describe("requestPasswordReset", () => {
  it("says the same thing whatever the address", async () => {
    const bodies = capture(
      "post",
      "/v1/password-resets",
      () => new HttpResponse(null, { status: 202 }),
    );
    expect(
      await requestPasswordReset({}, form({ email: " a@example.com " })),
    ).toEqual({
      done: true,
    });
    expect(bodies).toEqual([{ email: "a@example.com" }]);
  });
});

describe("resetPassword", () => {
  it("sets the password, clears the cookie, and goes to log in", async () => {
    const bodies = capture(
      "post",
      "/v1/password-resets/confirm",
      () => new HttpResponse(null, { status: 204 }),
    );
    fakeRequest.cookies.set(SESSION_COOKIE, "old-session");

    const to = await redirectOf(() =>
      resetPassword(
        {},
        form({ token: "t", password: "a new passphrase", code: " 123456 " }),
      ),
    );

    expect(to).toBe("/login?notice=password-reset");
    expect(bodies).toEqual([
      { token: "t", password: "a new passphrase", code: "123456" },
    ]);
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)?.options?.maxAge).toBe(0);
  });

  it("shows a needed or wrong 2FA code next to its field", async () => {
    capture("post", "/v1/password-resets/confirm", () =>
      HttpResponse.json(
        apiError("validation_failed", "Check the form.", [
          { field: "code", code: "required", message: "Enter a code." },
        ]),
        { status: 422 },
      ),
    );
    expect(
      await resetPassword({}, form({ token: "t", password: "p" })),
    ).toEqual({ fieldErrors: { code: "Enter a code." } });

    apiServer.resetHandlers();
    capture("post", "/v1/password-resets/confirm", () =>
      HttpResponse.json(
        apiError("invalid_two_factor_code", "That code isn't right."),
        {
          status: 401,
        },
      ),
    );
    expect(
      await resetPassword({}, form({ token: "t", password: "p", code: "1" })),
    ).toEqual({ fieldErrors: { code: "That code isn't right." } });
    expect(fakeRequest.setCookies.size).toBe(0);
  });
});

describe("confirmEmailChange", () => {
  it("confirms, clears the cookie, and goes to log in", async () => {
    const bodies = capture(
      "post",
      "/v1/email-changes/confirm",
      () => new HttpResponse(null, { status: 204 }),
    );
    const to = await redirectOf(() =>
      confirmEmailChange({}, form({ token: "t" })),
    );
    expect(to).toBe("/login?notice=email-changed");
    expect(bodies).toEqual([{ token: "t" }]);
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)?.options?.maxAge).toBe(0);
  });

  it("keeps the session when the link is expired", async () => {
    capture("post", "/v1/email-changes/confirm", invalidLink);
    const state = await confirmEmailChange({}, form({ token: "t" }));
    expect(state.message).toBe("This link is invalid or has expired.");
    expect(fakeRequest.setCookies.size).toBe(0);
  });
});

describe("holdInvitation", () => {
  it("keeps the token in an HttpOnly cookie for a day", async () => {
    expect(await redirectOf(() => holdInvitation("invitation-token"))).toBe(
      "/accept-invitation",
    );
    expect(fakeRequest.setCookies.get(INVITATION_COOKIE)).toEqual({
      value: "invitation-token",
      options: {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        path: "/",
        maxAge: 86400,
      },
    });
  });

  it("ignores anything that isn't a token", async () => {
    await redirectOf(() => holdInvitation("x".repeat(600)));
    await redirectOf(() => holdInvitation(""));
    expect(fakeRequest.setCookies.size).toBe(0);
  });
});

describe("acceptInvitation", () => {
  function acceptAnswers(reply: () => Response) {
    const seen: Request[] = [];
    apiServer.use(
      http.post(`${API}/v1/invitations/accept`, ({ request }) => {
        seen.push(request.clone());
        return reply();
      }),
    );
    return seen;
  }

  it("joins as the logged-in user, and forgets the invitation", async () => {
    const seen = acceptAnswers(() =>
      HttpResponse.json({ id: "org-1", name: "Acme", role: "member" }),
    );
    fakeRequest.cookies.set(INVITATION_COOKIE, "invitation-token");
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");

    expect(await acceptInvitation({})).toEqual({
      done: true,
      message: "You've joined Acme.",
    });
    expect(seen[0].headers.get("authorization")).toBe("Bearer session-token");
    expect(await seen[0].json()).toEqual({ token: "invitation-token" });
    expect(fakeRequest.setCookies.get(INVITATION_COOKIE)?.options?.maxAge).toBe(
      0,
    );
  });

  it("keeps an invitation for another address, to log in with that one", async () => {
    acceptAnswers(() =>
      HttpResponse.json(
        apiError(
          "invitation_email_mismatch",
          "This invitation is for another address.",
        ),
        { status: 403 },
      ),
    );
    fakeRequest.cookies.set(INVITATION_COOKIE, "invitation-token");
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");

    const state = await acceptInvitation({});

    expect(state.message).toBe("This invitation is for another address.");
    expect(fakeRequest.setCookies.size).toBe(0);
  });

  it("forgets an invitation that's no use any more", async () => {
    acceptAnswers(invalidLink);
    fakeRequest.cookies.set(INVITATION_COOKIE, "invitation-token");
    fakeRequest.cookies.set(SESSION_COOKIE, "session-token");

    await acceptInvitation({});

    expect(fakeRequest.setCookies.get(INVITATION_COOKIE)?.options?.maxAge).toBe(
      0,
    );
  });

  it("sends a logged-out user to log in first", async () => {
    fakeRequest.cookies.set(INVITATION_COOKIE, "invitation-token");
    expect(await redirectOf(() => acceptInvitation({}))).toBe(
      "/login?next=%2Faccept-invitation",
    );
  });
});
