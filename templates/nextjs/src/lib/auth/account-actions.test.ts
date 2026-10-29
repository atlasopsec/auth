import { refresh } from "next/cache";
import { HttpResponse, http } from "msw/http";
import { describe, expect, it } from "vitest";

import {
  changePassword,
  confirmTwoFactorSetup,
  endSession,
  logOutEverywhere,
  regenerateRecoveryCodes,
  requestEmailChange,
  startTwoFactorSetup,
  turnOffTwoFactor,
} from "@/lib/auth/account-actions";
import { SESSION_COOKIE } from "@/lib/auth/cookies";
import { API, apiError, apiServer } from "@/test/api";
import { fakeRequest, redirectOf } from "@/test/next";

function form(fields: Record<string, string>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(fields)) {
    f.set(k, v);
  }
  return f;
}

type Method = "post" | "delete";

// answer makes the fake Go API answer one call, and records what was sent.
function answer(method: Method, path: string, reply: () => Response) {
  const calls: { auth: string | null; body: unknown }[] = [];
  apiServer.use(
    http[method](`${API}${path}`, async ({ request }) => {
      const text = await request.text();
      calls.push({
        auth: request.headers.get("authorization"),
        body: text ? JSON.parse(text) : undefined,
      });
      return reply();
    }),
  );
  return calls;
}

const noContent = () => new HttpResponse(null, { status: 204 });

function loggedIn() {
  fakeRequest.cookies.set(SESSION_COOKIE, "session-token");
}

describe("calls as the user", () => {
  it("sends a visitor without a session to log in", async () => {
    expect(
      await redirectOf(() =>
        changePassword({}, form({ current_password: "a", new_password: "b" })),
      ),
    ).toBe("/login?next=%2Faccount");
  });

  it("sends a user whose session ended to log in", async () => {
    loggedIn();
    answer("post", "/v1/users/me/password", () =>
      HttpResponse.json(apiError("unauthenticated", "Log in."), {
        status: 401,
      }),
    );
    expect(
      await redirectOf(() =>
        changePassword({}, form({ current_password: "a", new_password: "b" })),
      ),
    ).toBe("/login?next=%2Faccount");
  });

  it("sends a user who must set up 2FA to do that", async () => {
    loggedIn();
    answer("post", "/v1/users/me/password", () =>
      HttpResponse.json(apiError("two_factor_setup_required", "Set up 2FA."), {
        status: 403,
      }),
    );
    expect(
      await redirectOf(() =>
        changePassword({}, form({ current_password: "a", new_password: "b" })),
      ),
    ).toBe("/account/two-factor");
  });
});

describe("changePassword", () => {
  it("sends both passwords with the session", async () => {
    loggedIn();
    const calls = answer("post", "/v1/users/me/password", noContent);

    const state = await changePassword(
      {},
      form({ current_password: "old pass", new_password: "new pass" }),
    );

    expect(state.done).toBe(true);
    expect(calls).toEqual([
      {
        auth: "Bearer session-token",
        body: { current_password: "old pass", new_password: "new pass" },
      },
    ]);
  });

  it("shows a wrong current password next to its field", async () => {
    loggedIn();
    answer("post", "/v1/users/me/password", () =>
      HttpResponse.json(
        apiError("validation_failed", "Check the form.", [
          {
            field: "current_password",
            code: "incorrect",
            message: "That password isn't right.",
          },
        ]),
        { status: 422 },
      ),
    );
    const state = await changePassword(
      {},
      form({ current_password: "x", new_password: "y" }),
    );
    expect(state.fieldErrors).toEqual({
      current_password: "That password isn't right.",
    });
  });
});

describe("requestEmailChange", () => {
  it("asks the Go API to email the new address", async () => {
    loggedIn();
    const calls = answer(
      "post",
      "/v1/email-changes",
      () => new HttpResponse(null, { status: 202 }),
    );
    const state = await requestEmailChange(
      {},
      form({ email: " new@example.com ", current_password: "pw" }),
    );
    expect(state.done).toBe(true);
    expect(state.message).toContain("new@example.com");
    expect(calls[0].body).toEqual({
      email: "new@example.com",
      current_password: "pw",
    });
  });
});

describe("2FA setup", () => {
  it("returns the secret and a QR code image for it", async () => {
    loggedIn();
    answer("post", "/v1/users/me/two-factor", () =>
      HttpResponse.json(
        {
          secret: "JBSWY3DPEHPK3PXP",
          otpauth_uri: "otpauth://totp/Example:a?secret=JBSWY3DPEHPK3PXP",
        },
        { status: 201 },
      ),
    );

    const state = await startTwoFactorSetup(
      {},
      form({ current_password: "pw" }),
    );

    expect(state.setup?.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(state.setup?.qrCode).toMatch(/^data:image\/png;base64,/);
  });

  it("returns the recovery codes once the code is confirmed", async () => {
    loggedIn();
    const calls = answer("post", "/v1/users/me/two-factor/confirm", () =>
      HttpResponse.json({ recovery_codes: ["AAAA-BBBB", "CCCC-DDDD"] }),
    );
    const state = await confirmTwoFactorSetup({}, form({ code: " 123456 " }));
    expect(state.recoveryCodes).toEqual(["AAAA-BBBB", "CCCC-DDDD"]);
    expect(calls[0].body).toEqual({ code: "123456" });
  });
});

describe("turnOffTwoFactor and regenerateRecoveryCodes", () => {
  it("need the password and a code", async () => {
    for (const action of [turnOffTwoFactor, regenerateRecoveryCodes]) {
      const state = await action({}, form({}));
      expect(Object.keys(state.fieldErrors ?? {})).toEqual([
        "current_password",
        "code",
      ]);
    }
  });

  it("turn 2FA off and refresh the page", async () => {
    loggedIn();
    const calls = answer("delete", "/v1/users/me/two-factor", noContent);
    const state = await turnOffTwoFactor(
      {},
      form({ current_password: "pw", code: "123456" }),
    );
    expect(state.done).toBe(true);
    expect(calls[0].body).toEqual({ current_password: "pw", code: "123456" });
    expect(refresh).toHaveBeenCalled();
  });

  it("show a refusal for users who must keep 2FA", async () => {
    loggedIn();
    answer("delete", "/v1/users/me/two-factor", () =>
      HttpResponse.json(
        apiError("two_factor_required", "It can't be turned off."),
        { status: 403 },
      ),
    );
    const state = await turnOffTwoFactor(
      {},
      form({ current_password: "pw", code: "123456" }),
    );
    expect(state.message).toBe("It can't be turned off.");
  });
});

describe("endSession", () => {
  const id = "01920000-0000-7000-8000-000000000009";

  it("ends the session by its ID", async () => {
    loggedIn();
    const calls = answer("delete", `/v1/sessions/${id}`, noContent);
    expect(await endSession({}, form({ id }))).toEqual({ done: true });
    expect(calls).toHaveLength(1);
  });

  it("refuses anything that isn't a session ID", async () => {
    loggedIn();
    const state = await endSession({}, form({ id: "../users/me" }));
    expect(state.message).toMatch(/wasn't found/);
  });
});

describe("logOutEverywhere", () => {
  it("ends every session, then clears this cookie", async () => {
    loggedIn();
    const calls = answer("delete", "/v1/sessions", noContent);
    expect(await redirectOf(() => logOutEverywhere({}))).toBe("/login");
    expect(calls).toHaveLength(1);
    expect(fakeRequest.setCookies.get(SESSION_COOKIE)?.options?.maxAge).toBe(0);
  });

  it("keeps the cookie if the sessions couldn't be ended", async () => {
    loggedIn();
    answer("delete", "/v1/sessions", () =>
      HttpResponse.json(apiError("internal_error", "Oops."), { status: 500 }),
    );
    const state = await logOutEverywhere({});
    expect(state.message).toBe("Oops.");
    expect(fakeRequest.setCookies.size).toBe(0);
  });
});
