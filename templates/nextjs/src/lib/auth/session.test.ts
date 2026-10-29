import { HttpResponse, http } from "msw/http";
import { describe, expect, it } from "vitest";

import { SESSION_COOKIE } from "@/lib/auth/cookies";
import { getSession, requireSession } from "@/lib/auth/session";
import { API, apiError, apiServer } from "@/test/api";
import { testMe } from "@/test/fixtures";
import { fakeRequest, redirectOf } from "@/test/next";

function meAnswers(status: number) {
  apiServer.use(
    http.get(`${API}/v1/users/me`, ({ request }) => {
      if (request.headers.get("authorization") !== "Bearer good-token") {
        return HttpResponse.json(apiError("unauthenticated", "Log in."), {
          status: 401,
        });
      }
      return status === 200
        ? HttpResponse.json(testMe)
        : HttpResponse.json(apiError("internal_error", "Oops."), { status });
    }),
  );
}

describe("getSession", () => {
  it("returns the user the Go API says the cookie belongs to", async () => {
    meAnswers(200);
    fakeRequest.cookies.set(SESSION_COOKIE, "good-token");
    expect(await getSession()).toEqual(testMe);
  });

  it("returns null without a cookie, without asking the API", async () => {
    expect(await getSession()).toBeNull();
  });

  it("returns null for a session that has ended", async () => {
    meAnswers(200);
    fakeRequest.cookies.set(SESSION_COOKIE, "ended-token");
    expect(await getSession()).toBeNull();
  });

  it("fails, rather than logging out, when the API has a problem", async () => {
    meAnswers(500);
    fakeRequest.cookies.set(SESSION_COOKIE, "good-token");
    await expect(getSession()).rejects.toThrow();
  });
});

describe("requireSession", () => {
  it("returns the session", async () => {
    meAnswers(200);
    fakeRequest.cookies.set(SESSION_COOKIE, "good-token");
    expect(await requireSession("/dashboard")).toEqual(testMe);
  });

  it("sends a visitor whose cookie doesn't work to log in", async () => {
    meAnswers(200);
    fakeRequest.cookies.set(SESSION_COOKIE, "made-up-token");
    expect(await redirectOf(() => requireSession("/dashboard?x=1"))).toBe(
      "/login?next=%2Fdashboard%3Fx%3D1",
    );
  });
});

describe("requireSession for users who must set up 2FA", () => {
  function meIs(me: object) {
    apiServer.use(http.get(`${API}/v1/users/me`, () => HttpResponse.json(me)));
    fakeRequest.cookies.set(SESSION_COOKIE, "good-token");
  }

  it("sends them to set it up", async () => {
    meIs({ ...testMe, two_factor_required: true, two_factor_enabled: false });
    expect(await redirectOf(() => requireSession("/dashboard"))).toBe(
      "/account/two-factor",
    );
  });

  it("lets them see the setup page", async () => {
    const me = {
      ...testMe,
      two_factor_required: true,
      two_factor_enabled: false,
    };
    meIs(me);
    expect(
      await requireSession("/account/two-factor", {
        duringTwoFactorSetup: true,
      }),
    ).toEqual(me);
  });

  it("lets them in once it's set up", async () => {
    const me = {
      ...testMe,
      two_factor_required: true,
      two_factor_enabled: true,
    };
    meIs(me);
    expect(await requireSession("/dashboard")).toEqual(me);
  });
});
