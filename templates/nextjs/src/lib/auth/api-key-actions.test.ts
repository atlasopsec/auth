import { refresh } from "next/cache";
import { HttpResponse, http } from "msw/http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createApiKey, revokeApiKey } from "@/lib/auth/account-actions";
import { SESSION_COOKIE } from "@/lib/auth/cookies";
import { API, apiError, apiServer } from "@/test/api";
import { fakeRequest, redirectOf } from "@/test/next";

const NOW = Date.parse("2026-11-23T12:00:00Z");

function form(fields: Record<string, string | string[]>): FormData {
  const f = new FormData();
  for (const [k, v] of Object.entries(fields)) {
    for (const one of Array.isArray(v) ? v : [v]) {
      f.append(k, one);
    }
  }
  return f;
}

// answer makes the fake Go API answer one call, and records what was sent.
function answer(
  method: "post" | "delete",
  path: string,
  reply: () => Response,
) {
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

const created = {
  id: "01920000-0000-7000-8000-000000000001",
  name: "Nightly sync",
  hint: "q3V9xk",
  permissions: ["reports:read"],
  created_at: "2026-11-23T12:00:00Z",
  expires_at: "2027-02-21T12:00:00Z",
  last_used_at: null,
  last_used_ip: null,
  key: "example_q3V9xkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};

const valid = {
  name: "Nightly sync",
  permissions: "reports:read",
  lifetime: "90",
  current_password: "pw",
};

beforeEach(() => {
  vi.spyOn(Date, "now").mockReturnValue(NOW);
  fakeRequest.cookies.set(SESSION_COOKIE, "session-token");
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("createApiKey", () => {
  it("sends the key's details and the password, and shows the key once", async () => {
    const calls = answer("post", "/v1/api-keys", () =>
      HttpResponse.json(created, { status: 201 }),
    );
    const state = await createApiKey({}, form(valid));
    expect(state).toEqual({ done: true, apiKey: created.key });
    expect(calls[0].auth).toBe("Bearer session-token");
    expect(calls[0].body).toEqual({
      name: "Nightly sync",
      permissions: ["reports:read"],
      expires_at: "2027-02-21T12:00:00.000Z",
      current_password: "pw",
    });
    expect(refresh).toHaveBeenCalled();
  });

  it("sends a 2FA code, several permissions, and the lifetime chosen", async () => {
    const calls = answer("post", "/v1/api-keys", () =>
      HttpResponse.json(created, { status: 201 }),
    );
    await createApiKey(
      {},
      form({
        ...valid,
        permissions: ["reports:read", "reports:export"],
        lifetime: "30",
        code: " 123456 ",
      }),
    );
    expect(calls[0].body).toMatchObject({
      permissions: ["reports:read", "reports:export"],
      expires_at: "2026-12-23T12:00:00.000Z",
      code: "123456",
    });
  });

  it("uses 90 days for a lifetime it doesn't offer", async () => {
    const calls = answer("post", "/v1/api-keys", () =>
      HttpResponse.json(created, { status: 201 }),
    );
    await createApiKey({}, form({ ...valid, lifetime: "3650" }));
    expect(calls[0].body).toMatchObject({
      expires_at: "2027-02-21T12:00:00.000Z",
    });
  });

  it("checks the form before calling the Go API, keeping the name", async () => {
    const calls = answer("post", "/v1/api-keys", () =>
      HttpResponse.json(created, { status: 201 }),
    );
    const state = await createApiKey({}, form({ name: "Nightly sync" }));
    expect(Object.keys(state.fieldErrors ?? {}).sort()).toEqual([
      "current_password",
      "permissions",
    ]);
    expect(state.values).toEqual({ name: "Nightly sync" });
    expect(state.apiKey).toBeUndefined();
    expect(calls).toHaveLength(0);

    const blank = await createApiKey({}, form({ ...valid, name: "  " }));
    expect(Object.keys(blank.fieldErrors ?? {})).toEqual(["name"]);
  });

  it("shows the Go API's refusal next to its field, never with a key", async () => {
    answer("post", "/v1/api-keys", () =>
      HttpResponse.json(
        apiError("validation_failed", "Some fields are invalid.", [
          {
            field: "permissions",
            code: "invalid",
            message:
              "Choose at least one permission you have that keys may carry.",
          },
        ]),
        { status: 422 },
      ),
    );
    const state = await createApiKey({}, form(valid));
    expect(state.fieldErrors?.permissions).toMatch(/keys may carry/);
    expect(state.apiKey).toBeUndefined();
    expect(state.values).toEqual({ name: "Nightly sync" });
  });

  it("sends a user whose session ended to log in, and back here", async () => {
    answer("post", "/v1/api-keys", () =>
      HttpResponse.json(apiError("unauthenticated", "Log in."), {
        status: 401,
      }),
    );
    expect(await redirectOf(() => createApiKey({}, form(valid)))).toBe(
      "/login?next=%2Faccount%2Fapi-keys",
    );
  });
});

describe("revokeApiKey", () => {
  const id = "01920000-0000-7000-8000-000000000001";

  it("revokes the key by its ID and refreshes the list", async () => {
    const calls = answer(
      "delete",
      `/v1/api-keys/${id}`,
      () => new HttpResponse(null, { status: 204 }),
    );
    expect(await revokeApiKey({}, form({ id }))).toEqual({ done: true });
    expect(calls).toHaveLength(1);
    expect(refresh).toHaveBeenCalled();
  });

  it("refuses anything that isn't a key ID", async () => {
    const state = await revokeApiKey({}, form({ id: "../sessions" }));
    expect(state.message).toMatch(/wasn't found/);
  });
});
