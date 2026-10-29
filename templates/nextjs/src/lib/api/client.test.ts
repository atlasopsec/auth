import { HttpResponse, http } from "msw/http";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { ApiError, callApi, callApiNoContent } from "@/lib/api/client";
import { API, apiError, apiServer } from "@/test/api";
import { fakeRequest } from "@/test/next";

describe("callApi", () => {
  it("sends the token, the browser's IP and user agent, and the body", async () => {
    let seen: Request | undefined;
    let body: unknown;
    apiServer.use(
      http.post(`${API}/v1/things`, async ({ request }) => {
        seen = request;
        body = await request.json();
        return HttpResponse.json({ ok: true }, { status: 201 });
      }),
    );
    fakeRequest.headers.set("x-real-ip", "203.0.113.7");
    fakeRequest.headers.set("user-agent", "Firefox/140");

    const got = await callApi("/v1/things", z.object({ ok: z.boolean() }), {
      method: "POST",
      body: { name: "a" },
      token: "tok",
    });

    expect(got).toEqual({ ok: true });
    expect(body).toEqual({ name: "a" });
    expect(seen?.headers.get("authorization")).toBe("Bearer tok");
    expect(seen?.headers.get("x-forwarded-for")).toBe("203.0.113.7");
    expect(seen?.headers.get("x-forwarded-user-agent")).toBe("Firefox/140");
  });

  it("doesn't forward an IP header that isn't an IP", async () => {
    let seen: Request | undefined;
    apiServer.use(
      http.get(`${API}/v1/things`, ({ request }) => {
        seen = request;
        return HttpResponse.json({});
      }),
    );
    fakeRequest.headers.set("x-real-ip", "203.0.113.7, 10.0.0.1");

    await callApi("/v1/things", z.object({}));

    expect(seen?.headers.has("x-forwarded-for")).toBe(false);
    expect(seen?.headers.has("authorization")).toBe(false);
  });

  it("throws the API's error, with its fields and Retry-After", async () => {
    apiServer.use(
      http.post(`${API}/v1/sessions`, () =>
        HttpResponse.json(
          apiError("rate_limited", "Too many requests.", [
            { field: "email", code: "required", message: "Enter it." },
          ]),
          { status: 429, headers: { "Retry-After": "30" } },
        ),
      ),
    );

    const err = await callApiNoContent("/v1/sessions", {
      method: "POST",
    }).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({
      status: 429,
      code: "rate_limited",
      message: "Too many requests.",
      retryAfter: 30,
      details: [{ field: "email", code: "required", message: "Enter it." }],
    });
  });

  it("doesn't show an unexpected error body to users", async () => {
    apiServer.use(
      http.get(`${API}/v1/things`, () =>
        HttpResponse.text("panic: secret internals", { status: 502 }),
      ),
    );

    const err = await callApi("/v1/things", z.object({})).catch(
      (e: unknown) => e,
    );

    expect(err).toMatchObject({
      status: 502,
      code: "unexpected_response",
      message: "Something went wrong. Please try again.",
    });
  });

  it("rejects a response that doesn't match the schema", async () => {
    apiServer.use(
      http.get(`${API}/v1/things`, () => HttpResponse.json({ ok: "yes" })),
    );

    await expect(
      callApi("/v1/things", z.object({ ok: z.boolean() })),
    ).rejects.toThrow();
  });
});
