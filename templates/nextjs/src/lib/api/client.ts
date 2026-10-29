// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import "server-only";

import { isIP } from "node:net";
import { headers } from "next/headers";
import { z } from "zod";

import { env } from "@/lib/env";

const fieldErrorSchema = z.object({
  field: z.string(),
  code: z.string(),
  message: z.string(),
});

const errorSchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
    request_id: z.string().optional(),
    details: z.array(fieldErrorSchema).nullish(),
  }),
});

export type FieldError = z.infer<typeof fieldErrorSchema>;

// ApiError is an error response from the Go API. Its message is written for
// users, so it's safe to show.
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details: FieldError[],
    // Seconds to wait, from Retry-After on 429 responses.
    readonly retryAfter: number | null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type Method = "GET" | "POST" | "PATCH" | "DELETE";

export type CallOptions = {
  method?: Method;
  body?: unknown;
  // The session token, for calls made as the user.
  token?: string;
};

// callApi calls the Go API and checks the response against schema. It
// throws ApiError for error responses.
export async function callApi<S extends z.ZodType>(
  path: string,
  schema: S,
  options: CallOptions = {},
): Promise<z.infer<S>> {
  const res = await send(path, options);
  return schema.parse(await res.json());
}

// callApiNoContent is callApi for endpoints that answer 204.
export async function callApiNoContent(
  path: string,
  options: CallOptions = {},
): Promise<void> {
  await send(path, options);
}

async function send(path: string, options: CallOptions): Promise<Response> {
  const h: Record<string, string> = {
    Accept: "application/json",
    ...(await forwardedHeaders()),
  };
  if (options.body !== undefined) {
    h["Content-Type"] = "application/json";
  }
  if (options.token) {
    h["Authorization"] = `Bearer ${options.token}`;
  }
  const res = await fetch(new URL(path, env().API_URL), {
    method: options.method ?? "GET",
    headers: h,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    cache: "no-store",
  });
  if (!res.ok) {
    throw await toApiError(res);
  }
  return res;
}

async function toApiError(res: Response): Promise<ApiError> {
  const parsed = errorSchema.safeParse(await res.json().catch(() => null));
  if (!parsed.success) {
    return new ApiError(
      res.status,
      "unexpected_response",
      "Something went wrong. Please try again.",
      [],
      null,
    );
  }
  const { code, message, details } = parsed.data.error;
  const retry = Number(res.headers.get("Retry-After"));
  return new ApiError(
    res.status,
    code,
    message,
    details ?? [],
    Number.isFinite(retry) && retry > 0 ? retry : null,
  );
}

// forwardedHeaders passes on the browser's IP and user agent. Without them,
// the Go API's rate limits would count this server as a single client, and
// every login would look like it came from the same device. The Go API
// only believes them from Config.TrustedProxies.
export async function forwardedHeaders(): Promise<Record<string, string>> {
  const incoming = await headers();
  const out: Record<string, string> = {};
  const ip = incoming.get(env().CLIENT_IP_HEADER)?.trim();
  if (ip && isIP(ip)) {
    out["X-Forwarded-For"] = ip;
  }
  const ua = incoming.get("user-agent");
  if (ua) {
    out["X-Forwarded-User-Agent"] = ua;
  }
  return out;
}
