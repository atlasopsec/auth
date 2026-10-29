// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import "server-only";

import { createHash, randomBytes } from "node:crypto";
import { z } from "zod";

import { env } from "@/lib/env";

export const PROVIDER_NAMES = { google: "Google", github: "GitHub" } as const;

export type Provider = keyof typeof PROVIDER_NAMES;

export const providerSchema = z.enum(["google", "github"]);

// enabledProviders are the providers whose buttons to show.
export function enabledProviders(): Provider[] {
  return env().OAUTH_PROVIDERS;
}

// Holds a sign-in in progress between leaving for the provider and coming
// back: the client verifier, which only this browser has, and what to do
// afterwards.
export const OAUTH_COOKIE = "__Host-oauth";

const flowSchema = z.object({
  verifier: z.string().min(43),
  purpose: z.enum(["login", "link"]),
  next: z.string().nullable(),
});

export type Flow = z.infer<typeof flowSchema>;

export function encodeFlow(flow: Flow): string {
  return Buffer.from(JSON.stringify(flow)).toString("base64url");
}

export function decodeFlow(value: string | undefined): Flow | null {
  if (!value) {
    return null;
  }
  try {
    const parsed = flowSchema.safeParse(
      JSON.parse(Buffer.from(value, "base64url").toString()),
    );
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

// newVerifier returns a random client verifier and the challenge sent to
// the Go API for it (§9 of the module's api.md). The verifier never leaves
// this server and the browser's HttpOnly cookie.
export function newVerifier(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: challengeOf(verifier) };
}

export function challengeOf(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}
