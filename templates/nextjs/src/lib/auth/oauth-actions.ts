"use server";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { cookies } from "next/headers";
import { refresh } from "next/cache";
import { redirect } from "next/navigation";
import { z } from "zod";

import { callApi, callApiNoContent } from "@/lib/api/client";
import { clearedCookie } from "@/lib/auth/cookies";
import { stateFromError, type FormState } from "@/lib/auth/form-state";
import { fieldErrors } from "@/lib/auth/login";
import {
  OAUTH_COOKIE,
  encodeFlow,
  enabledProviders,
  newVerifier,
  providerSchema,
  type Flow,
} from "@/lib/auth/oauth";
import { loginPath, safeNext } from "@/lib/auth/safe-next";
import { getSessionToken } from "@/lib/auth/session";

const startedSchema = z.object({
  authorization_url: z.url(),
  expires_at: z.string(),
});

// startFlow keeps the verifier in a cookie that lasts as long as the flow,
// then sends the browser to the provider.
async function startFlow(
  path: string,
  body: Record<string, string>,
  flow: Omit<Flow, "verifier">,
  token?: string,
): Promise<FormState> {
  const { verifier, challenge } = newVerifier();
  let started;
  try {
    started = await callApi(path, startedSchema, {
      method: "POST",
      body: { ...body, client: "web", client_challenge: challenge },
      token,
    });
  } catch (e) {
    return stateFromError(e);
  }
  const seconds = Math.floor(
    (new Date(started.expires_at).getTime() - Date.now()) / 1000,
  );
  (await cookies()).set(OAUTH_COOKIE, encodeFlow({ ...flow, verifier }), {
    ...clearedCookie,
    maxAge: Math.max(seconds, 0),
  });
  redirect(started.authorization_url);
}

function parseProvider(value: FormDataEntryValue | null) {
  const parsed = providerSchema.safeParse(value);
  return parsed.success && enabledProviders().includes(parsed.data)
    ? parsed.data
    : null;
}

// startOAuthLogin signs in, or signs up, with a provider.
export async function startOAuthLogin(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const provider = parseProvider(formData.get("provider"));
  if (!provider) {
    return { message: "That sign-in option isn't available." };
  }
  return startFlow(
    "/v1/oauth-flows",
    { provider },
    { purpose: "login", next: safeNext(formData.get("next")) },
  );
}

// startOAuthLink adds a provider to the logged-in user's account. The Go
// API asks for the current password, since it adds a way in.
export async function startOAuthLink(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const provider = parseProvider(formData.get("provider"));
  if (!provider) {
    return { message: "That sign-in option isn't available." };
  }
  const token = await getSessionToken();
  if (!token) {
    redirect(loginPath("/account"));
  }
  return startFlow(
    "/v1/users/me/oauth-accounts",
    {
      provider,
      current_password: String(formData.get("current_password") ?? ""),
    },
    { purpose: "link", next: null },
    token,
  );
}

// unlinkOAuth removes a provider from the account.
export async function unlinkOAuth(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = z
    .object({
      id: z.uuid("That account wasn't found."),
      // Empty for accounts without a password, which the Go API allows.
      current_password: z.string(),
    })
    .safeParse({
      id: formData.get("id"),
      current_password: formData.get("current_password") ?? "",
    });
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error) };
  }
  const token = await getSessionToken();
  if (!token) {
    redirect(loginPath("/account"));
  }
  try {
    await callApiNoContent(`/v1/users/me/oauth-accounts/${parsed.data.id}`, {
      method: "DELETE",
      body: { current_password: parsed.data.current_password },
      token,
    });
  } catch (e) {
    return stateFromError(e);
  }
  refresh();
  return { done: true };
}
