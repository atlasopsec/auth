"use server";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { z } from "zod";

import { ApiError, callApi, callApiNoContent } from "@/lib/api/client";
import {
  loginOrChallengeSchema,
  loginSchema,
  signUpSchema,
  type Login,
} from "@/lib/api/schemas";
import {
  SESSION_COOKIE,
  TWO_FACTOR_COOKIE,
  clearedCookie,
  cookieOptions,
} from "@/lib/auth/cookies";
import {
  SOMETHING_WENT_WRONG,
  stateFromError,
  type FormState,
} from "@/lib/auth/form-state";
import { DEFAULT_AFTER_LOGIN, safeNext } from "@/lib/auth/safe-next";
import { getSessionToken } from "@/lib/auth/session";

// Every action here re-checks its input: anyone can post anything to a
// server action, whatever the form looks like.

const credentialsSchema = z.object({
  email: z.string().trim().min(1, "Enter your email address."),
  password: z.string().min(1, "Enter your password."),
});

const twoFactorSchema = z.object({
  code: z.string().trim().min(1, "Enter the code from your authenticator app."),
});

function fieldErrors(error: z.ZodError): Record<string, string> {
  const out: Record<string, string> = {};
  for (const issue of error.issues) {
    const field = String(issue.path[0] ?? "");
    out[field] ??= issue.message;
  }
  return out;
}

async function startSession(login: Login): Promise<void> {
  (await cookies()).set(
    SESSION_COOKIE,
    login.token,
    // Until the latest the session can last: it's extended each time it's
    // used, and the Go API ends it sooner if it sits unused.
    cookieOptions(login.absolute_expires_at),
  );
}

export async function logIn(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const values = { email: String(formData.get("email") ?? "") };
  const parsed = credentialsSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error), values };
  }
  const next = safeNext(formData.get("next"));

  let result;
  try {
    result = await callApi("/v1/sessions", loginOrChallengeSchema, {
      method: "POST",
      body: { ...parsed.data, client: "web" },
    });
  } catch (e) {
    return stateFromError(e, values);
  }

  if ("two_factor_required" in result) {
    (await cookies()).set(
      TWO_FACTOR_COOKIE,
      result.challenge_token,
      cookieOptions(result.expires_at),
    );
    const query = next ? `?next=${encodeURIComponent(next)}` : "";
    redirect(`/login/two-factor${query}`);
  }
  await startSession(result);
  redirect(next ?? DEFAULT_AFTER_LOGIN);
}

export async function verifyTwoFactor(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = twoFactorSchema.safeParse({ code: formData.get("code") });
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error) };
  }
  const store = await cookies();
  const challenge = store.get(TWO_FACTOR_COOKIE)?.value;
  if (!challenge) {
    return {
      message: "This login has expired. Log in with your password again.",
    };
  }

  let login;
  try {
    login = await callApi("/v1/two-factor-challenges/verify", loginSchema, {
      method: "POST",
      body: { challenge_token: challenge, code: parsed.data.code },
    });
  } catch (e) {
    if (e instanceof ApiError && e.code === "two_factor_challenge_invalid") {
      store.set(TWO_FACTOR_COOKIE, "", clearedCookie);
    }
    if (e instanceof ApiError && e.code === "invalid_two_factor_code") {
      return { fieldErrors: { code: e.message } };
    }
    return stateFromError(e);
  }

  store.set(TWO_FACTOR_COOKIE, "", clearedCookie);
  await startSession(login);
  redirect(safeNext(formData.get("next")) ?? DEFAULT_AFTER_LOGIN);
}

export async function signUp(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const values = { email: String(formData.get("email") ?? "") };
  const parsed = credentialsSchema.safeParse({
    email: formData.get("email"),
    password: formData.get("password"),
  });
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error), values };
  }

  let result;
  try {
    result = await callApi("/v1/users", signUpSchema, {
      method: "POST",
      body: { ...parsed.data, client: "web" },
    });
  } catch (e) {
    return stateFromError(e, values);
  }

  if ("verification_required" in result) {
    redirect("/sign-up/check-email");
  }
  await startSession(result);
  redirect(DEFAULT_AFTER_LOGIN);
}

// logOut ends the session in the Go API, then clears the cookie. The auth
// standard says clearing only the cookie isn't enough, so if the API can't
// be reached the cookie stays and the user is asked to try again.
export async function logOut(_prev: FormState): Promise<FormState> {
  const store = await cookies();
  const token = await getSessionToken();
  if (token) {
    try {
      await callApiNoContent("/v1/sessions/current", {
        method: "DELETE",
        token,
      });
    } catch (e) {
      // 401: the session had already ended.
      if (!(e instanceof ApiError && e.status === 401)) {
        console.error(e);
        return { message: SOMETHING_WENT_WRONG };
      }
    }
  }
  store.set(SESSION_COOKIE, "", clearedCookie);
  redirect("/login");
}
