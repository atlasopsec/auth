"use server";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { z } from "zod";

import { ApiError, callApi, callApiNoContent } from "@/lib/api/client";
import { loginOrChallengeSchema } from "@/lib/api/schemas";
import {
  INVITATION_COOKIE,
  SESSION_COOKIE,
  clearedCookie,
} from "@/lib/auth/cookies";
import { stateFromError, type FormState } from "@/lib/auth/form-state";
import { afterLogin, fieldErrors, finishLogin } from "@/lib/auth/login";
import type { Notice } from "@/lib/auth/notices";
import { getSessionToken } from "@/lib/auth/session";

// Server actions for the pages that email links open. The token comes from
// the link's fragment, which the page reads in the browser and sends in a
// hidden field; it never appears in a URL the server sees.

const MISSING_TOKEN =
  "This link is incomplete. Copy the whole link from the email and try again.";

const tokenSchema = z.string().min(1, MISSING_TOKEN);
const emailSchema = z.string().trim().min(1, "Enter your email address.");

function loginPathWith(notice: Notice): string {
  return `/login?notice=${notice}`;
}

// verifyEmail confirms the address and logs in. The Go API asks for the
// password too, so a forwarded or leaked link alone can't log anyone in.
export async function verifyEmail(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = z
    .object({
      token: tokenSchema,
      password: z.string().min(1, "Enter your password."),
    })
    .safeParse({
      token: formData.get("token"),
      password: formData.get("password"),
    });
  if (!parsed.success) {
    const errors = fieldErrors(parsed.error);
    return errors.token ? { message: errors.token } : { fieldErrors: errors };
  }

  let result;
  try {
    result = await callApi(
      "/v1/email-verifications/confirm",
      loginOrChallengeSchema,
      { method: "POST", body: { ...parsed.data, client: "web" } },
    );
  } catch (e) {
    return stateFromError(e);
  }
  return finishLogin(result, await afterLogin());
}

// resendVerification sends a new verification link. The Go API answers the
// same whether or not the address has an account.
export async function resendVerification(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = emailSchema.safeParse(formData.get("email"));
  if (!parsed.success) {
    return { fieldErrors: { email: parsed.error.issues[0].message } };
  }
  try {
    await callApiNoContent("/v1/email-verifications", {
      method: "POST",
      body: { email: parsed.data },
    });
  } catch (e) {
    return stateFromError(e, { email: parsed.data });
  }
  return { done: true };
}

// requestPasswordReset emails a reset link. The Go API answers the same
// whether or not the address has an account, so this page can't be used to
// find out.
export async function requestPasswordReset(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = emailSchema.safeParse(formData.get("email"));
  if (!parsed.success) {
    return { fieldErrors: { email: parsed.error.issues[0].message } };
  }
  try {
    await callApiNoContent("/v1/password-resets", {
      method: "POST",
      body: { email: parsed.data },
    });
  } catch (e) {
    return stateFromError(e, { email: parsed.data });
  }
  return { done: true };
}

// resetPassword sets a new password from a reset link. Users with 2FA also
// enter a code. It ends every session, so the cookie is cleared too.
export async function resetPassword(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = z
    .object({
      token: tokenSchema,
      password: z.string().min(1, "Enter a new password."),
      code: z.string().trim(),
    })
    .safeParse({
      token: formData.get("token"),
      password: formData.get("password"),
      code: formData.get("code") ?? "",
    });
  if (!parsed.success) {
    const errors = fieldErrors(parsed.error);
    return errors.token ? { message: errors.token } : { fieldErrors: errors };
  }
  try {
    await callApiNoContent("/v1/password-resets/confirm", {
      method: "POST",
      body: parsed.data,
    });
  } catch (e) {
    if (e instanceof ApiError && e.code === "invalid_two_factor_code") {
      return { fieldErrors: { code: e.message } };
    }
    return stateFromError(e);
  }
  (await cookies()).set(SESSION_COOKIE, "", clearedCookie);
  redirect(loginPathWith("password-reset"));
}

// confirmEmailChange switches the account to its new address. It ends every
// session, so the cookie is cleared too.
export async function confirmEmailChange(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = tokenSchema.safeParse(formData.get("token"));
  if (!parsed.success) {
    return { message: MISSING_TOKEN };
  }
  try {
    await callApiNoContent("/v1/email-changes/confirm", {
      method: "POST",
      body: { token: parsed.data },
    });
  } catch (e) {
    return stateFromError(e);
  }
  (await cookies()).set(SESSION_COOKIE, "", clearedCookie);
  redirect(loginPathWith("email-changed"));
}

// An invitation is held for a day while the user logs in or signs up. The
// invitation itself lasts a week, and the Go API checks it when accepted.
const INVITATION_HOLD_SECONDS = 24 * 60 * 60;

// holdInvitation keeps an invitation's token in a cookie, so it survives
// logging in or signing up, and takes it out of the address bar.
export async function holdInvitation(token: string): Promise<void> {
  const parsed = tokenSchema.max(512).safeParse(token);
  if (parsed.success) {
    (await cookies()).set(INVITATION_COOKIE, parsed.data, {
      ...clearedCookie,
      maxAge: INVITATION_HOLD_SECONDS,
    });
  }
  redirect("/accept-invitation");
}

const acceptedSchema = z.object({ id: z.string(), name: z.string() });

// acceptInvitation joins the organization. The Go API checks that the
// invitation was sent to this user's address.
export async function acceptInvitation(_prev: FormState): Promise<FormState> {
  const store = await cookies();
  const token = store.get(INVITATION_COOKIE)?.value;
  if (!token) {
    return { message: "Open the invitation link from your email again." };
  }
  const session = await getSessionToken();
  if (!session) {
    redirect("/login?next=%2Faccept-invitation");
  }
  let org;
  try {
    org = await callApi("/v1/invitations/accept", acceptedSchema, {
      method: "POST",
      body: { token },
      token: session,
    });
  } catch (e) {
    // A used or expired invitation, or one already accepted, is no use
    // any more. A mismatched one is kept, so the user can log in with the
    // invited address instead.
    if (
      e instanceof ApiError &&
      (e.code === "token_invalid_or_expired" || e.code === "already_member")
    ) {
      store.set(INVITATION_COOKIE, "", clearedCookie);
    }
    return stateFromError(e);
  }
  store.set(INVITATION_COOKIE, "", clearedCookie);
  return { done: true, message: `You've joined ${org.name}.` };
}
