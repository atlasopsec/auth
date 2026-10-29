"use server";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { cookies } from "next/headers";
import { refresh } from "next/cache";
import { redirect } from "next/navigation";
import QRCode from "qrcode";
import { z } from "zod";

import { ApiError, callApi, callApiNoContent } from "@/lib/api/client";
import { recoveryCodesSchema, twoFactorSetupSchema } from "@/lib/api/schemas";
import { SESSION_COOKIE, clearedCookie } from "@/lib/auth/cookies";
import { stateFromError, type FormState } from "@/lib/auth/form-state";
import { fieldErrors } from "@/lib/auth/login";
import { loginPath } from "@/lib/auth/safe-next";
import { TWO_FACTOR_SETUP_PATH, getSessionToken } from "@/lib/auth/session";

// Server actions for /account. The Go API checks the session and the
// current password on every one of them; these only pass them on.

type Outcome<T> = { data: T } | { state: FormState };

// asUser calls the Go API as the logged-in user. A session that has ended
// goes to the login page, and a user who must set up 2FA goes to do that.
// Any other error becomes the form's state.
async function asUser<T>(
  path: string,
  call: (token: string) => Promise<T>,
  values?: Record<string, string>,
): Promise<Outcome<T>> {
  const token = await getSessionToken();
  if (!token) {
    redirect(loginPath(path));
  }
  let goTo: string;
  try {
    return { data: await call(token) };
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      goTo = loginPath(path);
    } else if (
      e instanceof ApiError &&
      e.code === "two_factor_setup_required"
    ) {
      goTo = TWO_FACTOR_SETUP_PATH;
    } else {
      return { state: stateFromError(e, values) };
    }
  }
  // Outside the catch: redirect works by throwing.
  redirect(goTo);
}

const currentPassword = z.string().min(1, "Enter your current password.");
const code = z
  .string()
  .trim()
  .min(1, "Enter a code from your authenticator app.");

function read(formData: FormData, ...names: string[]) {
  return Object.fromEntries(names.map((n) => [n, formData.get(n) ?? ""]));
}

export async function changePassword(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = z
    .object({
      current_password: currentPassword,
      new_password: z.string().min(1, "Enter a new password."),
    })
    .safeParse(read(formData, "current_password", "new_password"));
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error) };
  }
  const out = await asUser("/account", (token) =>
    callApiNoContent("/v1/users/me/password", {
      method: "POST",
      body: parsed.data,
      token,
    }),
  );
  if ("state" in out) {
    return out.state;
  }
  return {
    done: true,
    message: "Password changed. Your other sessions were logged out.",
  };
}

export async function requestEmailChange(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const values = { email: String(formData.get("email") ?? "") };
  const parsed = z
    .object({
      email: z.string().trim().min(1, "Enter your new email address."),
      current_password: currentPassword,
    })
    .safeParse(read(formData, "email", "current_password"));
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error), values };
  }
  const out = await asUser(
    "/account",
    (token) =>
      callApiNoContent("/v1/email-changes", {
        method: "POST",
        body: parsed.data,
        token,
      }),
    values,
  );
  if ("state" in out) {
    return out.state;
  }
  return {
    done: true,
    message: `We've sent a link to ${parsed.data.email}. Open it to finish changing your email.`,
  };
}

export async function startTwoFactorSetup(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = z
    .object({ current_password: currentPassword })
    .safeParse(read(formData, "current_password"));
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error) };
  }
  const out = await asUser(TWO_FACTOR_SETUP_PATH, (token) =>
    callApi("/v1/users/me/two-factor", twoFactorSetupSchema, {
      method: "POST",
      body: parsed.data,
      token,
    }),
  );
  if ("state" in out) {
    return out.state;
  }
  // An image the page shows with <img>, never as markup.
  const qrCode = await QRCode.toDataURL(out.data.otpauth_uri, { margin: 1 });
  return { setup: { secret: out.data.secret, qrCode } };
}

export async function confirmTwoFactorSetup(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = z.object({ code }).safeParse(read(formData, "code"));
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error) };
  }
  const out = await asUser(TWO_FACTOR_SETUP_PATH, (token) =>
    callApi("/v1/users/me/two-factor/confirm", recoveryCodesSchema, {
      method: "POST",
      body: parsed.data,
      token,
    }),
  );
  if ("state" in out) {
    return out.state;
  }
  return { done: true, recoveryCodes: out.data.recovery_codes };
}

const passwordAndCode = z.object({ current_password: currentPassword, code });

export async function turnOffTwoFactor(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = passwordAndCode.safeParse(
    read(formData, "current_password", "code"),
  );
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error) };
  }
  const out = await asUser(TWO_FACTOR_SETUP_PATH, (token) =>
    callApiNoContent("/v1/users/me/two-factor", {
      method: "DELETE",
      body: parsed.data,
      token,
    }),
  );
  if ("state" in out) {
    return out.state;
  }
  refresh();
  return { done: true, message: "Two-factor authentication is off." };
}

export async function regenerateRecoveryCodes(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = passwordAndCode.safeParse(
    read(formData, "current_password", "code"),
  );
  if (!parsed.success) {
    return { fieldErrors: fieldErrors(parsed.error) };
  }
  const out = await asUser(TWO_FACTOR_SETUP_PATH, (token) =>
    callApi("/v1/users/me/two-factor/recovery-codes", recoveryCodesSchema, {
      method: "POST",
      body: parsed.data,
      token,
    }),
  );
  if ("state" in out) {
    return out.state;
  }
  return { done: true, recoveryCodes: out.data.recovery_codes };
}

// endSession logs out one of the user's other sessions.
export async function endSession(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const id = z.uuid().safeParse(formData.get("id"));
  if (!id.success) {
    return { message: "That session wasn't found." };
  }
  const out = await asUser("/account", (token) =>
    callApiNoContent(`/v1/sessions/${id.data}`, { method: "DELETE", token }),
  );
  if ("state" in out) {
    return out.state;
  }
  refresh();
  return { done: true };
}

// logOutEverywhere ends every session, this one included.
export async function logOutEverywhere(_prev: FormState): Promise<FormState> {
  const out = await asUser("/account", (token) =>
    callApiNoContent("/v1/sessions", { method: "DELETE", token }),
  );
  if ("state" in out) {
    return out.state;
  }
  (await cookies()).set(SESSION_COOKIE, "", clearedCookie);
  redirect("/login");
}
