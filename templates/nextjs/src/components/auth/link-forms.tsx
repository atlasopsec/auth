"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState } from "react";

import { Field, FormMessage } from "@/components/auth/field";
import { TokenForm } from "@/components/auth/token-form";
import { Button } from "@/components/ui/button";
import type { FormState } from "@/lib/auth/form-state";
import {
  confirmEmailChange,
  requestPasswordReset,
  resendVerification,
  resetPassword,
  verifyEmail,
} from "@/lib/auth/link-actions";

export function VerifyEmailForm() {
  return (
    <TokenForm action={verifyEmail} submit="Confirm and log in">
      {(state) => (
        <Field
          name="password"
          label="Password"
          type="password"
          autoComplete="current-password"
          required
          error={state.fieldErrors?.password}
        />
      )}
    </TokenForm>
  );
}

export function ResetPasswordForm() {
  return (
    <TokenForm action={resetPassword} submit="Set new password">
      {(state) => (
        <>
          <Field
            name="password"
            label="New password"
            type="password"
            autoComplete="new-password"
            required
            error={state.fieldErrors?.password}
          />
          <Field
            name="code"
            label="Two-factor code (if you've turned it on)"
            autoComplete="one-time-code"
            error={state.fieldErrors?.code}
          />
        </>
      )}
    </TokenForm>
  );
}

export function ConfirmEmailChangeForm() {
  return <TokenForm action={confirmEmailChange} submit="Confirm new email" />;
}

// EmailRequestForm asks for an address and says the email is on its way,
// whether or not the address has an account.
function EmailRequestForm({
  action,
  submit,
  sent,
}: {
  action: (prev: FormState, formData: FormData) => Promise<FormState>;
  submit: string;
  sent: string;
}) {
  const [state, formAction, pending] = useActionState<FormState, FormData>(
    action,
    {},
  );
  if (state.done) {
    return <p role="status">{sent}</p>;
  }
  return (
    <form action={formAction} className="grid gap-4">
      <Field
        name="email"
        label="Email"
        type="email"
        autoComplete="email"
        required
        defaultValue={state.values?.email}
        error={state.fieldErrors?.email}
      />
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending}>
        {submit}
      </Button>
    </form>
  );
}

export function ForgotPasswordForm() {
  return (
    <EmailRequestForm
      action={requestPasswordReset}
      submit="Send reset link"
      sent="If an account uses that address, we've sent it a link to reset the password."
    />
  );
}

export function ResendVerificationForm() {
  return (
    <EmailRequestForm
      action={resendVerification}
      submit="Send a new link"
      sent="If that address needs verifying, we've sent it a new link."
    />
  );
}
