"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState } from "react";

import { Field, FormMessage } from "@/components/auth/field";
import { Button } from "@/components/ui/button";
import {
  changePassword,
  endSession,
  logOutEverywhere,
  requestEmailChange,
} from "@/lib/auth/account-actions";
import type { FormState } from "@/lib/auth/form-state";

export function ChangePasswordForm() {
  const [state, action, pending] = useActionState<FormState, FormData>(
    changePassword,
    {},
  );
  return (
    <form action={action} className="grid gap-4">
      <Field
        name="current_password"
        label="Current password"
        type="password"
        autoComplete="current-password"
        required
        error={state.fieldErrors?.current_password}
      />
      <Field
        name="new_password"
        label="New password"
        type="password"
        autoComplete="new-password"
        required
        error={state.fieldErrors?.new_password}
      />
      {state.done ? (
        <p role="status">{state.message}</p>
      ) : (
        <FormMessage message={state.message} />
      )}
      <Button type="submit" disabled={pending}>
        Change password
      </Button>
    </form>
  );
}

export function ChangeEmailForm() {
  const [state, action, pending] = useActionState<FormState, FormData>(
    requestEmailChange,
    {},
  );
  if (state.done) {
    return <p role="status">{state.message}</p>;
  }
  return (
    <form action={action} className="grid gap-4">
      <Field
        name="email"
        label="New email"
        type="email"
        autoComplete="email"
        required
        defaultValue={state.values?.email}
        error={state.fieldErrors?.email}
      />
      <Field
        name="current_password"
        label="Current password"
        type="password"
        autoComplete="current-password"
        required
        error={state.fieldErrors?.current_password}
      />
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending}>
        Change email
      </Button>
    </form>
  );
}

export function EndSessionButton({ id }: { id: string }) {
  const [state, action, pending] = useActionState<FormState, FormData>(
    endSession,
    {},
  );
  return (
    <form action={action}>
      <input type="hidden" name="id" value={id} />
      <Button type="submit" variant="outline" disabled={pending}>
        Log out
      </Button>
      <FormMessage message={state.message} />
    </form>
  );
}

export function LogOutEverywhereButton() {
  const [state, action, pending] = useActionState<FormState>(
    logOutEverywhere,
    {},
  );
  return (
    <form action={action} className="grid gap-2">
      <Button type="submit" variant="outline" disabled={pending}>
        Log out everywhere
      </Button>
      <FormMessage message={state.message} />
    </form>
  );
}
