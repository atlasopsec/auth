"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState } from "react";

import { Field, FormMessage } from "@/components/auth/field";
import { Button } from "@/components/ui/button";
import { signUp } from "@/lib/auth/actions";
import type { FormState } from "@/lib/auth/form-state";

export function SignUpForm() {
  const [state, action, pending] = useActionState<FormState, FormData>(
    signUp,
    {},
  );
  return (
    <form action={action} className="grid gap-4">
      <Field
        name="email"
        label="Email"
        type="email"
        autoComplete="email"
        required
        defaultValue={state.values?.email}
        error={state.fieldErrors?.email}
      />
      <Field
        name="password"
        label="Password"
        type="password"
        autoComplete="new-password"
        required
        error={state.fieldErrors?.password}
      />
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending}>
        Sign up
      </Button>
    </form>
  );
}
