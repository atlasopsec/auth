"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState } from "react";

import { Field, FormMessage } from "@/components/auth/field";
import { Button } from "@/components/ui/button";
import { verifyTwoFactor } from "@/lib/auth/actions";
import type { FormState } from "@/lib/auth/form-state";

export function TwoFactorForm({ next }: { next?: string }) {
  const [state, action, pending] = useActionState<FormState, FormData>(
    verifyTwoFactor,
    {},
  );
  return (
    <form action={action} className="grid gap-4">
      {next && <input type="hidden" name="next" value={next} />}
      <Field
        name="code"
        label="Code from your authenticator app, or a recovery code"
        autoComplete="one-time-code"
        required
        error={state.fieldErrors?.code}
      />
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending}>
        Continue
      </Button>
    </form>
  );
}
