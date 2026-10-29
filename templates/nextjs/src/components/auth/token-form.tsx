"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState, type ReactNode } from "react";

import { FormMessage } from "@/components/auth/field";
import {
  INCOMPLETE_LINK,
  useFragmentToken,
} from "@/components/auth/use-fragment-token";
import { Button } from "@/components/ui/button";
import type { FormState } from "@/lib/auth/form-state";

type TokenFormProps = {
  action: (prev: FormState, formData: FormData) => Promise<FormState>;
  submit: string;
  // The form's own fields, given the state to show their errors.
  children?: (state: FormState) => ReactNode;
};

// TokenForm is a form for an email link's page: it sends the token from the
// link's fragment with the form's fields.
export function TokenForm({ action, submit, children }: TokenFormProps) {
  const token = useFragmentToken();
  const [state, formAction, pending] = useActionState<FormState, FormData>(
    action,
    {},
  );
  if (token === null) {
    return <FormMessage message={INCOMPLETE_LINK} />;
  }
  return (
    <form action={formAction} className="grid gap-4">
      <input type="hidden" name="token" value={token ?? ""} />
      {children?.(state)}
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending || token === undefined}>
        {submit}
      </Button>
    </form>
  );
}
