"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState, useEffect } from "react";

import { FormMessage } from "@/components/auth/field";
import { useFragmentToken } from "@/components/auth/use-fragment-token";
import { Button } from "@/components/ui/button";
import type { FormState } from "@/lib/auth/form-state";
import { acceptInvitation, holdInvitation } from "@/lib/auth/link-actions";

// HoldInvitation moves the token from the link into a cookie, so it
// survives logging in or signing up. It renders nothing.
export function HoldInvitation() {
  const token = useFragmentToken();
  useEffect(() => {
    if (token) {
      void holdInvitation(token);
    }
  }, [token]);
  return null;
}

export function AcceptInvitationForm() {
  const [state, action, pending] = useActionState<FormState>(
    acceptInvitation,
    {},
  );
  if (state.done) {
    return <p role="status">{state.message}</p>;
  }
  return (
    <form action={action} className="grid gap-4">
      <FormMessage message={state.message} />
      <Button type="submit" disabled={pending}>
        Join the organization
      </Button>
    </form>
  );
}
