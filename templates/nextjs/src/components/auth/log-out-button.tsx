"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useActionState } from "react";

import { FormMessage } from "@/components/auth/field";
import { Button } from "@/components/ui/button";
import { logOut } from "@/lib/auth/actions";
import type { FormState } from "@/lib/auth/form-state";

export function LogOutButton() {
  const [state, action, pending] = useActionState<FormState>(logOut, {});
  return (
    <form action={action} className="grid gap-2">
      <Button type="submit" variant="outline" disabled={pending}>
        Log out
      </Button>
      <FormMessage message={state.message} />
    </form>
  );
}
