"use client";

// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { useEffect, useState } from "react";

// FragmentToken is the token from the link: unknown until the page runs in
// the browser, then the token or null if the link had none.
export type FragmentToken = string | null | undefined;

// useFragmentToken reads the token from an email link's #token=..., which
// browsers never send to the server, and then removes it from the address
// bar so it isn't left in history or shared by accident.
export function useFragmentToken(): FragmentToken {
  const [token, setToken] = useState<FragmentToken>(undefined);
  useEffect(() => {
    const params = new URLSearchParams(window.location.hash.slice(1));
    const found = params.get("token");
    if (found) {
      const { pathname, search } = window.location;
      window.history.replaceState(window.history.state, "", pathname + search);
    }
    // eslint-disable-next-line react-hooks/set-state-in-effect -- the fragment only exists in the browser, after the first render
    setToken(found || null);
  }, []);
  return token;
}

export const INCOMPLETE_LINK =
  "This link is incomplete. Copy the whole link from the email and try again.";
