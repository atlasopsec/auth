// @vitest-environment jsdom
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TokenForm } from "@/components/auth/token-form";

describe("TokenForm", () => {
  beforeEach(() => {
    window.history.replaceState(
      null,
      "",
      "/reset-password?x=1#token=link-token",
    );
  });

  it("sends the token from the link, and removes it from the address bar", async () => {
    const action = vi.fn().mockResolvedValue({});
    render(<TokenForm action={action} submit="Go" />);

    await waitFor(() => expect(window.location.hash).toBe(""));
    expect(window.location.pathname + window.location.search).toBe(
      "/reset-password?x=1",
    );
    await userEvent.click(screen.getByRole("button", { name: "Go" }));

    expect(Object.fromEntries(action.mock.calls[0][1])).toEqual({
      token: "link-token",
    });
  });

  it("says so when the link has no token", async () => {
    window.history.replaceState(null, "", "/reset-password");
    render(<TokenForm action={vi.fn()} submit="Go" />);

    expect(await screen.findByRole("alert")).toHaveTextContent(
      /link is incomplete/,
    );
    expect(screen.queryByRole("button")).toBeNull();
  });
});
