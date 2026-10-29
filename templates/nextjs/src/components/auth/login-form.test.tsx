// @vitest-environment jsdom
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { LoginForm } from "@/components/auth/login-form";
import { logIn } from "@/lib/auth/actions";

vi.mock("@/lib/auth/actions", () => ({ logIn: vi.fn() }));

async function submit() {
  await userEvent.type(screen.getByLabelText("Email"), "ada@example.com");
  await userEvent.type(screen.getByLabelText("Password"), "a fake passphrase");
  await userEvent.click(screen.getByRole("button", { name: "Log in" }));
}

describe("LoginForm", () => {
  it("sends what was typed, and next", async () => {
    vi.mocked(logIn).mockResolvedValue({});
    render(<LoginForm next="/account" />);

    await userEvent.type(screen.getByLabelText("Email"), "ada@example.com");
    await userEvent.type(
      screen.getByLabelText("Password"),
      "a fake passphrase",
    );
    await userEvent.click(screen.getByRole("button", { name: "Log in" }));

    const sent = vi.mocked(logIn).mock.calls[0][1];
    expect(Object.fromEntries(sent)).toEqual({
      next: "/account",
      email: "ada@example.com",
      password: "a fake passphrase",
    });
  });

  it("shows field errors on their fields, and keeps the email", async () => {
    vi.mocked(logIn).mockResolvedValue({
      fieldErrors: { password: "Enter your password." },
      values: { email: "ada@example.com" },
    });
    render(<LoginForm />);

    await submit();

    const password = screen.getByLabelText("Password");
    await waitFor(() =>
      expect(password).toHaveAttribute("aria-invalid", "true"),
    );
    expect(password).toHaveAccessibleDescription("Enter your password.");
    expect(screen.getByLabelText("Email")).toHaveValue("ada@example.com");
    expect(screen.getByLabelText("Email")).not.toHaveAttribute("aria-invalid");
  });

  it("shows a message for the whole form", async () => {
    vi.mocked(logIn).mockResolvedValue({
      message: "The email or password is incorrect.",
    });
    render(<LoginForm />);

    await submit();

    await waitFor(() =>
      expect(screen.getByRole("alert")).toHaveTextContent(
        "The email or password is incorrect.",
      ),
    );
  });
});
