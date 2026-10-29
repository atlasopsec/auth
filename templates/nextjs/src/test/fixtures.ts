// Go API responses for tests. Values are obviously fake.

export const testUser = {
  id: "01920000-0000-7000-8000-000000000001",
  email: "ada@example.com",
  email_verified: true,
  created_at: "2026-01-01T12:00:00Z",
};

export const testMe = {
  ...testUser,
  two_factor_enabled: false,
  two_factor_required: false,
};

// A login that ends in half an hour if unused, and an hour from now at the
// latest.
export function testLogin(token = "session-token") {
  const at = (minutes: number) =>
    new Date(Date.now() + minutes * 60 * 1000).toISOString();
  return {
    user: testUser,
    token,
    expires_at: at(30),
    absolute_expires_at: at(60),
  };
}
