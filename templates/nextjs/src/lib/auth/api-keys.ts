// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.6.0.

// API_KEY_PERMISSIONS are what the API keys page offers: the permissions
// in the Go API's Config.APIKeyPermissions, with a label for each. Edit
// them to match. The Go API checks every one again, and refuses any the
// user's role doesn't have.
export const API_KEY_PERMISSIONS: { value: string; label: string }[] = [
  { value: "reports:read", label: "Read reports" },
];

// API_KEY_LIFETIMES are the choices for how long a new key lasts, in days.
// The Go API allows a year at most.
export const API_KEY_LIFETIMES = [30, 90, 180, 365] as const;

export const DEFAULT_API_KEY_LIFETIME = 90;
