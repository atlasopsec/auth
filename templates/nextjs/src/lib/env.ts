// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import "server-only";

import { z } from "zod";

const envSchema = z.object({
  // The Go API's private address, e.g. http://api.railway.internal:8080.
  API_URL: z.url(),
  // The header the hosting edge puts the browser's IP in. Railway's edge
  // sets X-Real-IP.
  CLIENT_IP_HEADER: z
    .string()
    .regex(/^[A-Za-z0-9-]+$/)
    .default("x-real-ip")
    .transform((h) => h.toLowerCase()),
});

export type Env = z.infer<typeof envSchema>;

let parsed: Env | undefined;

// env returns the settings, checked on first use. instrumentation.ts calls
// it when the server starts, so a missing variable stops the deploy instead
// of failing requests. It isn't read at build time, so a Docker build
// doesn't need the runtime settings.
export function env(): Env {
  parsed ??= envSchema.parse(process.env);
  return parsed;
}
