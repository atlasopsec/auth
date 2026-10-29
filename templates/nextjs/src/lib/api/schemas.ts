// From the auth module's Next.js template (github.com/atlasopsec/auth, templates/nextjs), version 0.1.0.
import { z } from "zod";

export const userSchema = z.object({
  id: z.string(),
  email: z.string(),
  email_verified: z.boolean(),
  created_at: z.string(),
});

export type User = z.infer<typeof userSchema>;

// A new session, from logging in, signing up, or finishing 2FA.
export const loginSchema = z.object({
  user: userSchema,
  token: z.string(),
  expires_at: z.string(),
  absolute_expires_at: z.string(),
});

export type Login = z.infer<typeof loginSchema>;

// The answer to a login when the user has 2FA.
export const challengeSchema = z.object({
  two_factor_required: z.literal(true),
  challenge_token: z.string(),
  expires_at: z.string(),
});

export type Challenge = z.infer<typeof challengeSchema>;

export const loginOrChallengeSchema = z.union([loginSchema, challengeSchema]);

// The answer to signing up when the email must be verified first.
export const verificationRequiredSchema = z.object({
  verification_required: z.literal(true),
});

export const signUpSchema = z.union([loginSchema, verificationRequiredSchema]);

// GET /v1/users/me.
export const meSchema = userSchema.extend({
  two_factor_enabled: z.boolean(),
  two_factor_required: z.boolean(),
});

export type Me = z.infer<typeof meSchema>;
