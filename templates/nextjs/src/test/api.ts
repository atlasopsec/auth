import { setupServer } from "msw/node";

// The fake Go API. Tests add handlers with apiServer.use(...).
export const apiServer = setupServer();

export const API = "http://api.test";

// apiError is a Go API error response.
export function apiError(
  code: string,
  message: string,
  details: { field: string; code: string; message: string }[] = [],
) {
  return { error: { code, message, request_id: "req-1", details } };
}
