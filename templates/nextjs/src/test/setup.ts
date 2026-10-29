import "@testing-library/jest-dom/vitest";

import { cleanup } from "@testing-library/react";
import { afterAll, afterEach, beforeAll, beforeEach, vi } from "vitest";

import { apiServer } from "@/test/api";
import { resetFakeRequest } from "@/test/next";

vi.mock("next/headers", () => import("@/test/next"));
vi.mock("next/navigation", () => import("@/test/next"));

beforeAll(() => apiServer.listen({ onUnhandledFrame: "error" }));
beforeEach(() => resetFakeRequest());
afterEach(() => {
  apiServer.resetHandlers();
  cleanup();
});
afterAll(() => apiServer.close());
