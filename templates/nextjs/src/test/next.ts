// Hand-written stand-ins for the parts of Next.js that only work inside a
// request: cookies(), headers(), and redirect(). setup.ts swaps them in.

export type SetCookie = {
  value: string;
  options?: Record<string, unknown>;
};

// The fake request and response, reset before each test.
export const fakeRequest = {
  // Cookies the browser sent.
  cookies: new Map<string, string>(),
  // Headers the browser sent.
  headers: new Headers(),
  // Cookies the response sets.
  setCookies: new Map<string, SetCookie>(),
};

export function resetFakeRequest() {
  fakeRequest.cookies.clear();
  fakeRequest.headers = new Headers();
  fakeRequest.setCookies.clear();
}

export async function cookies() {
  return {
    get(name: string) {
      const value = fakeRequest.cookies.get(name);
      return value === undefined ? undefined : { name, value };
    },
    has(name: string) {
      return fakeRequest.cookies.has(name);
    },
    set(name: string, value: string, options?: Record<string, unknown>) {
      fakeRequest.setCookies.set(name, { value, options });
    },
  };
}

export async function headers() {
  return fakeRequest.headers;
}

// RedirectError is what redirect() throws, like Next.js's own.
export class RedirectError extends Error {
  constructor(readonly url: string) {
    super(`redirect to ${url}`);
  }
}

export function redirect(url: string): never {
  throw new RedirectError(url);
}

// redirectOf runs fn and returns where it redirected to.
export async function redirectOf(fn: () => Promise<unknown>): Promise<string> {
  try {
    await fn();
  } catch (e) {
    if (e instanceof RedirectError) {
      return e.url;
    }
    throw e;
  }
  throw new Error("expected a redirect");
}
