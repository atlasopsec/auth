import type { Metadata } from "next";

import "./globals.css";

// Every page is rendered per request, so its scripts carry that
// response's Content Security Policy nonce (see src/proxy.ts).
export const dynamic = "force-dynamic";

export const metadata: Metadata = {
  title: "Example",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="flex min-h-full flex-col">{children}</body>
    </html>
  );
}
