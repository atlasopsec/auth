import Link from "next/link";

export default function Home() {
  return (
    <main className="mx-auto grid w-full max-w-sm gap-4 px-4 py-16">
      <h1 className="text-2xl font-semibold">Example</h1>
      <nav className="flex gap-4 text-sm underline">
        <Link href="/login">Log in</Link>
        <Link href="/sign-up">Sign up</Link>
        <Link href="/dashboard">Dashboard</Link>
      </nav>
    </main>
  );
}
