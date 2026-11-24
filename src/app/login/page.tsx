import type { Metadata } from "next";
import { LoginCard } from "./LoginCard";

export const metadata: Metadata = {
  title: "Sign in",
  description: "Sign in with Google to save your progress across devices.",
};

export default function LoginPage() {
  return (
    <main className="flex-1 grid place-items-center px-[max(16px,env(safe-area-inset-left,0px))] py-10">
      <LoginCard />
    </main>
  );
}
