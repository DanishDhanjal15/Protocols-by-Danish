"use client";

import { useEffect, useState } from "react";
import { Logo } from "@/components/TopBar";

const ERRORS: Record<string, string> = {
  "not-configured": "Google sign-in isn't set up on this server yet.",
  cancelled: "Sign-in was cancelled. Try again when you're ready.",
  state: "That sign-in link expired. Please try again.",
  google: "Google couldn't complete the sign-in. Please try again.",
  email: "Your Google account needs a verified email address.",
  database: "We couldn't save your account right now. Please try again in a minute.",
};

function GoogleMark() {
  return (
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.4-.4-3.5z" />
      <path fill="#FF3D00" d="m6.3 14.7 6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.9 1.2 8 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
      <path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z" />
      <path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.4-.4-3.5z" />
    </svg>
  );
}

export function LoginCard() {
  const [next, setNext] = useState("/");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const sp = new URLSearchParams(window.location.search);
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setNext(sp.get("next") || "/");
    const e = sp.get("error");
    if (e) setError(ERRORS[e] ?? "Sign-in failed. Please try again.");
  }, []);

  return (
    <div className="w-full max-w-[400px] flex flex-col items-center text-center gap-6">
      <Logo size={56} />
      <div className="flex flex-col gap-2">
        <h1 className="text-[28px] font-bold leading-tight">Protocols by Danish</h1>
        <p className="text-[15px] text-ink-2">See the internet work, packet by packet. Sign in to keep your lessons, quiz scores and labs saved on every device.</p>
      </div>
      <div className="card w-full p-6 flex flex-col gap-4">
        <a
          href={`/api/auth/google?next=${encodeURIComponent(next)}`}
          className="inline-flex items-center justify-center gap-3 h-11 rounded-lg bg-white text-[#1f1f1f] font-medium text-[14.5px] hover:bg-[#f2f2f2] border border-[#dadce0]"
        >
          <GoogleMark /> Continue with Google
        </a>
        {error && <p className="text-[13.5px] rounded-lg p-3 bg-[var(--c-red-soft)] text-[var(--c-red)]">{error}</p>}
        <p className="text-[12.5px] text-muted">We only use your name, email and profile photo from Google to save your progress. No password is stored.</p>
      </div>
    </div>
  );
}
