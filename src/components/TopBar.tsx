"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { Linkedin, LogOut, Search } from "lucide-react";
import { useApp } from "./Providers";

export const LINKEDIN_URL = "https://www.linkedin.com/in/danish-dhanjal-758838373";

/** A "P" drawn as a tiny network: two hosts on the stem, a packet riding the loop. */
export function Logo({ size = 34 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <defs>
        <linearGradient id="pbd-logo" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#3fd39b" />
          <stop offset="1" stopColor="#1596a6" />
        </linearGradient>
      </defs>
      <rect width="32" height="32" rx="8" fill="url(#pbd-logo)" />
      <path d="M11 24.5V8h6a6 6 0 0 1 0 12h-6" fill="none" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="11" cy="24.5" r="2.7" fill="#fff" />
      <circle cx="11" cy="8" r="2.7" fill="#fff" />
      <circle cx="23" cy="14" r="2.6" fill="#0e1116" stroke="#fff" strokeWidth="1.8" />
    </svg>
  );
}

const NAV = [
  { href: "/", key: "home" as const },
  { href: "/learn", key: "learn" as const },
  { href: "/labs", key: "labs" as const },
  { href: "/compare", key: "compare" as const },
  { href: "/paths", key: "paths" as const },
  { href: "/tools", key: "tools" as const },
];

const isActive = (href: string, path: string) => (href === "/" ? path === "/" : path === href || path.startsWith(href + "/"));

export function TopBar() {
  const { t, lang, setLang, setPaletteOpen, catalog, progress, user } = useApp();
  const path = usePathname();
  if (path === "/login") return null;
  const done = progress.done.filter((d) => catalog.some((c) => c.id === d)).length;

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-[color-mix(in_srgb,var(--bg)_90%,transparent)] backdrop-blur" style={{ paddingTop: "env(safe-area-inset-top, 0px)" }}>
      <div className="flex items-center gap-3 lg:gap-6 h-[60px] px-[max(16px,env(safe-area-inset-left,0px))]">
        <Link href="/" className="flex items-center gap-2.5 shrink-0" aria-label="Protocols by Danish, home">
          <Logo />
          <span className="hidden sm:flex flex-col leading-none gap-1">
            <span className="display font-bold text-[17px] text-ink tracking-[-.01em]">Protocols</span>
            <span className="text-[11px] text-muted tracking-[.12em] uppercase">by Danish</span>
          </span>
        </Link>

        <nav className="hidden lg:flex items-center gap-1" aria-label="Main">
          {NAV.map((n) => {
            const active = isActive(n.href, path);
            return (
              <Link key={n.href} href={n.href}
                className={`px-3 h-8 inline-flex items-center rounded-lg text-[13.5px] font-medium whitespace-nowrap ${active ? "bg-panel-3 text-ink" : "text-muted hover:text-ink"}`}>
                {t[n.key]}
              </Link>
            );
          })}
        </nav>

        <div className="flex-1" />

        <button onClick={() => setPaletteOpen(true)} className="flex items-center gap-2 h-9 pl-3 pr-2 rounded-lg border border-line bg-panel text-muted hover:border-line-2 text-[13px] lg:w-60" aria-label={t.search}>
          <Search size={15} />
          <span className="hidden sm:inline flex-1 text-left truncate">{t.searchShort}</span>
          <span className="kbd hidden sm:inline">Ctrl K</span>
        </button>

        {done > 0 && (
          <Link href="/paths" className="hidden xl:inline-flex items-center gap-2 text-[12.5px] text-muted hover:text-ink whitespace-nowrap" title={t.progress}>
            <span className="mono tnum text-ink-2">{done}/{catalog.length}</span> done
          </Link>
        )}

        <a href={LINKEDIN_URL} target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-2 h-9 px-3 rounded-lg border border-line bg-panel hover:border-line-2 text-[13px] text-ink-2 hover:text-ink whitespace-nowrap shrink-0"
          title="Danish on LinkedIn">
          <Linkedin size={15} className="text-[#5b9bd5]" />
          <span className="hidden md:inline">Danish on LinkedIn</span>
        </a>

        {user && <UserMenu />}

        <button
          className="h-9 px-2.5 rounded-lg border border-line bg-panel text-[12.5px] font-semibold hover:border-line-2 whitespace-nowrap shrink-0"
          onClick={() => setLang(lang === "en" ? "hi" : "en")}
          aria-label={lang === "en" ? "हिन्दी में बदलें" : "Switch to English"}
          title={lang === "en" ? "हिन्दी" : "English"}
        >
          {lang === "en" ? "हिन्दी" : "English"}
        </button>
      </div>
      <nav className="lg:hidden flex gap-1 px-4 pb-2 overflow-x-auto" aria-label="Main">
        {NAV.map((n) => (
          <Link key={n.href} href={n.href} className={`px-3 h-8 inline-flex items-center rounded-lg text-[13px] font-medium shrink-0 ${isActive(n.href, path) ? "bg-panel-3 text-ink" : "text-muted"}`}>
            {t[n.key]}
          </Link>
        ))}
      </nav>
    </header>
  );
}

function UserMenu() {
  const { user, flushProgress } = useApp();
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open]);
  if (!user) return null;
  const initial = (user.name || user.email).slice(0, 1).toUpperCase();
  return (
    <div ref={box} className="relative shrink-0">
      <button onClick={() => setOpen((o) => !o)} className="w-9 h-9 rounded-full overflow-hidden border border-line-2 grid place-items-center bg-panel-3 text-[13px] font-semibold" aria-label="Account" aria-expanded={open}>
        {user.avatar_url ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={user.avatar_url} alt="" width={36} height={36} referrerPolicy="no-referrer" className="w-full h-full object-cover" />
        ) : initial}
      </button>
      {open && (
        <div className="absolute right-0 top-11 w-64 card p-3 flex flex-col gap-2 z-50 fade-up" role="menu">
          <div className="min-w-0">
            <div className="text-[14px] font-semibold truncate">{user.name || "Signed in"}</div>
            <div className="text-[12.5px] text-muted truncate">{user.email}</div>
          </div>
          <p className="text-[12px] text-muted">Your progress is saved to this account.</p>
          <form action="/api/auth/logout" method="post" onSubmit={() => { flushProgress(); try { localStorage.removeItem("pbd:progress:v1"); } catch {} }}>
            <button className="btn w-full justify-center" role="menuitem"><LogOut size={15} /> Sign out</button>
          </form>
        </div>
      )}
    </div>
  );
}
