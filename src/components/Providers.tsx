"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { LessonMeta } from "@/lib/catalog";
import { Lang, STRINGS, Strings } from "@/lib/i18n";
import { loadProgress, mergeProgress, Progress, saveProgress, touchStreak } from "@/lib/progress";
import type { ContentLang } from "@/lib/text";
import { CommandPalette } from "./CommandPalette";

export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  avatar_url: string | null;
}

interface AppCtx {
  user: SessionUser | null;
  catalog: LessonMeta[];
  lang: Lang;
  setLang: (l: Lang) => void;
  t: Strings;
  progress: Progress;
  updateProgress: (fn: (p: Progress) => Progress) => void;
  /** Send any progress save that is still waiting (call before signing out). */
  flushProgress: () => void;
  paletteOpen: boolean;
  layer: number;
  contentLang: ContentLang;
  setContentLang: (l: ContentLang) => void;
  setLayer: (n: number) => void;
  setPaletteOpen: (v: boolean) => void;
}

const Ctx = createContext<AppCtx | null>(null);

export function useApp() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useApp outside Providers");
  return c;
}

export function Providers({ catalog, children }: { catalog: LessonMeta[]; children: React.ReactNode }) {
  const [lang, setLangState] = useState<Lang>("en");
  const [progress, setProgress] = useState<Progress>({ done: [], quiz: {}, streak: { day: "", count: 0 } });
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [layer, setLayer] = useState(0);
  const [user, setUser] = useState<SessionUser | null>(null);
  const userRef = useRef<SessionUser | null>(null);
  const pushTimer = useRef<number>(0);
  const pending = useRef<Progress | null>(null);

  // save the whole progress object to the account, debounced
  const send = useCallback(() => {
    window.clearTimeout(pushTimer.current);
    const p = pending.current;
    pending.current = null;
    if (p) fetch("/api/progress", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(p), keepalive: true }).catch(() => {});
  }, []);
  const push = useCallback((p: Progress) => {
    if (!userRef.current) return;
    pending.current = p;
    window.clearTimeout(pushTimer.current);
    pushTimer.current = window.setTimeout(send, 1500);
  }, [send]);
  const flushProgress = send;

  // don't lose a waiting save when the tab is hidden or closed
  useEffect(() => {
    const onHide = () => { if (document.visibilityState === "hidden") send(); };
    document.addEventListener("visibilitychange", onHide);
    return () => document.removeEventListener("visibilitychange", onHide);
  }, [send]);

  // signed in? then merge the account's progress with this browser's and keep them in sync
  useEffect(() => {
    let live = true;
    fetch("/api/me", { cache: "no-store" })
      .then((r) => r.json())
      .then((j: { user: SessionUser | null; progress: Partial<Progress> | null }) => {
        if (!live || !j.user) return;
        userRef.current = j.user;
        setUser(j.user);
        setProgress((local) => {
          const merged = mergeProgress(local, j.progress);
          saveProgress(merged);
          push(merged);
          return merged;
        });
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [push]);
  const [contentLang, setContentLangState] = useState<ContentLang>("en");

  useEffect(() => {
    // read browser-only state after hydration
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setProgress(loadProgress());
    try {
      const l = localStorage.getItem("pbd:lang");
      if (l === "hi" || l === "en") setLangState(l);
      const c = localStorage.getItem("pbd:content-lang");
      if (c === "en" || c === "hinglish") setContentLangState(c);
    } catch {}
  }, []);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  const setLang = useCallback((l: Lang) => {
    setLangState(l);
    try {
      localStorage.setItem("pbd:lang", l);
    } catch {}
  }, []);

  const setContentLang = useCallback((l: ContentLang) => {
    setContentLangState(l);
    try {
      localStorage.setItem("pbd:content-lang", l);
    } catch {}
  }, []);

  const updateProgress = useCallback((fn: (p: Progress) => Progress) => {
    setProgress((p) => {
      const next = touchStreak(fn(p));
      saveProgress(next);
      push(next);
      return next;
    });
  }, [push]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const value = useMemo(
    () => ({ user, catalog, lang, setLang, t: STRINGS[lang], progress, updateProgress, flushProgress, paletteOpen, setPaletteOpen, layer, setLayer, contentLang, setContentLang }),
    [user, catalog, lang, setLang, progress, updateProgress, flushProgress, paletteOpen, layer, contentLang, setContentLang]
  );

  return (
    <Ctx.Provider value={value}>
      {children}
      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </Ctx.Provider>
  );
}
