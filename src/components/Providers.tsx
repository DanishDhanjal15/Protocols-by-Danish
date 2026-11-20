"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { LessonMeta } from "@/lib/catalog";
import { Lang, STRINGS, Strings } from "@/lib/i18n";
import { loadProgress, Progress, saveProgress, touchStreak } from "@/lib/progress";
import type { ContentLang } from "@/lib/text";
import { CommandPalette } from "./CommandPalette";

interface AppCtx {
  catalog: LessonMeta[];
  lang: Lang;
  setLang: (l: Lang) => void;
  t: Strings;
  progress: Progress;
  updateProgress: (fn: (p: Progress) => Progress) => void;
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
      return next;
    });
  }, []);

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
    () => ({ catalog, lang, setLang, t: STRINGS[lang], progress, updateProgress, paletteOpen, setPaletteOpen, layer, setLayer, contentLang, setContentLang }),
    [catalog, lang, setLang, progress, updateProgress, paletteOpen, layer, contentLang, setContentLang]
  );

  return (
    <Ctx.Provider value={value}>
      {children}
      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}
    </Ctx.Provider>
  );
}
