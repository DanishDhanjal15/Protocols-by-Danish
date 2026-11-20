"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { ArrowLeft, ArrowRight, Check, Lightbulb, Play, Ticket, X } from "lucide-react";
import type { Lesson } from "@/lib/lesson";
import type { Lab, T } from "@/lib/labs";
import { LABS } from "@/lib/labs";
import { expandLesson } from "@/lib/catalog";
import { useApp } from "./Providers";
import { groupsOf } from "./player/usePlayer";
import { CaptureTable, Inspector } from "./player/Packets";

const LEVEL = ["", "Easy", "Medium", "Hard"];

export function LabView({ lab, lesson: compact }: { lab: Lab; lesson: Lesson }) {
  const { contentLang, setContentLang, updateProgress, progress } = useApp();
  const L = (x: T) => (contentLang === "hinglish" ? x.hinglish : x.en);
  const lesson = useMemo(() => expandLesson(compact), [compact]);
  const scenario = lesson.scenarios.find((s) => s.id === lab.scenario) ?? lesson.scenarios[0];

  const captured = useMemo(() => {
    let no = 1;
    return scenario.steps.flatMap((st, i) => {
      const g = groupsOf(st.events, i, no).flatMap((x) => x.packets);
      no += g.length;
      return g;
    });
  }, [scenario]);

  const [sel, setSel] = useState<string>(captured[0]?.key ?? "");
  const [pick, setPick] = useState<number | null>(null);
  const [hints, setHints] = useState(0);
  const selected = captured.find((c) => c.key === sel);
  const solved = progress.done.includes(`lab:${lab.id}`);
  const idx = LABS.findIndex((l) => l.id === lab.id);
  const next = LABS[idx + 1];

  const move = (d: number) => {
    const i = captured.findIndex((c) => c.key === sel);
    const n = captured[Math.max(0, Math.min(captured.length - 1, i + d))];
    if (n) setSel(n.key);
  };

  const answer = (i: number) => {
    if (pick !== null) return;
    setPick(i);
    if (i === lab.answer) updateProgress((p) => (p.done.includes(`lab:${lab.id}`) ? p : { ...p, done: [...p.done, `lab:${lab.id}`] }));
  };

  return (
    <main className="max-w-[1500px] w-full mx-auto px-[max(16px,env(safe-area-inset-left,0px))] py-6 flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <Link href="/labs" className="inline-flex items-center gap-1.5 text-[13.5px] text-muted hover:text-ink"><ArrowLeft size={15} /> {contentLang === "hinglish" ? "Saare labs" : "All labs"}</Link>
        <span className="flex-1" />
        <div className="flex p-0.5 rounded-lg bg-panel-2" role="tablist" aria-label="Language">
          {(["en", "hinglish"] as const).map((l) => (
            <button key={l} role="tab" aria-selected={contentLang === l} onClick={() => setContentLang(l)}
              className={`h-8 px-3 rounded-md text-[12.5px] font-semibold ${contentLang === l ? "bg-panel-3 text-ink" : "text-muted hover:text-ink"}`}>
              {l === "en" ? "English" : "Hinglish"}
            </button>
          ))}
        </div>
      </div>

      {/* the ticket */}
      <section className="card p-5 flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Ticket size={18} className="text-[var(--c-amber)]" />
          <span className="eyebrow">Lab {idx + 1} · {LEVEL[lab.level]} · {lesson.name}</span>
          {solved && <span className="chip" style={{ background: "var(--c-green-soft)", color: "var(--c-green)" }}><Check size={12} /> {contentLang === "hinglish" ? "Solve kiya" : "Solved"}</span>}
        </div>
        <h1 className="text-[26px] font-bold leading-tight">{L(lab.title)}</h1>
        <p className="text-[15px] text-ink-2 leading-relaxed max-w-3xl">{L(lab.symptom)}</p>
        <p className="text-[13px] text-muted">
          {contentLang === "hinglish"
            ? "Neeche us waqt ka packet capture hai. Packets kholo, fields padho, aur batao gadbad kahan hai."
            : "Below is the packet capture from when it happened. Open packets, read the fields, and diagnose the problem."}
        </p>
      </section>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_420px] items-start">
        {/* evidence */}
        <section className="card overflow-hidden flex flex-col min-w-0">
          <div className="px-4 py-2.5 border-b border-line flex items-center gap-2">
            <span className="hud-title">{contentLang === "hinglish" ? "Evidence: packet capture" : "Evidence: packet capture"}</span>
            <span className="mono text-[11.5px] text-muted">{captured.length} packets</span>
          </div>
          <div className="h-[280px]">
            <CaptureTable rows={captured} selected={sel} onSelect={setSel} />
          </div>
          <div className="border-t border-line max-h-[520px] overflow-y-auto">
            <Inspector cap={selected} onPrev={() => move(-1)} onNext={() => move(1)} />
          </div>
        </section>

        {/* diagnosis */}
        <section className="card p-5 flex flex-col gap-3 xl:sticky xl:top-[76px]">
          <span className="eyebrow">{contentLang === "hinglish" ? "Diagnosis" : "Your diagnosis"}</span>
          <h2 className="text-[18px] font-bold">{L(lab.question)}</h2>
          <div className="flex flex-col gap-2">
            {lab.options.map((o, i) => {
              const done = pick !== null;
              const right = done && i === lab.answer;
              const wrong = done && i === pick && i !== lab.answer;
              return (
                <button key={i} disabled={done} onClick={() => answer(i)}
                  className={`text-left px-3 py-2.5 rounded-lg border text-[14px] flex items-start gap-2 ${right ? "border-[var(--c-green)] bg-[var(--c-green-soft)]" : wrong ? "border-[var(--c-red)] bg-[var(--c-red-soft)]" : "border-line bg-panel-2 hover:border-line-2"}`}>
                  <span className="mono text-[12px] text-muted w-4 pt-0.5">{String.fromCharCode(65 + i)}</span>
                  <span className="flex-1">{L(o)}</span>
                  {right && <Check size={16} className="mt-0.5" style={{ color: "var(--c-green)" }} />}
                  {wrong && <X size={16} className="mt-0.5" style={{ color: "var(--c-red)" }} />}
                </button>
              );
            })}
          </div>

          {pick === null && (
            <div className="flex flex-col gap-2">
              {lab.hints.slice(0, hints).map((h, i) => (
                <p key={i} className="text-[13.5px] rounded-lg p-3 bg-[var(--c-amber-soft)] text-ink-2 fade-up"><Lightbulb size={14} className="inline mr-1.5 text-[var(--c-amber)]" />{L(h)}</p>
              ))}
              {hints < lab.hints.length && (
                <button className="btn self-start" onClick={() => setHints((h) => h + 1)}><Lightbulb size={15} /> {contentLang === "hinglish" ? `Hint lo (${hints + 1}/${lab.hints.length})` : `Show a hint (${hints + 1}/${lab.hints.length})`}</button>
              )}
            </div>
          )}

          {pick !== null && (
            <div className="flex flex-col gap-3 fade-up">
              <p className="text-[14px] font-semibold" style={{ color: pick === lab.answer ? "var(--c-green)" : "var(--c-red)" }}>
                {pick === lab.answer ? (contentLang === "hinglish" ? "Sahi pakda!" : "Correct diagnosis!") : (contentLang === "hinglish" ? "Yeh nahi tha." : "Not quite.")}
              </p>
              <p className="text-[14px] leading-relaxed text-ink-2">{L(lab.explain)}</p>
              <div className="flex flex-wrap gap-2">
                <Link className="btn" href={`/learn/${lab.lesson}?s=${lab.scenario}`}><Play size={14} /> {contentLang === "hinglish" ? "Lesson mein chalta dekho" : "Watch it in the lesson"}</Link>
                {pick !== lab.answer && <button className="btn" onClick={() => { setPick(null); setHints(0); }}>{contentLang === "hinglish" ? "Dobara try karo" : "Try again"}</button>}
                {next && <Link className="btn btn-primary" href={`/labs/${next.id}`}>{contentLang === "hinglish" ? "Agla lab" : "Next lab"} <ArrowRight size={14} /></Link>}
              </div>
            </div>
          )}
        </section>
      </div>
    </main>
  );
}

export function LabList() {
  const { contentLang, setContentLang, progress, catalog } = useApp();
  const L = (x: T) => (contentLang === "hinglish" ? x.hinglish : x.en);
  const solved = LABS.filter((l) => progress.done.includes(`lab:${l.id}`)).length;
  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3">
        <span className="mono text-[13px] text-ink-2">{solved}/{LABS.length} {contentLang === "hinglish" ? "solve kiye" : "solved"}</span>
        <span className="flex-1" />
        <div className="flex p-0.5 rounded-lg bg-panel-2" role="tablist" aria-label="Language">
          {(["en", "hinglish"] as const).map((l) => (
            <button key={l} role="tab" aria-selected={contentLang === l} onClick={() => setContentLang(l)}
              className={`h-8 px-3 rounded-md text-[12.5px] font-semibold ${contentLang === l ? "bg-panel-3 text-ink" : "text-muted hover:text-ink"}`}>
              {l === "en" ? "English" : "Hinglish"}
            </button>
          ))}
        </div>
      </div>
      <div className="grid gap-3 grid-cols-[repeat(auto-fill,minmax(300px,1fr))]">
        {LABS.map((lab, i) => {
          const done = progress.done.includes(`lab:${lab.id}`);
          const lesson = catalog.find((c) => c.id === lab.lesson);
          return (
            <Link key={lab.id} href={`/labs/${lab.id}`} className={`card !shadow-none p-4 flex flex-col gap-2 hover:bg-panel-2 hover:border-line-2 ${done ? "!border-[rgba(76,195,138,.35)]" : ""}`}>
              <div className="flex items-center gap-2 text-[11.5px] text-muted">
                <Ticket size={14} className="text-[var(--c-amber)]" />
                <span className="mono">Lab {i + 1}</span>·<span>{LEVEL[lab.level]}</span>·<span>{lesson?.name}</span>
                <span className="flex-1" />
                {done && <span className="inline-flex items-center gap-1 font-semibold text-brand"><Check size={13} /> {contentLang === "hinglish" ? "Solve" : "Solved"}</span>}
              </div>
              <h3 className="text-[16.5px] font-bold leading-snug text-ink">{L(lab.title)}</h3>
              <p className="text-[13.5px] text-ink-2 leading-snug">{L(lab.symptom)}</p>
            </Link>
          );
        })}
      </div>
    </div>
  );
}
