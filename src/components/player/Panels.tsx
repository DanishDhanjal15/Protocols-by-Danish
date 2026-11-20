"use client";

import { useState } from "react";
import { Check, RotateCcw, X } from "lucide-react";
import type { Lesson, Quiz, Step } from "@/lib/lesson";
import { OSI_NAMES } from "@/lib/lesson";
import { useApp } from "../Providers";

export function Facts({ facts }: { facts: [string, string][]; cols?: number }) {
  return (
    <dl className="border-t border-line">
      {facts.map(([k, v]) => (
        <div key={k} className="grid grid-cols-[minmax(0,38%)_minmax(0,1fr)] gap-3 py-2 border-b border-line text-[13.5px]">
          <dt className="text-muted">{k}</dt>
          <dd className="text-ink font-medium break-words">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

// ------------------------------------------------------------------ quiz

export function QuizCard({ quiz, onAnswered, answered }: { quiz: Quiz; onAnswered: (correct: boolean) => void; answered?: number }) {
  const { t } = useApp();
  const [pick, setPick] = useState<number | null>(answered ?? null);
  const done = pick !== null;
  return (
    <div className="rounded-lg border-2 border-dashed border-[var(--brand)] p-4 bg-[color-mix(in_srgb,var(--brand-soft)_55%,var(--panel))] fade-up">
      <div className="eyebrow !text-[var(--brand)]">{t.quiz}</div>
      <p className="font-semibold text-[15.5px] mt-1.5">{quiz.q}</p>
      <div className="grid gap-2 mt-3">
        {quiz.options.map((o, i) => {
          const right = done && i === quiz.answer;
          const wrong = done && i === pick && i !== quiz.answer;
          return (
            <button
              key={i}
              disabled={done}
              onClick={() => {
                setPick(i);
                onAnswered(i === quiz.answer);
              }}
              className={`text-left px-3 py-2.5 rounded-lg border text-[14px] flex items-center gap-2 transition-colors ${
                right ? "border-[var(--c-green)] bg-[var(--c-green-soft)]" : wrong ? "border-[var(--c-red)] bg-[var(--c-red-soft)]" : "border-line bg-panel hover:border-line-2"
              }`}
            >
              <span className="mono text-[12px] text-muted w-4">{String.fromCharCode(65 + i)}</span>
              <span className="flex-1">{o}</span>
              {right && <Check size={16} style={{ color: "var(--c-green)" }} />}
              {wrong && <X size={16} style={{ color: "var(--c-red)" }} />}
            </button>
          );
        })}
      </div>
      {done && (
        <p className="mt-3 text-[13.5px] text-ink-2">
          <strong style={{ color: pick === quiz.answer ? "var(--c-green)" : "var(--c-red)" }}>{pick === quiz.answer ? t.correct : t.wrong}.</strong> {quiz.why}
        </p>
      )}
    </div>
  );
}

// ------------------------------------------------------------------ step panel

export function StepPanel({ step, index, total, children }: { step: Step; index: number; total: number; children?: React.ReactNode }) {
  const { t } = useApp();
  return (
    <div className="flex flex-col gap-3 fade-up" key={index}>
      <div className="eyebrow">{t.step} {index + 1} {t.of} {total}</div>
      <div>
        <h2 className="text-[22px] font-bold leading-tight">{step.title}</h2>
        <p className="text-muted text-[14.5px] mt-0.5">{step.desc}</p>
      </div>
      <p className="text-[15px] leading-relaxed text-ink-2">{step.detail}</p>
      <Facts facts={step.facts} />
      {children}
    </div>
  );
}

// ------------------------------------------------------------------ cheat sheet

export function CheatSheet({ lesson }: { lesson: Lesson }) {
  const sections = [
    {
      title: "At a glance",
      items: [
        ["Full name", lesson.full] as [string, string],
        ["OSI layer", `${lesson.layer} · ${OSI_NAMES[lesson.layer]}`] as [string, string],
        ...(lesson.ports ? [["Ports", lesson.ports] as [string, string]] : []),
        ...(lesson.rfc ? [["Defined in", lesson.rfc] as [string, string]] : []),
      ],
    },
    ...(lesson.cheatsheet ?? []),
  ];
  return (
    <div className="p-3 grid gap-3 sm:grid-cols-2">
      {sections.map((s) => (
        <section key={s.title} className="rounded-lg border border-line overflow-hidden min-w-0">
          <h3 className="eyebrow px-3 py-2 bg-panel-2">{s.title}</h3>
          <dl className="divide-y divide-[var(--line)]">
            {s.items.map(([k, v]) => (
              <div key={k} className="grid grid-cols-[minmax(0,40%)_minmax(0,1fr)] gap-3 px-3 py-2 text-[13px]">
                <dt className="mono font-semibold break-words">{k}</dt>
                <dd className="text-ink-2 break-words">{v}</dd>
              </div>
            ))}
          </dl>
        </section>
      ))}
    </div>
  );
}

// ------------------------------------------------------------------ full quiz

interface QuizItem { step: number; title: string; quiz: Quiz }

/** Test yourself: every step question of the scenario, one at a time, with a score. */
export function QuizRun({ items, onAnswer, onGoStep }: { items: QuizItem[]; onAnswer: (ok: boolean) => void; onGoStep: (step: number) => void }) {
  const [i, setI] = useState(0);
  const [results, setResults] = useState<(boolean | undefined)[]>([]);
  const [round, setRound] = useState(0);

  if (!items.length)
    return <p className="p-4 text-[14px] text-muted">This scenario has no quiz questions. Switch to the main scenario to test yourself.</p>;

  const done = i >= items.length;
  const correct = results.filter(Boolean).length;
  const restart = () => { setI(0); setResults([]); setRound((r) => r + 1); };

  if (done) {
    const pct = Math.round((correct / items.length) * 100);
    const missed = items.filter((_, k) => !results[k]);
    return (
      <div className="p-4 flex flex-col gap-4 fade-up">
        <div className="eyebrow">Your score</div>
        <div className="flex items-end gap-3">
          <span className="display text-[44px] font-bold leading-none text-ink tnum">{correct}/{items.length}</span>
          <span className="text-[14px] text-muted pb-1">{pct >= 80 ? "Great, you know this protocol." : pct >= 50 ? "Good start. Review the steps you missed." : "Watch the lesson again, then retry."}</span>
        </div>
        <div className="h-2 rounded-full bg-panel-3 overflow-hidden"><div className="h-full bg-brand rounded-full" style={{ width: `${pct}%` }} /></div>
        {missed.length > 0 && (
          <div className="flex flex-col gap-1.5">
            <div className="eyebrow">Review these steps</div>
            {missed.map((m) => (
              <button key={m.step} onClick={() => onGoStep(m.step)} className="text-left text-[13.5px] px-3 py-2 rounded-lg bg-panel-2 hover:bg-panel-3">
                Step {m.step + 1}: {m.title}
              </button>
            ))}
          </div>
        )}
        <button className="btn self-start" onClick={restart}><RotateCcw size={14} /> Try again</button>
      </div>
    );
  }

  const item = items[i];
  return (
    <div className="p-4 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <span className="eyebrow">Question {i + 1} of {items.length}</span>
        <span className="flex-1" />
        <span className="text-[12px] text-muted">from step {item.step + 1}: {item.title}</span>
      </div>
      <div className="flex gap-1">
        {items.map((_, k) => (
          <span key={k} className="h-1.5 flex-1 rounded-full" style={{ background: results[k] === undefined ? (k === i ? "var(--ink-2)" : "var(--panel-3)") : results[k] ? "var(--c-green)" : "var(--c-red)" }} />
        ))}
      </div>
      <QuizCard key={`${round}-${i}`} quiz={item.quiz} onAnswered={(ok) => { setResults((r) => { const n = [...r]; n[i] = ok; return n; }); onAnswer(ok); }} />
      {results[i] !== undefined && (
        <button className="btn btn-primary self-start" onClick={() => setI(i + 1)}>{i + 1 < items.length ? "Next question" : "See my score"}</button>
      )}
    </div>
  );
}
