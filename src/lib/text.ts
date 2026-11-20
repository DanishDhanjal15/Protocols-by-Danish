// Translatable lesson text. A translation file mirrors the English text of a
// lesson (same keys, same array lengths); applyText() swaps it in, falling back
// to English for anything missing. Packet labels, field names and bytes stay English.

import type { Lesson } from "./lesson";

type Pair = [string, string];

export interface StepText {
  title?: string;
  desc?: string;
  detail?: string;
  facts?: Pair[];
  quiz?: { q?: string; options?: string[]; why?: string };
}

export interface ScenarioText {
  name?: string;
  summary?: string;
  steps?: StepText[];
  outro?: { title?: string; text?: string; facts?: Pair[] };
}

export interface LessonText {
  tagline?: string;
  description?: string;
  facts?: Pair[];
  legend?: string[];
  scenarios?: Record<string, ScenarioText>;
  cheatsheet?: { title?: string; items?: Pair[] }[];
}

export type ContentLang = "en" | "hinglish";

/** English text of a lesson, in the shape translators fill in. */
export function extractText(l: Lesson): LessonText {
  return {
    tagline: l.tagline,
    description: l.description,
    facts: l.facts,
    legend: l.legend.map(([, label]) => label),
    scenarios: Object.fromEntries(
      l.scenarios.map((s) => [
        s.id,
        {
          name: s.name,
          summary: s.summary,
          steps: s.steps.map((st) => ({
            title: st.title,
            desc: st.desc,
            detail: st.detail,
            facts: st.facts,
            ...(st.quiz ? { quiz: { q: st.quiz.q, options: st.quiz.options, why: st.quiz.why } } : {}),
          })),
          outro: { title: s.outro.title, text: s.outro.text, facts: s.outro.facts },
        },
      ])
    ),
    cheatsheet: l.cheatsheet?.map((c) => ({ title: c.title, items: c.items })),
  };
}

const pairs = (en: Pair[], tr?: Pair[]): Pair[] => en.map((p, i) => (tr?.[i]?.[0] && tr?.[i]?.[1] ? (tr[i] as Pair) : p));

export function applyText(l: Lesson, t?: LessonText | null): Lesson {
  if (!t) return l;
  return {
    ...l,
    tagline: t.tagline || l.tagline,
    description: t.description || l.description,
    facts: pairs(l.facts, t.facts),
    legend: l.legend.map(([c, label], i) => [c, t.legend?.[i] || label]),
    cheatsheet: l.cheatsheet?.map((c, i) => ({ title: t.cheatsheet?.[i]?.title || c.title, items: pairs(c.items, t.cheatsheet?.[i]?.items) })),
    scenarios: l.scenarios.map((s) => {
      const st = t.scenarios?.[s.id];
      if (!st) return s;
      return {
        ...s,
        name: st.name || s.name,
        summary: st.summary || s.summary,
        outro: { title: st.outro?.title || s.outro.title, text: st.outro?.text || s.outro.text, facts: pairs(s.outro.facts, st.outro?.facts) },
        steps: s.steps.map((step, i) => {
          const x = st.steps?.[i];
          if (!x) return step;
          return {
            ...step,
            title: x.title || step.title,
            desc: x.desc || step.desc,
            detail: x.detail || step.detail,
            facts: pairs(step.facts, x.facts),
            quiz: step.quiz && x.quiz
              ? {
                  ...step.quiz,
                  q: x.quiz.q || step.quiz.q,
                  why: x.quiz.why || step.quiz.why,
                  options: step.quiz.options.map((o, k) => x.quiz?.options?.[k] || o),
                }
              : step.quiz,
          };
        }),
      };
    }),
  };
}

// ------------------------------------------------------------------ "Try it yourself" commands

export interface TryItCommand {
  title: { en: string; hinglish: string };
  why: { en: string; hinglish: string };
  windows?: string;
  unix?: string;
  /** Wireshark display filter to use on this lesson's downloaded .pcap */
  wireshark?: string;
  expect: { en: string; hinglish: string };
  /** 1-based step of the main scenario this command relates to */
  step?: number;
}

export interface TryIt {
  commands: TryItCommand[];
}
