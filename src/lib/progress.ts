// Per-browser learning progress, kept in localStorage.

export interface Progress {
  done: string[];
  quiz: Record<string, { correct: number; total: number }>;
  last?: { id: string; step: number; at: number };
  streak: { day: string; count: number };
}

const KEY = "pbd:progress:v1";
const empty = (): Progress => ({ done: [], quiz: {}, streak: { day: "", count: 0 } });

export function loadProgress(): Progress {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? { ...empty(), ...JSON.parse(raw) } : empty();
  } catch {
    return empty();
  }
}

export function saveProgress(p: Progress) {
  try {
    localStorage.setItem(KEY, JSON.stringify(p));
  } catch {
    /* storage unavailable: progress just isn't kept */
  }
}

const today = () => new Date().toISOString().slice(0, 10);

export function touchStreak(p: Progress): Progress {
  const d = today();
  if (p.streak.day === d) return p;
  const y = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  return { ...p, streak: { day: d, count: p.streak.day === y ? p.streak.count + 1 : 1 } };
}

/** Combine progress from this browser and from the account, keeping the best of both. */
export function mergeProgress(a: Progress, b: Partial<Progress> | null | undefined): Progress {
  if (!b) return a;
  const done = [...new Set([...(a.done ?? []), ...(b.done ?? [])])];
  const quiz: Progress["quiz"] = { ...(b.quiz ?? {}) };
  for (const [k, v] of Object.entries(a.quiz ?? {})) if (!quiz[k] || v.total > quiz[k].total) quiz[k] = v;
  const bs = b.streak;
  const streak = bs && (bs.day > a.streak.day || (bs.day === a.streak.day && bs.count > a.streak.count)) ? bs : a.streak;
  const last = b.last && (!a.last || b.last.at > a.last.at) ? b.last : a.last;
  return { done, quiz, streak, last };
}
