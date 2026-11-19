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
