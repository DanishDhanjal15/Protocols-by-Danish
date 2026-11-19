// Stage geometry: device positions, paths over links, points along a path.
import type { Device } from "./lesson";

export const STAGE_W = 1000;
export const STAGE_H = 460;

export interface Pt { x: number; y: number }

export const devicePoint = (d: Device, w = STAGE_W, h = STAGE_H): Pt => ({ x: (d.x / 100) * w, y: (d.y / 100) * h });

/** Narrow screens use a smaller, taller canvas so icons and labels stay readable. */
export const MOBILE_W = 470;
export const MOBILE_H = 500;

export function findPath(links: [string, string][], from: string, to: string, via?: string[]): string[] {
  if (via?.length) {
    const hops = [from, ...via, to];
    const out: string[] = [from];
    for (let i = 0; i < hops.length - 1; i++) out.push(...findPath(links, hops[i], hops[i + 1]).slice(1));
    return out;
  }
  const adj = new Map<string, string[]>();
  for (const [a, b] of links) {
    adj.set(a, [...(adj.get(a) ?? []), b]);
    adj.set(b, [...(adj.get(b) ?? []), a]);
  }
  const prev = new Map<string, string | null>([[from, null]]);
  const q = [from];
  while (q.length) {
    const n = q.shift()!;
    if (n === to) break;
    for (const m of adj.get(n) ?? []) if (!prev.has(m)) { prev.set(m, n); q.push(m); }
  }
  if (!prev.has(to)) return [from, to];
  const path: string[] = [];
  for (let c: string | null = to; c; c = prev.get(c) ?? null) path.unshift(c);
  return path;
}

export interface Poly { pts: Pt[]; cum: number[]; total: number }

export function poly(pts: Pt[]): Poly {
  const cum = [0];
  for (let i = 1; i < pts.length; i++) cum.push(cum[i - 1] + Math.hypot(pts[i].x - pts[i - 1].x, pts[i].y - pts[i - 1].y));
  return { pts, cum, total: cum[cum.length - 1] || 1 };
}

export function pointAt(p: Poly, t: number): Pt {
  const d = Math.max(0, Math.min(1, t)) * p.total;
  for (let i = 1; i < p.pts.length; i++) {
    if (d <= p.cum[i]) {
      const seg = p.cum[i] - p.cum[i - 1] || 1;
      const k = (d - p.cum[i - 1]) / seg;
      return { x: p.pts[i - 1].x + (p.pts[i].x - p.pts[i - 1].x) * k, y: p.pts[i - 1].y + (p.pts[i].y - p.pts[i - 1].y) * k };
    }
  }
  return p.pts[p.pts.length - 1];
}

export const ease = (t: number) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
