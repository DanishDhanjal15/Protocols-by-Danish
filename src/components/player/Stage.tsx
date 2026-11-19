"use client";

import { useEffect, useMemo, useRef } from "react";
import type { Device, Scenario } from "@/lib/lesson";
import { devicePoint as dp, ease, findPath, MOBILE_H, MOBILE_W, poly, pointAt, Poly, STAGE_H, STAGE_W } from "@/lib/route";
import type { Device as Dev } from "@/lib/lesson";
import { DeviceGlyphG } from "../DeviceIcon";
import { Captured, PlayerApi, useProgress } from "./usePlayer";

const cvar = (c: string) => `var(--c-${c})`;
const csoft = (c: string) => `var(--c-${c}-soft)`;

interface StageProps {
  devices: Device[];
  links: [string, string][];
  api: PlayerApi;
  selected?: string;
  onSelect: (key: string) => void;
}

function useInflight(api: PlayerApi) {
  const progress = useProgress(api.store);
  const g = api.groups[api.groupIdx];
  const active = g && (api.playing || progress > 0) ? g : null;
  return { progress, active };
}

// ------------------------------------------------------------------ network view

export function NetworkView({ devices, links, api, selected, onSelect, narrow }: StageProps & { narrow?: boolean }) {
  const { progress, active } = useInflight(api);
  const W = narrow ? MOBILE_W : STAGE_W, H = narrow ? MOBILE_H : STAGE_H;
  const devicePoint = (d: Dev) => dp(d, W, H);
  const byId = useMemo(() => new Map(devices.map((d) => [d.id, d])), [devices]);

  const paths = useMemo(() => {
    const m = new Map<string, { poly: Poly; ids: string[] }>();
    if (!active) return m;
    for (const c of active.packets) {
      const ids = findPath(links, c.ev.from, c.ev.to, c.ev.via);
      const pts = ids.map((id) => byId.get(id)).filter(Boolean).map((d) => devicePoint(d!));
      m.set(c.key, { poly: poly(pts), ids });
    }
    return m;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [active, links, byId, W, H]);

  const hotLinks = new Map<string, string>();
  const hotDevices = new Set<string>();
  if (active) {
    for (const c of active.packets) {
      const p = paths.get(c.key);
      if (!p) continue;
      hotDevices.add(c.ev.from);
      hotDevices.add(c.ev.to);
      for (let i = 0; i < p.ids.length - 1; i++) {
        hotLinks.set([p.ids[i], p.ids[i + 1]].sort().join("|"), c.ev.color);
      }
    }
  }

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-full block select-none" role="img" aria-label="Network diagram">
      <defs>
        <filter id="soft" x="-40%" y="-40%" width="180%" height="180%">
          <feGaussianBlur stdDeviation="4" result="b" />
          <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
        </filter>
      </defs>

      {/* links */}
      {links.map(([a, b]) => {
        const da = byId.get(a), db = byId.get(b);
        if (!da || !db) return null;
        const pa = devicePoint(da), pb = devicePoint(db);
        const hot = hotLinks.get([a, b].sort().join("|"));
        return (
          <g key={`${a}-${b}`}>
            <line x1={pa.x} y1={pa.y} x2={pb.x} y2={pb.y} stroke="var(--line-2)" strokeWidth={2} strokeLinecap="round" />
            {hot && (
              <line x1={pa.x} y1={pa.y} x2={pb.x} y2={pb.y} stroke={cvar(hot)} strokeWidth={2.4} strokeDasharray="7 9" opacity={0.75} style={{ animation: "dash 1.2s linear infinite" }} />
            )}
          </g>
        );
      })}

      {/* devices: flat tiles with a coloured top edge when active */}
      {devices.map((d) => {
        const p = devicePoint(d);
        const hot = hotDevices.has(d.id);
        const cloud = d.kind === "cloud";
        const k = narrow ? 1.4 : 1;
        const half = 30;
        const accent = d.kind === "attacker" ? "var(--c-red)" : "var(--brand)";
        return (
          <g key={d.id} transform={`translate(${p.x} ${p.y})`}>
            <g transform={`scale(${k})`}>
              {cloud ? (
                <path d="M-46 22a18 18 0 0 1 2-36a25 25 0 0 1 47-10a19 19 0 0 1 33 9a17 17 0 0 1 4 37z" fill="var(--panel-2)" stroke={hot ? accent : "var(--line-2)"} strokeWidth={1.5} />
              ) : (
                <>
                  <rect x={-half} y={-half} width={half * 2} height={half * 2} rx={14} fill="var(--panel-2)" stroke={hot ? accent : "var(--line-2)"} strokeWidth={1.5} />
                  <path d={`M${-half + 14} ${-half} h${half * 2 - 28}`} stroke={hot ? accent : "var(--line-2)"} strokeWidth={3} strokeLinecap="round" />
                </>
              )}
              <g style={{ color: d.kind === "attacker" ? "var(--c-red)" : hot ? "var(--ink)" : "var(--ink-2)" }} transform={cloud ? "translate(0 4)" : undefined}>
                <DeviceGlyphG kind={cloud ? "dns" : d.kind} size={cloud ? 28 : 30} />
              </g>
            </g>
            <text y={(cloud ? 44 : 50) * k} textAnchor="middle" fill="var(--ink)" stroke="var(--stage)" strokeWidth={5} paintOrder="stroke" style={{ font: `600 ${narrow ? 14 : 15}px var(--font-inter), sans-serif` }}>
              {d.label}
            </text>
            {d.sub && (
              <text y={(cloud ? 44 : 50) * k + (narrow ? 14 : 17)} textAnchor="middle" fill="var(--muted)" stroke="var(--stage)" strokeWidth={4} paintOrder="stroke" style={{ font: `500 ${narrow ? 10.5 : 12}px var(--font-mono), monospace` }}>
                {d.sub}
              </text>
            )}
          </g>
        );
      })}

      {/* notes */}
      {api.notes.map((n, i) => {
        const d = byId.get(n.at);
        if (!d) return null;
        const p = devicePoint(d);
        const w = n.text.length * 8.4 + 26;
        const tone = n.tone ?? "amber";
        const y = p.y - (d.kind === "cloud" ? 56 : 56) - (api.notes.slice(0, i).filter((x) => x.at === n.at).length * 34);
        return (
          <g key={i} transform={`translate(${p.x} ${y})`}><g className="fade-up">
            <rect x={-w / 2} y={-15} width={w} height={28} rx={8} fill="var(--panel)" stroke={cvar(tone)} strokeWidth={1.4} />
            <circle cx={-w / 2 + 12} cy={-1} r={4} fill={cvar(tone)} />
            <text x={6} y={4} textAnchor="middle" fill={cvar(tone)} style={{ font: "700 12px var(--font-mono), monospace", letterSpacing: ".03em" }}>
              {n.text}
            </text>
          </g></g>
        );
      })}

      {/* packets in flight */}
      {active?.packets.map((c, i) => {
        const p = paths.get(c.key);
        if (!p) return null;
        const lost = c.ev.lost;
        const t = lost ? Math.min(ease(Math.min(progress / 0.55, 1)) * 0.5, 0.5) : ease(progress);
        const pt = pointAt(p.poly, t);
        const offset = active.packets.length > 1 ? (i - (active.packets.length - 1) / 2) * 34 : 0;
        const w = Math.max(58, c.ev.label.length * 9 + 30);
        const dead = lost && progress > 0.55;
        return (
          <g
            key={c.key}
            transform={`translate(${pt.x} ${pt.y - 44 + offset})`}
            style={{ cursor: "pointer", opacity: dead ? Math.max(0, 1 - (progress - 0.55) * 1.6) : 1 }}
            onClick={() => onSelect(c.key)}
          >
            <line x1={0} y1={14} x2={0} y2={44 - offset} stroke={cvar(c.ev.color)} strokeWidth={1.2} strokeDasharray="2 3" opacity={0.6} />
            <rect x={-w / 2} y={-15} width={w} height={30} rx={15} fill={cvar(c.ev.color)} stroke={selected === c.key ? "var(--ink)" : "none"} strokeWidth={2} />
            <text y={5} textAnchor="middle" fill="#0e1116" style={{ font: "700 13.5px var(--font-mono), monospace", letterSpacing: ".02em" }}>
              {c.ev.label}
            </text>
            {c.ev.lines?.length ? (
              <g transform="translate(0 -22)">
                {c.ev.lines.slice(0, 2).map((l, li, arr) => (
                  <text key={li} y={-(arr.length - 1 - li) * 15} textAnchor="middle" fill="var(--ink)" stroke="var(--stage)" strokeWidth={5} paintOrder="stroke" style={{ font: "500 13px var(--font-mono), monospace" }}>
                    {l}
                  </text>
                ))}
              </g>
            ) : null}
            {dead && (
              <g stroke="var(--c-red)" strokeWidth={4} strokeLinecap="round">
                <path d="M-10 -10 L10 10 M10 -10 L-10 10" />
              </g>
            )}
          </g>
        );
      })}
    </svg>
  );
}

// ------------------------------------------------------------------ sequence view

export function SequenceView({ devices, scenario, api, selected, onSelect }: StageProps & { scenario: Scenario }) {
  const { progress, active } = useInflight(api);
  const scroller = useRef<HTMLDivElement>(null);

  const cols = useMemo(() => {
    const used = new Set<string>();
    scenario.steps.forEach((s) => s.events.forEach((e) => e.type === "packet" && (used.add(e.from), used.add(e.to))));
    const ds = devices.filter((d) => used.has(d.id)).sort((a, b) => a.x - b.x);
    const left = 150, right = 960;
    const gap = ds.length > 1 ? (right - left) / (ds.length - 1) : 0;
    return new Map(ds.map((d, i) => [d.id, { d, x: ds.length > 1 ? left + i * gap : (left + right) / 2 }]));
  }, [devices, scenario]);

  type Row = { kind: "step"; title: string; step: number } | { kind: "pkt"; c: Captured; live?: boolean };
  const rows: Row[] = [];
  let lastStep = -1;
  const pushPkt = (c: Captured, live = false) => {
    if (c.step !== lastStep) {
      rows.push({ kind: "step", title: scenario.steps[c.step]?.title ?? "", step: c.step });
      lastStep = c.step;
    }
    rows.push({ kind: "pkt", c, live });
  };
  api.captured.forEach((c) => pushPkt(c));
  active?.packets.forEach((c) => pushPkt(c, true));

  const ROW = 46, STEP = 34, HEAD = 70;
  let y = HEAD;
  const placed = rows.map((r) => {
    const ry = y;
    y += r.kind === "step" ? STEP : ROW;
    return { r, y: ry };
  });
  const height = Math.max(y + 30, 300);

  useEffect(() => {
    const el = scroller.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [rows.length]);

  return (
    <div ref={scroller} className="w-full h-full overflow-auto scroll-thin">
      <svg viewBox={`0 0 1000 ${height}`} className="w-full min-w-[640px] block" style={{ height: "auto" }} role="img" aria-label="Sequence diagram">
        {[...cols.values()].map(({ d, x }) => (
          <g key={d.id}>
            <line x1={x} y1={HEAD - 8} x2={x} y2={height - 10} stroke="var(--line-2)" strokeWidth={2} strokeDasharray="4 5" />
            <rect x={x - 70} y={8} width={140} height={44} rx={10} fill="var(--panel)" stroke="var(--line-2)" />
            <text x={x} y={28} textAnchor="middle" fill="var(--ink)" style={{ font: "600 14px var(--font-inter), sans-serif" }}>{d.label}</text>
            {d.sub && <text x={x} y={44} textAnchor="middle" fill="var(--muted)" style={{ font: "500 11px var(--font-mono), monospace" }}>{d.sub}</text>}
          </g>
        ))}
        {placed.map(({ r, y }, i) => {
          if (r.kind === "step")
            return (
              <g key={`s${i}`}>
                <rect x={10} y={y + 6} width={980} height={22} rx={6} fill="var(--panel-2)" />
                <text x={22} y={y + 21} fill="var(--muted)" style={{ font: "700 11.5px var(--font-mono), monospace", letterSpacing: ".08em" }}>
                  {`STEP ${r.step + 1} · ${r.title.toUpperCase()}`}
                </text>
              </g>
            );
          const { c, live } = r;
          const a = cols.get(c.ev.from), b = cols.get(c.ev.to);
          if (!a || !b) return null;
          const yy = y + 30;
          const lost = c.ev.lost;
          let frac = live ? ease(progress) : 1;
          if (lost) frac = Math.min(frac, 0.5);
          const x2 = a.x + (b.x - a.x) * frac;
          const dir = Math.sign(b.x - a.x) || 1;
          const sel = selected === c.key;
          return (
            <g key={c.key} style={{ cursor: "pointer" }} onClick={() => onSelect(c.key)} className={live ? "" : "fade-up"}>
              <rect x={10} y={y + 4} width={980} height={ROW - 4} rx={8} fill={sel ? "var(--panel-2)" : "transparent"} />
              <text x={22} y={yy + 4} fill="var(--muted)" style={{ font: "500 11px var(--font-mono), monospace" }}>{c.ev.time.toFixed(3)}s</text>
              <line x1={a.x} y1={yy} x2={x2} y2={yy} stroke={`var(--c-${c.ev.color})`} strokeWidth={2.4} />
              {(!lost || frac < 0.5) && frac > 0.05 && (
                <path d={`M${x2} ${yy} l${-9 * dir} -5 l0 10 z`} fill={`var(--c-${c.ev.color})`} />
              )}
              {lost && frac >= 0.5 && (
                <path d={`M${x2 - 7} ${yy - 7} l14 14 M${x2 + 7} ${yy - 7} l-14 14`} stroke="var(--c-red)" strokeWidth={3} strokeLinecap="round" />
              )}
              <text x={(a.x + b.x) / 2} y={yy - 8} textAnchor="middle" fill={`var(--c-${c.ev.color})`} stroke="var(--stage)" strokeWidth={4} paintOrder="stroke" style={{ font: "700 12.5px var(--font-mono), monospace" }}>
                {c.ev.label}
                {c.ev.lines?.[0] ? `  ·  ${c.ev.lines[0]}` : ""}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}
