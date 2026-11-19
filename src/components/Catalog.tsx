"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { Check, Search } from "lucide-react";
import { GROUPS, OSI_NAMES } from "@/lib/lesson";
import type { LessonMeta } from "@/lib/catalog";
import { useApp } from "./Providers";

const DIFF = ["", "Beginner", "Intermediate", "Advanced"];

export function LessonCard({ m, done, index }: { m: LessonMeta; done?: boolean; index?: string }) {
  const extra = m.scenarios.filter((s) => s.kind !== "normal");
  return (
    <Link href={`/learn/${m.id}`}
      className={`group relative card !shadow-none p-4 flex flex-col gap-2 min-w-0 hover:border-line-2 hover:bg-panel-2 transition-colors osi-${m.layer} ${done ? "!border-[rgba(76,195,138,.35)]" : ""}`}>
      <div className="flex items-center gap-2">
        {index && <span className="mono text-[11px] text-muted tnum">{index}</span>}
        <span className="mono text-[10px] font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--ls)", color: "var(--lc)" }}>L{m.layer}</span>
        <span className="text-[11.5px] text-muted">{OSI_NAMES[m.layer]}</span>
        <span className="flex-1" />
        {done ? (
          <span className="inline-flex items-center gap-1 text-[11.5px] font-semibold text-brand"><Check size={14} /> Done</span>
        ) : (
          <span className="text-[11.5px] text-muted">{DIFF[m.difficulty]}</span>
        )}
      </div>
      <div>
        <h3 className="text-[17px] font-bold leading-tight text-ink">{m.name}</h3>
        <p className="text-[12.5px] text-muted truncate">{m.full}</p>
      </div>
      <p className="text-[13.5px] text-ink-2 leading-snug flex-1">{m.tagline}</p>
      <div className="flex flex-wrap gap-1.5 pt-1">
        <span className="chip">{m.scenarios[0]?.steps.length ?? 0} steps</span>
        <span className="chip">{m.packets} packets</span>
        {extra.some((s) => s.kind === "attack") && <span className="chip" style={{ background: "var(--c-red-soft)", color: "var(--c-red)" }}>attack + defence</span>}
        {extra.some((s) => s.kind === "failure") && <span className="chip" style={{ background: "var(--c-amber-soft)", color: "var(--c-amber)" }}>what-if</span>}
      </div>
    </Link>
  );
}

/** The lessons page as a learning roadmap: stages in order, joined by a spine. */
export function Catalog() {
  const { catalog, progress, t, layer, setLayer } = useApp();
  const [q, setQ] = useState("");

  const list = useMemo(() => {
    const query = q.trim().toLowerCase();
    return catalog.filter(
      (m) => (!layer || m.layer === layer) && (!query || [m.name, m.full, m.tagline, m.ports ?? "", ...m.keywords].some((s) => s.toLowerCase().includes(query)))
    );
  }, [catalog, q, layer]);

  const doneAll = catalog.filter((m) => progress.done.includes(m.id)).length;
  const stages = GROUPS.map((g) => ({ g, items: list.filter((m) => m.group === g.id), all: catalog.filter((m) => m.group === g.id) })).filter((s) => s.all.length);
  const nextUp = catalog.find((m) => !progress.done.includes(m.id));

  return (
    <div className="flex flex-col gap-8">
      {/* progress + filters */}
      <div className="card !shadow-none p-4 flex flex-wrap items-center gap-4">
        <div className="flex-1 min-w-[220px]">
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-[14px] font-semibold">{t.progress}</span>
            <span className="mono text-[13px] text-ink-2 tnum">{doneAll}/{catalog.length} lessons</span>
          </div>
          <div className="h-2 rounded-full bg-panel-3 overflow-hidden mt-2">
            <div className="h-full bg-brand rounded-full transition-[width]" style={{ width: `${(doneAll / Math.max(1, catalog.length)) * 100}%` }} />
          </div>
        </div>
        {nextUp && (
          <Link href={`/learn/${nextUp.id}`} className="btn btn-primary">Continue: {nextUp.name}</Link>
        )}
      </div>

      <div className="flex flex-wrap gap-2 items-center">
        <label className="flex items-center gap-2 h-10 px-3 rounded-lg border border-line bg-panel flex-1 min-w-[220px] max-w-md">
          <Search size={16} className="text-muted" />
          <input id="catalog-search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by name, port or keyword" className="flex-1 bg-transparent outline-none text-[14px]" />
        </label>
        <select id="catalog-layer" value={layer} onChange={(e) => setLayer(Number(e.target.value))} className="h-10 rounded-lg border border-line bg-panel px-2 text-[14px]" aria-label={t.layer}>
          <option value={0}>All OSI layers</option>
          {[2, 3, 4, 6, 7].map((l) => <option key={l} value={l}>Layer {l}: {OSI_NAMES[l]}</option>)}
        </select>
      </div>

      {/* roadmap */}
      <ol className="relative flex flex-col gap-10">
        <span aria-hidden className="absolute left-[19px] top-3 bottom-3 w-[2px] bg-line-2" />
        {stages.map(({ g, items, all }, si) => {
          const done = all.filter((m) => progress.done.includes(m.id)).length;
          const complete = done === all.length;
          return (
            <li key={g.id} className="relative pl-14">
              <span className={`absolute left-0 top-0 w-10 h-10 rounded-full grid place-items-center mono text-[14px] font-bold border-2 ${complete ? "bg-brand text-brand-ink border-brand" : done ? "bg-panel border-brand text-brand" : "bg-panel border-line-2 text-ink-2"}`}>
                {complete ? <Check size={18} /> : si + 1}
              </span>
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="eyebrow">Stage {si + 1}</span>
                <h2 className="text-[21px] font-bold text-ink">{g.name}</h2>
                <span className="mono text-[12px] text-muted tnum">{done}/{all.length} done</span>
              </div>
              <p className="text-[13.5px] text-muted mt-0.5">{g.blurb}</p>
              {items.length ? (
                <div className="grid gap-3 mt-4 grid-cols-[repeat(auto-fill,minmax(240px,1fr))]">
                  {items.map((m) => (
                    <LessonCard key={m.id} m={m} done={progress.done.includes(m.id)} index={`${si + 1}.${all.indexOf(m) + 1}`} />
                  ))}
                </div>
              ) : (
                <p className="text-[13px] text-muted mt-3">No lesson in this stage matches the filter.</p>
              )}
            </li>
          );
        })}
      </ol>
      {!list.length && <p className="text-muted">Nothing matches “{q}”. Try a port like 443 or a word like “handshake”.</p>}
    </div>
  );
}
