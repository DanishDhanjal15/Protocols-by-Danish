"use client";

import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { CornerDownLeft, Search } from "lucide-react";
import { GROUPS } from "@/lib/lesson";
import { useApp } from "./Providers";

interface Hit {
  href: string;
  title: string;
  sub: string;
  tag: string;
  score: number;
}

const PAGES = [
  { href: "/learn/journey", title: "Journey: type google.com", sub: "The capstone: the whole life of a web request", tag: "Journey" },
  { href: "/learn", title: "All lessons", sub: "Browse every protocol by group", tag: "Page" },
  { href: "/compare", title: "Compare protocols", sub: "TCP vs UDP vs QUIC, TLS 1.2 vs 1.3…", tag: "Page" },
  { href: "/paths", title: "Learning paths", sub: "CCNA, web developer, security, interview prep", tag: "Page" },
  { href: "/tools", title: "Tools", sub: "Subnet calculator, port finder, packet playground, live DNS", tag: "Page" },
];

export function CommandPalette({ onClose }: { onClose: () => void }) {
  const { catalog, t } = useApp();
  const router = useRouter();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLUListElement>(null);

  useEffect(() => input.current?.focus(), []);

  const hits = useMemo<Hit[]>(() => {
    const query = q.trim().toLowerCase();
    const out: Hit[] = [];
    const score = (s: string) => {
      const x = s.toLowerCase();
      if (!query) return 1;
      if (x === query) return 100;
      if (x.startsWith(query)) return 60;
      if (x.includes(query)) return 30;
      return 0;
    };
    for (const p of PAGES) {
      const s = Math.max(score(p.title), score(p.sub) / 2);
      if (s) out.push({ ...p, score: s + (query ? 0 : 50) });
    }
    for (const m of catalog) {
      const group = GROUPS.find((g) => g.id === m.group)?.name ?? "";
      const s = Math.max(score(m.name) * 2, score(m.full), score(m.tagline) / 2, ...m.keywords.map((k) => score(k) / 1.5), score(m.ports ?? "") / 1.5);
      if (s) out.push({ href: `/learn/${m.id}`, title: m.name, sub: m.full, tag: group, score: s });
      if (query.length >= 3) {
        m.scenarios.forEach((sc, si) =>
          sc.steps.forEach((st, i) => {
            const ss = score(st);
            if (ss) out.push({ href: `/learn/${m.id}?s=${sc.id}&step=${i + 1}`, title: st, sub: `${m.name} · ${si ? sc.name + " · " : ""}step ${i + 1}`, tag: "Step", score: ss / 2 });
          })
        );
      }
    }
    return out.sort((a, b) => b.score - a.score).slice(0, 40);
  }, [q, catalog]);

  useEffect(() => {
    list.current?.querySelector(`[data-i="${sel}"]`)?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const go = (h?: Hit) => {
    if (!h) return;
    onClose();
    router.push(h.href);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center p-4 pt-[12vh]" role="dialog" aria-modal="true" aria-label={t.search}>
      <button className="absolute inset-0 bg-black/40 backdrop-blur-[2px]" aria-label="Close" onClick={onClose} />
      <div className="card relative w-full max-w-xl overflow-hidden fade-up" style={{ boxShadow: "var(--shadow)" }}>
        <div className="flex items-center gap-3 px-4 border-b border-line">
          <Search size={18} className="text-muted" />
          <input
            ref={input}
            id="palette-input"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setSel(0);
            }}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, hits.length - 1)); }
              else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
              else if (e.key === "Enter") go(hits[sel]);
              else if (e.key === "Escape") onClose();
            }}
            placeholder={t.search}
            className="flex-1 h-14 bg-transparent outline-none text-[15px] placeholder:text-muted"
          />
          <span className="kbd">Esc</span>
        </div>
        <ul ref={list} className="max-h-[52vh] overflow-y-auto scroll-thin p-2">
          {hits.length === 0 && <li className="p-6 text-center text-muted text-sm">No match for “{q}”. Try a port number or a protocol name.</li>}
          {hits.map((h, i) => (
            <li key={h.href + i} data-i={i}>
              <button
                onMouseEnter={() => setSel(i)}
                onClick={() => go(h)}
                className={`w-full text-left flex items-center gap-3 px-3 py-2.5 rounded-lg ${i === sel ? "bg-panel-2" : ""}`}
              >
                <div className="min-w-0 flex-1">
                  <div className="font-semibold text-[14.5px] truncate">{h.title}</div>
                  <div className="text-[12.5px] text-muted truncate">{h.sub}</div>
                </div>
                <span className="chip">{h.tag}</span>
                {i === sel && <CornerDownLeft size={14} className="text-muted" />}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
