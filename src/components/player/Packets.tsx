"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronLeft, ChevronRight, Copy, Lock } from "lucide-react";
import { expandPacket } from "@/lib/catalog";
import { fmtBytes, toHex } from "@/lib/bytes";
import { BuiltPacket, FlatField, flatten, Layer } from "@/lib/packet";
import { OSI_NAMES } from "@/lib/lesson";
import { useApp } from "../Providers";
import type { Captured } from "./usePlayer";

// ------------------------------------------------------------------ capture row helpers

export function rowOf(c: Captured, p: BuiltPacket) {
  const ip = p.layers.find((l) => l.id === "ipv4" || l.id === "ipv6");
  const l2 = p.layers[0];
  const val = (l: Layer | undefined, name: string) => l?.fields.find((f) => f.name === name)?.value;
  const src = c.ev.src ?? val(ip, "Source address") ?? val(l2, "Source") ?? c.ev.from;
  const dst = c.ev.dst ?? val(ip, "Destination address") ?? val(l2, "Destination") ?? c.ev.to;
  const top = [...p.layers].reverse().find((l) => l.id !== "data") ?? p.layers[p.layers.length - 1];
  return { src, dst, proto: c.ev.proto ?? top?.name ?? "?", len: p.bytes.length };
}

export function CaptureTable({ rows, selected, onSelect }: { rows: Captured[]; selected?: string; onSelect: (k: string) => void }) {
  const { t } = useApp();
  const body = useRef<HTMLDivElement>(null);
  const expanded = useMemo(() => rows.map((c) => ({ c, r: rowOf(c, expandPacket(c.ev.packet)) })), [rows]);
  useEffect(() => {
    body.current?.scrollTo({ top: body.current.scrollHeight, behavior: "smooth" });
  }, [rows.length]);
  return (
    <div ref={body} className="overflow-auto h-full min-h-[140px]">
      <table className="w-full text-[12.5px] mono tnum">
        <thead className="sticky top-0 bg-panel text-left z-[1]">
          <tr className="text-[11.5px] text-muted [&>th]:px-3 [&>th]:py-2 [&>th]:font-semibold border-b border-line">
            <th className="w-12">No.</th><th>Time</th><th>Source</th><th>Destination</th><th>Protocol</th><th className="w-full">Info</th><th className="text-right">Size</th>
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 && (
            <tr><td colSpan={7} className="px-3 py-4 text-muted">{t.noPackets}</td></tr>
          )}
          {expanded.map(({ c, r }) => (
            <tr
              key={c.key}
              onClick={() => onSelect(c.key)}
              className={`cursor-pointer [&>td]:px-3 [&>td]:py-[5px] [&>td]:whitespace-nowrap c-${c.ev.color} ${selected === c.key ? "bg-panel-3" : "hover:bg-panel-2"}`}
            >
              <td>
                <span className="inline-grid place-items-center w-5 h-5 rounded-full text-[10.5px] font-bold" style={{ background: "var(--cs)", color: "var(--c)" }}>{c.no}</span>
              </td>
              <td className="text-ink-2">{c.ev.time.toFixed(3)}s</td>
              <td>{r.src}</td>
              <td>{r.dst}</td>
              <td className="font-bold" style={{ color: "var(--c)" }}>{r.proto}</td>
              <td className="text-ink-2 max-w-0 overflow-hidden text-ellipsis">
                {c.ev.lost && <span className="chip mr-1.5 !h-[18px]" style={{ background: "var(--c-red-soft)", color: "var(--c-red)" }}>{t.lost}</span>}
                {c.ev.info}
              </td>
              <td className="text-right text-ink-2">{fmtBytes(r.len)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ------------------------------------------------------------------ inspector

export function Inspector({ cap, onPrev, onNext }: { cap?: Captured; onPrev: () => void; onNext: () => void }) {
  const { t } = useApp();
  const packet = useMemo(() => (cap ? expandPacket(cap.ev.packet) : null), [cap]);
  const flat = useMemo(() => (packet ? flatten(packet) : []), [packet]);
  const [openLayers, setOpenLayers] = useState<Set<number>>(new Set());
  const [focus, setFocus] = useState<FlatField | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    // open the top (most specific) layer by default
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setOpenLayers(new Set(packet ? [packet.layers.length - 1 - (packet.layers[packet.layers.length - 1]?.id === "data" && packet.layers.length > 1 ? 1 : 0)] : []));
    setFocus(null);
  }, [packet]);

  if (!cap || !packet) return <div className="p-4 text-[13px] text-muted">{t.noPackets}</div>;

  const r = rowOf(cap, packet);
  const layerStart: number[] = [];
  {
    let off = 0;
    packet.layers.forEach((l, i) => {
      layerStart[i] = off;
      off += l.fields.reduce((n, f) => n + f.bytes.length, 0);
    });
  }
  const byteLayer = new Array(packet.bytes.length).fill(-1);
  const opaque = new Array(packet.bytes.length).fill(false);
  flat.forEach((f) => {
    if (f.depth === 0) for (let i = f.start; i < f.end; i++) byteLayer[i] = f.layer;
    if (f.field.opaque) for (let i = f.start; i < f.end; i++) opaque[i] = true;
  });

  const copy = () => {
    navigator.clipboard?.writeText(toHex(packet.bytes)).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    }).catch(() => {});
  };

  return (
    <div className="flex flex-col min-h-0">
      <div className="flex items-center gap-2 px-3 h-10 border-b border-line">
        <span className={`dot c-${cap.ev.color}`} />
        <span className="mono text-[12.5px] font-semibold truncate">#{cap.no} · {r.proto} · {fmtBytes(r.len)}</span>
        <span className="flex-1" />
        <button className="icon-btn w-8 h-8" onClick={copy} title={t.copyHex} aria-label={t.copyHex}>
          {copied ? <span className="mono text-[10px]">✓</span> : <Copy size={15} />}
        </button>
        <button className="icon-btn w-8 h-8" onClick={onPrev} aria-label="Previous packet"><ChevronLeft size={17} /></button>
        <button className="icon-btn w-8 h-8" onClick={onNext} aria-label="Next packet"><ChevronRight size={17} /></button>
      </div>

      <div className="overflow-auto scroll-thin flex-1 min-h-0">
        {/* layer tree */}
        <ul className="p-2 flex flex-col gap-1.5">
          {packet.layers.map((l, li) => {
            const open = openLayers.has(li);
            const fields = flat.filter((f) => f.layer === li);
            return (
              <li key={li} className={`osi-${l.osi} rounded-lg border border-line overflow-hidden`}>
                <button
                  className="w-full flex items-center gap-2 px-2.5 py-2 text-left"
                  style={{ background: "var(--ls)" }}
                  onClick={() => setOpenLayers((s) => { const n = new Set(s); if (n.has(li)) n.delete(li); else n.add(li); return n; })}
                  onMouseEnter={() => setFocus({ key: `L${li}`, layer: li, depth: -1, field: { name: l.name, value: "", bytes: [] }, start: layerStart[li], end: layerStart[li] + l.fields.reduce((n, f) => n + f.bytes.length, 0) })}
                  aria-expanded={open}
                >
                  <ChevronDown size={14} className={`transition-transform ${open ? "" : "-rotate-90"}`} style={{ color: "var(--lc)" }} />
                  <span className="mono text-[10.5px] font-bold px-1.5 py-0.5 rounded" style={{ background: "var(--lc)", color: "var(--panel)" }}>L{l.osi}</span>
                  <span className="text-[13px] font-semibold truncate" title={l.summary}>{l.summary}</span>
                </button>
                {open && (
                  <ul className="py-1">
                    {fields.map((f) => (
                      <li key={f.key}>
                        <button
                          onMouseEnter={() => setFocus(f)}
                          onFocus={() => setFocus(f)}
                          onClick={() => setFocus(f)}
                          className={`w-full text-left px-2.5 py-1.5 grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 ${focus?.key === f.key ? "bg-panel-2" : "hover:bg-panel-2"}`}
                          style={{ paddingLeft: 14 + f.depth * 16 }}
                        >
                          <span className="text-[12.5px] min-w-0">
                            <span className="font-semibold">{f.field.name}</span>
                            <span className="text-muted">: </span>
                            <span className="mono break-all">{f.field.opaque ? <span className="inline-flex items-center gap-1 text-muted"><Lock size={11} />{f.field.value}</span> : f.field.value}</span>
                          </span>
                          <span className="mono text-[10.5px] text-muted self-start pt-0.5 tnum">{f.end - f.start}B</span>
                          {f.field.note && focus?.key === f.key && <span className="col-span-2 text-[12px] text-muted pt-0.5 leading-snug">{f.field.note}</span>}
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            );
          })}
        </ul>

        {/* hex */}
        <div className="px-3 pb-3">
          <div className="eyebrow mb-1.5 flex items-center gap-2">
            Bytes
            {focus && <span className="normal-case tracking-normal font-medium text-ink-2">· {focus.field.name || "layer"} · offset {focus.start}, {focus.end - focus.start} bytes</span>}
          </div>
          <HexView bytes={packet.bytes} byteLayer={byteLayer} layers={packet.layers} opaque={opaque} focus={focus} onPick={(i) => {
            const best = flat.filter((f) => i >= f.start && i < f.end).sort((a, b) => b.depth - a.depth)[0];
            if (best) { setFocus(best); setOpenLayers((s) => new Set(s).add(best.layer)); }
          }} />
          <div className="flex flex-wrap gap-2 mt-2">
            {packet.layers.map((l, i) => (
              <span key={i} className={`osi-${l.osi} chip`} style={{ background: "var(--ls)", color: "var(--lc)" }}>L{l.osi} {OSI_NAMES[l.osi]} · {l.name}</span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function HexView({ bytes, byteLayer, layers, opaque, focus, onPick }: { bytes: number[]; byteLayer: number[]; layers: Layer[]; opaque: boolean[]; focus: FlatField | null; onPick: (i: number) => void }) {
  const rows: number[] = [];
  for (let i = 0; i < bytes.length; i += 8) rows.push(i);
  const MAX_ROWS = 128;
  const shown = rows.slice(0, MAX_ROWS);
  return (
    <div className="mono text-[12px] leading-[20px] overflow-x-auto scroll-thin rounded-lg bg-panel-2 p-2">
      {shown.map((r) => (
        <div key={r} className="flex gap-3 whitespace-nowrap">
          <span className="text-muted tnum select-none">{r.toString(16).padStart(4, "0")}</span>
          <span className="flex">
            {bytes.slice(r, r + 8).map((b, j) => {
              const i = r + j;
              const l = byteLayer[i];
              const hit = focus && i >= focus.start && i < focus.end;
              return (
                <button
                  key={j}
                  onClick={() => onPick(i)}
                  className={`osi-${layers[l]?.osi ?? 7} px-[3px] rounded-md ${j === 4 ? "ml-1.5" : ""}`}
                  style={{
                    background: hit ? "var(--lc)" : "transparent",
                    color: hit ? "var(--panel)" : opaque[i] ? "var(--muted)" : "var(--lc)",
                    opacity: opaque[i] && !hit ? 0.65 : 1,
                  }}
                  tabIndex={-1}
                >
                  {b.toString(16).padStart(2, "0")}
                </button>
              );
            })}
          </span>
          <span className="text-muted">
            {bytes.slice(r, r + 8).map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "·")).join("")}
          </span>
        </div>
      ))}
      {rows.length > MAX_ROWS && <div className="text-muted pt-1">… {bytes.length - MAX_ROWS * 8} more bytes</div>}
    </div>
  );
}
