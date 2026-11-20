"use client";

import { useMemo } from "react";
import type { Device } from "@/lib/lesson";
import { OSI_NAMES } from "@/lib/lesson";
import { expandPacket } from "@/lib/catalog";
import { Field, Layer, layerBytes } from "@/lib/packet";
import { Captured, PlayerApi, useProgress } from "./usePlayer";

// The fields worth showing on each envelope, by layer id. Others: first short fields.
const KEY_FIELDS: Record<string, string[]> = {
  eth: ["Source", "Destination", "Type"],
  vlan: ["Priority, VLAN ID"],
  arp: ["Opcode", "Sender IP", "Target IP"],
  ipv4: ["Source address", "Destination address", "Time to live", "Protocol"],
  ipv6: ["Source address", "Destination address", "Hop limit", "Next header"],
  tcp: ["Source port", "Destination port", "Flags", "Sequence number"],
  udp: ["Source port", "Destination port", "Length"],
  icmp: ["Type", "Code"],
};

function keyFields(l: Layer): Field[] {
  const want = KEY_FIELDS[l.id];
  if (want) return want.map((n) => l.fields.find((f) => f.name === n)).filter((f): f is Field => !!f);
  return l.fields.filter((f) => !f.opaque && f.value.length <= 42).slice(0, 3);
}

type Phase = "wrap" | "wire" | "unwrap" | "still";

export function EncapView({ api, selected, devices, lang }: { api: PlayerApi; selected?: Captured; devices: Device[]; lang: "en" | "hinglish" }) {
  const progress = useProgress(api.store);
  const flying = api.groups[api.groupIdx]?.packets[0];
  const live = !!flying && (api.playing || progress > 0);
  const cap = live ? flying : selected;
  const packet = useMemo(() => (cap ? expandPacket(cap.ev.packet) : null), [cap]);

  if (!cap || !packet) {
    return (
      <div className="h-full grid place-items-center p-6 text-center text-muted text-[14px]">
        {lang === "hinglish" ? "Play dabao: har packet yahan layers mein khulta aur band hota dikhega." : "Press play: each packet will be wrapped and unwrapped here, layer by layer."}
      </div>
    );
  }

  const layers = packet.layers.filter((l) => l.id !== "data" || packet.layers.length === 1);
  const payload = packet.layers.find((l) => l.id === "data");
  const n = layers.length;

  // how many layers are visible, from the innermost outwards
  let phase: Phase = "still";
  let shown = n;
  if (live) {
    if (progress < 0.35) { phase = "wrap"; shown = Math.max(1, Math.ceil((progress / 0.35) * n)); }
    else if (progress < 0.65) phase = "wire";
    else { phase = "unwrap"; shown = Math.max(1, n - Math.floor(((progress - 0.65) / 0.35) * n)); }
  }
  const from = devices.find((d) => d.id === cap.ev.from)?.label ?? cap.ev.from;
  const to = devices.find((d) => d.id === cap.ev.to)?.label ?? cap.ev.to;
  const visible = layers.slice(n - shown);

  const T = lang === "hinglish"
    ? { wrap: `${from} packet ko wrap kar raha hai (encapsulation)`, wire: "Wire par: poora frame ja raha hai", unwrap: `${to} packet ko khol raha hai (decapsulation)`, still: "Selected packet", hdr: "header", data: "Data" }
    : { wrap: `${from} wraps the data (encapsulation)`, wire: "On the wire: the whole frame travels", unwrap: `${to} unwraps it (decapsulation)`, still: "Selected packet", hdr: "header", data: "Data" };

  const render = (i: number): React.ReactNode => {
    if (i >= visible.length) {
      const inner = payload && visible[visible.length - 1] !== payload ? payload : null;
      return inner ? (
        <div className="rounded-lg border border-dashed border-line-2 px-3 py-2 text-[12.5px] text-ink-2">
          <span className="font-semibold text-ink">{T.data}</span> · {layerBytes(inner).length} B
          <span className="text-muted"> · {inner.fields[0]?.name}</span>
        </div>
      ) : null;
    }
    const l = visible[i];
    const outermostNew = live && i === 0 && (phase === "wrap" || phase === "unwrap");
    return (
      <div className={`osi-${l.osi} rounded-xl border-2 p-2.5 pt-2 transition-all duration-300 ${outermostNew ? "fade-up" : ""}`} style={{ borderColor: "var(--lc)", background: "color-mix(in srgb, var(--ls) 60%, transparent)" }}>
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 mb-2">
          <span className="mono text-[10.5px] font-bold px-1.5 rounded" style={{ background: "var(--lc)", color: "var(--bg)" }}>L{l.osi}</span>
          <span className="font-semibold text-[13.5px] text-ink">{l.name}</span>
          <span className="text-[11.5px] text-muted">{OSI_NAMES[l.osi]} · {layerBytes(l).length} B {T.hdr}</span>
          <span className="flex-1" />
          <span className="flex flex-wrap gap-1">
            {keyFields(l).map((f) => (
              <span key={f.name} className="mono text-[11px] px-1.5 py-0.5 rounded bg-[rgba(0,0,0,.25)] text-ink-2" title={f.note}>
                <span className="text-muted">{f.name}:</span> {f.value}
              </span>
            ))}
          </span>
        </div>
        {render(i + 1)}
      </div>
    );
  };

  return (
    <div className="h-full overflow-auto p-4 sm:p-6 flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
        {(["wrap", "wire", "unwrap"] as const).map((p, k) => (
          <span key={p} className={`px-2.5 py-1 rounded-full border ${phase === p ? "border-brand text-ink bg-brand-soft" : "border-line text-muted"}`}>
            {k + 1}. {p === "wrap" ? (lang === "hinglish" ? "Wrap" : "Wrap") : p === "wire" ? (lang === "hinglish" ? "Wire" : "Wire") : (lang === "hinglish" ? "Unwrap" : "Unwrap")}
          </span>
        ))}
        <span className="flex-1" />
        <span className={`c-${cap.ev.color} inline-flex items-center gap-1.5 text-ink-2`}><span className="dot" />#{cap.no} {cap.ev.label}</span>
      </div>
      <div className="text-[14px] font-semibold text-ink">{T[phase]}</div>
      <div className="max-w-[820px] w-full">{render(0)}</div>
      <p className="text-[12px] text-muted">
        {lang === "hinglish"
          ? "Har layer apna header aage jodti hai: sabse andar app ka data, sabse bahar Ethernet. Receiver ulta karta hai: bahar se andar ki taraf ek-ek header hatata hai."
          : "Each layer adds its own header in front: the app's data sits innermost, Ethernet is outermost. The receiver does the reverse, peeling one header at a time from the outside in."}
      </p>
    </div>
  );
}
