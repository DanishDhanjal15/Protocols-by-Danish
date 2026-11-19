"use client";

import { useMemo, useState } from "react";
import { build, flatten, textLayer } from "@/lib/packet";
import { eth, ipv4, tcp, udp } from "@/lib/proto";
import { toHex } from "@/lib/bytes";

/** Edit a real packet's fields and watch the bytes and checksums change. */
export function Playground() {
  const [src, setSrc] = useState("192.168.1.10");
  const [dst, setDst] = useState("203.0.113.10");
  const [ttl, setTtl] = useState(64);
  const [proto, setProto] = useState<"tcp" | "udp">("tcp");
  const [sport, setSport] = useState(51234);
  const [dport, setDport] = useState(80);
  const [flags, setFlags] = useState("S");
  const [payload, setPayload] = useState("");
  const [hover, setHover] = useState<string | null>(null);

  const result = useMemo(() => {
    try {
      const l4 = proto === "tcp" ? tcp({ sport, dport, seq: 0, flags: flags || "A", seqBase: 0x6a1f2c00 }) : udp({ sport, dport });
      const layers = [eth({ src: "3c:22:fb:7a:91:0e", dst: "b0:be:76:12:4c:01" }), ipv4({ src, dst, ttl }), l4];
      if (payload) layers.push(textLayer({ id: "data", name: "Payload", lines: [], body: { text: payload, what: "Your text" } }));
      const p = build(...layers);
      return { p, flat: flatten(p), error: null as string | null };
    } catch (e) {
      return { p: null, flat: [], error: (e as Error).message };
    }
  }, [src, dst, ttl, proto, sport, dport, flags, payload]);

  const hit = result.flat.find((f) => f.key === hover);
  const highlight = (name: string) => result.flat.find((f) => f.depth === 0 && f.field.name === name);

  const num = (v: string, max: number) => Math.max(0, Math.min(max, Number(v) || 0));
  const input = "h-9 rounded-lg border border-line bg-panel px-2.5 text-[13.5px] mono w-full";

  return (
    <div className="card p-5 md:col-span-2 flex flex-col gap-4">
      <div>
        <h2 className="text-[18px] font-bold">Packet playground <span className="text-[13px] font-medium text-muted">· a mini Wireshark you can edit</span></h2>
        <p className="text-[13px] text-muted">Works like Wireshark’s packet view: every field on the left, the raw hex bytes on the right. Change any field and the IPv4 and {proto.toUpperCase()} checksums are recomputed on every keystroke, exactly as a real network stack would. The lesson player’s Packet tab uses the same decoder.</p>
      </div>
      <div className="grid gap-3 grid-cols-2 sm:grid-cols-4">
        <label className="grid gap-1 text-[12px] text-muted">Source IP<input id="pg-src" className={input} value={src} onChange={(e) => setSrc(e.target.value)} onFocus={() => setHover(highlight("Source address")?.key ?? null)} /></label>
        <label className="grid gap-1 text-[12px] text-muted">Destination IP<input id="pg-dst" className={input} value={dst} onChange={(e) => setDst(e.target.value)} onFocus={() => setHover(highlight("Destination address")?.key ?? null)} /></label>
        <label className="grid gap-1 text-[12px] text-muted">TTL<input id="pg-ttl" type="number" className={input} value={ttl} onChange={(e) => setTtl(num(e.target.value, 255))} onFocus={() => setHover(highlight("Time to live")?.key ?? null)} /></label>
        <label className="grid gap-1 text-[12px] text-muted">Transport
          <select id="pg-proto" className={input} value={proto} onChange={(e) => setProto(e.target.value as "tcp" | "udp")}>
            <option value="tcp">TCP</option><option value="udp">UDP</option>
          </select>
        </label>
        <label className="grid gap-1 text-[12px] text-muted">Source port<input id="pg-sport" type="number" className={input} value={sport} onChange={(e) => setSport(num(e.target.value, 65535))} onFocus={() => setHover(highlight("Source port")?.key ?? null)} /></label>
        <label className="grid gap-1 text-[12px] text-muted">Destination port<input id="pg-dport" type="number" className={input} value={dport} onChange={(e) => setDport(num(e.target.value, 65535))} onFocus={() => setHover(highlight("Destination port")?.key ?? null)} /></label>
        {proto === "tcp" && (
          <label className="grid gap-1 text-[12px] text-muted">TCP flags (S A P F R)<input id="pg-flags" className={input} value={flags} onChange={(e) => setFlags(e.target.value.toUpperCase().replace(/[^SAPFRUEC]/g, ""))} onFocus={() => setHover(highlight("Flags")?.key ?? null)} /></label>
        )}
        <label className="grid gap-1 text-[12px] text-muted col-span-2 sm:col-span-1">Payload text<input id="pg-payload" className={input} value={payload} placeholder="hello" onChange={(e) => setPayload(e.target.value.slice(0, 200))} /></label>
      </div>

      {result.error ? (
        <p className="text-[13.5px]" style={{ color: "var(--c-red)" }}>That value can’t go in a packet: {result.error}. Fix the field above.</p>
      ) : result.p && (
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <ul className="text-[12.5px] rounded-lg border border-line divide-y divide-[var(--line)] max-h-[340px] overflow-auto scroll-thin">
            {result.flat.filter((f) => f.depth === 0).map((f) => (
              <li key={f.key}>
                <button onMouseEnter={() => setHover(f.key)} onFocus={() => setHover(f.key)} className={`w-full text-left px-3 py-1.5 grid grid-cols-[minmax(0,1fr)_auto] gap-2 osi-${result.p!.layers[f.layer].osi} ${hover === f.key ? "bg-panel-2" : ""}`}>
                  <span><span className="font-semibold" style={{ color: "var(--lc)" }}>{result.p!.layers[f.layer].name}</span> · {f.field.name}: <span className="mono">{f.field.value}</span></span>
                  <span className="mono text-muted">{f.end - f.start}B</span>
                </button>
              </li>
            ))}
          </ul>
          <div className="mono text-[12px] leading-[20px] rounded-lg bg-panel-2 p-2 overflow-x-auto scroll-thin">
            {Array.from({ length: Math.ceil(result.p.bytes.length / 16) }, (_, r) => (
              <div key={r} className="flex gap-3 whitespace-nowrap">
                <span className="text-muted">{(r * 16).toString(16).padStart(4, "0")}</span>
                <span>
                  {result.p!.bytes.slice(r * 16, r * 16 + 16).map((b, j) => {
                    const i = r * 16 + j;
                    const on = hit && i >= hit.start && i < hit.end;
                    return <span key={j} className={`px-[3px] rounded-lg ${j === 8 ? "ml-1.5" : ""}`} style={{ background: on ? "var(--brand)" : undefined, color: on ? "var(--brand-ink)" : undefined }}>{toHex([b])}</span>;
                  })}
                </span>
              </div>
            ))}
            <div className="text-muted pt-1">{result.p.bytes.length} bytes on the wire</div>
          </div>
        </div>
      )}
    </div>
  );
}
