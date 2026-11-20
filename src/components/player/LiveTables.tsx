"use client";

import { useMemo } from "react";
import { expandPacket } from "@/lib/catalog";
import type { Field, Layer } from "@/lib/packet";
import type { Captured } from "./usePlayer";

// Tables a real host would keep, rebuilt from the packets captured so far:
// ARP / neighbour cache, DNS cache, and the connection table (like netstat).

const val = (l: Layer | undefined, name: string) => l?.fields.find((f) => f.name === name)?.value;
const isPrivate = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:)/i.test(ip);

interface ArpRow { ip: string; mac: string; how: string; no: number }
interface DnsRow { name: string; type: string; data: string; ttl: string; no: number }
interface ConnRow { key: string; proto: string; a: string; b: string; state: string; packets: number; bytes: number; last: number; fin: Set<string> }

function tcpState(prev: string | undefined, flags: string, fromA: boolean, fin: Set<string>): string {
  const has = (f: string) => flags.includes(f);
  if (has("RST")) return "RESET";
  if (has("SYN") && !has("ACK")) return "SYN_SENT";
  if (has("SYN") && has("ACK")) return "SYN_RECEIVED";
  if (has("FIN")) {
    fin.add(fromA ? "a" : "b");
    return fin.size >= 2 ? "CLOSING" : "FIN_WAIT";
  }
  if (prev === "CLOSING" && has("ACK")) return "CLOSED";
  if (prev === "SYN_RECEIVED" || prev === "SYN_SENT") return "ESTABLISHED";
  return prev ?? "ESTABLISHED";
}

function dnsAnswers(l: Layer): { name: string; type: string; data: string; ttl: string }[] {
  const out: { name: string; type: string; data: string; ttl: string }[] = [];
  const walk = (fs: Field[]) => {
    for (const f of fs) {
      if (/^(A|AAAA|CNAME|MX|TXT|NS|PTR|HTTPS|SRV|DS|DNSKEY|RRSIG) record/.test(f.name) && f.children) {
        const c = (n: string) => f.children!.find((x) => x.name === n)?.value ?? "";
        out.push({ name: c("Name"), type: c("Type").replace(/^\d+ \((.*)\)$/, "$1"), data: c("Data"), ttl: c("Time to live") });
      }
    }
  };
  walk(l.fields);
  return out;
}

export function deriveTables(rows: Captured[]) {
  const arp = new Map<string, ArpRow>();
  const dns = new Map<string, DnsRow>();
  const conns = new Map<string, ConnRow>();
  for (const c of rows) {
    if (c.ev.lost) continue;
    const p = expandPacket(c.ev.packet);
    const by = (id: string) => p.layers.find((l) => l.id === id);
    const eth = by("eth");
    const ip = by("ipv4") ?? by("ipv6");
    const arpL = by("arp");
    if (arpL) {
      const ipv = val(arpL, "Sender IP"), macv = val(arpL, "Sender MAC");
      if (ipv && macv) arp.set(ipv, { ip: ipv, mac: macv, how: val(arpL, "Opcode")?.includes("reply") ? "ARP reply" : "ARP request", no: c.no });
    } else if (eth && ip) {
      const src = val(ip, "Source address");
      const mac = val(eth, "Source");
      if (src && mac && isPrivate(src) && !arp.has(src)) arp.set(src, { ip: src, mac, how: "seen in a frame", no: c.no });
    }
    const dnsL = by("dns");
    if (dnsL) for (const a of dnsAnswers(dnsL)) dns.set(`${a.name}|${a.type}|${a.data}`, { ...a, no: c.no });

    const l4 = by("tcp") ?? by("udp");
    if (ip && l4) {
      const sa = `${val(ip, "Source address")}:${val(l4, "Source port")}`;
      const da = `${val(ip, "Destination address")}:${val(l4, "Destination port")}`;
      const [a, b] = [sa, da].sort();
      const key = `${l4.id}|${a}|${b}`;
      const row = conns.get(key) ?? { key, proto: l4.id.toUpperCase(), a: sa, b: da, state: "", packets: 0, bytes: 0, last: c.no, fin: new Set<string>() };
      row.packets++;
      row.bytes += p.bytes.length;
      row.last = c.no;
      row.state = l4.id === "tcp" ? tcpState(row.state || undefined, val(l4, "Flags") ?? "", sa === row.a, row.fin) : "ACTIVE";
      conns.set(key, row);
    }
  }
  return { arp: [...arp.values()], dns: [...dns.values()], conns: [...conns.values()] };
}

const STATE_COLOR: Record<string, string> = {
  ESTABLISHED: "var(--c-green)", SYN_SENT: "var(--c-amber)", SYN_RECEIVED: "var(--c-amber)", FIN_WAIT: "var(--c-slate)",
  CLOSING: "var(--c-slate)", CLOSED: "var(--muted)", RESET: "var(--c-red)", ACTIVE: "var(--c-blue)",
};

export function LiveTables({ rows, lang }: { rows: Captured[]; lang: "en" | "hinglish" }) {
  const t = useMemo(() => deriveTables(rows), [rows]);
  const lastNo = rows[rows.length - 1]?.no;
  const H = lang === "hinglish"
    ? { arp: "ARP / neighbour cache", arpE: "Abhi tak koi local MAC address nahi seekha.", dns: "DNS cache", dnsE: "Abhi tak koi DNS answer nahi aaya.", conn: "Connections (netstat jaisa)", connE: "Abhi tak koi TCP/UDP flow nahi.", note: "Yeh tables capture hue packets se bani hain, bilkul waise jaise ek asli computer banata hai. Naya entry highlight hota hai." }
    : { arp: "ARP / neighbour cache", arpE: "No local MAC address learned yet.", dns: "DNS cache", dnsE: "No DNS answers seen yet.", conn: "Connections (like netstat)", connE: "No TCP/UDP flows yet.", note: "Built from the captured packets, the way a real computer builds them. New entries are highlighted." };

  const cls = (no: number) => (no === lastNo ? "bg-brand-soft" : "");
  const th = "text-left font-semibold text-muted px-2 py-1.5 text-[11.5px]";
  const td = "px-2 py-1.5 whitespace-nowrap";

  return (
    <div className="h-full overflow-auto p-3 flex flex-col gap-3">
      <p className="text-[12px] text-muted">{H.note}</p>
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <section className="rounded-lg border border-line overflow-hidden min-w-0">
          <h3 className="hud-title px-3 py-2 bg-panel-2">{H.arp}</h3>
          {t.arp.length ? (
            <div className="overflow-x-auto"><table className="w-full mono text-[12px]">
              <thead><tr><th className={th}>IP</th><th className={th}>MAC</th><th className={th}>From</th></tr></thead>
              <tbody>{t.arp.map((r) => <tr key={r.ip} className={`border-t border-line ${cls(r.no)}`}><td className={td}>{r.ip}</td><td className={td}>{r.mac}</td><td className={`${td} text-muted`}>{r.how}</td></tr>)}</tbody>
            </table></div>
          ) : <p className="px-3 py-3 text-[12.5px] text-muted">{H.arpE}</p>}
        </section>
        <section className="rounded-lg border border-line overflow-hidden min-w-0">
          <h3 className="hud-title px-3 py-2 bg-panel-2">{H.dns}</h3>
          {t.dns.length ? (
            <div className="overflow-x-auto"><table className="w-full mono text-[12px]">
              <thead><tr><th className={th}>Name</th><th className={th}>Type</th><th className={th}>Answer</th><th className={th}>TTL</th></tr></thead>
              <tbody>{t.dns.map((r, i) => <tr key={i} className={`border-t border-line ${cls(r.no)}`}><td className={td}>{r.name}</td><td className={td}>{r.type}</td><td className={`${td} max-w-[220px] overflow-hidden text-ellipsis`}>{r.data}</td><td className={td}>{r.ttl}</td></tr>)}</tbody>
            </table></div>
          ) : <p className="px-3 py-3 text-[12.5px] text-muted">{H.dnsE}</p>}
        </section>
      </div>
      <section className="rounded-lg border border-line overflow-hidden min-w-0">
        <h3 className="hud-title px-3 py-2 bg-panel-2">{H.conn}</h3>
        {t.conns.length ? (
          <div className="overflow-x-auto"><table className="w-full mono text-[12px]">
            <thead><tr><th className={th}>Proto</th><th className={th}>Endpoint A</th><th className={th}>Endpoint B</th><th className={th}>State</th><th className={th}>Packets</th><th className={th}>Bytes</th></tr></thead>
            <tbody>{t.conns.map((r) => (
              <tr key={r.key} className={`border-t border-line ${cls(r.last)}`}>
                <td className={td}>{r.proto}</td><td className={td}>{r.a}</td><td className={td}>{r.b}</td>
                <td className={td}><span className="font-semibold" style={{ color: STATE_COLOR[r.state] ?? "var(--ink)" }}>{r.state}</span></td>
                <td className={td}>{r.packets}</td><td className={td}>{r.bytes.toLocaleString("en-IN")}</td>
              </tr>
            ))}</tbody>
          </table></div>
        ) : <p className="px-3 py-3 text-[12.5px] text-muted">{H.connE}</p>}
      </section>
    </div>
  );
}
