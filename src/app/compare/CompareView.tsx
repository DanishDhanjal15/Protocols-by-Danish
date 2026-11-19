"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { FlowRace } from "@/components/FlowRace";
import { OSI_NAMES } from "@/lib/lesson";
import type { LessonMeta } from "@/lib/catalog";

const DIFF = ["", "Beginner", "Intermediate", "Advanced"];

const PRESETS: [string, string, string][] = [
  ["TCP vs UDP", "tcp", "udp"],
  ["HTTP/2 vs HTTP/3 (QUIC)", "http2", "quic"],
  ["HTTP vs HTTPS", "http", "https"],
  ["DNS vs DNS over HTTPS", "dns", "doh"],
  ["WireGuard vs IPsec", "wireguard", "ipsec"],
  ["POP3 vs IMAP", "pop3", "imap"],
  ["MQTT vs CoAP", "mqtt", "coap"],
];

function Selector({
  label,
  value,
  onChange,
  catalog,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  catalog: LessonMeta[];
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[13px] font-semibold text-muted">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="h-10 rounded-lg border border-line bg-panel px-3 text-[14px] min-w-[200px]"
      >
        <option value="">Pick a protocol</option>
        {catalog.map((m) => (
          <option key={m.id} value={m.id}>
            {m.name} — {m.full}
          </option>
        ))}
      </select>
    </label>
  );
}

function Row({ label, a, b }: { label: string; a: string; b: string }) {
  return (
    <tr className="border-b border-line last:border-0">
      <td className="py-2.5 pr-4 text-[13px] font-semibold text-muted whitespace-nowrap align-top">{label}</td>
      <td className="py-2.5 px-4 text-[14px]">{a || "—"}</td>
      <td className="py-2.5 pl-4 text-[14px]">{b || "—"}</td>
    </tr>
  );
}

export function CompareView({ catalog }: { catalog: LessonMeta[] }) {
  const [aId, setAId] = useState("tcp");
  const [bId, setBId] = useState("udp");
  const raceIds = useMemo(() => [aId, bId].filter(Boolean), [aId, bId]);
  const a = catalog.find((m) => m.id === aId);
  const b = catalog.find((m) => m.id === bId);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap gap-1.5">
        {PRESETS.filter(([, x, y]) => catalog.some((m) => m.id === x) && catalog.some((m) => m.id === y)).map(([label, x, y]) => (
          <button
            key={label}
            onClick={() => { setAId(x); setBId(y); }}
            className={`h-8 px-3 rounded-lg text-[12.5px] font-semibold border ${aId === x && bId === y ? "bg-panel-3 text-ink border-line-2" : "bg-panel border-line text-ink-2 hover:border-line-2"}`}
          >
            {label}
          </button>
        ))}
      </div>
      <div className="flex flex-wrap gap-4">
        <Selector label="Protocol A" value={aId} onChange={setAId} catalog={catalog} />
        <Selector label="Protocol B" value={bId} onChange={setBId} catalog={catalog} />
      </div>

      {a && b && (
        <div className="card overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="border-b border-line">
                <th className="py-3 pr-4 text-[13px] font-semibold text-muted w-[120px]" />
                <th className="py-3 px-4 text-[16px] font-bold">
                  <Link href={`/learn/${a.id}`} className="hover:underline">
                    {a.name}
                  </Link>
                </th>
                <th className="py-3 pl-4 text-[16px] font-bold">
                  <Link href={`/learn/${b.id}`} className="hover:underline">
                    {b.name}
                  </Link>
                </th>
              </tr>
            </thead>
            <tbody>
              <Row label="Full name" a={a.full} b={b.full} />
              <Row label="OSI layer" a={`L${a.layer} ${OSI_NAMES[a.layer]}`} b={`L${b.layer} ${OSI_NAMES[b.layer]}`} />
              <Row label="Difficulty" a={DIFF[a.difficulty]} b={DIFF[b.difficulty]} />
              <Row label="Ports" a={a.ports ?? "—"} b={b.ports ?? "—"} />
              <Row label="RFC" a={a.rfc ?? "—"} b={b.rfc ?? "—"} />
              <Row label="Tagline" a={a.tagline} b={b.tagline} />
              <Row label="Scenarios" a={String(a.scenarios.length)} b={String(b.scenarios.length)} />
              <Row label="Packets" a={String(a.packets)} b={String(b.packets)} />
            </tbody>
          </table>
        </div>
      )}

      {a && b && <FlowRace ids={raceIds} />}

      {(!a || !b) && (
        <p className="text-muted text-[14px]">Select two protocols above to see them side by side.</p>
      )}
    </div>
  );
}
