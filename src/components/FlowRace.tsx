"use client";

import { useEffect, useRef, useState } from "react";
import { Play, RotateCcw } from "lucide-react";
import type { Lesson, PacketEvent } from "@/lib/lesson";
import { expandPacket } from "@/lib/catalog";
import { loaders } from "@/lessons";

interface Flow {
  name: string;
  scenario: string;
  packets: PacketEvent[];
  total: number;
  bytes: number;
  firstData?: number;
}

const HANDSHAKE = /SYN|ACK|HELLO|HANDSHAKE|FIN|INIT|KEX|NEWKEYS|FINISHED|CCS|CERT|KEY|QUERY|RESPONSE/i;

function toFlow(l: Lesson): Flow {
  const sc = l.scenarios[0];
  const packets = sc.steps.flatMap((s) => s.events.filter((e): e is PacketEvent => e.type === "packet"));
  const bytes = packets.reduce((n, p) => n + expandPacket(p.packet).bytes.length, 0);
  const t0 = packets[0]?.time ?? 0;
  const firstData = packets.find((p) => !HANDSHAKE.test(p.label))?.time;
  return {
    name: l.name,
    scenario: sc.name,
    packets,
    total: (packets[packets.length - 1]?.time ?? 0) - t0,
    bytes,
    firstData: firstData !== undefined ? firstData - t0 : undefined,
  };
}

export function FlowRace({ ids }: { ids: string[] }) {
  const [flows, setFlows] = useState<(Flow | null)[]>([]);
  const [head, setHead] = useState(1);
  const raf = useRef(0);

  useEffect(() => {
    let live = true;
    Promise.all(ids.map((id) => loaders[id]?.().then((m) => toFlow(m.default)).catch(() => null) ?? Promise.resolve(null))).then((f) => {
      if (live) {
        setFlows(f);
        setHead(1);
      }
    });
    return () => {
      live = false;
    };
  }, [ids]);

  const max = Math.max(0.001, ...flows.map((f) => f?.total ?? 0));

  const race = () => {
    cancelAnimationFrame(raf.current);
    const start = performance.now();
    const dur = 4500;
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / dur);
      setHead(p);
      if (p < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
  };
  useEffect(() => () => cancelAnimationFrame(raf.current), []);

  if (!flows.length) return <div className="card p-5 text-muted text-[14px]">Loading packet timelines…</div>;

  return (
    <div className="card p-5 flex flex-col gap-4 min-w-0">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex-1 min-w-[200px]">
          <h2 className="text-[18px] font-bold">Packet race</h2>
          <p className="text-[13px] text-muted">Every packet of each lesson’s main scenario on one shared clock. Hover a tick to see the packet.</p>
        </div>
        <button className="btn btn-primary" onClick={race}><Play size={16} fill="currentColor" /> Race</button>
        <button className="icon-btn" onClick={() => setHead(1)} aria-label="Show all"><RotateCcw size={16} /></button>
      </div>

      <div className="flex flex-col gap-4">
        {flows.map((f, i) =>
          f ? (
            <div key={i} className="grid gap-2">
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="font-bold text-[15px]">{f.name}</span>
                <span className="text-[12.5px] text-muted truncate">{f.scenario}</span>
                <span className="flex-1" />
                <span className="chip tnum">{f.packets.length} packets</span>
                <span className="chip tnum">{(f.total * 1000).toFixed(0)} ms</span>
                <span className="chip tnum">{f.bytes.toLocaleString("en-IN")} bytes</span>
                {f.firstData !== undefined && <span className="chip tnum">first data at {(f.firstData * 1000).toFixed(0)} ms</span>}
              </div>
              <div className="relative h-12 rounded-lg bg-panel-2 overflow-hidden">
                {f.packets.map((p, j) => {
                  const x = ((p.time - (f.packets[0]?.time ?? 0)) / max) * 100;
                  const shown = x / 100 <= head + 1e-6;
                  const up = p.from < p.to; // stable visual split by direction
                  return (
                    <span
                      key={j}
                      title={`${p.time.toFixed(3)} s · ${p.label} · ${p.info}`}
                      className={`absolute w-[3px] rounded-full c-${p.color} transition-opacity`}
                      style={{ left: `calc(${Math.min(x, 99.6)}% )`, top: up ? 6 : 24, height: 18, background: "var(--c)", opacity: shown ? (p.lost ? 0.35 : 1) : 0.08 }}
                    />
                  );
                })}
                <span className="absolute top-0 bottom-0 w-px bg-[var(--brand)]" style={{ left: `${head * 100}%`, opacity: head < 1 ? 1 : 0 }} />
              </div>
            </div>
          ) : (
            <p key={i} className="text-[13px] text-muted">This lesson couldn’t be loaded.</p>
          )
        )}
        <div className="flex justify-between text-[11.5px] mono text-muted tnum">
          <span>0 ms</span>
          <span>{((max * 1000) / 2).toFixed(0)} ms</span>
          <span>{(max * 1000).toFixed(0)} ms</span>
        </div>
      </div>
    </div>
  );
}
