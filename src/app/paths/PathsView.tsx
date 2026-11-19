"use client";

import Link from "next/link";
import { CheckCircle2, Circle } from "lucide-react";
import type { LessonMeta } from "@/lib/catalog";
import { useApp } from "@/components/Providers";

interface Path {
  id: string;
  name: string;
  desc: string;
  lessons: string[];
}

const PATHS: Path[] = [
  {
    id: "web-request",
    name: "Life of a web request",
    desc: "Follow a request from your keyboard to the server and back. Start with IP, go through DNS, TCP, TLS, and HTTP.",
    lessons: ["journey", "ip", "dns", "tcp", "tls", "http", "https", "http2", "quic"],
  },
  {
    id: "first-hop",
    name: "The first hop",
    desc: "What happens on your local network before packets reach the internet.",
    lessons: ["ethernet", "arp", "dhcp", "vlan", "wifi", "nat"],
  },
  {
    id: "security",
    name: "Security deep dive",
    desc: "Encryption, authentication, and trust: how the internet stays safe.",
    lessons: ["tls", "ssh", "mtls", "oauth", "kerberos", "ldap", "radius", "wireguard", "ipsec"],
  },
  {
    id: "realtime",
    name: "Real-time communication",
    desc: "Voice calls, video streams, and live media delivery.",
    lessons: ["udp", "webrtc", "sip", "rtsp", "rtmp"],
  },
  {
    id: "routing",
    name: "How the internet finds routes",
    desc: "From your home router to the global backbone.",
    lessons: ["ip", "icmp", "bgp", "ospf", "mpls"],
  },
  {
    id: "iot",
    name: "IoT and industrial",
    desc: "Lightweight protocols for sensors, controllers, and constrained devices.",
    lessons: ["mqtt", "coap", "modbus", "snmp", "ble"],
  },
  {
    id: "email",
    name: "How email works",
    desc: "Sending, receiving, and securing email.",
    lessons: ["dns", "smtp", "imap", "pop3", "emailauth"],
  },
];

export function PathsView({ catalog }: { catalog: LessonMeta[] }) {
  const { progress } = useApp();

  return (
    <div className="flex flex-col gap-8">
      {PATHS.map((path) => {
        const resolved = path.lessons
          .map((id) => catalog.find((m) => m.id === id))
          .filter((m): m is LessonMeta => !!m);
        const completed = resolved.filter((m) => progress.done.includes(m.id)).length;
        const pct = resolved.length ? Math.round((completed / resolved.length) * 100) : 0;

        return (
          <section key={path.id} className="card p-5">
            <div className="flex items-start justify-between gap-4 flex-wrap">
              <div>
                <h2 className="text-[20px] font-bold">{path.name}</h2>
                <p className="text-[13.5px] text-muted mt-0.5 max-w-lg">{path.desc}</p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className="relative w-20 h-2 rounded-full bg-panel-3 overflow-hidden">
                  <span
                    className="absolute inset-y-0 left-0 bg-brand rounded-full transition-all"
                    style={{ width: `${pct}%` }}
                  />
                </span>
                <span className="text-[13px] text-muted tnum mono">
                  {completed}/{resolved.length}
                </span>
              </div>
            </div>
            <ol className="mt-4 flex flex-col gap-1">
              {resolved.map((m, i) => {
                const done = progress.done.includes(m.id);
                return (
                  <li key={m.id}>
                    <Link
                      href={`/learn/${m.id}`}
                      className="flex items-center gap-3 py-2 px-3 -mx-3 rounded-lg hover:bg-panel-2 transition-colors"
                    >
                      {done ? (
                        <CheckCircle2 size={18} style={{ color: "var(--c-green)" }} />
                      ) : (
                        <Circle size={18} className="text-line-2" />
                      )}
                      <span className="text-[14px] text-muted w-5 tnum">{i + 1}.</span>
                      <span className={`text-[14px] font-medium ${done ? "text-muted" : ""}`}>
                        {m.name}
                      </span>
                      <span className="text-[12.5px] text-muted truncate">{m.tagline}</span>
                    </Link>
                  </li>
                );
              })}
            </ol>
          </section>
        );
      })}
    </div>
  );
}
