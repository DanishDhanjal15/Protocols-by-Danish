"use client";

import { useState } from "react";
import { Playground } from "@/components/tools/Playground";
import { LiveDns } from "@/components/tools/LiveDns";

// ---- Subnet Calculator ----

function SubnetCalc() {
  const [input, setInput] = useState("192.168.1.0/24");
  const parsed = parseSubnet(input.trim());

  return (
    <div className="card p-5">
      <h2 className="text-[18px] font-bold mb-1">Subnet calculator</h2>
      <p className="text-[13px] text-muted mb-3">Enter a CIDR like 192.168.1.0/24 or 10.0.0.0/8.</p>
      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="192.168.1.0/24"
        className="h-10 rounded-lg border border-line bg-panel px-3 text-[14px] w-full max-w-xs mono"
      />
      {parsed && (
        <table className="mt-4 text-[14px]">
          <tbody>
            {[
              ["Network", parsed.network],
              ["Broadcast", parsed.broadcast],
              ["Netmask", parsed.netmask],
              ["Wildcard", parsed.wildcard],
              ["Host range", `${parsed.firstHost} – ${parsed.lastHost}`],
              ["Total hosts", parsed.totalHosts.toLocaleString()],
              ["Usable hosts", Math.max(0, parsed.totalHosts - 2).toLocaleString()],
            ].map(([k, v]) => (
              <tr key={k} className="border-b border-line last:border-0">
                <td className="py-1.5 pr-4 font-semibold text-muted whitespace-nowrap">{k}</td>
                <td className="py-1.5 mono">{v}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {!parsed && input.trim() && <p className="mt-3 text-[13px] text-red-500">Invalid CIDR. Try 10.0.0.0/8.</p>}
    </div>
  );
}

function parseSubnet(cidr: string) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return null;
  const octets = [+m[1], +m[2], +m[3], +m[4]];
  const prefix = +m[5];
  if (octets.some((o) => o > 255) || prefix > 32) return null;
  const ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const net = (ip & mask) >>> 0;
  const bcast = (net | ~mask) >>> 0;
  const toStr = (n: number) => `${(n >>> 24) & 0xff}.${(n >>> 16) & 0xff}.${(n >>> 8) & 0xff}.${n & 0xff}`;
  return {
    network: toStr(net),
    broadcast: toStr(bcast),
    netmask: toStr(mask),
    wildcard: toStr((~mask) >>> 0),
    firstHost: toStr((net + 1) >>> 0),
    lastHost: toStr((bcast - 1) >>> 0),
    totalHosts: Math.pow(2, 32 - prefix),
  };
}

// ---- Port Lookup ----

const PORTS: [number, string, string][] = [
  [20, "FTP Data", "TCP"],
  [21, "FTP Control", "TCP"],
  [22, "SSH", "TCP"],
  [23, "Telnet", "TCP"],
  [25, "SMTP", "TCP"],
  [53, "DNS", "TCP/UDP"],
  [67, "DHCP Server", "UDP"],
  [68, "DHCP Client", "UDP"],
  [80, "HTTP", "TCP"],
  [110, "POP3", "TCP"],
  [123, "NTP", "UDP"],
  [143, "IMAP", "TCP"],
  [161, "SNMP", "UDP"],
  [179, "BGP", "TCP"],
  [443, "HTTPS", "TCP"],
  [445, "SMB", "TCP"],
  [500, "IKE (IPsec)", "UDP"],
  [514, "Syslog", "UDP"],
  [587, "SMTP Submission", "TCP"],
  [636, "LDAPS", "TCP"],
  [853, "DNS over TLS", "TCP"],
  [993, "IMAPS", "TCP"],
  [995, "POP3S", "TCP"],
  [1194, "OpenVPN", "UDP"],
  [1433, "MS SQL", "TCP"],
  [1883, "MQTT", "TCP"],
  [3306, "MySQL", "TCP"],
  [3389, "RDP", "TCP"],
  [5060, "SIP", "TCP/UDP"],
  [5432, "PostgreSQL", "TCP"],
  [5672, "AMQP", "TCP"],
  [5683, "CoAP", "UDP"],
  [6379, "Redis", "TCP"],
  [8080, "HTTP alt", "TCP"],
  [8443, "HTTPS alt", "TCP"],
  [8883, "MQTT over TLS", "TCP"],
  [27017, "MongoDB", "TCP"],
  [51820, "WireGuard", "UDP"],
];

function PortLookup() {
  const [q, setQ] = useState("");
  const query = q.trim().toLowerCase();
  const results = query
    ? PORTS.filter(([port, name]) => String(port).includes(query) || name.toLowerCase().includes(query))
    : PORTS;

  return (
    <div className="card p-5">
      <h2 className="text-[18px] font-bold mb-1">Port lookup</h2>
      <p className="text-[13px] text-muted mb-3">Search by port number or service name.</p>
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="443 or HTTPS"
        className="h-10 rounded-lg border border-line bg-panel px-3 text-[14px] w-full max-w-xs mono"
      />
      <div className="mt-3 max-h-64 overflow-y-auto">
        <table className="w-full text-[14px]">
          <thead>
            <tr className="border-b border-line text-[12px] text-muted uppercase">
              <th className="py-1.5 pr-3 text-left">Port</th>
              <th className="py-1.5 px-3 text-left">Service</th>
              <th className="py-1.5 pl-3 text-left">Protocol</th>
            </tr>
          </thead>
          <tbody>
            {results.map(([port, name, proto]) => (
              <tr key={port} className="border-b border-line last:border-0">
                <td className="py-1.5 pr-3 mono font-semibold">{port}</td>
                <td className="py-1.5 px-3">{name}</td>
                <td className="py-1.5 pl-3 text-muted">{proto}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ---- Main ----

export function ToolsView() {
  return (
    <div className="grid gap-6 md:grid-cols-2">
      <Playground />
      <SubnetCalc />
      <PortLookup />
      <LiveDns />
    </div>
  );
}
