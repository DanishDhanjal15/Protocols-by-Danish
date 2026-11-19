// Ready-made layer builders for the common protocols. Each returns a LayerSpec
// for build(). Lengths and checksums are computed from the real bytes.

import {
  Bytes, fmtIp4, fmtIp6, fmtMac, hex, inetChecksum, ip4, ip6, mac, text, toHex, u16, u32, u8, zeros,
} from "./bytes";
import { Field, FieldSpec, LayerSpec, field, layerBytes } from "./packet";

// ---------------------------------------------------------------- Ethernet

const ETHERTYPE_NAMES: Record<number, string> = {
  0x0800: "IPv4", 0x86dd: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q VLAN", 0x8863: "PPPoE Discovery",
  0x8864: "PPPoE Session", 0x888e: "EAPOL (802.1X)", 0x88cc: "LLDP", 0x8847: "MPLS",
};

export const BROADCAST_MAC = "ff:ff:ff:ff:ff:ff";

export function eth(o: { src: string; dst: string; type?: number; pad?: boolean }): LayerSpec {
  return {
    kind: "eth",
    build: (payload, ctx) => {
      const type = o.type ?? ctx.inner?.ethertype ?? 0x0800;
      const dst = mac(o.dst), src = mac(o.src);
      const isBcast = o.dst.toLowerCase() === BROADCAST_MAC;
      const isMcast = (dst[0] & 1) === 1;
      const fields: Field[] = [
        field({ name: "Destination", bytes: dst, value: fmtMac(dst), note: isBcast ? "Broadcast: every device on the network receives it." : isMcast ? "A multicast address: every device that joined the group listens." : "The MAC address of the next device on this link." }),
        field({ name: "Source", bytes: src, value: fmtMac(src), note: "The sender’s network card." }),
        field({ name: "Type", u16: type, value: `0x${type.toString(16).padStart(4, "0")} (${ETHERTYPE_NAMES[type] ?? "?"})`, note: `What is inside: ${ETHERTYPE_NAMES[type] ?? "an unknown protocol"}.` }),
      ];
      const total = 14 + payload.length;
      const trailer = o.pad !== false && total < 60 ? [field({ name: "Padding", zero: 60 - total, note: "Ethernet frames are at least 60 bytes (plus a 4-byte FCS the card adds), so short ones are padded with zeros." })] : undefined;
      return {
        id: "eth", name: "Ethernet II", osi: 2,
        summary: `Ethernet II, Src: ${fmtMac(src)}, Dst: ${fmtMac(dst)}`,
        fields, trailer,
      };
    },
  };
}

export function vlan(o: { id: number; pcp?: number; type?: number }): LayerSpec {
  return {
    kind: "vlan",
    ethertype: 0x8100,
    build: (_p, ctx) => {
      const type = o.type ?? ctx.inner?.ethertype ?? 0x0800;
      const tci = ((o.pcp ?? 0) << 13) | (o.id & 0xfff);
      return {
        id: "vlan", name: "802.1Q VLAN", osi: 2,
        summary: `802.1Q Virtual LAN, PRI: ${o.pcp ?? 0}, ID: ${o.id}`,
        fields: [
          field({ name: "Priority, VLAN ID", u16: tci, value: `PRI ${o.pcp ?? 0}, VLAN ${o.id}`, note: "3 bits of priority, 1 bit drop-eligible, 12 bits of VLAN number (1–4094)." }),
          field({ name: "Type", u16: type, value: `0x${type.toString(16).padStart(4, "0")} (${ETHERTYPE_NAMES[type] ?? "?"})` }),
        ],
      };
    },
  };
}

// ---------------------------------------------------------------- ARP

export function arp(o: { op: 1 | 2; senderMac: string; senderIp: string; targetMac?: string; targetIp: string }): LayerSpec {
  return {
    kind: "arp",
    ethertype: 0x0806,
    build: () => {
      const tm = o.targetMac ?? "00:00:00:00:00:00";
      return {
        id: "arp", name: "ARP", osi: 2,
        summary: o.op === 1 ? `ARP: Who has ${o.targetIp}? Tell ${o.senderIp}` : `ARP: ${o.senderIp} is at ${o.senderMac}`,
        fields: [
          field({ name: "Hardware type", u16: 1, value: "1 (Ethernet)" }),
          field({ name: "Protocol type", u16: 0x0800, value: "0x0800 (IPv4)" }),
          field({ name: "Hardware size", u8: 6, note: "MAC addresses are 6 bytes." }),
          field({ name: "Protocol size", u8: 4, note: "IPv4 addresses are 4 bytes." }),
          field({ name: "Opcode", u16: o.op, value: o.op === 1 ? "1 (request)" : "2 (reply)" }),
          field({ name: "Sender MAC", bytes: mac(o.senderMac), value: o.senderMac }),
          field({ name: "Sender IP", bytes: ip4(o.senderIp), value: o.senderIp }),
          field({ name: "Target MAC", bytes: mac(tm), value: tm, note: o.op === 1 ? "All zeros: this is what the request wants to find out." : undefined }),
          field({ name: "Target IP", bytes: ip4(o.targetIp), value: o.targetIp }),
        ],
      };
    },
  };
}

// ---------------------------------------------------------------- IPv4

const IP_PROTO_NAMES: Record<number, string> = {
  1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
};

export function ipv4(o: {
  src: string; dst: string; ttl?: number; id?: number; df?: boolean; dscp?: number; ecn?: number; proto?: number;
  options?: Bytes; optionNote?: string; mf?: boolean; fragOffset?: number;
}): LayerSpec {
  return {
    kind: "ipv4",
    ethertype: 0x0800,
    ipProto: 4,
    meta: (ctx) => {
      // the innermost IP header wins for pseudo-headers (tunnels set it again)
      ctx.ipSrc = ip4(o.src);
      ctx.ipDst = ip4(o.dst);
      ctx.ipVersion = 4;
    },
    build: (payload, ctx) => {
      const proto = o.proto ?? ctx.inner?.ipProto ?? 6;
      const opts = o.options ?? [];
      const ihl = 5 + Math.ceil(opts.length / 4);
      const total = ihl * 4 + payload.length;
      const ttl = o.ttl ?? 64;
      const id = o.id ?? 0x1c46;
      const flags = (o.df !== false ? 0x4000 : 0) | (o.mf ? 0x2000 : 0) | ((o.fragOffset ?? 0) & 0x1fff);
      const tos = ((o.dscp ?? 0) << 2) | (o.ecn ?? 0);
      const header = [
        ...u8(0x40 | ihl), ...u8(tos), ...u16(total), ...u16(id), ...u16(flags), ...u8(ttl), ...u8(proto), 0, 0,
        ...ip4(o.src), ...ip4(o.dst), ...opts, ...zeros((4 - (opts.length % 4)) % 4),
      ];
      const cs = inetChecksum(header);
      const fields: Field[] = [
        field({ name: "Version, header length", u8: 0x40 | ihl, value: `4, ${ihl * 4} bytes`, note: ihl > 5 ? "IPv4, with options." : "IPv4, with no options: the header is 20 bytes." }),
        field({ name: "DSCP, ECN", u8: tos, value: tos ? `0x${tos.toString(16).padStart(2, "0")}` : "0 (ordinary traffic)", note: "Priority marking for queues, and congestion signalling." }),
        field({ name: "Total length", u16: total, value: `${total} bytes`, note: "This header plus everything after it." }),
        field({ name: "Identification", u16: id, value: `0x${id.toString(16).padStart(4, "0")}`, note: "Ties the pieces together if the packet gets fragmented." }),
        field({ name: "Flags, fragment offset", u16: flags, value: o.mf ? `MF, offset ${(flags & 0x1fff) * 8}` : o.df !== false ? "DF (don’t fragment)" : `offset ${(flags & 0x1fff) * 8}`, note: o.df !== false ? "Don’t fragment: routers must drop it rather than split it." : "Routers may split it if a link is too small." }),
        field({ name: "Time to live", u8: ttl, note: "Every router lowers it by one; at zero the packet is dropped, so loops can’t last forever." }),
        field({ name: "Protocol", u8: proto, value: `${proto} (${IP_PROTO_NAMES[proto] ?? "?"})`, note: "Which protocol the payload belongs to." }),
        field({ name: "Header checksum", u16: cs, value: `0x${cs.toString(16).padStart(4, "0")}`, note: "Covers this header only; every router recomputes it after lowering the TTL." }),
        field({ name: "Source address", bytes: ip4(o.src), value: o.src }),
        field({ name: "Destination address", bytes: ip4(o.dst), value: o.dst }),
      ];
      if (opts.length) fields.push(field({ name: "Options", bytes: [...opts, ...zeros((4 - (opts.length % 4)) % 4)], note: o.optionNote }));
      void ctx;
      return {
        id: "ipv4", name: "IPv4", osi: 3,
        summary: `Internet Protocol Version 4, Src: ${o.src}, Dst: ${o.dst}`,
        fields,
      };
    },
  };
}

// ---------------------------------------------------------------- IPv6

export function ipv6(o: { src: string; dst: string; hop?: number; next?: number; flow?: number; tclass?: number; ext?: Bytes; extNote?: string; extNext?: number }): LayerSpec {
  return {
    kind: "ipv6",
    ethertype: 0x86dd,
    ipProto: 41,
    meta: (ctx) => {
      ctx.ipSrc = ip6(o.src);
      ctx.ipDst = ip6(o.dst);
      ctx.ipVersion = 6;
    },
    build: (payload, ctx) => {
      const inner = o.next ?? ctx.inner?.ipProto ?? 6;
      const ext = o.ext ?? [];
      const next = ext.length ? (o.extNext ?? 0) : inner;
      const first = (6 << 28) | ((o.tclass ?? 0) << 20) | (o.flow ?? 0);
      const fields: Field[] = [
        field({ name: "Version, class, flow label", u32: first >>> 0, value: `6, class ${o.tclass ?? 0}, flow 0x${(o.flow ?? 0).toString(16)}`, note: "IPv6; traffic class for priority; flow label to keep a stream on one path." }),
        field({ name: "Payload length", u16: ext.length + payload.length, value: `${ext.length + payload.length} bytes`, note: "Everything after this fixed 40-byte header." }),
        field({ name: "Next header", u8: next, value: `${next} (${next === 0 ? "Hop-by-hop options" : IP_PROTO_NAMES[next] ?? "?"})` }),
        field({ name: "Hop limit", u8: o.hop ?? 64, note: "IPv6’s TTL: every router lowers it by one." }),
        field({ name: "Source address", bytes: ip6(o.src), value: fmtIp6(ip6(o.src)) }),
        field({ name: "Destination address", bytes: ip6(o.dst), value: fmtIp6(ip6(o.dst)) }),
      ];
      if (ext.length) fields.push(field({ name: "Extension header", bytes: ext, note: o.extNote }));
      return { id: "ipv6", name: "IPv6", osi: 3, summary: `Internet Protocol Version 6, Src: ${o.src}, Dst: ${o.dst}`, fields };
    },
  };
}

// ---------------------------------------------------------------- pseudo header checksum

function l4Checksum(proto: number, segment: Bytes, ctx: { ipSrc?: Bytes; ipDst?: Bytes; ipVersion?: 4 | 6 }): number {
  if (!ctx.ipSrc || !ctx.ipDst) return inetChecksum(segment);
  const pseudo =
    ctx.ipVersion === 6
      ? [...ctx.ipSrc, ...ctx.ipDst, ...u32(segment.length), 0, 0, 0, proto]
      : [...ctx.ipSrc, ...ctx.ipDst, 0, proto, ...u16(segment.length)];
  return inetChecksum([...pseudo, ...segment]);
}

// ---------------------------------------------------------------- TCP

export type TcpOpt =
  | { mss: number }
  | { ws: number }
  | { ts: [number, number] }
  | { sack: [number, number][] }
  | "sackOk"
  | "nop";

const FLAG_BITS: Record<string, number> = { F: 0x01, S: 0x02, R: 0x04, P: 0x08, A: 0x10, U: 0x20, E: 0x40, C: 0x80 };
const FLAG_NAMES: Record<string, string> = { F: "FIN", S: "SYN", R: "RST", P: "PSH", A: "ACK", U: "URG", E: "ECE", C: "CWR" };

export function tcp(o: {
  sport: number; dport: number; seq?: number; ack?: number; flags: string; win?: number; opts?: TcpOpt[];
  /** relative seq/ack numbers are shown; real ones add this base */
  seqBase?: number; ackBase?: number;
}): LayerSpec {
  return {
    kind: "tcp",
    ipProto: 6,
    build: (payload, ctx) => {
      const flagVal = o.flags.split("").reduce((a, c) => a | (FLAG_BITS[c] ?? 0), 0);
      const flagNames = ["C", "E", "U", "A", "P", "R", "S", "F"].filter((c) => o.flags.includes(c)).map((c) => FLAG_NAMES[c]);
      const optBytes: Bytes = [];
      const optFields: FieldSpec[] = [];
      for (const op of o.opts ?? []) {
        if (op === "nop") { optBytes.push(1); optFields.push({ name: "No-op", bytes: [1], value: "NOP", note: "Padding so the next option lines up." }); }
        else if (op === "sackOk") { optBytes.push(4, 2); optFields.push({ name: "SACK permitted", bytes: [4, 2], value: "yes", note: "This side can report exactly which bytes arrived (selective ACK)." }); }
        else if ("mss" in op) { const b = [2, 4, ...u16(op.mss)]; optBytes.push(...b); optFields.push({ name: "Maximum segment size", bytes: b, value: `${op.mss} bytes`, note: "The biggest chunk of data this side wants in one segment." }); }
        else if ("ws" in op) { const b = [3, 3, op.ws]; optBytes.push(...b); optFields.push({ name: "Window scale", bytes: b, value: `×${2 ** op.ws}`, note: "Multiplies the window field so it can describe big buffers." }); }
        else if ("ts" in op) { const b = [8, 10, ...u32(op.ts[0]), ...u32(op.ts[1])]; optBytes.push(...b); optFields.push({ name: "Timestamps", bytes: b, value: `TSval ${op.ts[0]}, TSecr ${op.ts[1]}`, note: "Lets each side measure the round-trip time." }); }
        else if ("sack" in op) {
          const b = [5, 2 + 8 * op.sack.length, ...op.sack.flatMap(([l, r]) => [...u32(l), ...u32(r)])];
          optBytes.push(...b);
          optFields.push({ name: "SACK", bytes: b, value: op.sack.map(([l, r]) => `${l}–${r - 1}`).join(", "), note: "Bytes that arrived after a gap, so only the gap needs resending." });
        }
      }
      while (optBytes.length % 4) { optBytes.push(0); optFields.push({ name: "End of options", bytes: [0], value: "EOL" }); }
      const hlen = 20 + optBytes.length;
      const seq = ((o.seq ?? 0) + (o.seqBase ?? 0)) >>> 0;
      const ack = ((o.ack ?? 0) + (o.ackBase ?? 0)) >>> 0;
      const win = o.win ?? 64240;
      const seg = [
        ...u16(o.sport), ...u16(o.dport), ...u32(seq), ...u32(ack), ((hlen / 4) << 4), flagVal, ...u16(win), 0, 0, 0, 0, ...optBytes, ...payload,
      ];
      const cs = l4Checksum(6, seg, ctx);
      const fields: Field[] = [
        field({ name: "Source port", u16: o.sport }),
        field({ name: "Destination port", u16: o.dport }),
        field({ name: "Sequence number", u32: seq, value: `${o.seq ?? 0}${o.seqBase ? ` (relative)` : ""}`, note: o.flags.includes("S") ? "The starting number for this side’s bytes. Real stacks pick it at random." : "The number of the first byte in this segment." }),
        field({ name: "Acknowledgment number", u32: ack, value: o.flags.includes("A") ? `${o.ack ?? 0}${o.ackBase ? " (relative)" : ""}` : "0", note: o.flags.includes("A") ? "The next byte this side expects: everything before it has arrived." : "No ACK flag, so this is ignored." }),
        field({ name: "Header length", u8: (hlen / 4) << 4, value: `${hlen} bytes`, note: hlen > 20 ? "20 bytes plus options." : "20 bytes, no options." }),
        field({ name: "Flags", u8: flagVal, value: `0x${flagVal.toString(16).padStart(3, "0")} (${flagNames.join(", ")})` }),
        field({ name: "Window", u16: win, note: "How much more data this side can take right now." }),
        field({ name: "Checksum", u16: cs, value: `0x${cs.toString(16).padStart(4, "0")}`, note: "Covers the header, the data and the IP addresses, so damage is caught." }),
        field({ name: "Urgent pointer", u16: 0 }),
      ];
      if (optFields.length) fields.push(field({ name: "Options", fields: optFields, value: `${optBytes.length} bytes` }));
      return {
        id: "tcp", name: "TCP", osi: 4,
        summary: `Transmission Control Protocol, Src Port: ${o.sport}, Dst Port: ${o.dport}, Seq: ${o.seq ?? 0}, Ack: ${o.ack ?? 0}, Len: ${payload.length}`,
        fields,
      };
    },
  };
}

// ---------------------------------------------------------------- UDP

export function udp(o: { sport: number; dport: number; zeroChecksum?: boolean }): LayerSpec {
  return {
    kind: "udp",
    ipProto: 17,
    build: (payload, ctx) => {
      const len = 8 + payload.length;
      let cs = o.zeroChecksum ? 0 : l4Checksum(17, [...u16(o.sport), ...u16(o.dport), ...u16(len), 0, 0, ...payload], ctx);
      if (cs === 0 && !o.zeroChecksum) cs = 0xffff;
      return {
        id: "udp", name: "UDP", osi: 4,
        summary: `User Datagram Protocol, Src Port: ${o.sport}, Dst Port: ${o.dport}`,
        fields: [
          field({ name: "Source port", u16: o.sport }),
          field({ name: "Destination port", u16: o.dport }),
          field({ name: "Length", u16: len, value: `${len} bytes`, note: "8-byte header plus the data." }),
          field({ name: "Checksum", u16: cs, value: `0x${cs.toString(16).padStart(4, "0")}`, note: o.zeroChecksum ? "Zero: not used." : "Covers the header, the data and the IP addresses." }),
        ],
      };
    },
  };
}

// ---------------------------------------------------------------- ICMP / ICMPv6

export function icmp(o: { type: number; code?: number; name: string; rest?: Bytes; restFields?: FieldSpec[]; data?: Bytes; dataName?: string; dataNote?: string }): LayerSpec {
  return {
    kind: "icmp",
    ipProto: 1,
    build: () => {
      const restSpec: FieldSpec[] = o.restFields ?? (o.rest ? [{ name: "Rest of header", bytes: o.rest }] : [{ name: "Unused", zero: 4 }]);
      const rest = restSpec.map(field);
      const data = o.data ?? [];
      const msg = [o.type, o.code ?? 0, 0, 0, ...rest.flatMap((r) => r.bytes), ...data];
      const cs = inetChecksum(msg);
      const fields: Field[] = [
        field({ name: "Type", u8: o.type, value: `${o.type} (${o.name})` }),
        field({ name: "Code", u8: o.code ?? 0 }),
        field({ name: "Checksum", u16: cs, value: `0x${cs.toString(16).padStart(4, "0")}`, note: "Covers the whole ICMP message." }),
        ...rest,
      ];
      if (data.length) fields.push(field({ name: o.dataName ?? "Data", bytes: data, note: o.dataNote }));
      return { id: "icmp", name: "ICMP", osi: 3, summary: `Internet Control Message Protocol: ${o.name}`, fields };
    },
  };
}

export function icmpv6(o: { type: number; code?: number; name: string; body: FieldSpec[] }): LayerSpec {
  return {
    kind: "icmpv6",
    ipProto: 58,
    build: (_p, ctx) => {
      const body = o.body.map(field);
      const msg = [o.type, o.code ?? 0, 0, 0, ...body.flatMap((b) => b.bytes)];
      const cs = l4Checksum(58, msg, ctx);
      return {
        id: "icmpv6", name: "ICMPv6", osi: 3, summary: `ICMPv6: ${o.name}`,
        fields: [
          field({ name: "Type", u8: o.type, value: `${o.type} (${o.name})` }),
          field({ name: "Code", u8: o.code ?? 0 }),
          field({ name: "Checksum", u16: cs, value: `0x${cs.toString(16).padStart(4, "0")}`, note: "Covers the message and both IPv6 addresses." }),
          ...body,
        ],
      };
    },
  };
}

// ---------------------------------------------------------------- DNS

const RR_TYPES: Record<string, number> = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, OPT: 41, DS: 43, RRSIG: 46, DNSKEY: 48, HTTPS: 65,
};

export const dnsName = (name: string): Bytes =>
  name === "." || name === "" ? [0] : [...name.replace(/\.$/, "").split(".").flatMap((l) => [l.length, ...text(l)]), 0];

export interface DnsRR {
  name: string;
  type: keyof typeof RR_TYPES | string;
  ttl?: number;
  /** A, AAAA, CNAME, NS, PTR, TXT, MX ("10 mail.example.com") get encoded automatically */
  data?: string;
  /** raw rdata for anything else */
  rdata?: Bytes;
  value?: string;
  note?: string;
  cls?: number;
}

function rdataOf(rr: DnsRR): Bytes {
  if (rr.rdata) return rr.rdata;
  const d = rr.data ?? "";
  switch (rr.type) {
    case "A": return ip4(d);
    case "AAAA": return ip6(d);
    case "CNAME": case "NS": case "PTR": return dnsName(d);
    case "TXT": return text(d).length ? [text(d).length, ...text(d)] : [0];
    case "MX": { const [pref, host] = d.split(" "); return [...u16(Number(pref)), ...dnsName(host)]; }
    default: return [];
  }
}

export function dns(o: {
  id: number; response?: boolean; rd?: boolean; ra?: boolean; aa?: boolean; ad?: boolean; cd?: boolean; rcode?: number;
  qd: { name: string; type: string }[];
  an?: DnsRR[]; ns?: DnsRR[]; ar?: DnsRR[];
  name?: string; id_?: string;
}): LayerSpec {
  return {
    kind: "dns",
    build: () => {
      const flags = (o.response ? 0x8000 : 0) | (o.aa ? 0x0400 : 0) | (o.rd !== false ? 0x0100 : 0) | (o.ra ? 0x0080 : 0) | (o.ad ? 0x0020 : 0) | (o.cd ? 0x0010 : 0) | (o.rcode ?? 0);
      const flagText = [o.response ? "response" : "query", o.aa && "AA", o.rd !== false && "RD", o.ra && "RA", o.ad && "AD", o.cd && "CD"].filter(Boolean).join(", ");
      const rcodeName = ["NOERROR", "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED"][o.rcode ?? 0] ?? String(o.rcode);
      const rrField = (rr: DnsRR, i: number): FieldSpec => {
        const t = RR_TYPES[rr.type] ?? 0;
        if (rr.type === "OPT") {
          const rd = rr.rdata ?? [];
          return {
            name: "OPT (EDNS)",
            value: rr.value ?? "UDP size 1232",
            note: rr.note ?? "EDNS: lets answers be bigger than 512 bytes and carries extra flags.",
            fields: [
              { name: "Name", bytes: [0], value: "<root>" },
              { name: "Type", u16: 41, value: "OPT" },
              { name: "UDP payload size", u16: rr.cls ?? 1232 },
              { name: "Extended flags", u32: rr.ttl ?? 0, value: (rr.ttl ?? 0) & 0x8000 ? "DO (wants DNSSEC records)" : "0" },
              { name: "Data length", u16: rd.length },
              ...(rd.length ? [{ name: "Options", bytes: rd }] : []),
            ],
          };
        }
        const rd = rdataOf(rr);
        return {
          name: `${rr.type} record ${i + 1}`,
          value: rr.value ?? `${rr.name} ${rr.type} ${rr.data ?? ""}`.trim(),
          note: rr.note,
          fields: [
            { name: "Name", bytes: dnsName(rr.name), value: rr.name },
            { name: "Type", u16: t, value: `${t} (${rr.type})` },
            { name: "Class", u16: rr.cls ?? 1, value: "IN (internet)" },
            { name: "Time to live", u32: rr.ttl ?? 300, value: `${rr.ttl ?? 300} s`, note: "How long resolvers may cache this answer." },
            { name: "Data length", u16: rd.length },
            { name: "Data", bytes: rd, value: rr.data ?? `${rd.length} bytes` },
          ],
        };
      };
      const fields: FieldSpec[] = [
        { name: "Transaction ID", u16: o.id, value: `0x${o.id.toString(16).padStart(4, "0")}`, note: "Chosen by the client; the response repeats it so they can be matched." },
        { name: "Flags", u16: flags, value: `0x${flags.toString(16).padStart(4, "0")} (${flagText}${o.response ? `, ${rcodeName}` : ""})`, note: o.response ? (o.rcode === 3 ? "NXDOMAIN: the name does not exist." : "QR=1 marks a response.") : "RD: please do the whole lookup for me (recursion desired)." },
        { name: "Questions", u16: o.qd.length },
        { name: "Answer records", u16: o.an?.length ?? 0 },
        { name: "Authority records", u16: o.ns?.length ?? 0 },
        { name: "Additional records", u16: o.ar?.length ?? 0 },
        ...o.qd.map((q, i) => ({
          name: `Question ${i + 1}`,
          value: `${q.name} ${q.type}`,
          fields: [
            { name: "Name", bytes: dnsName(q.name), value: q.name, note: "Each label is preceded by its length; a zero byte ends the name." },
            { name: "Type", u16: RR_TYPES[q.type] ?? 1, value: `${RR_TYPES[q.type]} (${q.type})` },
            { name: "Class", u16: 1, value: "IN (internet)" },
          ],
        })),
        ...(o.an ?? []).map(rrField),
        ...(o.ns ?? []).map((r, i) => ({ ...rrField(r, i), name: `Authority ${r.type} ${i + 1}` })),
        ...(o.ar ?? []).map((r, i) => ({ ...rrField(r, i), name: r.type === "OPT" ? "OPT (EDNS)" : `Additional ${r.type} ${i + 1}` })),
      ];
      const ans = o.an?.map((a) => `${a.type} ${a.data ?? ""}`).join(", ");
      return {
        id: "dns", name: o.name ?? "DNS", osi: 7,
        summary: o.response
          ? `Domain Name System (response) 0x${o.id.toString(16)}: ${o.qd[0]?.name} ${o.qd[0]?.type}${ans ? ` → ${ans}` : ` ${rcodeName}`}`
          : `Domain Name System (query) 0x${o.id.toString(16)}: ${o.qd[0]?.name} ${o.qd[0]?.type}`,
        fields: fields.map(field),
      };
    },
  };
}

// ---------------------------------------------------------------- DHCP

const DHCP_TYPES = ["", "DISCOVER", "OFFER", "REQUEST", "DECLINE", "ACK", "NAK", "RELEASE", "INFORM"];

export interface DhcpOpt { code: number; name: string; data: Bytes; value?: string; note?: string }

export const dhcpOpt = {
  msgType: (t: number): DhcpOpt => ({ code: 53, name: "Message type", data: [t], value: DHCP_TYPES[t] }),
  serverId: (ip: string): DhcpOpt => ({ code: 54, name: "Server identifier", data: ip4(ip), value: ip, note: "Which DHCP server this is." }),
  requestedIp: (ip: string): DhcpOpt => ({ code: 50, name: "Requested IP address", data: ip4(ip), value: ip }),
  lease: (s: number): DhcpOpt => ({ code: 51, name: "Lease time", data: u32(s), value: `${s} s (${(s / 3600).toFixed(0)} h)`, note: "How long the address is the laptop’s before it must renew." }),
  subnet: (m: string): DhcpOpt => ({ code: 1, name: "Subnet mask", data: ip4(m), value: m }),
  router: (ip: string): DhcpOpt => ({ code: 3, name: "Router", data: ip4(ip), value: ip, note: "The default gateway: where to send traffic for other networks." }),
  dns: (...ips: string[]): DhcpOpt => ({ code: 6, name: "DNS servers", data: ips.flatMap(ip4), value: ips.join(", ") }),
  hostname: (h: string): DhcpOpt => ({ code: 12, name: "Host name", data: text(h), value: h }),
  clientId: (m: string): DhcpOpt => ({ code: 61, name: "Client identifier", data: [1, ...mac(m)], value: m }),
  paramList: (...codes: number[]): DhcpOpt => ({ code: 55, name: "Parameter request list", data: codes, value: codes.join(", "), note: "Settings the client would like: 1 mask, 3 router, 6 DNS, 15 domain…" }),
  domain: (d: string): DhcpOpt => ({ code: 15, name: "Domain name", data: text(d), value: d }),
  renewal: (s: number): DhcpOpt => ({ code: 58, name: "Renewal time (T1)", data: u32(s), value: `${s} s` }),
  rebind: (s: number): DhcpOpt => ({ code: 59, name: "Rebinding time (T2)", data: u32(s), value: `${s} s` }),
  raw: (code: number, name: string, data: Bytes, value?: string, note?: string): DhcpOpt => ({ code, name, data, value, note }),
};

export function dhcp(o: {
  op: 1 | 2; xid: number; chaddr: string; ciaddr?: string; yiaddr?: string; siaddr?: string; giaddr?: string; secs?: number; broadcast?: boolean;
  options: DhcpOpt[];
}): LayerSpec {
  return {
    kind: "dhcp",
    build: () => {
      const type = o.options.find((x) => x.code === 53)?.data[0] ?? 0;
      const optFields: FieldSpec[] = o.options.map((op) => ({
        name: `Option ${op.code}: ${op.name}`,
        bytes: [op.code, op.data.length, ...op.data],
        value: op.value ?? toHex(op.data),
        note: op.note,
      }));
      optFields.push({ name: "Option 255: End", bytes: [255], value: "end" });
      const fields: FieldSpec[] = [
        { name: "Message type (op)", u8: o.op, value: o.op === 1 ? "1 (boot request)" : "2 (boot reply)" },
        { name: "Hardware type", u8: 1, value: "Ethernet" },
        { name: "Hardware address length", u8: 6 },
        { name: "Hops", u8: 0, note: "Relay agents count up here." },
        { name: "Transaction ID", u32: o.xid, value: `0x${o.xid.toString(16).padStart(8, "0")}`, note: "Chosen by the client; every reply repeats it." },
        { name: "Seconds elapsed", u16: o.secs ?? 0 },
        { name: "Flags", u16: o.broadcast ? 0x8000 : 0, value: o.broadcast ? "Broadcast" : "Unicast", note: o.broadcast ? "Please broadcast the reply: I have no address yet." : "The server may reply straight to the client’s MAC." },
        { name: "Client IP address", bytes: ip4(o.ciaddr ?? "0.0.0.0"), value: o.ciaddr ?? "0.0.0.0", note: "Filled in only when the client already has an address (renewing)." },
        { name: "Your IP address", bytes: ip4(o.yiaddr ?? "0.0.0.0"), value: o.yiaddr ?? "0.0.0.0", note: o.op === 2 ? "The address being handed to the client." : undefined },
        { name: "Next server IP", bytes: ip4(o.siaddr ?? "0.0.0.0"), value: o.siaddr ?? "0.0.0.0" },
        { name: "Relay agent IP", bytes: ip4(o.giaddr ?? "0.0.0.0"), value: o.giaddr ?? "0.0.0.0" },
        { name: "Client MAC address", bytes: [...mac(o.chaddr), ...zeros(10)], value: o.chaddr, note: "16 bytes reserved; Ethernet uses the first 6." },
        { name: "Server name, boot file", zero: 192, value: "unused", note: "Legacy BOOTP fields, nearly always empty." },
        { name: "Magic cookie", bytes: "63825363", value: "DHCP", note: "Marks the options that follow as DHCP." },
        { name: "Options", fields: optFields, value: `${o.options.length} options` },
      ];
      return {
        id: "dhcp", name: "DHCP", osi: 7,
        summary: `Dynamic Host Configuration Protocol (${DHCP_TYPES[type] ?? "?"}) xid 0x${o.xid.toString(16)}`,
        fields: fields.map(field),
      };
    },
  };
}

// ---------------------------------------------------------------- TLS records

export const TLS_CT: Record<string, number> = { ccs: 20, alert: 21, handshake: 22, appdata: 23, heartbeat: 24 };
const TLS_CT_NAME: Record<number, string> = { 20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data" };

export const HS_TYPES: Record<string, number> = {
  client_hello: 1, server_hello: 2, new_session_ticket: 4, encrypted_extensions: 8, certificate: 11, server_key_exchange: 12,
  certificate_request: 13, server_hello_done: 14, certificate_verify: 15, client_key_exchange: 16, finished: 20,
};

/** One TLS handshake message: type + 3-byte length + body fields. */
export function hsMsg(type: keyof typeof HS_TYPES, name: string, body: FieldSpec[], note?: string): FieldSpec {
  const bodyBytes = body.map(field).flatMap((f) => f.bytes);
  return {
    name,
    note,
    value: `${bodyBytes.length + 4} bytes`,
    fields: [
      { name: "Handshake type", u8: HS_TYPES[type], value: `${HS_TYPES[type]} (${name})` },
      { name: "Length", u24: bodyBytes.length },
      ...body,
    ],
  };
}

/** Length-prefixed list helper: {name, len: 1|2|3, items} → a field whose first bytes are the length. */
export function vec(name: string, lenBytes: 1 | 2 | 3, items: FieldSpec[], value?: string, note?: string): FieldSpec {
  const inner = items.map(field).flatMap((f) => f.bytes);
  const lenSpec: FieldSpec = lenBytes === 1 ? { name: "Length", u8: inner.length } : lenBytes === 2 ? { name: "Length", u16: inner.length } : { name: "Length", u24: inner.length };
  return { name, value: value ?? `${inner.length} bytes`, note, fields: [lenSpec, ...items] };
}

/** TLS extension: type(2) + length(2) + data */
export function ext(type: number, name: string, data: FieldSpec[] | Bytes, value?: string, note?: string): FieldSpec {
  const items: FieldSpec[] = Array.isArray(data) && typeof data[0] !== "object" ? [{ name: "Data", bytes: data as Bytes }] : (data as FieldSpec[]);
  const inner = items.map(field).flatMap((f) => f.bytes);
  return {
    name: `Extension: ${name}`,
    value: value ?? `${inner.length} bytes`,
    note,
    fields: [{ name: "Type", u16: type, value: `${type} (${name})` }, { name: "Length", u16: inner.length }, ...(inner.length ? items : [])],
  };
}

export interface TlsRecord {
  type: keyof typeof TLS_CT;
  version?: number;
  /** handshake messages or other inner fields */
  fields?: FieldSpec[];
  /** an encrypted record of this many bytes (including 16-byte tag) */
  encrypted?: number;
  what?: string;
  note?: string;
}

export function tls(o: { records: TlsRecord[]; name?: string; summary?: string }): LayerSpec {
  return {
    kind: "tls",
    build: () => {
      const recFields: Field[] = o.records.map((r, i) => {
        const inner: FieldSpec[] = r.encrypted
          ? [{ name: r.what ?? "Encrypted data", random: r.encrypted, opaque: true, note: r.note ?? "Ciphertext ending in a 16-byte tag that shows any change. Only the two ends can read it." }]
          : (r.fields ?? []);
        const innerBytes = inner.map(field).flatMap((f) => f.bytes);
        const ct = TLS_CT[r.type];
        const ver = r.version ?? 0x0303;
        return field({
          name: `Record ${i + 1}: ${TLS_CT_NAME[ct]}`,
          value: `${innerBytes.length + 5} bytes`,
          note: r.type === "appdata" && r.encrypted ? "Every encrypted record says Application Data on the outside; the real type is inside." : undefined,
          fields: [
            { name: "Content type", u8: ct, value: `${ct} (${TLS_CT_NAME[ct]})` },
            { name: "Version", u16: ver, value: ver === 0x0303 ? "TLS 1.2 (0x0303)" : ver === 0x0301 ? "TLS 1.0 (0x0301)" : `0x${ver.toString(16)}`, note: ver === 0x0303 ? "Frozen at 1.2 for compatibility, even in TLS 1.3." : "Old value kept for compatibility." },
            { name: "Length", u16: innerBytes.length },
            ...inner,
          ],
        });
      });
      return { id: "tls", name: o.name ?? "TLS", osi: 6, summary: o.summary ?? `Transport Layer Security: ${o.records.map((r) => TLS_CT_NAME[TLS_CT[r.type]]).join(", ")}`, fields: recFields };
    },
  };
}

// ---------------------------------------------------------------- misc helpers

/** IPv4 / IPv6 / MAC as FieldSpec shorthands for proto() authors */
export const F = {
  ip4: (name: string, ip: string, note?: string): FieldSpec => ({ name, bytes: ip4(ip), value: ip, note }),
  ip6: (name: string, ip: string, note?: string): FieldSpec => ({ name, bytes: ip6(ip), value: ip, note }),
  mac: (name: string, m: string, note?: string): FieldSpec => ({ name, bytes: mac(m), value: m, note }),
  text: (name: string, s: string, note?: string): FieldSpec => ({ name, text: s, value: s, note }),
  hex: (name: string, h: string, value?: string, note?: string): FieldSpec => ({ name, bytes: hex(h), value, note }),
};

export { fmtIp4, layerBytes };
