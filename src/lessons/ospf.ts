import { Device, defineLesson, note, pkt } from "@/lib/lesson";
import { build, field, FieldSpec, proto } from "@/lib/packet";
import { eth, icmp, ipv4 } from "@/lib/proto";
import { Bytes, inetChecksum, ip4, u16 } from "@/lib/bytes";

// ---------------------------------------------------------------- the company network
// R1, R2 and R3 share one Ethernet segment (192.0.2.0/24) through a switch.
// R2 and R3 each have a point-to-point link to R4, which has the server network.
// R3–R4 costs 10 (fast fibre), R2–R4 costs 50 (slower backup link).

const RID = { r1: "1.1.1.1", r2: "2.2.2.2", r3: "3.3.3.3", r4: "4.4.4.4" };
const IP = { r1: "192.0.2.1", r2: "192.0.2.2", r3: "192.0.2.3", r2p: "198.51.100.1", r4a: "198.51.100.2", r3p: "198.51.100.5", r4b: "198.51.100.6" };
const MAC = { r1: "00:0c:29:01:01:01", r2: "00:0c:29:02:02:02", r3: "00:0c:29:03:03:03", r2p: "00:0c:29:02:02:a4", r4a: "00:0c:29:04:04:a2", r3p: "00:0c:29:03:03:a4", r4b: "00:0c:29:04:04:a3", srv: "00:16:3e:5a:01:22" };
const ALL_SPF = "224.0.0.5";
const ALL_DR = "224.0.0.6";
const MAC_SPF = "01:00:5e:00:00:05";
const MAC_DR = "01:00:5e:00:00:06";
const SERVER = "203.0.113.10";
const DESK = "192.168.10.20";

const bytesOf = (specs: FieldSpec[]): Bytes => specs.map(field).flatMap((f) => f.bytes);

// ---------------------------------------------------------------- LSAs with a real Fletcher checksum

/** ISO 8473 Fletcher checksum as used by OSPF (RFC 2328 12.1.7): over the LSA minus the age field. */
function fletcher(lsa: Bytes): number {
  const data = lsa.slice(2); // skip LS age
  const L = data.length;
  const P = 15; // 1-based position of the checksum's first byte inside `data` (LSA offset 16)
  let c0 = 0, c1 = 0;
  for (let i = 0; i < L; i++) {
    const b = i === 14 || i === 15 ? 0 : data[i];
    c0 = (c0 + b) % 255;
    c1 = (c1 + c0) % 255;
  }
  const mod = (n: number) => ((n % 255) + 255) % 255;
  let x = mod((L - P) * c0 - c1);
  let y = mod(c1 - (L - P + 1) * c0);
  if (x === 0) x = 255;
  if (y === 0) y = 255;
  return (x << 8) | y;
}

const LS_TYPES: Record<number, string> = { 1: "Router-LSA", 2: "Network-LSA", 3: "Summary-LSA", 5: "AS-External-LSA" };

interface Lsa { header: FieldSpec; full: FieldSpec; type: number; id: string; adv: string; seq: number; label: string }

function lsa(o: { type: number; id: string; adv: string; seq: number; age?: number; body: FieldSpec[]; label: string }): Lsa {
  const body = bytesOf(o.body);
  const len = 20 + body.length;
  const age = o.age ?? 1;
  const head0: Bytes = [...u16(age), 0x22, o.type, ...ip4(o.id), ...ip4(o.adv), ...u16(o.seq >>> 16), ...u16(o.seq & 0xffff), 0, 0, ...u16(len)];
  const cs = fletcher([...head0, ...body]);
  const hdr: FieldSpec[] = [
    { name: "LS age", u16: age, value: `${age} s`, note: "Seconds since the LSA was created. At 3600 s (MaxAge) it is thrown away." },
    { name: "Options", u8: 0x22, value: "0x22 (E, DC)", note: "E: this area carries external routes." },
    { name: "LS type", u8: o.type, value: `${o.type} (${LS_TYPES[o.type]})` },
    { name: "Link state ID", bytes: ip4(o.id), value: o.id, note: o.type === 2 ? "For a Network-LSA: the DR's interface address." : "For a Router-LSA: the router ID." },
    { name: "Advertising router", bytes: ip4(o.adv), value: o.adv },
    { name: "Sequence number", u32: o.seq >>> 0, value: `0x${(o.seq >>> 0).toString(16)}`, note: "Starts at 0x80000001 and goes up each time the LSA changes. Higher means newer." },
    { name: "Checksum", u16: cs, value: `0x${cs.toString(16).padStart(4, "0")}`, note: "Fletcher checksum over the whole LSA except the age, so it stays valid while the age ticks up." },
    { name: "Length", u16: len, value: `${len} bytes` },
  ];
  return {
    type: o.type, id: o.id, adv: o.adv, seq: o.seq, label: o.label,
    header: { name: `LSA header: ${o.label}`, value: `${LS_TYPES[o.type]} ${o.id} seq 0x${(o.seq >>> 0).toString(16)}`, fields: hdr },
    full: { name: `LSA: ${o.label}`, value: `${len} bytes`, fields: [...hdr, ...o.body] },
  };
}

type Link = { id: string; data: string; type: 1 | 2 | 3; metric: number; what: string };
const LINK_TYPES = ["", "point-to-point", "transit network", "stub network"];

function routerLsa(rid: string, seq: number, linkList: Link[], label: string, age?: number): Lsa {
  const body: FieldSpec[] = [
    { name: "Flags", u8: 0, value: "0 (plain internal router)", note: "V, E and B bits mark virtual-link ends, AS boundary routers and area border routers." },
    { name: "Reserved", u8: 0 },
    { name: "Number of links", u16: linkList.length },
    ...linkList.map((l) => ({
      name: `Link: ${l.what}`,
      value: `${LINK_TYPES[l.type]}, cost ${l.metric}`,
      fields: [
        { name: "Link ID", bytes: ip4(l.id), value: l.id, note: l.type === 1 ? "Neighbour's router ID." : l.type === 2 ? "The DR's address on that segment." : "The network address." },
        { name: "Link data", bytes: ip4(l.data), value: l.data, note: l.type === 3 ? "The network mask." : "This router's own interface address." },
        { name: "Type", u8: l.type, value: `${l.type} (${LINK_TYPES[l.type]})` },
        { name: "Number of TOS metrics", u8: 0 },
        { name: "Metric", u16: l.metric, value: `cost ${l.metric}` },
      ],
    } as FieldSpec)),
  ];
  return lsa({ type: 1, id: rid, adv: rid, seq, body, label, age });
}

const lsaR1 = routerLsa(RID.r1, 0x80000001, [
  { id: IP.r3, data: IP.r1, type: 2, metric: 10, what: "office segment" },
  { id: "192.168.10.0", data: "255.255.255.0", type: 3, metric: 1, what: "desk network" },
], "R1 router");
const lsaR2 = routerLsa(RID.r2, 0x80000004, [
  { id: IP.r3, data: IP.r2, type: 2, metric: 10, what: "office segment" },
  { id: RID.r4, data: IP.r2p, type: 1, metric: 50, what: "link to R4" },
  { id: "198.51.100.0", data: "255.255.255.252", type: 3, metric: 50, what: "R2–R4 subnet" },
], "R2 router", 412);
const r3Links = (withR4: boolean): Link[] => [
  { id: IP.r3, data: IP.r3, type: 2, metric: 10, what: "office segment" },
  ...(withR4
    ? ([
      { id: RID.r4, data: IP.r3p, type: 1, metric: 10, what: "link to R4" },
      { id: "198.51.100.4", data: "255.255.255.252", type: 3, metric: 10, what: "R3–R4 subnet" },
    ] as Link[])
    : []),
];
const lsaR3 = routerLsa(RID.r3, 0x80000002, r3Links(true), "R3 router", 398);
const lsaR3down = routerLsa(RID.r3, 0x80000003, r3Links(false), "R3 router (R4 link gone)");
const r4Links = (withR3: boolean): Link[] => [
  { id: RID.r2, data: IP.r4a, type: 1, metric: 50, what: "link to R2" },
  { id: "198.51.100.0", data: "255.255.255.252", type: 3, metric: 50, what: "R2–R4 subnet" },
  ...(withR3
    ? ([
      { id: RID.r3, data: IP.r4b, type: 1, metric: 10, what: "link to R3" },
      { id: "198.51.100.4", data: "255.255.255.252", type: 3, metric: 10, what: "R3–R4 subnet" },
    ] as Link[])
    : []),
  { id: "203.0.113.0", data: "255.255.255.0", type: 3, metric: 1, what: "server network" },
];
const lsaR4 = routerLsa(RID.r4, 0x80000003, r4Links(true), "R4 router", 377);
const lsaR4down = routerLsa(RID.r4, 0x80000004, r4Links(false), "R4 router (R3 link gone)");
const netLsa = (attached: string[], seq: number, age?: number) =>
  lsa({
    type: 2, id: IP.r3, adv: RID.r3, seq, age, label: "office segment",
    body: [
      { name: "Network mask", bytes: ip4("255.255.255.0"), value: "255.255.255.0" },
      ...attached.map((r) => ({ name: "Attached router", bytes: ip4(r), value: r })),
    ],
  });
const lsaNetOld = netLsa([RID.r3, RID.r2], 0x80000002, 398);

// ---------------------------------------------------------------- OSPF packets

const OSPF_TYPES = ["", "Hello", "Database Description", "Link State Request", "Link State Update", "Link State Acknowledgment"];

function ospf(type: number, rid: string, body: FieldSpec[], summary: string) {
  const b = bytesOf(body);
  const len = 24 + b.length;
  const head = [2, type, ...u16(len), ...ip4(rid), 0, 0, 0, 0, 0, 0, 0, 0];
  const cs = inetChecksum([...head, ...b]); // auth field (8 bytes) left out, as RFC 2328 says
  return proto({
    id: "ospf",
    name: "OSPF",
    osi: 3,
    ipProto: 89,
    summary: `Open Shortest Path First, ${OSPF_TYPES[type]}: ${summary}`,
    fields: [
      { name: "Version", u8: 2, note: "OSPFv2, for IPv4. OSPFv3 is the IPv6 version." },
      { name: "Message type", u8: type, value: `${type} (${OSPF_TYPES[type]})` },
      { name: "Packet length", u16: len, value: `${len} bytes`, note: "The OSPF header plus body." },
      { name: "Source router", bytes: ip4(rid), value: rid, note: "The router ID: a 32-bit number written like an IPv4 address." },
      { name: "Area ID", bytes: [0, 0, 0, 0], value: "0.0.0.0 (backbone)", note: "Every router here is in area 0, the backbone." },
      { name: "Checksum", u16: cs, value: `0x${cs.toString(16).padStart(4, "0")}`, note: "Internet checksum over the whole OSPF packet except the 8-byte authentication field." },
      { name: "Auth type", u16: 0, value: "0 (none)", note: "1 is a plain password, 2 is a cryptographic hash. Real networks should use 2." },
      { name: "Authentication", zero: 8, value: "none" },
      ...body,
    ],
  });
}

const hello = (o: { rid: string; pri?: number; dr: string; bdr: string; nbrs: string[] }) =>
  ospf(1, o.rid, [
    { name: "Network mask", bytes: ip4("255.255.255.0"), value: "255.255.255.0", note: "Neighbours must agree on the mask." },
    { name: "Hello interval", u16: 10, value: "10 s", note: "Must match on both sides, or they ignore each other." },
    { name: "Options", u8: 0x02, value: "0x02 (E)", note: "E: can take external routes. Must match." },
    { name: "Router priority", u8: o.pri ?? 1, note: "Used in the DR election. 0 means never become DR." },
    { name: "Dead interval", u32: 40, value: "40 s", note: "No Hello for this long and the neighbour is declared down." },
    { name: "Designated router", bytes: ip4(o.dr), value: o.dr === "0.0.0.0" ? "0.0.0.0 (none yet)" : o.dr },
    { name: "Backup designated router", bytes: ip4(o.bdr), value: o.bdr === "0.0.0.0" ? "0.0.0.0 (none yet)" : o.bdr },
    ...o.nbrs.map((n) => ({ name: "Active neighbour", bytes: ip4(n), value: n, note: "A router whose Hello this router has heard. Seeing yourself here means two-way contact." })),
  ], `DR ${o.dr}, ${o.nbrs.length} neighbour(s)`);

const dbd = (o: { rid: string; flags: number; seq: number; lsas: Lsa[] }) => {
  const fl = [o.flags & 4 && "I", o.flags & 2 && "M", o.flags & 1 && "MS"].filter(Boolean).join(", ") || "none";
  return ospf(2, o.rid, [
    { name: "Interface MTU", u16: 1500, note: "Must match, or the exchange gets stuck. A classic OSPF problem." },
    { name: "Options", u8: 0x42, value: "0x42 (O, E)", note: "O: supports opaque LSAs." },
    { name: "Flags", u8: o.flags, value: `0x${o.flags.toString(16).padStart(2, "0")} (${fl})`, note: "I: first packet. M: more to come. MS: I am the master." },
    { name: "DD sequence number", u32: o.seq, note: "The master picks it and the slave echoes it, so each DBD is acknowledged." },
    ...o.lsas.map((l) => l.header),
  ], `flags ${fl}, ${o.lsas.length} LSA header(s)`);
};

const lsr = (rid: string, want: Lsa[]) =>
  ospf(3, rid, want.map((l) => ({
    name: `Request: ${l.label}`,
    value: `${LS_TYPES[l.type]} ${l.id}`,
    fields: [
      { name: "LS type", u32: l.type, value: `${l.type} (${LS_TYPES[l.type]})` },
      { name: "Link state ID", bytes: ip4(l.id), value: l.id },
      { name: "Advertising router", bytes: ip4(l.adv), value: l.adv },
    ],
  })), `${want.length} LSA(s) requested`);

const lsu = (rid: string, lsas: Lsa[]) =>
  ospf(4, rid, [{ name: "Number of LSAs", u32: lsas.length }, ...lsas.map((l) => l.full)], `${lsas.length} LSA(s)`);

const lsack = (rid: string, lsas: Lsa[]) => ospf(5, rid, lsas.map((l) => l.header), `${lsas.length} LSA header(s)`);

// frame helpers
const onSeg = (from: "r1" | "r2" | "r3", dst: string, dmac: string, spec: ReturnType<typeof ospf>, id: number) =>
  build(eth({ src: MAC[from], dst: dmac }), ipv4({ src: IP[from], dst, ttl: 1, dscp: 48, df: false, id }), spec);
const onP2p = (smac: string, src: string, spec: ReturnType<typeof ospf>, id: number) =>
  build(eth({ src: smac, dst: MAC_SPF }), ipv4({ src, dst: ALL_SPF, ttl: 1, dscp: 48, df: false, id }), spec);

const ping = (via: "r3" | "r2", id: number) =>
  build(
    eth({ src: MAC.r1, dst: MAC[via] }),
    ipv4({ src: DESK, dst: SERVER, ttl: 63, id, proto: 1 }),
    icmp({ type: 8, name: "Echo request", restFields: [{ name: "Identifier", u16: 0x0001 }, { name: "Sequence number", u16: id & 0xff }], data: Array.from({ length: 32 }, (_, i) => 0x61 + (i % 23)), dataName: "Data" }),
  );

// ---------------------------------------------------------------- normal scenario packets

const net3 = netLsa([RID.r3, RID.r2, RID.r1], 0x80000003);
const pHello1 = onSeg("r1", ALL_SPF, MAC_SPF, hello({ rid: RID.r1, dr: "0.0.0.0", bdr: "0.0.0.0", nbrs: [] }), 0x0101);
const pHello3 = onSeg("r3", ALL_SPF, MAC_SPF, hello({ rid: RID.r3, dr: IP.r3, bdr: IP.r2, nbrs: [RID.r2, RID.r1] }), 0x0301);
const pHello2 = onSeg("r2", ALL_SPF, MAC_SPF, hello({ rid: RID.r2, dr: IP.r3, bdr: IP.r2, nbrs: [RID.r3, RID.r1] }), 0x0201);
const pHello1b = onSeg("r1", ALL_SPF, MAC_SPF, hello({ rid: RID.r1, dr: IP.r3, bdr: IP.r2, nbrs: [RID.r2, RID.r3] }), 0x0102);
const DD = 0x00004e21;
const pDbd1 = onSeg("r1", IP.r3, MAC.r3, dbd({ rid: RID.r1, flags: 7, seq: 0x1a2b, lsas: [] }), 0x0103);
const pDbd3 = onSeg("r3", IP.r1, MAC.r1, dbd({ rid: RID.r3, flags: 7, seq: DD, lsas: [] }), 0x0302);
const pDbd1b = onSeg("r1", IP.r3, MAC.r3, dbd({ rid: RID.r1, flags: 0, seq: DD, lsas: [lsaR1] }), 0x0104);
const pDbd3b = onSeg("r3", IP.r1, MAC.r1, dbd({ rid: RID.r3, flags: 1, seq: DD + 1, lsas: [lsaR2, lsaR3, lsaR4, lsaNetOld] }), 0x0303);
const pDbd1c = onSeg("r1", IP.r3, MAC.r3, dbd({ rid: RID.r1, flags: 0, seq: DD + 1, lsas: [] }), 0x0105);
const pLsr = onSeg("r1", IP.r3, MAC.r3, lsr(RID.r1, [lsaR2, lsaR3, lsaR4, lsaNetOld]), 0x0106);
const pLsu = onSeg("r3", IP.r1, MAC.r1, lsu(RID.r3, [lsaR2, lsaR3, lsaR4, lsaNetOld]), 0x0304);
const pAck = onSeg("r1", ALL_DR, MAC_DR, lsack(RID.r1, [lsaR2, lsaR3, lsaR4, lsaNetOld]), 0x0107);
const pLsuNew = onSeg("r3", ALL_SPF, MAC_SPF, lsu(RID.r3, [net3, lsaR1]), 0x0305);

// ---------------------------------------------------------------- failure scenario packets

const fLsu3 = onSeg("r3", ALL_SPF, MAC_SPF, lsu(RID.r3, [lsaR3down]), 0x0310);
const fLsu2 = onSeg("r2", ALL_DR, MAC_DR, lsu(RID.r2, [lsaR4down]), 0x0211);
const fLsu4 = onP2p(MAC.r4a, IP.r4a, lsu(RID.r4, [lsaR4down]), 0x0401);
const fAck1 = onSeg("r1", ALL_DR, MAC_DR, lsack(RID.r1, [lsaR3down, lsaR4down]), 0x0110);
const fAck2 = onP2p(MAC.r2p, IP.r2p, lsack(RID.r2, [lsaR4down]), 0x0210);

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "r1", kind: "router", label: "R1 (1.1.1.1)", sub: IP.r1, x: 10, y: 50 },
  { id: "switch", kind: "switch", label: "Office switch", sub: "192.0.2.0/24", x: 31, y: 50 },
  { id: "r2", kind: "router", label: "R2 (2.2.2.2)", sub: IP.r2, x: 52, y: 22 },
  { id: "r3", kind: "router", label: "R3 (3.3.3.3) DR", sub: IP.r3, x: 52, y: 78 },
  { id: "r4", kind: "router", label: "R4 (4.4.4.4)", sub: "server side", x: 73, y: 50 },
  { id: "server", kind: "server", label: "Server", sub: SERVER, x: 92, y: 50 },
];
const links: [string, string][] = [
  ["r1", "switch"],
  ["switch", "r2"],
  ["switch", "r3"],
  ["r2", "r4"],
  ["r3", "r4"],
  ["r4", "server"],
];
const linksDown: [string, string][] = links.filter(([a, b]) => !(a === "r3" && b === "r4"));

export default defineLesson({
  id: "ospf",
  name: "OSPF",
  full: "Open Shortest Path First",
  group: "routing",
  layer: 3,
  difficulty: 3,
  tagline: "Every router draws the same map, then finds the shortest path.",
  description:
    "OSPF is the routing protocol many companies and ISPs run inside their own network. Each router describes its links in a small record called an LSA, floods it to every other router, and then runs Dijkstra's shortest-path algorithm over the shared map to build its routing table.",
  facts: [
    ["Layer", "Network (IP protocol 89)"],
    ["Multicast", "224.0.0.5 all routers, 224.0.0.6 DR/BDR"],
    ["Algorithm", "Dijkstra shortest path first"],
    ["Timers", "Hello 10 s, dead 40 s"],
    ["Header", "24 bytes"],
    ["Defined in", "RFC 2328"],
  ],
  ports: "None: IP protocol 89",
  rfc: "RFC 2328",
  keywords: ["link state", "lsa", "dijkstra", "spf", "designated router", "dr", "bdr", "hello", "area 0", "igp", "convergence", "cost"],
  related: ["bgp", "ip", "mpls", "igmp"],
  devices,
  links,
  legend: [
    ["green", "Hellos and acknowledgements"],
    ["blue", "Database description and requests"],
    ["violet", "Link state updates (LSAs)"],
    ["amber", "User traffic"],
    ["red", "Failures"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "R1 joins the network",
      summary: "R1 boots, finds its neighbours with Hello, syncs its map with the DR and computes its routes.",
      kind: "normal",
      steps: [
        {
          title: "Hello, anyone there?",
          desc: "R1 multicasts a Hello to 224.0.0.5",
          detail:
            "R1 has just booted. Every 10 seconds it sends a Hello to 224.0.0.5, the address all OSPF routers listen on. The IP TTL is 1 so it never leaves this segment. R1 has not heard anyone yet, so its neighbour list is empty and it knows of no DR.",
          facts: [["To", "224.0.0.5 (AllSPFRouters)"], ["IP protocol", "89 (OSPF, no TCP or UDP)"], ["TTL", "1: this link only"]],
          quiz: {
            q: "R2's Hello says hello interval 10 s, but R1 was configured with 30 s. What happens?",
            options: ["They agree on 10 s", "They agree on 30 s", "They ignore each other's Hellos", "R1 becomes DR"],
            answer: 2,
            why: "Hello and dead intervals, area, mask and some options must match exactly. If not, the Hello is silently ignored and no neighbour forms.",
          },
          events: [
            pkt("r1", "switch", "green", "HELLO", ["224.0.0.5", "neighbours: none"], { time: 0, info: "Hello Packet", packet: pHello1 }),
          ],
        },
        {
          title: "Two-way contact",
          desc: "Each lists the others in its Hello",
          detail:
            "R3 and R2 hear R1 and add 1.1.1.1 to the neighbour list in their next Hellos. When R1 sees its own router ID in someone else's Hello, it knows the link works both ways. The neighbour is now in the 2-Way state.",
          facts: [["R3 lists", "2.2.2.2, 1.1.1.1"], ["State", "Init → 2-Way"], ["DR", "192.0.2.3 (R3)"]],
          events: [
            pkt("r3", "switch", "green", "HELLO", ["DR 192.0.2.3", "sees 1.1.1.1"], { time: 2.1, info: "Hello Packet", packet: pHello3 }),
            pkt("r2", "switch", "green", "HELLO", ["BDR 192.0.2.2", "sees 1.1.1.1"], { time: 4.6, info: "Hello Packet", packet: pHello2 }),
            pkt("r1", "switch", "green", "HELLO", ["sees 2.2.2.2, 3.3.3.3"], { time: 10, info: "Hello Packet", packet: pHello1b }),
            note("r1", "2-WAY", "green"),
          ],
        },
        {
          title: "Who is the DR?",
          desc: "One router speaks for the segment",
          detail:
            "On a shared segment, having every router sync with every other would be wasteful. So they elect a Designated Router (DR) and a backup (BDR). Highest priority wins, then highest router ID. R3 (3.3.3.3) won before R1 arrived, and R2 is the backup. A newcomer never takes over a working DR, so R1 just accepts it.",
          facts: [["DR", "R3, 192.0.2.3"], ["BDR", "R2, 192.0.2.2"], ["R1", "DROTHER: syncs only with DR and BDR"]],
          quiz: {
            q: "If R1 had priority 200 (higher than everyone), what would happen when it joins?",
            options: ["It takes over as DR at once", "Nothing until the current DR fails", "It becomes BDR at once", "The election restarts from scratch"],
            answer: 1,
            why: "OSPF elections are not pre-emptive. A higher-priority router only becomes DR once the current DR and BDR fail, which keeps the network stable.",
          },
          events: [note("r3", "DR", "blue"), note("r2", "BDR", "blue"), note("r1", "DROTHER", "blue")],
        },
        {
          title: "Compare databases",
          desc: "Database Description packets list what each has",
          detail:
            "R1 now forms a full adjacency with the DR. First they decide who leads: the higher router ID (R3) becomes master and picks the DD sequence number. Then each sends Database Description packets with just the 20-byte headers of the LSAs it holds, so both can see which ones they are missing or which are out of date.",
          facts: [["Master", "R3 (higher router ID)"], ["R1 has", "1 LSA (its own)"], ["R3 has", "4 LSAs"]],
          events: [
            pkt("r1", "r3", "blue", "DBD", ["I, M, MS", "I want to lead"], { time: 10.01, info: `DB Description, flags I M MS, seq ${0x1a2b}`, packet: pDbd1 }),
            pkt("r3", "r1", "blue", "DBD", ["I, M, MS", "no, I lead"], { time: 10.0105, info: `DB Description, flags I M MS, seq ${DD}`, packet: pDbd3 }),
            pkt("r1", "r3", "blue", "DBD", ["slave", "1 LSA header"], { time: 10.011, info: `DB Description, seq ${DD}`, packet: pDbd1b }),
            pkt("r3", "r1", "blue", "DBD", ["MS", "4 LSA headers"], { time: 10.0115, info: `DB Description, flags MS, seq ${DD + 1}`, packet: pDbd3b }),
            pkt("r1", "r3", "blue", "DBD", ["done"], { time: 10.012, info: `DB Description, seq ${DD + 1}`, packet: pDbd1c }),
          ],
        },
        {
          title: "Request, update, acknowledge",
          desc: "LSR, LSU, LSAck",
          detail:
            "R1 sends a Link State Request for the four LSAs it lacks. R3 replies with a Link State Update carrying the full LSAs. R1 acknowledges them to 224.0.0.6, the address only the DR and BDR listen on. Each LSA carries a Fletcher checksum, so a damaged one is caught and asked for again.",
          facts: [["Requested", "4 LSAs"], ["LSAck to", "224.0.0.6 (AllDRouters)"], ["State", "Loading → Full"]],
          quiz: {
            q: "R3 now has R1's new Router-LSA. Who will R3 send it to?",
            options: ["Nobody, R1 already has it", "Every OSPF router, via 224.0.0.5", "Only R4", "Only the BDR"],
            answer: 1,
            why: "The DR floods new or changed LSAs to the whole segment on 224.0.0.5, and every router passes them on, so all routers in the area end up with the identical map.",
          },
          events: [
            pkt("r1", "r3", "blue", "LSR", ["need 4 LSAs"], { time: 10.013, info: "LS Request", packet: pLsr }),
            pkt("r3", "r1", "violet", "LSU", ["4 full LSAs"], { time: 10.0135, info: "LS Update", packet: pLsu }),
            pkt("r1", "switch", "green", "LSACK", ["to 224.0.0.6"], { time: 10.5, info: "LS Acknowledge", packet: pAck }),
            pkt("r3", "switch", "violet", "LSU", ["R1 joined", "to 224.0.0.5"], { time: 10.51, info: "LS Update", packet: pLsuNew }),
            note("r1", "FULL", "green"),
          ],
        },
        {
          title: "Run SPF",
          desc: "Dijkstra over the shared map",
          detail:
            "With the full map, R1 runs Dijkstra's algorithm with itself at the root. To reach 203.0.113.0/24 it can go via R3 (10 + 10 + 1 = 21) or via R2 (10 + 50 + 1 = 61). The cheaper path via R3 goes into the routing table, and the desk's ping follows it.",
          facts: [["Via R3", "cost 21 (chosen)"], ["Via R2", "cost 61"], ["Route", "203.0.113.0/24 via 192.0.2.3"]],
          quiz: {
            q: "What does OSPF add up to choose the best path?",
            options: ["Number of routers", "Link costs on the way", "Ping times", "AS numbers"],
            answer: 1,
            why: "Each link has a cost, often based on its speed. OSPF picks the path with the lowest total cost, not the fewest hops.",
          },
          events: [
            note("r1", "SPF: VIA R3, COST 21", "green"),
            pkt("r1", "server", "amber", "PING", ["to 203.0.113.10", "via R3"], { time: 11, via: ["switch", "r3", "r4"], info: "Echo (ping) request id=0x0001", packet: ping("r3", 0x2001) }),
          ],
        },
      ],
      outro: {
        title: "Same map everywhere",
        text: "R1 found neighbours with Hellos, accepted the existing DR, compared databases, pulled the missing LSAs and ran Dijkstra. Every router in the area now holds an identical map and computes its own shortest paths from it.",
        facts: [["Packet types used", "All 5"], ["Adjacency", "Full with DR and BDR"], ["Best path", "via R3, cost 21"], ["Time to full", "About 10 s"]],
      },
    },
    {
      id: "link-down",
      name: "A link fails",
      summary: "The R3–R4 fibre is cut. New LSAs flood, every router reruns SPF and traffic moves to R2.",
      kind: "failure",
      links: linksDown,
      steps: [
        {
          title: "The fibre is cut",
          desc: "R3 and R4 lose their link",
          detail:
            "Someone unplugs the R3–R4 cable. Both routers see the interface go down at once, so they don't need to wait 40 seconds for the dead timer. Each one builds a new Router-LSA without that link and gives it a higher sequence number.",
          facts: [["Link", "R3–R4, cost 10"], ["Detected by", "Loss of signal, instantly"], ["New LSAs", "R3 and R4, sequence +1"]],
          events: [note("r3", "LINK DOWN", "red"), note("r4", "LINK DOWN", "red")],
        },
        {
          title: "Flood the news",
          desc: "Link State Updates to 224.0.0.5",
          detail:
            "R3 is the DR, so it floods its new LSA straight to 224.0.0.5. R4 sends its own to R2, and R2 passes it to the DR and BDR on 224.0.0.6; R3 then re-floods it to everyone. Routers accept an LSA only if its sequence number is higher than the copy they hold, and pass it on to everyone except the sender.",
          facts: [["R3 seq", "0x80000002 → 0x80000003"], ["R4 seq", "0x80000003 → 0x80000004"], ["Sent to", "224.0.0.5"]],
          quiz: {
            q: "R2 receives R4's new LSA from R4 and a moment later the same LSA re-flooded by R3. What does it do with the second copy?",
            options: ["Installs it again", "Ignores it: same sequence number, already has it", "Sends it back to R3", "Reruns the DR election"],
            answer: 1,
            why: "The sequence number tells R2 it already has this exact version, so the duplicate is just acknowledged and dropped. That is what stops flooding from looping forever.",
          },
          events: [
            pkt("r3", "switch", "violet", "LSU", ["R3 changed"], { time: 0.002, info: "LS Update", packet: fLsu3 }),
            pkt("r4", "r2", "violet", "LSU", ["R4 changed"], { time: 0.002, parallel: true, info: "LS Update", packet: fLsu4 }),
            pkt("r2", "switch", "violet", "LSU", ["R4 changed", "to 224.0.0.6"], { time: 0.003, info: "LS Update", packet: fLsu2 }),
          ],
        },
        {
          title: "Acknowledge",
          desc: "Every LSA must be confirmed",
          detail:
            "Flooding is reliable: each LSA is acknowledged, and a router resends it every 5 seconds until it is. R1 acknowledges to the DR and BDR on 224.0.0.6, and R2 acknowledges to R4.",
          facts: [["R1 acks to", "224.0.0.6"], ["R2 acks to", "R4"], ["Resend if lost", "Every 5 s"]],
          events: [
            pkt("r1", "switch", "green", "LSACK", ["2 LSAs"], { time: 0.5, info: "LS Acknowledge", packet: fAck1 }),
            pkt("r2", "r4", "green", "LSACK", ["1 LSA"], { time: 0.5, parallel: true, info: "LS Acknowledge", packet: fAck2 }),
          ],
        },
        {
          title: "Reconverge",
          desc: "SPF runs again, traffic moves to R2",
          detail:
            "After a short wait to collect any other changes, every router reruns SPF. For R1 the only path left to the servers is via R2, cost 10 + 50 + 1 = 61. The routing table is updated and the next ping goes via R2. The whole change took well under a second.",
          facts: [["New path", "R1 → R2 → R4"], ["New cost", "61"], ["Outage", "Under 1 s"]],
          quiz: {
            q: "When the fibre is repaired, what will R1 do?",
            options: ["Keep using R2 forever", "Switch back to R3 after new LSAs and SPF", "Wait for an admin", "Split traffic evenly"],
            answer: 1,
            why: "The repaired link produces new LSAs, everyone reruns SPF, and the cheaper path (cost 21 via R3) wins again automatically.",
          },
          events: [
            note("r1", "SPF: VIA R2, COST 61", "green"),
            pkt("r1", "server", "amber", "PING", ["to 203.0.113.10", "via R2"], { time: 1.2, via: ["switch", "r2", "r4"], info: "Echo (ping) request id=0x0001", packet: ping("r2", 0x2002) }),
          ],
        },
      ],
      outro: {
        title: "Healed itself",
        text: "A link went down, the two routers next to it flooded new LSAs, and every router recalculated from the same updated map. No one had to change a static route; traffic simply moved to the backup link.",
        facts: [["LSAs flooded", "2"], ["SPF reruns", "Every router"], ["Recovery", "Under a second"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Packet types",
      items: [["1 Hello", "Find neighbours, elect DR"], ["2 DBD", "List of LSA headers"], ["3 LSR", "Please send these LSAs"], ["4 LSU", "Here are full LSAs"], ["5 LSAck", "Got them"]],
    },
    {
      title: "Neighbour states",
      items: [["Down → Init", "Heard a Hello"], ["2-Way", "Saw myself in their Hello"], ["ExStart / Exchange", "Pick master, swap DBDs"], ["Loading", "Fetching LSAs"], ["Full", "Databases match"]],
    },
    {
      title: "Numbers to know",
      items: [["IP protocol", "89"], ["Multicast", "224.0.0.5 all, 224.0.0.6 DR/BDR"], ["Timers", "Hello 10 s, dead 40 s, LSA refresh 30 min"], ["Default cost", "100 Mbit/s ÷ link speed"], ["LSA header", "20 bytes"]],
    },
  ],
});
