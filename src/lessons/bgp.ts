import { Device, defineLesson, note, pkt } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, tcp } from "@/lib/proto";
import { ip4 } from "@/lib/bytes";

// ---------------------------------------------------------------- addresses
// AS 64500 owns 203.0.113.0/24 (the web server's network).
// AS 64496 is the transit provider in the middle.
// AS 64510 is the second ISP, where the laptop lives (198.51.100.0/24).
// AS 64511 is the badly behaved network in the hijack scenario.
const A_IP = "192.0.2.2"; // AS64500 side of link 1
const TA_IP = "192.0.2.1"; // transit side of link 1
const TB_IP = "192.0.2.5"; // transit side of link 2
const B_IP = "192.0.2.6"; // AS64510 side of link 2
const TX_IP = "192.0.2.9"; // transit side of the link to the bad AS
const X_IP = "192.0.2.10"; // bad AS
const RPKI_IP = "192.0.2.200";
const LAPTOP = "198.51.100.20";
const WEB = "203.0.113.10";

const MAC = {
  a: "00:1c:73:a5:00:01",
  t1: "00:1c:73:b6:00:01",
  t2: "00:1c:73:b6:00:02",
  t3: "00:1c:73:b6:00:03",
  t4: "00:1c:73:b6:00:04",
  b: "00:1c:73:c7:00:01",
  x: "02:42:66:66:00:01",
  rpki: "00:16:3e:7e:00:c8",
};

// ---------------------------------------------------------------- BGP message builders

const size = (specs: FieldSpec[]) => specs.map(field).flatMap((f) => f.bytes).length;

interface Msg { spec: LayerSpec; len: number }

function bgp(type: number, typeName: string, body: FieldSpec[], summary: string): Msg {
  const len = 19 + size(body);
  return {
    len,
    spec: proto({
      id: "bgp",
      name: "BGP",
      osi: 7,
      summary: `Border Gateway Protocol - ${summary}`,
      fields: [
        { name: "Marker", bytes: new Array(16).fill(0xff), value: "ff × 16", note: "16 bytes of all ones. Older versions used it for authentication; today it just marks where a message starts." },
        { name: "Length", u16: len, value: `${len} bytes`, note: "The whole message, marker included. Between 19 and 4096 bytes." },
        { name: "Type", u8: type, value: `${type} (${typeName})` },
        ...body,
      ],
    }),
  };
}

const capParam = (name: string, code: number, data: FieldSpec[], note: string): FieldSpec => {
  const dlen = size(data);
  return {
    name: `Capability: ${name}`,
    note,
    fields: [
      { name: "Parameter type", u8: 2, value: "2 (Capabilities)" },
      { name: "Parameter length", u8: dlen + 2 },
      { name: "Capability code", u8: code, value: `${code} (${name})` },
      { name: "Capability length", u8: dlen },
      ...data,
    ],
  };
};

const open = (asn: number, hold: number, id: string): Msg => {
  const params: FieldSpec[] = [
    capParam("Multiprotocol extensions", 1, [
      { name: "AFI", u16: 1, value: "1 (IPv4)" },
      { name: "Reserved", u8: 0 },
      { name: "SAFI", u8: 1, value: "1 (Unicast)" },
    ], "I can exchange IPv4 unicast routes."),
    capParam("Route refresh", 2, [], "You may ask me to resend all my routes without restarting the session."),
    capParam("4-octet AS number", 65, [{ name: "AS number", u32: asn }], "I understand 4-byte AS numbers. My real AS number is repeated here."),
  ];
  return bgp(1, "OPEN", [
    { name: "Version", u8: 4, note: "BGP-4, the version the whole internet runs." },
    { name: "My AS", u16: asn, note: "The sender's Autonomous System number. AS numbers above 65535 write 23456 here and use the capability below." },
    { name: "Hold time", u16: hold, value: `${hold} s`, note: "If nothing arrives for this long, the session is declared dead. Both sides use the smaller of the two values." },
    { name: "BGP identifier", bytes: ip4(id), value: id, note: "The router ID: a 32-bit number written like an IPv4 address, unique per router." },
    { name: "Optional parameters length", u8: size(params) },
    ...params,
  ], "OPEN Message");
};

const keepalive = (): Msg => bgp(4, "KEEPALIVE", [], "KEEPALIVE Message");

const prefixBytes = (len: number, pfx: string) => [len, ...ip4(pfx).slice(0, Math.ceil(len / 8))];

const update = (o: { withdrawn?: [string, number][]; path?: number[]; nh?: string; nlri?: [string, number][] }): Msg => {
  const wd: FieldSpec[] = (o.withdrawn ?? []).map(([p, l]) => ({ name: "Withdrawn route", bytes: prefixBytes(l, p), value: `${p}/${l}`, note: "Length in bits, then only as many bytes of the prefix as needed." }));
  const attrs: FieldSpec[] = [];
  if (o.path && o.nh) {
    attrs.push(
      {
        name: "ORIGIN", value: "IGP", note: "Where the route came from originally. IGP means the owner announced it on purpose.",
        fields: [
          { name: "Flags", u8: 0x40, value: "0x40 (well-known, transitive)" },
          { name: "Type code", u8: 1, value: "1 (ORIGIN)" },
          { name: "Length", u8: 1 },
          { name: "Origin", u8: 0, value: "0 (IGP)" },
        ],
      },
      {
        name: "AS_PATH", value: o.path.join(" "), note: "Every AS that passes the route on adds its own number to the front. Routers reject a route that already contains their own AS, which stops loops.",
        fields: [
          { name: "Flags", u8: 0x40, value: "0x40 (well-known, transitive)" },
          { name: "Type code", u8: 2, value: "2 (AS_PATH)" },
          { name: "Length", u8: 2 + 4 * o.path.length },
          { name: "Segment type", u8: 2, value: "2 (AS_SEQUENCE)" },
          { name: "Segment length", u8: o.path.length, value: `${o.path.length} AS` },
          ...o.path.map((asn) => ({ name: "AS number", u32: asn, note: "4 bytes each, because both sides announced the 4-octet AS capability." })),
        ],
      },
      {
        name: "NEXT_HOP", value: o.nh, note: "Send traffic for these prefixes to this address.",
        fields: [
          { name: "Flags", u8: 0x40, value: "0x40 (well-known, transitive)" },
          { name: "Type code", u8: 3, value: "3 (NEXT_HOP)" },
          { name: "Length", u8: 4 },
          { name: "Next hop", bytes: ip4(o.nh), value: o.nh },
        ],
      },
    );
  }
  const nlri: FieldSpec[] = (o.nlri ?? []).map(([p, l]) => ({ name: "NLRI prefix", bytes: prefixBytes(l, p), value: `${p}/${l}`, note: "A reachable network: prefix length in bits, then the needed bytes of the address." }));
  const what = o.nlri?.length ? `announce ${o.nlri.map(([p, l]) => `${p}/${l}`).join(", ")}` : `withdraw ${(o.withdrawn ?? []).map(([p, l]) => `${p}/${l}`).join(", ")}`;
  return bgp(2, "UPDATE", [
    { name: "Withdrawn routes length", u16: size(wd), value: `${size(wd)} bytes` },
    ...wd,
    { name: "Total path attribute length", u16: size(attrs), value: `${size(attrs)} bytes` },
    ...attrs,
    ...nlri,
  ], `UPDATE Message (${what})`);
};

const notification = (code: number, sub: number, name: string): Msg =>
  bgp(3, "NOTIFICATION", [
    { name: "Error code", u8: code, value: `${code} (${name})` },
    { name: "Error subcode", u8: sub, value: `${sub} (unspecific)` },
  ], `NOTIFICATION Message (${name})`);

// ---------------------------------------------------------------- TCP sessions with running sequence numbers

interface Side { ip: string; mac: string; port: number; base: number; seq: number }

function session(a: Side, b: Side) {
  let ipId = 0x2a00;
  const seg = (from: Side, to: Side, flags: string, payload?: LayerSpec, len = 0) => {
    const p = build(
      eth({ src: from.mac, dst: to.mac }),
      ipv4({ src: from.ip, dst: to.ip, ttl: 1, dscp: 48, id: ipId++ }),
      tcp({ sport: from.port, dport: to.port, seq: from.seq, ack: flags.includes("A") ? to.seq : 0, flags, win: 16384, seqBase: from.base, ackBase: to.base, opts: flags.includes("S") ? [{ mss: 1460 }] : undefined }),
      ...(payload ? [payload] : []),
    );
    const info = { seq: from.seq, ack: to.seq, len };
    from.seq += len;
    return { p, ...info };
  };
  return {
    msg: (fromA: boolean, m: Msg) => (fromA ? seg(a, b, "PA", m.spec, m.len) : seg(b, a, "PA", m.spec, m.len)),
    syn: () => { const r = seg(a, b, "S"); a.seq = 1; return r; },
    synack: () => { const r = seg(b, a, "SA"); b.seq = 1; return r; },
    ack: (fromA: boolean) => (fromA ? seg(a, b, "A") : seg(b, a, "A")),
    fin: (fromA: boolean) => { const r = fromA ? seg(a, b, "FA") : seg(b, a, "FA"); (fromA ? a : b).seq += 1; return r; },
  };
}

// ---------------------------------------------------------------- normal scenario packets (built in order)

const sA = { ip: A_IP, mac: MAC.a, port: 50112, base: 0x3e8a1100, seq: 0 };
const sT = { ip: TA_IP, mac: MAC.t1, port: 179, base: 0x91c40a00, seq: 0 };
const s1 = session(sA, sT);
const syn = s1.syn();
const synack = s1.synack();
const ack3 = s1.ack(true);
const openA = s1.msg(true, open(64500, 90, "10.255.0.1"));
const openT = s1.msg(false, open(64496, 180, "10.255.0.2"));
const kaA = s1.msg(true, keepalive());
const kaT = s1.msg(false, keepalive());
const upd1 = update({ path: [64500], nh: A_IP, nlri: [["203.0.113.0", 24]] });
const updA = s1.msg(true, upd1);
const ka2A = s1.msg(true, keepalive());
const ka2T = s1.msg(false, keepalive());

// transit ↔ AS64510 session was already up (OPEN 49 + KEEPALIVE 19 each way = 68 bytes)
const sT2 = { ip: TB_IP, mac: MAC.t2, port: 179, base: 0x5d0e7700, seq: 69 };
const sB = { ip: B_IP, mac: MAC.b, port: 41870, base: 0x0c4f2200, seq: 69 };
const s2 = session(sB, sT2);
const updToB = s2.msg(false, update({ path: [64496, 64500], nh: TB_IP, nlri: [["203.0.113.0", 24]] }));

const seqInfo = (r: { seq: number; ack: number; len: number }) => `Seq=${r.seq} Ack=${r.ack} Len=${r.len}`;

// ---------------------------------------------------------------- hold timer failure packets

const fA = { ip: A_IP, mac: MAC.a, port: 50112, base: 0x3e8a1100, seq: 4021 };
const fT = { ip: TA_IP, mac: MAC.t1, port: 179, base: 0x91c40a00, seq: 3388 };
const f1 = session(fA, fT);
const fKa1 = f1.msg(false, keepalive());
const fKa2 = f1.msg(false, keepalive());
const fKa3 = f1.msg(false, keepalive());
const fNote = f1.msg(false, notification(4, 0, "Hold Timer Expired"));
const fFin = f1.fin(false);
const fB = { ip: B_IP, mac: MAC.b, port: 41870, base: 0x0c4f2200, seq: 2210 };
const fT2 = { ip: TB_IP, mac: MAC.t2, port: 179, base: 0x5d0e7700, seq: 2871 };
const f2 = session(fB, fT2);
const fWd = f2.msg(false, update({ withdrawn: [["203.0.113.0", 24]] }));

// ---------------------------------------------------------------- hijack scenario packets

const hX = { ip: X_IP, mac: MAC.x, port: 38001, base: 0x66600000, seq: 69 };
const hT = { ip: TX_IP, mac: MAC.t3, port: 179, base: 0x77100000, seq: 69 };
const h1 = session(hX, hT);
const hijack = update({ path: [64511], nh: X_IP, nlri: [["203.0.113.0", 25]] });
const hUpd = h1.msg(true, hijack);
const hB = { ip: B_IP, mac: MAC.b, port: 41870, base: 0x0c4f2200, seq: 1305 };
const hT2 = { ip: TB_IP, mac: MAC.t2, port: 179, base: 0x5d0e7700, seq: 1877 };
const h2 = session(hB, hT2);
const hFwd = h2.msg(false, update({ path: [64496, 64511], nh: TB_IP, nlri: [["203.0.113.0", 25]] }));
const hUpd2 = h1.msg(true, hijack);

// a web request from the laptop, captured on AS64510's uplink to the transit
const visit = (id: number) =>
  build(eth({ src: MAC.b, dst: MAC.t2 }), ipv4({ src: LAPTOP, dst: WEB, ttl: 63, id }), tcp({ sport: 52044, dport: 443, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }], seqBase: 0x1f2e3d4c }));

// RPKI-to-Router (RFC 8210) IPv4 Prefix PDU from the validator to the transit router
const rtrPdu = proto({
  id: "rpki-rtr",
  name: "RPKI-Router",
  osi: 7,
  summary: "RPKI-Router Protocol, IPv4 Prefix PDU: 203.0.113.0/24-24 AS64500",
  fields: [
    { name: "Protocol version", u8: 1 },
    { name: "PDU type", u8: 4, value: "4 (IPv4 Prefix)" },
    { name: "Zero", u16: 0 },
    { name: "Length", u32: 20, value: "20 bytes" },
    { name: "Flags", u8: 1, value: "1 (announce)", note: "1 adds this ROA to the router's table, 0 removes it." },
    { name: "Prefix length", u8: 24 },
    { name: "Max length", u8: 24, note: "The longest prefix AS64500 may announce. A /25 is longer than allowed, so it is invalid." },
    { name: "Zero", u8: 0 },
    { name: "IPv4 prefix", bytes: ip4("203.0.113.0"), value: "203.0.113.0" },
    { name: "AS number", u32: 64500, note: "The only AS allowed to originate this prefix." },
  ],
});
const rtrPkt = build(
  eth({ src: MAC.rpki, dst: MAC.t4 }),
  ipv4({ src: RPKI_IP, dst: "192.0.2.201", ttl: 64, id: 0x0d11 }),
  tcp({ sport: 323, dport: 33012, seq: 241, ack: 37, flags: "PA", win: 502, seqBase: 0x4b1c0000, ackBase: 0x2d900000 }),
  rtrPdu,
);

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "laptop", kind: "laptop", label: "Laptop", sub: LAPTOP, x: 8, y: 72 },
  { id: "isp-b", kind: "router", label: "ISP B · AS64510", sub: B_IP, x: 26, y: 55 },
  { id: "transit", kind: "isp", label: "Transit · AS64496", sub: `${TA_IP} / ${TB_IP}`, x: 50, y: 30 },
  { id: "isp-a", kind: "router", label: "ISP A · AS64500", sub: A_IP, x: 72, y: 55 },
  { id: "server", kind: "web", label: "Web server", sub: WEB, x: 91, y: 72 },
];
const links: [string, string][] = [
  ["laptop", "isp-b"],
  ["isp-b", "transit"],
  ["transit", "isp-a"],
  ["isp-a", "server"],
];
const hijackDevices: Device[] = [
  ...devices,
  { id: "bad-as", kind: "attacker", label: "Bad AS64511", sub: X_IP, x: 72, y: 16 },
  { id: "rpki", kind: "auth", label: "RPKI validator", sub: RPKI_IP, x: 28, y: 18 },
];
const hijackLinks: [string, string][] = [...links, ["transit", "bad-as"], ["transit", "rpki"]];

export default defineLesson({
  id: "bgp",
  name: "BGP",
  full: "Border Gateway Protocol",
  group: "routing",
  layer: 7,
  difficulty: 3,
  tagline: "How the networks of the internet tell each other who lives where.",
  description:
    "The internet is about 75,000 separate networks called Autonomous Systems. BGP is how they tell their neighbours which address blocks they can reach and through which chain of networks. Every route you use to reach a website was learned through BGP.",
  facts: [
    ["Layer", "Application (runs over TCP)"],
    ["Port", "TCP 179"],
    ["Messages", "OPEN, UPDATE, KEEPALIVE, NOTIFICATION"],
    ["Header", "19 bytes (16-byte marker + length + type)"],
    ["Route choice", "Policy first, then shortest AS_PATH"],
    ["Defined in", "RFC 4271"],
  ],
  ports: "TCP 179",
  rfc: "RFC 4271, RFC 6793, RFC 6811",
  keywords: ["autonomous system", "asn", "as path", "peering", "transit", "route hijack", "rpki", "rov", "roa", "prefix", "keepalive", "hold time", "ebgp"],
  related: ["tcp", "ospf", "mpls", "cdn", "ip"],
  devices,
  links,
  legend: [
    ["green", "TCP setup and KEEPALIVEs"],
    ["blue", "OPEN: session settings"],
    ["violet", "UPDATE: routes announced"],
    ["red", "Errors and hijacks"],
    ["teal", "RPKI data"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Two ISPs learn a route through a transit",
      summary: "ISP A brings up a BGP session with its transit provider and announces 203.0.113.0/24; the transit passes it on to ISP B.",
      kind: "normal",
      steps: [
        {
          title: "Open a TCP session",
          desc: "ISP A connects to the transit on port 179",
          detail:
            "BGP does not have its own reliability. It rides on TCP, so lost messages are resent and arrive in order. ISP A's router has the transit's address configured as a neighbour and opens a connection to port 179. The IP TTL is 1 because external BGP neighbours are normally directly connected.",
          facts: [["From", `${A_IP} (AS64500)`], ["To", `${TA_IP}:179 (AS64496)`], ["IP TTL", "1 (neighbour is one hop away)"]],
          quiz: {
            q: "Why can BGP send each route just once, instead of repeating it every few seconds?",
            options: ["Routes never change", "TCP guarantees each message arrives", "Routers save routes to disk", "UDP is fast enough to repeat"],
            answer: 1,
            why: "Because TCP delivers every byte reliably, a route only needs to be sent when it changes. That is why BGP scales to about a million routes.",
          },
          events: [
            pkt("isp-a", "transit", "green", "SYN", ["to port 179"], {
              time: 0, info: `${sA.port} → 179 [SYN] Seq=0 Win=16384 Len=0 MSS=1460`, packet: syn.p,
            }),
            pkt("transit", "isp-a", "green", "SYN-ACK", ["seq=0 ack=1"], {
              time: 0.0004, info: `179 → ${sA.port} [SYN, ACK] Seq=0 Ack=1 Win=16384 Len=0 MSS=1460`, packet: synack.p,
            }),
            pkt("isp-a", "transit", "green", "ACK", ["connected"], {
              time: 0.0008, info: `${sA.port} → 179 [ACK] Seq=1 Ack=1 Win=16384 Len=0`, packet: ack3.p,
            }),
          ],
        },
        {
          title: "Exchange OPEN",
          desc: "Who are you, and what can you do?",
          detail:
            "Each router sends an OPEN with its AS number, a hold time, its router ID and a list of capabilities. Here both sides support IPv4 unicast routes, route refresh and 4-byte AS numbers. If the AS number is not what the other side has configured, it rejects the session straight away.",
          facts: [["ISP A says", "AS64500, hold 90 s"], ["Transit says", "AS64496, hold 180 s"], ["OPEN size", `${openA.len} bytes each`]],
          quiz: {
            q: "ISP A offers a hold time of 90 s and the transit offers 180 s. Which hold time does the session use?",
            options: ["180 s", "90 s", "135 s (the average)", "Each side uses its own"],
            answer: 1,
            why: "Both sides take the smaller value, so the session uses 90 s. KEEPALIVEs are then usually sent every third of that: 30 s.",
          },
          events: [
            pkt("isp-a", "transit", "blue", "OPEN", ["AS64500", "hold 90 s"], {
              time: 0.001, info: `OPEN Message, ${seqInfo(openA)}`, packet: openA.p,
            }),
            pkt("transit", "isp-a", "blue", "OPEN", ["AS64496", "hold 180 s"], {
              time: 0.0014, info: `OPEN Message, ${seqInfo(openT)}`, packet: openT.p,
            }),
          ],
        },
        {
          title: "KEEPALIVE: Established",
          desc: "A 19-byte message that says “I agree”",
          detail:
            "A KEEPALIVE is only the 19-byte header with type 4. The first one confirms the other side's OPEN. Once both have arrived, the session moves to the Established state and routes can flow.",
          facts: [["Size", "19 bytes"], ["Type", "4 (KEEPALIVE)"], ["State", "OpenConfirm → Established"]],
          events: [
            pkt("isp-a", "transit", "green", "KEEPALIVE", ["OPEN accepted"], {
              time: 0.0018, info: `KEEPALIVE Message, ${seqInfo(kaA)}`, packet: kaA.p,
            }),
            pkt("transit", "isp-a", "green", "KEEPALIVE", ["OPEN accepted"], {
              time: 0.0022, info: `KEEPALIVE Message, ${seqInfo(kaT)}`, packet: kaT.p,
            }),
            note("isp-a", "ESTABLISHED", "green"),
            note("transit", "ESTABLISHED", "green"),
          ],
        },
        {
          title: "Announce 203.0.113.0/24",
          desc: "UPDATE: this block of addresses lives with me",
          detail:
            "ISP A sends an UPDATE for its address block. The path attributes describe the route: ORIGIN says it was announced on purpose, AS_PATH lists the networks it has passed through (just 64500 so far), and NEXT_HOP says where to send the traffic. The prefix itself comes last as the NLRI.",
          facts: [["Prefix", "203.0.113.0/24"], ["AS_PATH", "64500"], ["NEXT_HOP", A_IP]],
          quiz: {
            q: "The transit passes this route on to ISP B. What AS_PATH will ISP B see?",
            options: ["64500", "64496 64500", "64500 64496", "64510 64496 64500"],
            answer: 1,
            why: "Each AS adds its own number to the front when it sends the route to another AS. ISP B sees 64496 64500 and only adds 64510 if it passes the route on again.",
          },
          events: [
            pkt("isp-a", "transit", "violet", "UPDATE", ["203.0.113.0/24", "path 64500"], {
              time: 0.05, info: `UPDATE Message, ${seqInfo(updA)}`, packet: updA.p,
            }),
          ],
        },
        {
          title: "Pass it on to ISP B",
          desc: "The transit adds its AS and its own next hop",
          detail:
            "The transit's session with ISP B is already up. It sends the route on with 64496 added to the front of the AS_PATH and its own address as NEXT_HOP. ISP B installs it, and its customers can now reach 203.0.113.0/24 through the transit.",
          facts: [["AS_PATH", "64496 64500"], ["NEXT_HOP", `${TB_IP} (the transit)`], ["Path length", "2 AS hops"]],
          quiz: {
            q: "If ISP B received this route with 64510 already in the AS_PATH, what would it do?",
            options: ["Install it as the best route", "Reject it, because that would be a loop", "Forward it back to the transit", "Ask the transit to refresh"],
            answer: 1,
            why: "Seeing its own AS number means the route has already passed through it. Rejecting such routes is how BGP prevents loops between networks.",
          },
          events: [
            pkt("transit", "isp-b", "violet", "UPDATE", ["203.0.113.0/24", "path 64496 64500"], {
              time: 0.06, info: `UPDATE Message, ${seqInfo(updToB)}`, packet: updToB.p,
            }),
            note("isp-b", "ROUTE INSTALLED", "green"),
          ],
        },
        {
          title: "Stay in touch",
          desc: "KEEPALIVEs every 30 seconds",
          detail:
            "With nothing new to say, the routers just send KEEPALIVEs, every 30 seconds here (a third of the 90 s hold time). If no message of any kind arrives for 90 seconds, the session is torn down and every route learned over it is removed.",
          facts: [["Interval", "30 s"], ["Hold time", "90 s"], ["Routes", "Only resent when they change"]],
          events: [
            pkt("isp-a", "transit", "green", "KEEPALIVE", ["still here"], {
              time: 30.0018, info: `KEEPALIVE Message, ${seqInfo(ka2A)}`, packet: ka2A.p,
            }),
            pkt("transit", "isp-a", "green", "KEEPALIVE", ["me too"], {
              time: 30.0022, info: `KEEPALIVE Message, ${seqInfo(ka2T)}`, packet: ka2T.p,
            }),
          ],
        },
      ],
      outro: {
        title: "The route is out there",
        text: "Two routers set up a TCP session, agreed on settings with OPEN, confirmed with KEEPALIVE and exchanged a route in one UPDATE. The transit passed it on with its own AS added, which is how every network on the internet learns a path to every other.",
        facts: [["BGP messages", "8"], ["Route", "203.0.113.0/24 via 64496 64500"], ["Keeps alive", "Every 30 s"], ["Port", "TCP 179"]],
      },
    },
    {
      id: "hold-timer",
      name: "Hold timer expires",
      summary: "ISP A's router freezes and stops talking. After 90 seconds the transit gives up and withdraws the route.",
      kind: "failure",
      steps: [
        {
          title: "Silence from ISP A",
          desc: "The transit keeps sending, nothing comes back",
          detail:
            "ISP A's router has a stuck BGP process: the link is up, but it no longer sends KEEPALIVEs. The transit carries on sending its own every 30 seconds and starts counting down its hold timer.",
          facts: [["Link", "Up"], ["KEEPALIVEs from A", "None"], ["Hold timer", "Counting down from 90 s"]],
          events: [
            pkt("transit", "isp-a", "green", "KEEPALIVE", ["t = 0 s"], { time: 0, info: `KEEPALIVE Message, ${seqInfo(fKa1)}`, packet: fKa1.p }),
            pkt("transit", "isp-a", "green", "KEEPALIVE", ["t = 30 s"], { time: 30, info: `KEEPALIVE Message, ${seqInfo(fKa2)}`, packet: fKa2.p }),
            pkt("transit", "isp-a", "green", "KEEPALIVE", ["t = 60 s"], { time: 60, info: `KEEPALIVE Message, ${seqInfo(fKa3)}`, packet: fKa3.p }),
            note("isp-a", "BGP PROCESS STUCK", "amber"),
          ],
        },
        {
          title: "NOTIFICATION",
          desc: "Error code 4: Hold Timer Expired",
          detail:
            "After 90 seconds with nothing received, the transit sends a NOTIFICATION with error code 4 and closes the TCP connection. A NOTIFICATION always ends the session. All routes learned from ISP A are thrown away.",
          facts: [["Error code", "4 (Hold Timer Expired)"], ["Size", "21 bytes"], ["Then", "TCP FIN, session Idle"]],
          quiz: {
            q: "What happens to 203.0.113.0/24 in the transit's routing table now?",
            options: ["It stays until someone deletes it", "It is removed, and neighbours are told", "It is kept for 24 hours", "It moves to ISP B"],
            answer: 1,
            why: "Routes only live as long as the session they came from. The transit removes them and tells its other neighbours with a withdrawal.",
          },
          events: [
            pkt("transit", "isp-a", "red", "NOTIFY", ["hold timer expired"], { time: 90, info: `NOTIFICATION Message (Hold Timer Expired), ${seqInfo(fNote)}`, packet: fNote.p }),
            pkt("transit", "isp-a", "slate", "FIN", ["closing TCP"], { time: 90.0001, info: `179 → ${fA.port} [FIN, ACK] Seq=${fFin.seq} Ack=${fFin.ack} Len=0`, packet: fFin.p }),
            note("transit", "SESSION DOWN", "red"),
          ],
        },
        {
          title: "Withdraw the route",
          desc: "UPDATE with a withdrawn prefix",
          detail:
            "The transit sends ISP B an UPDATE that has no path attributes, just a withdrawn route. ISP B removes 203.0.113.0/24. If ISP A had a second provider, traffic would now flow that way; with only one, the web server is unreachable until the session comes back.",
          facts: [["Withdrawn", "203.0.113.0/24"], ["Path attributes", "None"], ["UPDATE size", "27 bytes"]],
          events: [
            pkt("transit", "isp-b", "red", "WITHDRAW", ["203.0.113.0/24"], { time: 90.01, info: `UPDATE Message (withdraw), ${seqInfo(fWd)}`, packet: fWd.p }),
            note("isp-b", "ROUTE REMOVED", "red"),
          ],
        },
      ],
      outro: {
        title: "Unreachable until it recovers",
        text: "The hold timer is how BGP notices a neighbour that has quietly died. The cost is up to 90 seconds of black-holed traffic, which is why many networks also run BFD, a tiny hello protocol that detects failures in under a second.",
        facts: [["Detected after", "90 s"], ["Error", "NOTIFICATION code 4"], ["Faster option", "BFD (RFC 5880)"]],
      },
    },
    {
      id: "hijack",
      name: "Route hijack and RPKI",
      summary: "A bad network announces a more specific /25 for ISP A's addresses; RPKI route origin validation stops it.",
      kind: "attack",
      devices: hijackDevices,
      links: hijackLinks,
      steps: [
        {
          title: "A false announcement",
          desc: "AS64511 claims 203.0.113.0/25",
          detail:
            "A network that does not own these addresses announces 203.0.113.0/25, the first half of ISP A's block. This happens by accident (a typo in a filter) or on purpose (to steal traffic). BGP itself has no way to check who owns an address block.",
          facts: [["Announced by", "AS64511"], ["Prefix", "203.0.113.0/25"], ["Real owner", "AS64500 (/24)"]],
          quiz: {
            q: "Routers now know 203.0.113.0/24 via AS64500 and 203.0.113.0/25 via AS64511. Where does traffic to 203.0.113.10 go?",
            options: ["AS64500, it was there first", "AS64511, the longer prefix wins", "Split evenly between them", "Nowhere, the routes conflict"],
            answer: 1,
            why: "Routers always use the most specific matching prefix. A /25 is more specific than a /24, so it wins no matter how long the AS_PATH is.",
          },
          events: [
            pkt("bad-as", "transit", "red", "UPDATE", ["203.0.113.0/25", "path 64511"], { time: 0, info: `UPDATE Message, ${seqInfo(hUpd)}`, packet: hUpd.p }),
          ],
        },
        {
          title: "Without checks: hijacked",
          desc: "The transit believes it and spreads it",
          detail:
            "With no validation, the transit accepts the route and passes it on to ISP B. The laptop's connection to 203.0.113.10 now heads to AS64511, which can drop it, read it or pretend to be the server.",
          facts: [["ISP B sees", "203.0.113.0/25 via 64496 64511"], ["Traffic to", "AS64511"], ["Real server", "Never sees it"]],
          events: [
            pkt("transit", "isp-b", "red", "UPDATE", ["203.0.113.0/25", "path 64496 64511"], { time: 0.01, info: `UPDATE Message, ${seqInfo(hFwd)}`, packet: hFwd.p }),
            pkt("laptop", "bad-as", "red", "SYN", ["to 203.0.113.10", "hijacked"], {
              time: 5, via: ["isp-b", "transit"], info: "52044 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128", packet: visit(0x51c0),
            }),
            note("bad-as", "TRAFFIC STOLEN", "red"),
          ],
        },
        {
          title: "Learn who owns what",
          desc: "RPKI: signed Route Origin Authorisations",
          detail:
            "ISP A has published a ROA, a certificate-signed statement in the RPKI saying “203.0.113.0/24, max length 24, may only be originated by AS64500”. A validator downloads and checks all ROAs and hands the results to routers over the RPKI-to-Router protocol on TCP 323.",
          facts: [["ROA", "203.0.113.0/24, max /24, AS64500"], ["Signed by", "The regional internet registry"], ["To routers via", "RPKI-RTR, TCP 323"]],
          events: [
            pkt("rpki", "transit", "teal", "ROA", ["203.0.113.0/24", "AS64500 only"], { time: 60, info: "IPv4 Prefix PDU: 203.0.113.0/24-24 AS64500", packet: rtrPkt }),
            note("transit", "ROV ENABLED", "green"),
          ],
        },
        {
          title: "Same attack, now rejected",
          desc: "Route origin validation marks it Invalid",
          detail:
            "AS64511 announces the /25 again. The transit compares it with the ROA: the origin AS is wrong and /25 is longer than the allowed max length, so the route is Invalid and dropped. It is never passed to ISP B.",
          facts: [["Origin AS", "64511 (should be 64500)"], ["Length", "/25 (max allowed /24)"], ["Result", "Invalid → dropped"]],
          quiz: {
            q: "What if AS64511 instead announced 203.0.113.0/24 with AS_PATH “64511 64500”, faking AS64500 as the origin?",
            options: ["ROV would catch it", "ROV would mark it Valid, because only the origin is checked", "BGP would reject the duplicate prefix", "The ROA would expire"],
            answer: 1,
            why: "ROV only checks the last AS in the path. Faking the origin gets past it, though the route is longer than the real one. BGPsec and ASPA are newer tools that check the whole path.",
          },
          events: [
            pkt("bad-as", "transit", "red", "UPDATE", ["203.0.113.0/25", "path 64511"], { time: 120, info: `UPDATE Message, ${seqInfo(hUpd2)}`, packet: hUpd2.p }),
            note("transit", "RPKI INVALID: DROPPED", "green"),
          ],
        },
        {
          title: "Traffic goes home",
          desc: "Only the real /24 is left",
          detail:
            "ISP B never hears about the /25, so the laptop's traffic follows the genuine route through the transit to AS64500 and reaches the real web server.",
          facts: [["Route used", "203.0.113.0/24 via 64496 64500"], ["Reaches", "The real server"], ["Protected by", "ROA + ROV"]],
          events: [
            pkt("laptop", "server", "green", "SYN", ["to 203.0.113.10", "right place"], {
              time: 125, via: ["isp-b", "transit", "isp-a"], info: "52044 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128", packet: visit(0x51c1),
            }),
          ],
        },
      ],
      outro: {
        title: "Hijack blocked",
        text: "BGP trusts what neighbours say, so a single wrong announcement can pull traffic across the world. RPKI lets address owners sign who may originate their prefixes, and route origin validation drops announcements that break those rules.",
        facts: [["Attack", "More-specific prefix hijack"], ["Defence", "ROA + ROV (RFC 6811)"], ["Still open", "Forged paths: BGPsec, ASPA"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Message types",
      items: [["1 OPEN", "Start a session: AS, hold time, router ID, capabilities"], ["2 UPDATE", "Announce or withdraw routes"], ["3 NOTIFICATION", "Fatal error, session closes"], ["4 KEEPALIVE", "I'm alive / I accept your OPEN"]],
    },
    {
      title: "Path attributes",
      items: [["1 ORIGIN", "IGP, EGP or incomplete"], ["2 AS_PATH", "Networks the route has passed"], ["3 NEXT_HOP", "Where to send traffic"], ["4 MED", "Hint to a neighbour which entry to use"], ["5 LOCAL_PREF", "Preference inside one AS"]],
    },
    {
      title: "Numbers to know",
      items: [["Port", "TCP 179"], ["Header", "19 bytes; max message 4096"], ["Default timers", "Keepalive 60 s, hold 180 s (Cisco)"], ["Doc AS numbers", "64496–64511, 65536–65551"], ["Private AS numbers", "64512–65534"]],
    },
  ],
});
