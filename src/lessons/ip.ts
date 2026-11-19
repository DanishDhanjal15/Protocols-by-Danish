import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, proto } from "@/lib/packet";
import { eth, icmp, ipv4, tcp, TcpOpt } from "@/lib/proto";
import { Bytes, u32le } from "@/lib/bytes";
import { ADDR } from "./_common";

// Addresses for this lesson. The home router does NAT, so beyond it the
// source address is the router's public one (198.51.100.7).
const LAPTOP = ADDR.laptop;
const PUB = ADDR.routerWan;
const ISP = "198.51.100.1";
const CORE = "203.0.113.1";
const S = ADDR.web;

const MAC = {
  laptop: ADDR.laptopMac,
  routerLan: ADDR.routerMac,
  routerWan: "b0:be:76:12:4c:02",
  ispA: "00:25:90:aa:10:01", // ISP router, port facing the home
  ispB: "00:25:90:aa:10:02", // ISP router, port facing the core
  coreA: "5c:5e:ab:20:00:01", // core router, port facing the ISP
  coreB: "5c:5e:ab:20:00:02", // core router, port facing the server
  server: ADDR.serverMac,
};

const SP = 51234;
const SEQ = 0x3c11a000;
const synOpts: TcpOpt[] = [{ mss: 1460 }, "sackOk", { ts: [1203311, 0] }, "nop", { ws: 7 }];
const syn = () => tcp({ sport: SP, dport: 443, seq: 0, flags: "S", opts: synOpts, seqBase: SEQ });
const IPID = 0x5e2a;

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: LAPTOP, x: 8, y: 64 },
  { id: "router", kind: "router", label: "Home router", sub: ADDR.router, x: 28, y: 64 },
  { id: "isp", kind: "isp", label: "ISP router", sub: ISP, x: 48, y: 32 },
  { id: "core", kind: "router", label: "Core router", sub: CORE, x: 69, y: 64 },
  { id: "server", kind: "web", label: "Web server", sub: S, x: 91, y: 36 },
];
const links: [string, string][] = [
  ["client", "router"],
  ["router", "isp"],
  ["isp", "core"],
  ["core", "server"],
];

// ---------------------------------------------------------------- ping data for the fragmentation story

/** Linux ping payload: 16-byte timestamp, then counting bytes 0x10, 0x11, ... */
const pingData = (len: number, sec: number, usec: number): Bytes => {
  const ts = [...u32le(sec), 0, 0, 0, 0, ...u32le(usec), 0, 0, 0, 0];
  const rest: Bytes = [];
  for (let i = 16; i < len; i++) rest.push(i & 0xff);
  return [...ts, ...rest];
};

const PING_ID = 0x2f1c;
const BIG = 1472; // ping -s 1472: 1472 + 8 ICMP + 20 IP = 1500 bytes
const FRAG1 = 1376; // 1400 MTU - 20 header = 1380, rounded down to a multiple of 8
const reqData = pingData(BIG, 1763548800, 412233);
const echo = (type: 0 | 8) =>
  icmp({ type, name: type === 8 ? "Echo (ping) request" : "Echo (ping) reply", restFields: [{ name: "Identifier", u16: PING_ID, value: `0x${PING_ID.toString(16)}` }, { name: "Sequence number", u16: 1 }], data: reqData, dataName: "Data", dataNote: "16-byte timestamp, then counting bytes. 1472 bytes in all." });
const fullMsg = (type: 0 | 8) => build(echo(type)).bytes; // whole ICMP message, 1480 bytes

/** first fragment: the ICMP header plus the start of the data */
const firstPart = (type: 0 | 8) => {
  const m = fullMsg(type);
  return proto({
    id: "icmp", name: "ICMP (first fragment)", osi: 3, ipProto: 1,
    summary: `Internet Control Message Protocol: ${type === 8 ? "Echo request" : "Echo reply"} (fragment 1 of 2)`,
    fields: [
      { name: "Type", u8: type, value: type === 8 ? "8 (Echo request)" : "0 (Echo reply)" },
      { name: "Code", u8: 0 },
      { name: "Checksum", bytes: m.slice(2, 4), note: "Covers the whole 1480-byte message, not just this piece. It can only be checked after reassembly." },
      { name: "Identifier", u16: PING_ID, value: `0x${PING_ID.toString(16)}` },
      { name: "Sequence number", u16: 1 },
      { name: "Data (first part)", bytes: m.slice(8, FRAG1), value: `${FRAG1 - 8} bytes` },
    ],
  });
};
/** second fragment: just the rest of the bytes, no ICMP header */
const secondPart = (type: 0 | 8) =>
  proto({
    id: "data", name: "Fragment data", osi: 3,
    summary: `IPv4 fragment: bytes ${FRAG1}–${BIG + 8 - 1} of the original ICMP message`,
    fields: [{ name: "Rest of the ICMP message", bytes: fullMsg(type).slice(FRAG1), value: `${BIG + 8 - FRAG1} bytes`, note: "No ICMP header here. Only the first fragment carries it." }],
  });

const REQ_ID = 0x8a21;
const REP_ID = 0x4c07;

/** first 28 bytes of the original packet, quoted inside ICMP errors */
const quote = (...specs: Parameters<typeof build>) => build(...specs).bytes.slice(0, 28);

const t = (n: number) => Number(n.toFixed(4));

export default defineLesson({
  id: "ip",
  name: "IP",
  full: "Internet Protocol version 4",
  group: "foundations",
  layer: 3,
  difficulty: 1,
  tagline: "The address on every packet, carried router by router.",
  description:
    "IPv4 puts a source and destination address on every packet so routers can pass it along, one hop at a time, until it reaches the right network. It does not promise delivery. It counts hops with TTL so lost packets can’t circle forever, and it can cut packets into fragments when a link is too small.",
  facts: [
    ["Layer", "Network (Layer 3)"],
    ["Address size", "32 bits (4 bytes)"],
    ["Header", "20 bytes, up to 60 with options"],
    ["Delivery", "Best effort, no ACKs"],
    ["Loop guard", "TTL, lowered by every router"],
    ["Defined in", "RFC 791"],
  ],
  ports: "None: IP has protocol numbers (1 ICMP, 6 TCP, 17 UDP)",
  rfc: "RFC 791",
  keywords: ["ipv4", "routing", "ttl", "fragmentation", "mtu", "hop", "router", "longest prefix", "time exceeded", "routing loop", "df", "mf"],
  related: ["icmp", "tcp", "udp", "ipv6", "arp", "nat"],
  devices,
  links,
  legend: [
    ["amber", "The laptop’s packet"],
    ["violet", "Reply from the server"],
    ["pink", "Fragments"],
    ["blue", "ICMP messages"],
    ["red", "Errors and drops"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "One packet, three routers",
      summary: "A connection request travels hop by hop to a web server, losing one TTL at each router.",
      kind: "normal",
      steps: [
        {
          title: "Local or not?",
          desc: "The laptop checks the destination against its own network",
          detail:
            "The laptop wants to open a connection to 203.0.113.10. Its own network is 192.168.1.0/24, and the destination is outside it, so the packet goes to the default gateway. The IP header carries the final address; the Ethernet header carries the gateway’s MAC.",
          facts: [["Destination", `${S} (not local)`], ["Next hop", `${ADDR.router} (default gateway)`], ["TTL", "64 (Linux default)"]],
          quiz: {
            q: "Which MAC address does the laptop put in the Ethernet header?",
            options: ["The web server’s MAC", "The home router’s MAC", "The broadcast MAC ff:ff:ff:ff:ff:ff", "Its own MAC twice"],
            answer: 1,
            why: "Ethernet only reaches the next device on the link. The router is the next hop, so its MAC goes in the frame; the server’s address lives only in the IP header.",
          },
          events: [
            pkt("client", "router", "amber", "IP", ["TTL 64", `to ${S}`], {
              time: 0, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(eth({ src: MAC.laptop, dst: MAC.routerLan }), ipv4({ src: LAPTOP, dst: S, ttl: 64, id: IPID }), syn()),
            }),
          ],
        },
        {
          title: "First hop: home router",
          desc: "TTL 64 becomes 63, new Ethernet header",
          detail:
            "The home router strips the old Ethernet header, lowers the TTL by one and recomputes the header checksum, because the header changed. It also swaps the private source address for its public one (that’s NAT, a lesson of its own). Then it wraps the packet in a fresh frame for the ISP link.",
          facts: [["TTL", "64 → 63"], ["Checksum", "Recomputed"], ["Source", `${LAPTOP} → ${PUB} (NAT)`]],
          quiz: {
            q: "What TTL will the ISP router see in this packet?",
            options: ["64", "63", "62", "1"],
            answer: 1,
            why: "Only the home router has touched it so far, and it lowered 64 to 63. The ISP router will lower it again when it forwards.",
          },
          events: [
            pkt("router", "isp", "amber", "IP", ["TTL 63", "new MACs"], {
              time: 0.0004, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(eth({ src: MAC.routerWan, dst: MAC.ispA }), ipv4({ src: PUB, dst: S, ttl: 63, id: IPID }), syn()),
            }),
          ],
        },
        {
          title: "Across the ISP",
          desc: "Longest prefix match picks the route",
          detail:
            "The ISP router has thousands of routes. Several can match 203.0.113.10, such as the default route 0.0.0.0/0 and 203.0.113.0/24. It picks the most specific one, the longest prefix, and sends the packet towards the core router with TTL 62.",
          facts: [["Route used", "203.0.113.0/24 via core"], ["Rule", "Longest prefix wins"], ["TTL", "63 → 62"]],
          quiz: {
            q: "The table has 0.0.0.0/0, 203.0.0.0/8 and 203.0.113.0/24. Which one is used?",
            options: ["0.0.0.0/0, it matches everything", "203.0.0.0/8, it was added first", "203.0.113.0/24, the most specific", "All three, the packet is copied"],
            answer: 2,
            why: "Routers always choose the matching route with the longest prefix, because it describes the destination most precisely.",
          },
          events: [
            pkt("isp", "core", "amber", "IP", ["TTL 62", "/24 route"], {
              time: 0.006, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(eth({ src: MAC.ispB, dst: MAC.coreA }), ipv4({ src: PUB, dst: S, ttl: 62, id: IPID }), syn()),
            }),
          ],
        },
        {
          title: "Last hop delivers",
          desc: "The core router is directly connected",
          detail:
            "The core router sees that 203.0.113.0/24 is on one of its own ports, so there is no next router. It finds the server’s MAC with ARP and delivers the packet with TTL 61. The IP addresses never changed after NAT; only the Ethernet header was replaced at every hop.",
          facts: [["TTL at server", "61"], ["Hops", "3 routers"], ["Changed per hop", "MACs, TTL, checksum"]],
          events: [
            pkt("core", "server", "amber", "IP", ["TTL 61", "arrived"], {
              time: 0.014, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(eth({ src: MAC.coreB, dst: MAC.server }), ipv4({ src: PUB, dst: S, ttl: 61, id: IPID }), syn()),
            }),
            note("server", "TTL 61 = 3 HOPS", "green"),
          ],
        },
        {
          title: "The reply comes back",
          desc: "A new packet, a new TTL",
          detail:
            "The server answers with its own packet, starting at TTL 64. It may even take a different path back, because each router decides on its own. The home router translates the address back to 192.168.1.10 before handing it to the laptop.",
          facts: [["Server starts at", "TTL 64"], ["Laptop sees", "TTL 61"], ["Round trip", "28 ms"]],
          quiz: {
            q: "The server sends with TTL 64 over the same three routers. What TTL arrives at the laptop?",
            options: ["64", "63", "61", "0"],
            answer: 2,
            why: "Three routers each subtract one: 64 − 3 = 61. Looking at the TTL of a reply is a quick way to guess how far away a host is.",
          },
          events: [
            pkt("server", "client", "violet", "IP", ["TTL 61 on arrival"], {
              time: 0.028, info: `443 → ${SP} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(eth({ src: MAC.routerLan, dst: MAC.laptop }), ipv4({ src: S, dst: LAPTOP, ttl: 61, id: 0 }), tcp({ sport: 443, dport: SP, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1460 }, "sackOk", { ts: [77310021, 1203311] }, "nop", { ws: 7 }], seqBase: 0x90e1b200, ackBase: SEQ })),
            }),
          ],
        },
      ],
      outro: {
        title: "Delivered, hop by hop",
        text: "No router knew the whole path. Each one looked at the destination address, picked the best route, lowered the TTL and passed the packet on in a new Ethernet frame. That simple rule, repeated, is how the whole internet moves packets.",
        facts: [["Routers crossed", "3"], ["TTL", "64 → 61"], ["Header size", "20 bytes"], ["Round trip", "28 ms"]],
      },
    },
    {
      id: "fragment",
      name: "A big packet meets a small link",
      summary: "A 1500-byte ping must cross a link that only takes 1400 bytes, so a router cuts it in two.",
      kind: "normal",
      steps: [
        {
          title: "A full-size packet",
          desc: "ping -s 1472 -M dont: 1500 bytes, DF off",
          detail:
            "The laptop sends a 1500-byte ping: 20 bytes of IP header, 8 bytes of ICMP header and 1472 bytes of data. That is the largest packet normal Ethernet carries (its MTU). The Don’t Fragment flag is off, so routers are allowed to split it.",
          facts: [["Total length", "1500 bytes"], ["DF flag", "0 (may fragment)"], ["Identification", `0x${REQ_ID.toString(16)}`]],
          events: [
            pkt("client", "core", "amber", "PING", ["1500 bytes", "DF = 0"], {
              time: 0, info: `Echo (ping) request id=0x${PING_ID.toString(16)}, seq=1/256, ttl=64`,
              packet: build(eth({ src: MAC.laptop, dst: MAC.routerLan }), ipv4({ src: LAPTOP, dst: S, ttl: 64, id: REQ_ID, df: false, proto: 1 }), echo(8)),
            }),
          ],
        },
        {
          title: "Cut into fragments",
          desc: "The next link has an MTU of 1400",
          detail:
            "The link from the core router to the server is a tunnel with an MTU of 1400. The router cuts the 1480 bytes after the IP header into pieces whose size is a multiple of 8: 1376 bytes and 104 bytes. Each piece gets its own IP header with the same Identification, and the first one has the More Fragments (MF) flag set.",
          facts: [["Fragment 1", "1376 bytes, offset 0, MF = 1"], ["Fragment 2", "104 bytes, offset 1376, MF = 0"], ["Offset unit", "8 bytes (field holds 172)"]],
          quiz: {
            q: "Fragment 1 carries 1376 bytes. What offset does fragment 2 have?",
            options: ["0", "1", "1376", "1400"],
            answer: 2,
            why: "The offset says where this piece starts in the original data. The first piece covered bytes 0–1375, so the second starts at 1376 (stored as 1376 ÷ 8 = 172).",
          },
          events: [
            pkt("core", "server", "pink", "FRAG 1", ["offset 0", "MF = 1"], {
              time: 0.014, info: `Fragmented IP protocol (proto=ICMP 1, off=0, ID=${REQ_ID.toString(16)})`,
              packet: build(eth({ src: MAC.coreB, dst: MAC.server }), ipv4({ src: PUB, dst: S, ttl: 61, id: REQ_ID, df: false, mf: true, fragOffset: 0, proto: 1 }), firstPart(8)),
            }),
            pkt("core", "server", "pink", "FRAG 2", ["offset 1376", "MF = 0"], {
              time: 0.0141, info: `Echo (ping) request id=0x${PING_ID.toString(16)}, seq=1/256, ttl=61 (reassembled in #2)`,
              packet: build(eth({ src: MAC.coreB, dst: MAC.server }), ipv4({ src: PUB, dst: S, ttl: 61, id: REQ_ID, df: false, fragOffset: FRAG1 / 8, proto: 1 }), secondPart(8)),
            }),
          ],
        },
        {
          title: "Reassembly and reply",
          desc: "Only the destination puts the pieces back",
          detail:
            "Routers never glue fragments together; only the final host does. The server collects pieces with the same source, destination, protocol and Identification, waits until the one without MF arrives, then rebuilds the 1500-byte packet. Its reply is also too big for its 1400-byte link, so the server fragments it itself.",
          facts: [["Reassembled by", "The destination only"], ["Matched on", "Src, dst, protocol, ID"], ["If a piece is lost", "The whole packet is thrown away"]],
          quiz: {
            q: "Fragment 2 of the reply is lost. What happens?",
            options: ["Only fragment 2 is resent by IP", "The laptop drops fragment 1 after a timeout; the ping counts as lost", "The laptop uses fragment 1 alone", "The core router rebuilds it"],
            answer: 1,
            why: "IP has no retransmission. Without every piece, the packet can’t be rebuilt, so the receiver gives up after a reassembly timeout (30 s on Linux).",
          },
          events: [
            pkt("server", "client", "pink", "FRAG 1", ["reply, MF = 1"], {
              time: 0.029, info: `Fragmented IP protocol (proto=ICMP 1, off=0, ID=${REP_ID.toString(16)})`,
              packet: build(eth({ src: MAC.routerLan, dst: MAC.laptop }), ipv4({ src: S, dst: LAPTOP, ttl: 61, id: REP_ID, df: false, mf: true, fragOffset: 0, proto: 1 }), firstPart(0)),
            }),
            pkt("server", "client", "pink", "FRAG 2", ["reply, offset 1376"], {
              time: 0.0291, info: `Echo (ping) reply id=0x${PING_ID.toString(16)}, seq=1/256, ttl=61 (reassembled in #4)`,
              packet: build(eth({ src: MAC.routerLan, dst: MAC.laptop }), ipv4({ src: S, dst: LAPTOP, ttl: 61, id: REP_ID, df: false, fragOffset: FRAG1 / 8, proto: 1 }), secondPart(0)),
            }),
            note("client", "REASSEMBLED: 1500 BYTES", "green"),
          ],
        },
        {
          title: "What if DF is set?",
          desc: "The router refuses and reports the MTU",
          detail:
            "Most traffic today sets Don’t Fragment, because fragments are slow and easy to lose. Now the core router may not split the packet, so it drops it and sends back ICMP “Fragmentation needed” with the link’s MTU. The sender learns to send smaller packets. This is called Path MTU Discovery.",
          facts: [["ICMP", "Type 3, code 4"], ["Next-hop MTU", "1400"], ["ping says", "Message too long, mtu=1400"]],
          events: [
            pkt("client", "core", "amber", "PING", ["1500 bytes", "DF = 1"], {
              time: 2.0, info: `Echo (ping) request id=0x${PING_ID.toString(16)}, seq=2/512, ttl=64`,
              packet: build(eth({ src: MAC.laptop, dst: MAC.routerLan }), ipv4({ src: LAPTOP, dst: S, ttl: 64, id: REQ_ID + 1, proto: 1 }), icmp({ type: 8, name: "Echo (ping) request", restFields: [{ name: "Identifier", u16: PING_ID }, { name: "Sequence number", u16: 2 }], data: reqData })),
            }),
            note("core", "TOO BIG, DF SET: DROP", "red"),
            pkt("core", "client", "blue", "ICMP 3/4", ["frag needed", "MTU 1400"], {
              time: 2.014, info: "Destination unreachable (Fragmentation needed), MTU 1400",
              packet: build(
                eth({ src: MAC.routerLan, dst: MAC.laptop }),
                ipv4({ src: CORE, dst: LAPTOP, ttl: 62, id: 0x0d31, df: false, dscp: 48 }),
                icmp({
                  type: 3, code: 4, name: "Destination unreachable (Fragmentation needed)",
                  restFields: [{ name: "Unused", u16: 0 }, { name: "Next-hop MTU", u16: 1400, note: "The biggest packet the next link takes. The sender should shrink to this." }],
                  data: quote(ipv4({ src: LAPTOP, dst: S, ttl: 62, id: REQ_ID + 1, proto: 1 }), icmp({ type: 8, name: "Echo (ping) request", restFields: [{ name: "Identifier", u16: PING_ID }, { name: "Sequence number", u16: 2 }], data: reqData })),
                  dataName: "Original packet (start)", dataNote: "The IP header and first 8 bytes of the packet that was dropped, so the sender knows which one it was.",
                })
              ),
            }),
          ],
        },
      ],
      outro: {
        title: "Split, carried, rebuilt",
        text: "When DF is off, a router can cut a packet to fit a small link, and only the destination puts it back together. When DF is on, the router drops it and reports the MTU instead. Modern stacks prefer the second way and size their packets to fit the whole path.",
        facts: [["Fragment sizes", "Multiples of 8 bytes"], ["Same in all pieces", "Identification"], ["Last piece", "MF = 0"], ["DF set", "ICMP 3/4 + MTU"]],
      },
    },
    {
      id: "loop",
      name: "Routing loop: TTL runs out",
      summary: "Two routers point at each other, the packet bounces until TTL reaches zero, and an ICMP error comes back.",
      kind: "failure",
      steps: [
        {
          title: "A wrong route",
          desc: "Two routers send the same network to each other",
          detail:
            "An engineer mistyped a route. The ISP router sends 203.0.113.0/24 to the core router, and the core router, which has lost its direct link to the server, sends it back to the ISP router. The laptop knows nothing about this and sends its packet as usual.",
          facts: [["ISP router says", "203.0.113.0/24 → core"], ["Core router says", "203.0.113.0/24 → ISP"], ["Laptop TTL", "64"]],
          events: [
            pkt("client", "core", "amber", "IP", ["TTL 64", `to ${S}`], {
              time: 0, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(eth({ src: MAC.laptop, dst: MAC.routerLan }), ipv4({ src: LAPTOP, dst: S, ttl: 64, id: IPID }), syn()),
            }),
          ],
        },
        {
          title: "Ping-pong",
          desc: "Each bounce costs one TTL",
          detail:
            "The core router sends the packet back to the ISP router, which sends it to the core again, and so on. Every pass lowers the TTL by one. Without TTL this packet, and every packet after it, would loop until the link was full.",
          facts: [["Bounce time", "About 0.5 ms"], ["TTL per bounce", "−1"], ["Without TTL", "Loops forever"]],
          quiz: {
            q: "The packet reached the core router with TTL 62. After it is sent back, how many more bounces until TTL is gone?",
            options: ["Never, it loops forever", "About 60", "Exactly 2", "It depends on packet size"],
            answer: 1,
            why: "Each router lowers TTL by one before forwarding, so a TTL of about 61 lasts about 61 more hops, then the packet is dropped.",
          },
          events: [
            pkt("core", "isp", "red", "IP", ["TTL 61", "sent back!"], {
              time: 0.0065, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 (TTL 61)`,
              packet: build(eth({ src: MAC.coreA, dst: MAC.ispB }), ipv4({ src: PUB, dst: S, ttl: 61, id: IPID }), syn()),
            }),
            pkt("isp", "core", "red", "IP", ["TTL 60"], {
              time: 0.007, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 (TTL 60)`,
              packet: build(eth({ src: MAC.ispB, dst: MAC.coreA }), ipv4({ src: PUB, dst: S, ttl: 60, id: IPID }), syn()),
            }),
            pkt("core", "isp", "red", "IP", ["TTL 59"], {
              time: 0.0075, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 (TTL 59)`,
              packet: build(eth({ src: MAC.coreA, dst: MAC.ispB }), ipv4({ src: PUB, dst: S, ttl: 59, id: IPID }), syn()),
            }),
            note("isp", "LOOP: SAME PACKET AGAIN", "red"),
          ],
        },
        {
          title: "TTL hits zero",
          desc: "The ISP router receives it with TTL 1",
          detail:
            "About 58 bounces later the core router hands the packet over with TTL 1. The ISP router would have to lower it to 0, which is not allowed, so it throws the packet away. A router must never forward a packet with TTL 0.",
          facts: [["Arrived with", "TTL 1"], ["Action", "Drop"], ["Total bounces", "About 61"]],
          events: [
            pkt("core", "isp", "red", "IP", ["TTL 1", "last hop"], {
              time: 0.037, lost: true, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 (TTL 1)`,
              packet: build(eth({ src: MAC.coreA, dst: MAC.ispB }), ipv4({ src: PUB, dst: S, ttl: 1, id: IPID }), syn()),
            }),
            note("isp", "TTL 0: DROPPED", "red"),
          ],
        },
        {
          title: "Time Exceeded",
          desc: "ICMP type 11 goes back to the sender",
          detail:
            "The ISP router tells the sender what happened with an ICMP Time Exceeded message. It quotes the dropped packet’s IP header and first 8 bytes, so the laptop can match it to the right connection. The home router translates it back to the laptop’s private address.",
          facts: [["ICMP", "Type 11, code 0"], ["From", `${ISP} (ISP router)`], ["Quoted TTL", "1"]],
          quiz: {
            q: "What would traceroute show for this destination?",
            options: ["Only the server’s address", "The ISP and core routers repeating until it gives up", "Nothing at all", "The home router 30 times"],
            answer: 1,
            why: "Traceroute lists the router where each TTL ran out. In a loop the same two routers alternate, which is the classic sign of a routing loop.",
          },
          events: [
            pkt("isp", "client", "blue", "ICMP 11", ["TTL exceeded", `from ${ISP}`], {
              time: 0.0375, info: "Time-to-live exceeded (Time to live exceeded in transit)",
              packet: build(
                eth({ src: MAC.routerLan, dst: MAC.laptop }),
                ipv4({ src: ISP, dst: LAPTOP, ttl: 63, id: 0x77a0, df: false, dscp: 48 }),
                icmp({
                  type: 11, code: 0, name: "Time-to-live exceeded",
                  data: quote(ipv4({ src: LAPTOP, dst: S, ttl: 1, id: IPID }), syn()),
                  dataName: "Original packet (start)", dataNote: "The dropped packet’s IP header (TTL 1) and the first 8 bytes of its TCP header: the ports and sequence number.",
                })
              ),
            }),
            note("client", "TIME EXCEEDED", "red"),
          ],
        },
      ],
      outro: {
        title: "TTL saved the network",
        text: "A routing loop can’t deliver anything, but TTL makes sure each looping packet dies after a fixed number of hops instead of piling up. The ICMP error, and traceroute, point straight at the two routers that disagree.",
        facts: [["Error", "ICMP 11 / 0"], ["Sign in traceroute", "Two hops repeating"], ["Fix", "Correct the route"], ["Packets lost", "All of them, until fixed"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Header fields",
      items: [["Version / IHL", "4, and header length in 4-byte words"], ["Total length", "Header + data, max 65535"], ["Identification", "Groups fragments of one packet"], ["Flags", "DF (don’t fragment), MF (more fragments)"], ["Fragment offset", "Position in 8-byte units"], ["TTL", "Hops left; −1 per router"], ["Protocol", "1 ICMP, 6 TCP, 17 UDP"]],
    },
    {
      title: "Routing rules",
      items: [["Local destination", "Send straight to its MAC"], ["Remote destination", "Send to the gateway’s MAC"], ["Many matching routes", "Longest prefix wins"], ["Default route", "0.0.0.0/0, matches everything"]],
    },
    {
      title: "Numbers to know",
      items: [["Ethernet MTU", "1500 bytes"], ["Min header", "20 bytes"], ["Default TTL", "64 Linux/macOS, 128 Windows"], ["Private ranges", "10/8, 172.16/12, 192.168/16"]],
    },
  ],
});
