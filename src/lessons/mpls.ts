import { Device, defineLesson, note, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, tcp } from "@/lib/proto";

// ---------------------------------------------------------------- the ISP
// PE1 (ingress) → P1 → P2 → PE2 (egress). Loopbacks 192.0.2.1–4.
// Labels were handed out earlier by LDP: towards PE2's loopback, P1 wants 24001, P2 wants 24017,
// and PE2 asked for "implicit null" (label 3), so P2 pops the label (penultimate hop popping).

const MAC = {
  client: "3c:22:fb:7a:91:0e",
  pe1a: "00:1f:ca:01:00:01", pe1b: "00:1f:ca:01:00:02",
  p1a: "00:1f:ca:02:00:01", p1b: "00:1f:ca:02:00:02",
  p2a: "00:1f:ca:03:00:01", p2b: "00:1f:ca:03:00:02",
  pe2a: "00:1f:ca:04:00:01", pe2b: "00:1f:ca:04:00:02",
  server: "00:16:3e:5a:01:22",
};
type Hop = "in" | "pe1-p1" | "p1-p2" | "p2-pe2" | "out";
const HOP_MACS: Record<Hop, [string, string]> = {
  in: [MAC.client, MAC.pe1a],
  "pe1-p1": [MAC.pe1b, MAC.p1a],
  "p1-p2": [MAC.p1b, MAC.p2a],
  "p2-pe2": [MAC.p2b, MAC.pe2a],
  out: [MAC.pe2b, MAC.server],
};

interface Label { label: number; tc?: number; ttl: number; why: string }

const LABEL_NAMES: Record<number, string> = { 0: "IPv4 explicit null", 3: "implicit null" };

/** One MPLS layer holding the whole label stack. Each entry is 4 bytes: label 20 bits, TC 3, S 1, TTL 8. */
function mpls(stack: Label[]): LayerSpec {
  const fields: FieldSpec[] = stack.map((l, i) => {
    const s = i === stack.length - 1 ? 1 : 0;
    const tc = l.tc ?? 0;
    const word = l.label * 4096 + (tc << 9) + (s << 8) + l.ttl;
    return {
      name: `Label stack entry ${i + 1}`,
      u32: word,
      value: `Label ${l.label}${LABEL_NAMES[l.label] ? ` (${LABEL_NAMES[l.label]})` : ""}, TC ${tc}, S ${s}, TTL ${l.ttl}`,
      note: `${l.why} Bits: label (20) = ${l.label}, traffic class (3) = ${tc}, bottom of stack (1) = ${s}${s ? ": the IP packet comes next" : ": another label follows"}, TTL (8) = ${l.ttl}.`,
    };
  });
  return proto({
    id: "mpls",
    name: "MPLS",
    osi: 2,
    ethertype: 0x8847,
    summary: `MultiProtocol Label Switching Header, ${stack.map((l) => `Label: ${l.label}`).join(", ")}`,
    fields,
  });
}

const SP = 52044;
const syn = (src: string, dst: string, ipTtl: number) => [
  ipv4({ src, dst, ttl: ipTtl, id: 0x7d21 }),
  tcp({ sport: SP, dport: 443, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }], seqBase: 0x5a17c0de }),
];
const frame = (hop: Hop, labels: Label[], src: string, dst: string, ipTtl: number) => {
  const [s, d] = HOP_MACS[hop];
  return build(eth({ src: s, dst: d }), ...(labels.length ? [mpls(labels)] : []), ...syn(src, dst, ipTtl));
};

// ---------------------------------------------------------------- normal: plain label switching

const C = "198.51.100.20";
const S = "203.0.113.10";
const n1 = frame("in", [], C, S, 64);
const n2 = frame("pe1-p1", [{ label: 24001, ttl: 63, why: "Pushed by PE1: the label P1 asked for to reach PE2." }], C, S, 63);
const n3 = frame("p1-p2", [{ label: 24017, ttl: 62, why: "Swapped by P1: the label P2 asked for." }], C, S, 63);
const n4 = frame("p2-pe2", [], C, S, 61);
const n5 = frame("out", [], C, S, 60);

// ---------------------------------------------------------------- L3VPN: two labels

const VA = "10.1.1.20";
const VB = "10.2.2.10";
const VPN = 18;
const v1 = frame("in", [], VA, VB, 64);
const v2 = frame("pe1-p1", [
  { label: 24001, ttl: 63, why: "Transport label: gets the packet across the core to PE2." },
  { label: VPN, ttl: 63, why: "VPN label from MP-BGP: tells PE2 which customer (VRF) this belongs to." },
], VA, VB, 63);
const v3 = frame("p1-p2", [
  { label: 24017, ttl: 62, why: "Only the top label was swapped." },
  { label: VPN, ttl: 63, why: "Untouched: P1 never looks below the top label." },
], VA, VB, 63);
const v4 = frame("p2-pe2", [{ label: VPN, ttl: 61, why: "The transport label was popped; the VPN label is now on top (TTL copied down)." }], VA, VB, 63);
const v5 = frame("out", [], VA, VB, 60);

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Customer", sub: C, x: 7, y: 70 },
  { id: "pe1", kind: "router", label: "PE1 (ingress)", sub: "192.0.2.1", x: 24, y: 50 },
  { id: "p1", kind: "router", label: "P1 (core)", sub: "192.0.2.2", x: 42, y: 25 },
  { id: "p2", kind: "router", label: "P2 (core)", sub: "192.0.2.3", x: 60, y: 25 },
  { id: "pe2", kind: "router", label: "PE2 (egress)", sub: "192.0.2.4", x: 77, y: 50 },
  { id: "server", kind: "web", label: "Web server", sub: S, x: 93, y: 70 },
];
const links: [string, string][] = [
  ["client", "pe1"],
  ["pe1", "p1"],
  ["p1", "p2"],
  ["p2", "pe2"],
  ["pe2", "server"],
];
const vpnDevices: Device[] = devices.map((d) =>
  d.id === "client" ? { ...d, kind: "desktop", label: "Shop A, Pune", sub: VA } : d.id === "server" ? { ...d, kind: "server", label: "Shop A, Delhi", sub: VB } : d,
);

const facts3 = (a: string, b: string, c: string): [string, string][] => [["Label stack", a], ["IP TTL inside", b], ["Router action", c]];

export default defineLesson({
  id: "mpls",
  name: "MPLS",
  full: "Multiprotocol Label Switching",
  group: "routing",
  layer: 2,
  difficulty: 3,
  tagline: "Short labels instead of full address lookups inside an ISP.",
  description:
    "Inside many ISP networks, packets don't get routed hop by hop on their IP address. The first router sticks a short label in front, the core routers just swap labels, and the label is removed near the exit. The same trick lets one ISP carry thousands of private company networks (VPNs) side by side.",
  facts: [
    ["Layer", "Between 2 and 3 (“layer 2.5”)"],
    ["EtherType", "0x8847 (unicast MPLS)"],
    ["Label entry", "4 bytes: label 20, TC 3, S 1, TTL 8"],
    ["Labels from", "LDP, RSVP-TE, BGP, segment routing"],
    ["Common uses", "L3VPN, traffic engineering, fast reroute"],
    ["Defined in", "RFC 3031, RFC 3032"],
  ],
  ports: "None: EtherType 0x8847",
  rfc: "RFC 3031, RFC 3032, RFC 4364",
  keywords: ["label", "push", "swap", "pop", "php", "penultimate hop popping", "lsp", "ldp", "l3vpn", "vrf", "pe", "p router", "ethertype 8847", "label switching"],
  related: ["ospf", "bgp", "vxlan", "ip"],
  devices,
  links,
  legend: [
    ["amber", "Plain IP packet"],
    ["violet", "Labelled packet (one label)"],
    ["teal", "VPN packet (two labels)"],
    ["blue", "Label decisions"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Push, swap, pop",
      summary: "A customer's packet crosses the ISP core on a label-switched path from PE1 to PE2.",
      kind: "normal",
      steps: [
        {
          title: "Plain IP arrives",
          desc: "PE1 receives an ordinary packet",
          detail:
            "A customer's connection to 203.0.113.10 arrives at PE1, the provider edge router. PE1 does one normal IP lookup and finds the exit is PE2. Earlier, LDP (the Label Distribution Protocol) told PE1 that P1 wants label 24001 for anything going to PE2.",
          facts: [["Destination", S], ["Exit router", "PE2 (192.0.2.4)"], ["Label for that path", "24001 (from P1, via LDP)"]],
          events: [
            pkt("client", "pe1", "amber", "IP", ["to 203.0.113.10"], { time: 0, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: n1 }),
          ],
        },
        {
          title: "Push a label",
          desc: "PE1 adds a 4-byte label",
          detail:
            "PE1 puts a 4-byte label entry between the Ethernet header and the IP header and sets the EtherType to 0x8847. The label's TTL is copied from the IP TTL after it was lowered (63), so traceroute still sees each hop. The S bit is 1 because this is the only, so the bottom, label.",
          facts: facts3("24001", "63", "PUSH"),
          quiz: {
            q: "How does the next router know an MPLS label follows the Ethernet header, not IP?",
            options: ["The label starts with 0xFF", "The EtherType is 0x8847", "The IP version field says 5", "It guesses from the size"],
            answer: 1,
            why: "The Ethernet Type field announces what comes next: 0x0800 for IPv4, 0x8847 for an MPLS label stack.",
          },
          events: [
            pkt("pe1", "p1", "violet", "L 24001", ["PUSH", "TTL 63"], { time: 0.0003, info: `MPLS Label 24001: ${SP} → 443 [SYN]`, packet: n2 }),
          ],
        },
        {
          title: "Swap in the core",
          desc: "P1 swaps 24001 for 24017",
          detail:
            "P1 looks up 24001 in a small label table, not the full internet routing table. The table says: replace it with 24017 and send it to P2. P1 lowers the label TTL to 62 and never reads the IP header at all.",
          facts: facts3("24017", "63 (not touched)", "SWAP"),
          quiz: {
            q: "The IP header inside still says TTL 63. Why didn't P1 lower it?",
            options: ["P1 forgot", "P1 only reads and updates the top label", "IP TTL only changes at the server", "Labels have no TTL"],
            answer: 1,
            why: "Core routers work only on the top label: they lower the label's TTL and leave the IP header alone. The IP TTL is fixed up when the label is removed.",
          },
          events: [
            pkt("p1", "p2", "violet", "L 24017", ["SWAP", "TTL 62"], { time: 0.0011, info: `MPLS Label 24017: ${SP} → 443 [SYN]`, packet: n3 }),
          ],
        },
        {
          title: "Pop one hop early",
          desc: "Penultimate hop popping",
          detail:
            "PE2 told P2 to use label 3, “implicit null”. That label is never sent: it means “remove the label before giving it to me”. So P2, the second-to-last router, pops the label and copies its TTL minus one (61) into the IP header. PE2 receives plain IP.",
          facts: facts3("none", "61 (copied from label)", "POP (PHP)"),
          quiz: {
            q: "Why let P2 remove the label instead of PE2?",
            options: ["Labels can't reach the last router", "PE2 then does one IP lookup instead of a label lookup and then an IP lookup", "To hide the label from the customer", "P2 owns the label"],
            answer: 1,
            why: "If the label arrived at PE2, it would look up the label only to find “remove it”, then do an IP lookup. Popping one hop earlier saves PE2 that extra step.",
          },
          events: [
            pkt("p2", "pe2", "amber", "IP", ["POP", "TTL 61"], { time: 0.0019, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: n4 }),
          ],
        },
        {
          title: "Deliver",
          desc: "PE2 routes the packet normally",
          detail:
            "PE2 does an ordinary IP lookup and sends the packet to the server, lowering the IP TTL to 60. The server sees a normal packet and has no idea labels were ever used.",
          facts: [["IP TTL", "60"], ["Labels seen by server", "None"], ["IP lookups in the core", "0"]],
          events: [
            pkt("pe2", "server", "amber", "IP", ["to 203.0.113.10"], { time: 0.0022, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: n5 }),
            note("server", "PLAIN IP, TTL 60", "green"),
          ],
        },
      ],
      outro: {
        title: "Across the core on labels",
        text: "PE1 did one IP lookup and pushed a label, P1 swapped it, P2 popped it, and PE2 delivered a plain IP packet. The core routers only ever looked at a 4-byte label.",
        facts: [["Labels used", "24001 → 24017 → popped"], ["Overhead", "4 bytes per label"], ["EtherType", "0x8847"], ["Labels learned by", "LDP"]],
      },
    },
    {
      id: "l3vpn",
      name: "Two labels: a company VPN",
      summary: "The ISP carries a shop chain's private 10.x network between Pune and Delhi using a transport label and a VPN label.",
      kind: "normal",
      devices: vpnDevices,
      steps: [
        {
          title: "Into the customer's VRF",
          desc: "PE1 keeps a separate table per customer",
          detail:
            "The shop's Pune office sends a packet to 10.2.2.10 in Delhi. Other customers use 10.x addresses too, so PE1 keeps a separate routing table, a VRF, for each customer. In this shop's VRF, PE2 advertised 10.2.2.0/24 over MP-BGP with VPN label 18.",
          facts: [["Customer VRF", "SHOP-A"], ["Destination", VB], ["VPN label", "18 (from PE2 via MP-BGP)"]],
          quiz: {
            q: "Two different customers both use 10.2.2.10. How does PE2 know which one a packet is for?",
            options: ["By the source MAC", "By the inner VPN label", "By the IP TTL", "It can't, so addresses must be unique"],
            answer: 1,
            why: "PE2 gives each customer's routes their own VPN label. When a packet arrives with label 18, PE2 knows it belongs to SHOP-A's table.",
          },
          events: [
            pkt("client", "pe1", "amber", "IP", ["to 10.2.2.10"], { time: 0, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: v1 }),
            note("pe1", "VRF SHOP-A", "blue"),
          ],
        },
        {
          title: "Push two labels",
          desc: "Transport label on top, VPN label below",
          detail:
            "PE1 pushes two labels. The inner one, 18, says which customer. The outer one, 24001, is the same transport label any traffic to PE2 uses. Only the inner one has the S (bottom of stack) bit set.",
          facts: [["Top label", "24001 (S = 0)"], ["Bottom label", "18 (S = 1)"], ["Overhead", "8 bytes"]],
          events: [
            pkt("pe1", "p1", "teal", "24001|18", ["PUSH ×2"], { time: 0.0003, info: `MPLS Label 24001, Label ${VPN}: ${SP} → 443 [SYN]`, packet: v2 }),
          ],
        },
        {
          title: "Core sees only the top",
          desc: "P1 swaps 24001 → 24017",
          detail:
            "P1 handles this exactly like the earlier plain packet. It swaps the top label and leaves label 18 untouched. P routers have no idea VPNs exist and hold no customer routes, which is why the design scales to thousands of customers.",
          facts: [["Top label", "24017"], ["Bottom label", "18 (untouched)"], ["Customer routes in P1", "0"]],
          quiz: {
            q: "After P2 does penultimate hop popping, what does PE2 receive?",
            options: ["A plain IP packet", "A packet with label 18 on top", "A packet with labels 24017 and 18", "Nothing: P2 drops it"],
            answer: 1,
            why: "P2 only pops the transport label. The VPN label stays, and PE2 needs it to pick the right customer table.",
          },
          events: [
            pkt("p1", "p2", "teal", "24017|18", ["SWAP top"], { time: 0.0011, info: `MPLS Label 24017, Label ${VPN}: ${SP} → 443 [SYN]`, packet: v3 }),
          ],
        },
        {
          title: "Transport label popped",
          desc: "Only the VPN label is left",
          detail:
            "As before, P2 pops the transport label because PE2 asked for implicit null. The VPN label 18 is now the top and only label, with S = 1.",
          facts: [["Label stack", "18 only"], ["Popped by", "P2 (PHP)"], ["S bit", "1"]],
          events: [
            pkt("p2", "pe2", "violet", "L 18", ["POP top"], { time: 0.0019, info: `MPLS Label ${VPN}: ${SP} → 443 [SYN]`, packet: v4 }),
          ],
        },
        {
          title: "VPN label picks the table",
          desc: "PE2 pops 18 and routes in SHOP-A",
          detail:
            "PE2 looks up label 18, which points to the SHOP-A VRF. It pops the label, looks up 10.2.2.10 in that customer's table and sends the packet to the Delhi office. To the shop it feels like one private network.",
          facts: [["Label 18", "→ VRF SHOP-A"], ["Delivered to", VB], ["Other customers", "Fully separate"]],
          events: [
            pkt("pe2", "server", "amber", "IP", ["to 10.2.2.10"], { time: 0.0022, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: v5 }),
            note("pe2", "LABEL 18 → SHOP-A", "blue"),
          ],
        },
      ],
      outro: {
        title: "Private network over a shared core",
        text: "Two labels split the work: the outer label moves the packet across the core, the inner label tells the exit router which customer it belongs to. This is how MPLS L3VPNs (RFC 4364) let ISPs sell private networks to many companies over one backbone.",
        facts: [["Outer label", "Transport, from LDP"], ["Inner label", "VPN, from MP-BGP"], ["Overhead", "8 bytes"], ["Defined in", "RFC 4364"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Label operations",
      items: [["PUSH", "Add a label (ingress PE)"], ["SWAP", "Replace the top label (P routers)"], ["POP", "Remove the top label"], ["PHP", "Pop at the second-to-last router"]],
    },
    {
      title: "Label stack entry (4 bytes)",
      items: [["Label", "20 bits: 0–1,048,575"], ["TC", "3 bits: priority (QoS)"], ["S", "1 bit: bottom of stack"], ["TTL", "8 bits: loop protection"]],
    },
    {
      title: "Reserved labels",
      items: [["0", "IPv4 explicit null"], ["2", "IPv6 explicit null"], ["3", "Implicit null (pop before me)"], ["16+", "Normal labels"]],
    },
  ],
});
