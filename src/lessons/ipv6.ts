import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, FieldSpec } from "@/lib/packet";
import { eth, F, icmpv6, ipv6 } from "@/lib/proto";
import { Bytes, u32le } from "@/lib/bytes";
import { ADDR } from "./_common";

// The laptop builds its addresses from its MAC 3c:22:fb:7a:91:0e (EUI-64):
// flip bit 0x02 of the first byte (3c → 3e) and put ff:fe in the middle.
const LMAC = ADDR.laptopMac;
const RMAC = ADDR.routerMac;
const NASMAC = "00:11:32:c4:5e:07";
const LL = "fe80::3e22:fbff:fe7a:910e";
const GUA = "2001:db8:1::3e22:fbff:fe7a:910e";
const RLL = ADDR.router6; // fe80::1
const PREFIX = "2001:db8:1::";
const DNS6 = "2001:db8:1::1";
const S = ADDR.web6;
const STATIC = ADDR.laptop6; // 2001:db8:1::10, already used by the NAS in the failure story

const ALL_NODES = "ff02::1";
const ALL_ROUTERS = "ff02::2";
const SN_LAPTOP = "ff02::1:ff7a:910e";
const SN_ROUTER = "ff02::1:ff00:1";
const SN_STATIC = "ff02::1:ff00:10";

const lla = (type: 1 | 2, m: string): FieldSpec => ({
  name: type === 1 ? "Option: source link-layer address" : "Option: target link-layer address",
  value: m,
  fields: [
    { name: "Type", u8: type, value: type === 1 ? "1 (Source link-layer address)" : "2 (Target link-layer address)" },
    { name: "Length", u8: 1, value: "1 (8 bytes)", note: "Option lengths count in units of 8 bytes." },
    F.mac("Link-layer address", m, type === 1 ? "The sender’s own MAC, so the receiver can answer without asking." : "The MAC that was asked for."),
  ],
});

const rsBody: FieldSpec[] = [{ name: "Reserved", u32: 0 }, lla(1, LMAC)];

const raBody: FieldSpec[] = [
  { name: "Cur hop limit", u8: 64, note: "Hosts should use this as their default hop limit." },
  { name: "Flags", u8: 0x00, value: "M=0, O=0", note: "M=0: no DHCPv6 for addresses. O=0: no DHCPv6 for other settings either. Pure SLAAC." },
  { name: "Router lifetime", u16: 1800, value: "1800 s", note: "How long hosts may use this router as their default gateway." },
  { name: "Reachable time", u32: 0, value: "0 (not specified)" },
  { name: "Retrans timer", u32: 0, value: "0 (not specified)" },
  {
    name: "Option: MTU", value: "1500",
    fields: [{ name: "Type", u8: 5, value: "5 (MTU)" }, { name: "Length", u8: 1, value: "1 (8 bytes)" }, { name: "Reserved", u16: 0 }, { name: "MTU", u32: 1500 }],
  },
  {
    name: "Option: prefix information", value: `${PREFIX}/64`,
    fields: [
      { name: "Type", u8: 3, value: "3 (Prefix information)" },
      { name: "Length", u8: 4, value: "4 (32 bytes)" },
      { name: "Prefix length", u8: 64 },
      { name: "Flags", u8: 0xc0, value: "L=1, A=1", note: "L: this prefix is on this link. A: hosts may build their own address from it (SLAAC)." },
      { name: "Valid lifetime", u32: 86400, value: "86400 s (1 day)" },
      { name: "Preferred lifetime", u32: 14400, value: "14400 s (4 hours)" },
      { name: "Reserved", u32: 0 },
      F.ip6("Prefix", PREFIX, "The first 64 bits of every address on this network."),
    ],
  },
  {
    name: "Option: recursive DNS server", value: DNS6,
    fields: [
      { name: "Type", u8: 25, value: "25 (RDNSS)" },
      { name: "Length", u8: 3, value: "3 (24 bytes)" },
      { name: "Reserved", u16: 0 },
      { name: "Lifetime", u32: 1800, value: "1800 s" },
      F.ip6("DNS server", DNS6, "A DNS server to use, so no DHCPv6 is needed (RFC 8106)."),
    ],
  },
];

const nsBody = (target: string, src?: string): FieldSpec[] => [
  { name: "Reserved", u32: 0 },
  F.ip6("Target address", target, "The address being asked about."),
  ...(src ? [lla(1, src)] : []),
];

const naBody = (flags: number, target: string, m: string): FieldSpec[] => [
  {
    name: "Flags", u32: flags >>> 0,
    value: [flags & 0x80000000 ? "R" : "", flags & 0x40000000 ? "S" : "", flags & 0x20000000 ? "O" : ""].filter(Boolean).join(", ") || "none",
    note: "R: I am a router. S: this answers your solicitation. O: replace any MAC you had cached.",
  },
  F.ip6("Target address", target),
  lla(2, m),
];

const pingData = (sec: number, usec: number): Bytes => {
  const out: Bytes = [...u32le(sec), 0, 0, 0, 0, ...u32le(usec), 0, 0, 0, 0];
  for (let i = 16; i < 56; i++) out.push(i);
  return out;
};
const echoBody = (seq: number): FieldSpec[] => [
  { name: "Identifier", u16: 0x3a7c, value: "0x3a7c" },
  { name: "Sequence number", u16: seq },
  { name: "Data", bytes: pingData(1763548810, 551200), value: "56 bytes", note: "Timestamp, then counting bytes, copied back in the reply." },
];

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: "fe80::3e22:…:910e", x: 8, y: 62 },
  { id: "switch", kind: "switch", label: "Switch", x: 27, y: 62 },
  { id: "router", kind: "router", label: "Home router", sub: RLL, x: 47, y: 62 },
  { id: "internet", kind: "cloud", label: "Internet", x: 68, y: 32 },
  { id: "server", kind: "web", label: "Web server", sub: S, x: 90, y: 62 },
];
const links: [string, string][] = [["client", "switch"], ["switch", "router"], ["router", "internet"], ["internet", "server"]];

const failDevices: Device[] = [
  ...devices,
  { id: "nas", kind: "nas", label: "NAS", sub: STATIC, x: 27, y: 22 },
];
const failLinks: [string, string][] = [...links, ["nas", "switch"]];

export default defineLesson({
  id: "ipv6",
  name: "IPv6",
  full: "Internet Protocol version 6, with SLAAC and Neighbor Discovery",
  group: "foundations",
  layer: 3,
  difficulty: 2,
  tagline: "Bigger addresses, and hosts that set themselves up.",
  description:
    "IPv6 uses 128-bit addresses, so every device can have a public one. A new host doesn’t need a DHCP server: it hears the router’s advertisement, builds its own address from the network prefix (SLAAC), checks nobody else has it, and finds neighbours’ MAC addresses with ICMPv6 instead of ARP.",
  facts: [
    ["Layer", "Network (Layer 3)"],
    ["Address size", "128 bits (16 bytes)"],
    ["Header", "40 bytes, fixed"],
    ["Auto setup", "SLAAC (RFC 4862)"],
    ["Replaces ARP", "Neighbor Discovery (RFC 4861)"],
    ["Defined in", "RFC 8200"],
  ],
  ports: "None: ICMPv6 is next header 58",
  rfc: "RFC 8200, RFC 4861, RFC 4862",
  keywords: ["ipv6", "slaac", "router advertisement", "router solicitation", "neighbor discovery", "ndp", "dad", "duplicate address", "eui-64", "multicast", "link-local", "ping6"],
  related: ["ip", "icmp", "arp", "dhcp"],
  devices,
  links,
  legend: [
    ["pink", "Multicast to a group"],
    ["blue", "Neighbor Discovery"],
    ["amber", "Data from the laptop"],
    ["green", "Replies"],
    ["red", "Conflicts"],
  ],
  scenarios: [
    {
      id: "slaac",
      name: "Plug in, get an address, ping",
      summary: "The laptop joins the network, builds its own IPv6 address, checks it, finds the router’s MAC and pings a server.",
      kind: "normal",
      steps: [
        {
          title: "Any routers here?",
          desc: "Router Solicitation to ff02::2",
          detail:
            "The laptop already made a link-local address, fe80::3e22:fbff:fe7a:910e, from its MAC. That only works on this cable. To find a router, it sends a Router Solicitation to ff02::2, the all-routers group. On Ethernet that group maps to MAC 33:33:00:00:00:02: 33:33 followed by the last 32 bits of the IPv6 address.",
          facts: [["ICMPv6 type", "133 (Router Solicitation)"], ["To", "ff02::2 → 33:33:00:00:00:02"], ["Hop limit", "255"]],
          quiz: {
            q: "The all-nodes group is ff02::1. Which MAC address does it use on Ethernet?",
            options: ["ff:ff:ff:ff:ff:ff", "33:33:00:00:00:01", "01:00:5e:00:00:01", "00:00:00:00:00:01"],
            answer: 1,
            why: "IPv6 multicast maps to 33:33 plus the last four bytes of the group address. IPv6 has no broadcast at all.",
          },
          events: [
            pkt("client", "router", "pink", "RS", ["to ff02::2", "routers?"], {
              time: 0, info: "Router Solicitation from 3c:22:fb:7a:91:0e",
              packet: build(eth({ src: LMAC, dst: "33:33:00:00:00:02" }), ipv6({ src: LL, dst: ALL_ROUTERS, hop: 255 }), icmpv6({ type: 133, name: "Router Solicitation", body: rsBody })),
            }),
          ],
        },
        {
          title: "Router Advertisement",
          desc: "Here is the prefix: 2001:db8:1::/64",
          detail:
            "The router answers to everyone (ff02::1) with a Router Advertisement. It says: I am a default gateway for 30 minutes, the network prefix is 2001:db8:1::/64, the MTU is 1500, and here is a DNS server. The A flag on the prefix means hosts may build their own address from it.",
          facts: [["ICMPv6 type", "134 (Router Advertisement)"], ["Prefix", "2001:db8:1::/64, A flag set"], ["Router lifetime", "1800 s"]],
          quiz: {
            q: "The prefix gives the first 64 bits. Where do the last 64 bits of the laptop’s address come from?",
            options: ["The router assigns them", "The laptop makes them itself", "A DHCP server", "The DNS server"],
            answer: 1,
            why: "That’s the point of SLAAC: the host builds its own interface ID, here from its MAC (EUI-64). Modern systems often use a random one instead for privacy.",
          },
          events: [
            pkt("router", "client", "pink", "RA", ["prefix 2001:db8:1::/64", "to all nodes"], {
              time: 0.0021, info: `Router Advertisement from ${RMAC}`,
              packet: build(eth({ src: RMAC, dst: "33:33:00:00:00:01" }), ipv6({ src: RLL, dst: ALL_NODES, hop: 255 }), icmpv6({ type: 134, name: "Router Advertisement", body: raBody })),
            }),
          ],
        },
        {
          title: "Is it taken? (DAD)",
          desc: "Neighbor Solicitation from ::",
          detail:
            "The laptop builds 2001:db8:1::3e22:fbff:fe7a:910e but keeps it “tentative”. It asks whether anyone already uses it, sending a Neighbor Solicitation from the unspecified address :: to the address’s solicited-node group ff02::1:ff7a:910e. Only devices whose address ends in 7a:91:0e listen there.",
          facts: [["ICMPv6 type", "135 (Neighbor Solicitation)"], ["From", ":: (no address yet)"], ["To", "ff02::1:ff7a:910e → 33:33:ff:7a:91:0e"]],
          quiz: {
            q: "Why does the laptop send DAD from :: instead of its new address?",
            options: ["To save bytes", "It may not use the address until it knows nobody else has it", "Routers ignore other sources", "The address is too long"],
            answer: 1,
            why: "A tentative address must not be used as a source. If another host owned it, replies would go to the wrong place.",
          },
          events: [
            pkt("client", "switch", "blue", "NS (DAD)", ["from ::", `is ${"…7a:910e"} taken?`], {
              time: 0.31, info: `Neighbor Solicitation for ${GUA}`,
              packet: build(eth({ src: LMAC, dst: "33:33:ff:7a:91:0e" }), ipv6({ src: "::", dst: SN_LAPTOP, hop: 255 }), icmpv6({ type: 135, name: "Neighbor Solicitation", body: nsBody(GUA) })),
            }),
            note("client", "WAITING 1 s…", "blue"),
          ],
        },
        {
          title: "Silence means yes",
          desc: "No answer in one second: the address is ours",
          detail:
            "Nobody replies within a second, so the address is unique. The laptop now has a global address it made by itself, plus a default gateway (fe80::1) from the advertisement. No server handed anything out.",
          facts: [["Address", GUA], ["Gateway", `${RLL} (link-local)`], ["DHCP used", "None"]],
          events: [note("client", "ADDRESS PREFERRED", "green")],
        },
        {
          title: "Find the router’s MAC",
          desc: "Neighbor Solicitation and Advertisement",
          detail:
            "To send anything off the network the laptop needs fe80::1’s MAC. Many routers include it in the RA; this one did not, so the laptop asks. It sends a Neighbor Solicitation to the router’s solicited-node group, and the router answers directly with a Neighbor Advertisement holding its MAC. This is IPv6’s version of ARP.",
          facts: [["Ask", `NS to ${SN_ROUTER}`], ["Answer", "NA, flags R S O"], ["Router MAC", RMAC]],
          quiz: {
            q: "How is this different from ARP in IPv4?",
            options: ["It uses a broadcast to everyone", "It uses a multicast group only the target listens to", "It needs a DHCP server", "It isn’t different at all"],
            answer: 1,
            why: "ARP requests go to every device. NS goes to a solicited-node group, so almost only the target’s network card has to look at it.",
          },
          events: [
            pkt("client", "router", "blue", "NS", ["who is fe80::1?"], {
              time: 1.32, info: `Neighbor Solicitation for ${RLL} from ${LMAC}`,
              packet: build(eth({ src: LMAC, dst: "33:33:ff:00:00:01" }), ipv6({ src: LL, dst: SN_ROUTER, hop: 255 }), icmpv6({ type: 135, name: "Neighbor Solicitation", body: nsBody(RLL, LMAC) })),
            }),
            pkt("router", "client", "green", "NA", [`fe80::1 is ${RMAC}`], {
              time: 1.3208, info: `Neighbor Advertisement ${RLL} (rtr, sol, ovr) is at ${RMAC}`,
              packet: build(eth({ src: RMAC, dst: LMAC }), ipv6({ src: RLL, dst: LL, hop: 255 }), icmpv6({ type: 136, name: "Neighbor Advertisement", body: naBody(0xe0000000, RLL, RMAC) })),
            }),
          ],
        },
        {
          title: "ping6 the server",
          desc: "Echo request and reply over IPv6",
          detail:
            "Now the laptop can reach the internet. It pings 2001:db8:ab::10 from its new global address with an ICMPv6 Echo Request (type 128), framed to the router’s MAC. The server answers with an Echo Reply (type 129). No NAT anywhere: the server sees the laptop’s real address.",
          facts: [["Request / reply", "Type 128 / 129"], ["Round trip", "28 ms"], ["NAT", "None"]],
          events: [
            pkt("client", "server", "amber", "ECHO REQ", ["type 128", `to ${S}`], {
              time: 1.321, info: "Echo (ping) request id=0x3a7c, seq=1, hop limit=64",
              packet: build(eth({ src: LMAC, dst: RMAC }), ipv6({ src: GUA, dst: S, hop: 64 }), icmpv6({ type: 128, name: "Echo (ping) request", body: echoBody(1) })),
            }),
            pkt("server", "client", "green", "ECHO REPLY", ["type 129"], {
              time: 1.349, info: "Echo (ping) reply id=0x3a7c, seq=1, hop limit=57",
              packet: build(eth({ src: RMAC, dst: LMAC }), ipv6({ src: S, dst: GUA, hop: 57 }), icmpv6({ type: 129, name: "Echo (ping) reply", body: echoBody(1) })),
            }),
          ],
        },
      ],
      outro: {
        title: "Set up with no server",
        text: "The laptop asked for routers, learned the prefix from the advertisement, built its own address, checked it was unique and found the router’s MAC, all with ICMPv6. Then it pinged a server with a real, public address and no NAT in the way.",
        facts: [["RS / RA", "133 / 134"], ["NS / NA", "135 / 136"], ["Multicast MACs", "33:33:xx:xx:xx:xx"], ["Header", "40 bytes"]],
      },
    },
    {
      id: "dad-fail",
      name: "Duplicate address detected",
      summary: "Someone typed in a static address that the NAS already uses. DAD catches it before anything breaks.",
      kind: "failure",
      devices: failDevices,
      links: failLinks,
      steps: [
        {
          title: "A hand-typed address",
          desc: "The laptop tries 2001:db8:1::10",
          detail:
            "Someone sets the laptop’s address by hand to 2001:db8:1::10. Even static addresses go through DAD. The laptop sends a Neighbor Solicitation from :: to ff02::1:ff00:10, the group for addresses ending in 00:00:10.",
          facts: [["Tentative", STATIC], ["Group", `${SN_STATIC} → 33:33:ff:00:00:10`], ["Listening", "The NAS, which owns ::10"]],
          events: [
            pkt("client", "switch", "blue", "NS (DAD)", ["from ::", "is ::10 taken?"], {
              time: 0, info: `Neighbor Solicitation for ${STATIC}`,
              packet: build(eth({ src: LMAC, dst: "33:33:ff:00:00:10" }), ipv6({ src: "::", dst: SN_STATIC, hop: 255 }), icmpv6({ type: 135, name: "Neighbor Solicitation", body: nsBody(STATIC) })),
            }),
          ],
        },
        {
          title: "The NAS objects",
          desc: "Neighbor Advertisement to all nodes",
          detail:
            "The NAS already uses 2001:db8:1::10, so it answers with a Neighbor Advertisement. The asker has no address yet, so the NAS can’t reply to it directly. It sends to ff02::1, all nodes, and the laptop hears it.",
          facts: [["ICMPv6 type", "136 (Neighbor Advertisement)"], ["To", "ff02::1 (asker had no address)"], ["Flags", "O only (not solicited)"]],
          quiz: {
            q: "Why does the NAS send its answer to ff02::1 instead of to the laptop?",
            options: ["It doesn’t know the laptop’s MAC", "The question came from ::, so there is no address to reply to", "All NAs go to ff02::1", "To warn the router"],
            answer: 1,
            why: "The DAD probe came from the unspecified address ::. The only way to reach the asker is the all-nodes group.",
          },
          events: [
            pkt("nas", "client", "red", "NA", ["::10 is mine!", NASMAC], {
              time: 0.0006, info: `Neighbor Advertisement ${STATIC} (ovr) is at ${NASMAC}`,
              packet: build(eth({ src: NASMAC, dst: "33:33:00:00:00:01" }), ipv6({ src: STATIC, dst: ALL_NODES, hop: 255 }), icmpv6({ type: 136, name: "Neighbor Advertisement", body: naBody(0x20000000, STATIC, NASMAC) })),
            }),
          ],
        },
        {
          title: "Address refused",
          desc: "Marked duplicate, never used",
          detail:
            "The laptop marks 2001:db8:1::10 as duplicate and never sends from it, so the NAS keeps working. Linux logs “IPv6 duplicate address 2001:db8:1::10 used by 00:11:32:c4:5e:07 detected!”. The fix is to pick another static address or let SLAAC choose one.",
          facts: [["State", "dadfailed"], ["NAS affected?", "No"], ["Fix", "Different address, or SLAAC"]],
          quiz: {
            q: "What would happen in IPv4 if two hosts had the same address and no check ran?",
            options: ["Nothing, it works fine", "Both would fight over ARP and traffic would go to the wrong one", "The router would renumber one", "The switch would block one"],
            answer: 1,
            why: "Without a check, both hosts answer ARP and other devices keep switching between them. DAD stops this before the address is ever used.",
          },
          events: [note("client", "DUPLICATE ADDRESS DETECTED", "red"), note("nas", "STILL WORKING", "green")],
        },
      ],
      outro: {
        title: "Caught before it hurt",
        text: "Duplicate Address Detection checks every new IPv6 address, even hand-typed ones, before it is used. One NS from :: and one NA back were enough to keep the laptop from stealing the NAS’s address.",
        facts: [["Probe", "NS from ::"], ["Objection", "NA to ff02::1"], ["Wait", "1 s by default"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "ICMPv6 Neighbor Discovery",
      items: [["133", "Router Solicitation"], ["134", "Router Advertisement"], ["135", "Neighbor Solicitation"], ["136", "Neighbor Advertisement"], ["137", "Redirect"]],
    },
    {
      title: "Addresses to know",
      items: [["fe80::/10", "Link-local, every interface has one"], ["ff02::1", "All nodes"], ["ff02::2", "All routers"], ["ff02::1:ffXX:XXXX", "Solicited-node group"], ["::", "Unspecified (no address yet)"], ["2001:db8::/32", "Documentation"]],
    },
    {
      title: "Numbers",
      items: [["Header", "40 bytes fixed"], ["Prefix for SLAAC", "/64"], ["Multicast MAC", "33:33 + last 32 bits"], ["ND hop limit", "Always 255"]],
    },
  ],
});
