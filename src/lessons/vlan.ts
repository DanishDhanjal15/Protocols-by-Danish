import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, LayerSpec } from "@/lib/packet";
import { arp, BROADCAST_MAC, eth, icmp, ipv4, tcp, TcpOpt, vlan } from "@/lib/proto";
import { ADDR } from "./_common";

// Addresses: office VLAN 10 = 192.168.10.0/24, guest VLAN 20 = 192.168.20.0/24
const PC = "192.168.10.21";
const SRV = "192.168.10.50";
const PHONE = "192.168.20.33";
const TV = "192.168.20.40";
const GW10 = "192.168.10.1";
const GW20 = "192.168.20.1";

const PC_MAC = "d4:81:d7:20:5a:11";
const SRV_MAC = ADDR.serverMac;
const PHONE_MAC = ADDR.phoneMac;
const TV_MAC = "a8:23:fe:41:0c:9e";
const R_MAC = "00:1e:bd:4a:7c:01"; // one router port, both sub-interfaces share its MAC

const devices: Device[] = [
  { id: "officepc", kind: "desktop", label: "Office PC", sub: `VLAN 10 · ${PC}`, x: 10, y: 30 },
  { id: "server", kind: "server", label: "File server", sub: `VLAN 10 · ${SRV}`, x: 10, y: 78 },
  { id: "switch", kind: "switch", label: "Switch", sub: "ports 1–4 + trunk 24", x: 50, y: 55 },
  { id: "router", kind: "router", label: "Router", sub: ".10.1 and .20.1", x: 50, y: 16 },
  { id: "phone", kind: "phone", label: "Guest phone", sub: `VLAN 20 · ${PHONE}`, x: 90, y: 30 },
  { id: "tv", kind: "tv", label: "Lobby screen", sub: `VLAN 20 · ${TV}`, x: 90, y: 78 },
];
const links: [string, string][] = [
  ["officepc", "switch"],
  ["server", "switch"],
  ["phone", "switch"],
  ["tv", "switch"],
  ["switch", "router"],
];

/** Ethernet frame, with an 802.1Q tag when `vid` is given (as seen on the trunk). */
const frame = (src: string, dst: string, vid: number | undefined, ...rest: LayerSpec[]) =>
  build(eth({ src, dst }), ...(vid ? [vlan({ id: vid })] : []), ...rest);

const synOpts: TcpOpt[] = [{ mss: 1460 }, "sackOk", { ts: [1203344, 0] }, "nop", { ws: 7 }];
const SEQ_PC = 0x3e9a1000;
const SEQ_TV = 0x77c20400;
const SEQ_PH = 0x5a017c00;

// Office PC → lobby screen, TCP port 80
const pcSyn = (vid: number | undefined, ttl: number) => {
  const toRouter = ttl === 64; // still on the first hop, heading to the gateway
  return frame(toRouter ? PC_MAC : R_MAC, toRouter ? R_MAC : TV_MAC, vid,
    ipv4({ src: PC, dst: TV, ttl, id: 0x4c21 }),
    tcp({ sport: 52811, dport: 80, seq: 0, flags: "S", opts: synOpts, seqBase: SEQ_PC }));
};
const tvSynAck = (vid: number | undefined, ttl: number) => {
  const toRouter = ttl === 64;
  return frame(toRouter ? TV_MAC : R_MAC, toRouter ? R_MAC : PC_MAC, vid,
    ipv4({ src: TV, dst: PC, ttl, id: 0 }),
    tcp({ sport: 80, dport: 52811, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1460 }, "sackOk", { ts: [88123, 1203344] }, "nop", { ws: 7 }], seqBase: SEQ_TV, ackBase: SEQ_PC }));
};
const SYN_INFO = "52811 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128";
const SYNACK_INFO = "80 → 52811 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128";

// Office PC → file server, same VLAN
const smbSyn = () =>
  frame(PC_MAC, SRV_MAC, undefined, ipv4({ src: PC, dst: SRV, ttl: 64, id: 0x4c10 }),
    tcp({ sport: 52800, dport: 445, seq: 0, flags: "S", opts: synOpts, seqBase: 0x1d2e3f00 }));

// Guest phone → file server (to be blocked)
const phoneIp = () => ipv4({ src: PHONE, dst: SRV, ttl: 64, id: 0x9a07 });
const phoneTcp = () => tcp({ sport: 49822, dport: 445, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", { ts: [5512002, 0] }, "nop", { ws: 8 }], seqBase: SEQ_PH });
const PH_INFO = "49822 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=256";
/** ICMP errors quote the original IP header plus the first 8 bytes of its payload */
const quoted = build(phoneIp(), phoneTcp()).bytes.slice(0, 28);
const prohibited = (vid: number | undefined) =>
  frame(R_MAC, PHONE_MAC, vid,
    ipv4({ src: GW20, dst: PHONE, ttl: 255, id: 0x0031, df: false }),
    icmp({
      type: 3, code: 13, name: "Destination unreachable (Communication administratively prohibited)",
      data: quoted, dataName: "Original packet (start)",
      dataNote: "The first 28 bytes of the blocked packet: its IP header and TCP ports, so the phone knows which connection failed.",
    }));
const PROHIB_INFO = `Destination unreachable (Communication administratively prohibited) for ${PHONE} → ${SRV}`;

const arpReq = (vid: number | undefined) =>
  frame(PHONE_MAC, BROADCAST_MAC, vid, arp({ op: 1, senderMac: PHONE_MAC, senderIp: PHONE, targetIp: GW20 }));
const arpRep = (vid: number | undefined) =>
  frame(R_MAC, PHONE_MAC, vid, arp({ op: 2, senderMac: R_MAC, senderIp: GW20, targetMac: PHONE_MAC, targetIp: PHONE }));

export default defineLesson({
  id: "vlan",
  name: "VLAN",
  full: "Virtual LANs (IEEE 802.1Q)",
  group: "lan",
  layer: 2,
  difficulty: 2,
  tagline: "One switch, several separate networks, a 4-byte tag.",
  description:
    "A VLAN splits one physical switch into several separate networks. Ports are given a VLAN number, and frames never cross from one VLAN to another on their own. Links that carry many VLANs add a 4-byte 802.1Q tag to each frame, and a router moves traffic between VLANs when the rules allow it.",
  facts: [
    ["Layer", "Data link (Layer 2)"],
    ["Tag size", "4 bytes (TPID 0x8100 + TCI)"],
    ["VLAN IDs", "1–4094 (12 bits)"],
    ["Priority", "3 bits (PCP, 802.1p)"],
    ["Port types", "Access (untagged), trunk (tagged)"],
    ["Defined in", "IEEE 802.1Q"],
  ],
  ports: "None: tag EtherType 0x8100",
  rfc: "IEEE 802.1Q",
  keywords: ["vlan", "802.1q", "dot1q", "trunk", "access port", "tag", "router on a stick", "inter-vlan routing", "subinterface", "acl", "guest network", "segmentation"],
  related: ["ethernet", "arp", "stp", "ip", "icmp", "vxlan"],
  devices,
  links,
  legend: [
    ["amber", "Office traffic (VLAN 10)"],
    ["violet", "Guest traffic (VLAN 20)"],
    ["blue", "Broadcasts and lookups"],
    ["green", "Replies"],
    ["red", "Blocked or errors"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Two VLANs and a router on a stick",
      summary: "Office and guest devices share one switch but stay apart; the router carries office traffic over to the guest VLAN.",
      kind: "normal",
      steps: [
        {
          title: "Same VLAN, no tag",
          desc: "Access ports send plain Ethernet frames",
          detail:
            "Ports 1 and 2 are access ports in VLAN 10. The office PC sends an ordinary frame to the file server, with no tag at all. The switch remembers the frame came in on a VLAN 10 port, so it will only ever forward it to other VLAN 10 ports or to the trunk.",
          facts: [["Port 1", "Access, VLAN 10"], ["Tag on the cable", "None"], ["Can reach", "VLAN 10 ports + trunk"]],
          quiz: {
            q: "The file server’s MAC is unknown to the switch. Where is this frame flooded?",
            options: ["Every port on the switch", "Only VLAN 10 ports and the trunk", "Only the trunk to the router", "Nowhere, it is dropped"],
            answer: 1,
            why: "Each VLAN is its own broadcast domain. Flooding stays inside VLAN 10, so guest ports 3 and 4 never see it.",
          },
          events: [
            pkt("officepc", "server", "amber", "FRAME", ["no tag", "VLAN 10 → VLAN 10"], {
              time: 0, info: "52800 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128", packet: smbSyn(),
            }),
            note("switch", "VLAN 10 PORTS ONLY", "blue"),
          ],
        },
        {
          title: "Broadcast stays in VLAN 20",
          desc: "The guest phone looks for its gateway",
          detail:
            "The guest phone asks with ARP who has 192.168.20.1. The switch floods this broadcast to the lobby screen and to the trunk, but not to the office ports. On the trunk the frame gets a tag that says VLAN 20, so the router knows which network it came from.",
          facts: [["Flooded to", "Port 4 and trunk 24"], ["Office ports", "Never see it"], ["Tag on trunk", "0x8100, VLAN 20"]],
          events: [
            pkt("phone", "switch", "blue", "ARP", ["who has .20.1?", "no tag"], {
              time: 1.0, info: `Who has ${GW20}? Tell ${PHONE}`, packet: arpReq(undefined),
            }),
            pkt("switch", "tv", "blue", "ARP", ["flooded, no tag"], {
              time: 1.00002, info: `Who has ${GW20}? Tell ${PHONE}`, packet: arpReq(undefined),
            }),
            pkt("switch", "router", "blue", "ARP", ["tag: VLAN 20"], {
              time: 1.00002, parallel: true, info: `Who has ${GW20}? Tell ${PHONE}`, packet: arpReq(20),
            }),
            pkt("router", "switch", "green", "ARP REPLY", [".20.1 is at", "tag: VLAN 20"], {
              time: 1.0003, info: `${GW20} is at ${R_MAC}`, packet: arpRep(20),
            }),
            pkt("switch", "phone", "green", "ARP REPLY", ["tag removed"], {
              time: 1.00032, info: `${GW20} is at ${R_MAC}`, packet: arpRep(undefined),
            }),
          ],
        },
        {
          title: "Up the trunk, tagged 10",
          desc: "Office PC wants the lobby screen",
          detail:
            "The office PC wants the lobby screen at 192.168.20.40. That is a different subnet, so the PC sends the frame to its gateway’s MAC. The switch forwards it out of the trunk and inserts a 4-byte tag between the source MAC and the type: 0x8100, then VLAN 10.",
          facts: [["Destination MAC", `${R_MAC} (gateway)`], ["Trunk tag", "VLAN 10"], ["IP destination", TV]],
          quiz: {
            q: "Which VLAN ID does the tag on the trunk carry for this frame?",
            options: ["10, the VLAN it came from", "20, the VLAN it is going to", "1, the default VLAN", "No tag, trunks are untagged"],
            answer: 0,
            why: "The switch only knows where the frame came from. It tags it with the VLAN of the incoming port. Moving it to VLAN 20 is the router’s job.",
          },
          events: [
            pkt("officepc", "switch", "amber", "SYN", ["to gateway MAC", "no tag"], { time: 2.0, info: SYN_INFO, packet: pcSyn(undefined, 64) }),
            pkt("switch", "router", "amber", "SYN", ["tag: VLAN 10"], { time: 2.00002, info: SYN_INFO, packet: pcSyn(10, 64) }),
            note("switch", "ADD TAG: VLAN 10", "blue"),
          ],
        },
        {
          title: "Router on a stick",
          desc: "In on VLAN 10, out on VLAN 20, same cable",
          detail:
            "The router has one physical port split into two sub-interfaces: one for VLAN 10 (192.168.10.1) and one for VLAN 20 (192.168.20.1). It reads the tag, routes the packet like any router (new MACs, TTL lowered from 64 to 63) and sends it back down the same cable with a VLAN 20 tag.",
          facts: [["In on", "Gi0/0.10, tag 10"], ["Out on", "Gi0/0.20, tag 20"], ["TTL", "64 → 63"]],
          quiz: {
            q: "What changes in the packet as the router moves it from VLAN 10 to VLAN 20?",
            options: ["Only the IP addresses", "The VLAN tag, both MACs and the TTL", "Nothing at all", "Only the TCP port"],
            answer: 1,
            why: "Routing rewrites the Ethernet header (new source and destination MAC), lowers the TTL, and the new sub-interface puts on its own tag. The IP addresses stay the same.",
          },
          events: [
            note("router", "ROUTE: VLAN 10 → 20", "green"),
            pkt("router", "switch", "violet", "SYN", ["tag: VLAN 20", "TTL 63"], { time: 2.0001, info: SYN_INFO, packet: pcSyn(20, 63) }),
          ],
        },
        {
          title: "Tag off, delivered",
          desc: "Access ports never show the tag",
          detail:
            "The switch sees VLAN 20 and a destination MAC it learned on port 4. It strips the tag and sends a plain frame to the lobby screen. The screen has no idea VLANs exist; it just sees a frame from the router’s MAC.",
          facts: [["Out of", "Port 4 (access, VLAN 20)"], ["Tag", "Removed"], ["Screen sees", "Normal Ethernet"]],
          events: [
            pkt("switch", "tv", "violet", "SYN", ["tag removed"], { time: 2.00012, info: SYN_INFO, packet: pcSyn(undefined, 63) }),
            note("switch", "STRIP TAG", "blue"),
          ],
        },
        {
          title: "The reply comes back",
          desc: "Same trip in reverse: 20 up, 10 down",
          detail:
            "The screen answers SYN-ACK to its own gateway. On the trunk it goes up tagged 20, the router routes it, and it comes back down tagged 10. The switch strips the tag and hands it to the office PC on port 1.",
          facts: [["Up the trunk", "Tag 20"], ["Down the trunk", "Tag 10"], ["Trunk crossings", "2 per direction"]],
          quiz: {
            q: "Every inter-VLAN packet crosses the trunk twice. What does that suggest?",
            options: ["Nothing, it is free", "The trunk carries double the traffic, so it can become a bottleneck", "The packet is sent twice to the screen", "VLAN tags double the packet size"],
            answer: 1,
            why: "Router on a stick is cheap and simple, but traffic between VLANs uses the trunk both ways. Bigger networks use a Layer 3 switch that routes internally.",
          },
          events: [
            pkt("tv", "switch", "green", "SYN-ACK", ["no tag"], { time: 2.0005, info: SYNACK_INFO, packet: tvSynAck(undefined, 64) }),
            pkt("switch", "router", "green", "SYN-ACK", ["tag: VLAN 20"], { time: 2.00052, info: SYNACK_INFO, packet: tvSynAck(20, 64) }),
            pkt("router", "switch", "green", "SYN-ACK", ["tag: VLAN 10", "TTL 63"], { time: 2.0006, info: SYNACK_INFO, packet: tvSynAck(10, 63) }),
            pkt("switch", "officepc", "green", "SYN-ACK", ["tag removed"], { time: 2.00062, info: SYNACK_INFO, packet: tvSynAck(undefined, 63) }),
          ],
        },
      ],
      outro: {
        title: "Separate networks on one switch",
        text: "Access ports put each device in one VLAN without the device knowing. The trunk carries both VLANs to the router with a 4-byte 802.1Q tag, and the router moves packets between them by swapping the tag, the MACs and the TTL.",
        facts: [["Access port", "Untagged, one VLAN"], ["Trunk", "Tagged, many VLANs"], ["Between VLANs", "Needs a router"], ["Tag", "0x8100 + 12-bit VLAN ID"]],
      },
    },
    {
      id: "acl-block",
      name: "Guest tries the office server",
      summary: "A guest phone tries to open the office file share; the router’s access list drops it and says why.",
      kind: "failure",
      steps: [
        {
          title: "Guest knocks on 445",
          desc: "A guest phone tries the office file share",
          detail:
            "Someone on the guest Wi-Fi tries to open the office file server on port 445. The phone is in VLAN 20 and the server is in VLAN 10, so the switch cannot deliver it directly. It goes up the trunk tagged 20 like any other packet for another subnet.",
          facts: [["From", `${PHONE} (VLAN 20)`], ["To", `${SRV}:445 (VLAN 10)`], ["Trunk tag", "VLAN 20"]],
          quiz: {
            q: "Can the switch send this frame straight to port 2, where the server is?",
            options: ["Yes, it knows the server’s MAC", "No, the frame is in VLAN 20 and port 2 is in VLAN 10", "Yes, if the phone uses the server’s MAC", "Only if the frame is a broadcast"],
            answer: 1,
            why: "A switch never moves a frame between VLANs. Even with the right MAC, a VLAN 20 frame can’t leave a VLAN 10 port. Only the router can join them, and it can check rules first.",
          },
          events: [
            pkt("phone", "switch", "violet", "SYN", ["to .10.50:445", "no tag"], {
              time: 0, info: PH_INFO, packet: frame(PHONE_MAC, R_MAC, undefined, phoneIp(), phoneTcp()),
            }),
            pkt("switch", "router", "violet", "SYN", ["tag: VLAN 20"], {
              time: 0.00002, info: PH_INFO, packet: frame(PHONE_MAC, R_MAC, 20, phoneIp(), phoneTcp()),
            }),
          ],
        },
        {
          title: "The ACL says no",
          desc: "Guest VLAN may not reach office VLAN",
          detail:
            "The VLAN 20 sub-interface has an access control list: deny anything from 192.168.20.0/24 to 192.168.10.0/24, permit everything else. The packet matches the deny line, so the router throws it away instead of sending it down tagged 10.",
          facts: [["ACL line", "deny 192.168.20.0/24 → 192.168.10.0/24"], ["Then", "permit any (internet)"], ["Result", "Dropped"]],
          events: [
            note("router", "ACL: DENY", "red"),
            pkt("router", "server", "red", "SYN", ["tag: VLAN 10", "dropped by ACL"], {
              time: 0.0001, lost: true, info: `[Dropped by ACL] ${PH_INFO}`, packet: frame(R_MAC, SRV_MAC, 10, ipv4({ src: PHONE, dst: SRV, ttl: 63, id: 0x9a07 }), phoneTcp()),
            }),
          ],
        },
        {
          title: "Administratively prohibited",
          desc: "ICMP type 3, code 13",
          detail:
            "Many routers then send an ICMP error back: Destination Unreachable, code 13, which means a rule blocked it. It quotes the start of the blocked packet so the phone can match it to the right connection. The app fails at once instead of waiting for a timeout.",
          facts: [["ICMP", "Type 3, code 13"], ["Sent from", `${GW20} (gateway)`], ["Quotes", "IP header + 8 bytes of TCP"]],
          quiz: {
            q: "If the router dropped the packet silently instead, what would the phone see?",
            options: ["The same error, just later", "Nothing: it retries the SYN and finally times out", "A TCP RST from the server", "An ARP reply"],
            answer: 1,
            why: "With no answer at all, TCP resends the SYN a few times with growing gaps and then gives up. Some admins prefer that because it tells an attacker less.",
          },
          events: [
            pkt("router", "switch", "red", "ICMP 3/13", ["prohibited", "tag: VLAN 20"], { time: 0.0002, info: PROHIB_INFO, packet: prohibited(20) }),
            pkt("switch", "phone", "red", "ICMP 3/13", ["tag removed"], { time: 0.00022, info: PROHIB_INFO, packet: prohibited(undefined) }),
            note("phone", "BLOCKED BY POLICY", "red"),
          ],
        },
      ],
      outro: {
        title: "VLANs separate, the router decides",
        text: "VLANs keep guest and office frames apart on the switch, but anything routed between them is only as safe as the router’s rules. Here an access list blocked guest-to-office traffic and an ICMP code 13 message told the phone why.",
        facts: [["Separation", "VLANs at Layer 2"], ["Policy", "ACL on the router"], ["Error", "ICMP type 3 code 13"], ["Silent drop", "Timeout instead"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "The 802.1Q tag",
      items: [["TPID", "0x8100 (2 bytes, sits where the EtherType was)"], ["PCP", "3 bits of priority (0–7)"], ["DEI", "1 bit: may drop first when busy"], ["VLAN ID", "12 bits: 1–4094 usable"], ["Then", "The original EtherType"]],
    },
    {
      title: "Port types",
      items: [["Access", "One VLAN, frames untagged"], ["Trunk", "Many VLANs, frames tagged"], ["Native VLAN", "The one VLAN a trunk sends untagged"], ["Sub-interface", "A router port per VLAN, e.g. Gi0/0.10"]],
    },
    {
      title: "Numbers to know",
      items: [["VLAN 0 / 4095", "Reserved"], ["VLAN 1", "Default on most switches"], ["Max tagged frame", "1518 bytes (+4 FCS = 1522)"], ["ICMP 3/13", "Communication administratively prohibited"]],
    },
  ],
});
