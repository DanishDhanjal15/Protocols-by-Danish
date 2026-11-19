import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, LayerSpec, opaque, proto } from "@/lib/packet";
import { eth, icmp, ipv4, tcp, udp } from "@/lib/proto";

// Underlay (the data centre's real network) and overlay (the tenant's virtual network).
const VTEP1 = "192.0.2.11";
const VTEP2 = "192.0.2.12";
const LEAF1_MAC = "0c:42:a1:10:00:11";
const LEAF2_MAC = "0c:42:a1:10:00:12";
const SPINE_MAC = "0c:42:a1:20:00:01";
const VM_A = "10.10.0.11";
const VM_B = "10.10.0.12";
const VM_A_MAC = "52:54:00:aa:00:11";
const VM_B_MAC = "52:54:00:bb:00:12";
const VM_C_MAC = "52:54:00:cc:00:11";
const VM_C2_MAC = "52:54:00:cc:00:12";
const VNI_RED = 10010;
const VNI_BLUE = 20020;

/** The 8-byte VXLAN header (RFC 7348). */
const vxlan = (vni: number): LayerSpec =>
  proto({
    id: "vxlan",
    name: "VXLAN",
    osi: 2,
    summary: `Virtual eXtensible Local Area Network, VNI: ${vni}`,
    fields: [
      { name: "Flags", u8: 0x08, value: "0x08 (I: VNI is valid)", note: "Only the I bit is set. It says the VNI field below is real." },
      { name: "Reserved", zero: 3, value: "0", note: "Must be zero." },
      { name: "VNI", u24: vni, value: String(vni), note: "VXLAN Network Identifier: which tenant network this frame belongs to. 24 bits, so about 16 million networks." },
      { name: "Reserved", zero: 1, value: "0" },
    ],
  });

/** Outer headers added by a VTEP. UDP checksum is zero, as RFC 7348 recommends for IPv4. */
const outer = (fromLeaf: 1 | 2, sport: number, vni: number, id: number): LayerSpec[] => [
  eth({ src: fromLeaf === 1 ? LEAF1_MAC : LEAF2_MAC, dst: SPINE_MAC }),
  ipv4({ src: fromLeaf === 1 ? VTEP1 : VTEP2, dst: fromLeaf === 1 ? VTEP2 : VTEP1, ttl: 64, id }),
  udp({ sport, dport: 4789, zeroChecksum: true }),
  vxlan(vni),
];

const pingData = Array.from({ length: 56 }, (_, i) => (0x10 + i) & 0xff);
const echo = (type: 0 | 8, seq: number) =>
  icmp({
    type, name: type === 8 ? "Echo (ping) request" : "Echo (ping) reply",
    restFields: [{ name: "Identifier", u16: 0x2b1c }, { name: "Sequence number", u16: seq }],
    data: pingData, dataName: "Data", dataNote: "56 bytes of filler, copied back in the reply.",
  });

const innerReq = (srcMac = VM_A_MAC, dstMac = VM_B_MAC) => [eth({ src: srcMac, dst: dstMac }), ipv4({ src: VM_A, dst: VM_B, ttl: 64, id: 0x4a01 }), echo(8, 1)];
const innerRep = () => [eth({ src: VM_B_MAC, dst: VM_A_MAC }), ipv4({ src: VM_B, dst: VM_A, ttl: 64, id: 0x7c10 }), echo(0, 1)];

// TCP segments for the MTU story
const seg = (dataLen: number, seq: number) => [
  eth({ src: VM_A_MAC, dst: VM_B_MAC }),
  ipv4({ src: VM_A, dst: VM_B, ttl: 64, id: 0x4b00 + seq % 7 }),
  tcp({ sport: 44120, dport: 5432, seq, ack: 1, flags: "PA", win: 502, seqBase: 0x3e2a1000, ackBase: 0x9a110000 }),
  opaque("Database data", dataLen, `Query results (${dataLen} bytes)`, 7),
];

const devices: Device[] = [
  { id: "vmA", kind: "server", label: "VM A (Red)", sub: VM_A, x: 8, y: 30 },
  { id: "vmC", kind: "server", label: "VM C (Blue)", sub: `${VM_A} too`, x: 8, y: 78 },
  { id: "leaf1", kind: "switch", label: "Leaf 1 (VTEP)", sub: VTEP1, x: 30, y: 55 },
  { id: "spine", kind: "router", label: "Spine", sub: "underlay", x: 52, y: 22 },
  { id: "leaf2", kind: "switch", label: "Leaf 2 (VTEP)", sub: VTEP2, x: 72, y: 55 },
  { id: "vmB", kind: "server", label: "VM B (Red)", sub: VM_B, x: 92, y: 55 },
];
const links: [string, string][] = [["vmA", "leaf1"], ["vmC", "leaf1"], ["leaf1", "spine"], ["spine", "leaf2"], ["leaf2", "vmB"]];

export default defineLesson({
  id: "vxlan",
  name: "VXLAN",
  full: "Virtual eXtensible Local Area Network",
  group: "vpn",
  layer: 2,
  difficulty: 3,
  tagline: "Ethernet networks for virtual machines, carried inside UDP.",
  description:
    "VXLAN lets virtual machines on different racks behave as if they sat on one Ethernet switch. The switch next to the sender wraps the whole Ethernet frame in UDP and sends it across the routed data-centre network, and the switch next to the receiver unwraps it. A 24-bit network number keeps millions of tenants apart.",
  facts: [
    ["Layer", "Layer 2 frames over Layer 3/4"],
    ["Transport", "UDP port 4789"],
    ["Header", "8 bytes (50 bytes of total overhead)"],
    ["Network ID", "24-bit VNI (16 million networks)"],
    ["Endpoints", "VTEPs (VXLAN tunnel endpoints)"],
    ["Defined in", "RFC 7348"],
  ],
  ports: "UDP 4789",
  rfc: "RFC 7348",
  keywords: ["vxlan", "vtep", "vni", "overlay", "underlay", "data centre", "evpn", "encapsulation", "mtu", "leaf spine"],
  related: ["ethernet", "vlan", "udp", "mpls", "bgp"],
  devices,
  links,
  legend: [
    ["amber", "Frames from a virtual machine"],
    ["violet", "Replies"],
    ["teal", "Wrapped in VXLAN (outer headers)"],
    ["pink", "A different tenant's traffic"],
    ["red", "Dropped"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A ping between racks",
      summary: "VM A pings VM B on another rack. The leaf switches wrap and unwrap the frame so both VMs think they share one LAN.",
      kind: "normal",
      steps: [
        {
          title: "VM A sends a ping",
          desc: "A plain Ethernet frame, nothing special",
          detail:
            "VM A and VM B are both on the Red tenant's network 10.10.0.0/24, so VM A simply sends an Ethernet frame to VM B's MAC address. It has no idea VM B lives on a different rack, behind routers. The frame reaches Leaf 1, the switch its host is plugged into.",
          facts: [["From", `${VM_A} (VM A)`], ["To", `${VM_B} (VM B)`], ["Frame size", "98 bytes"]],
          quiz: {
            q: "VM A and VM B are on different racks with routers between them. Who does VM A think it is talking to directly?",
            options: ["The spine router", "VM B, as if on the same switch", "Leaf 2", "Its default gateway"],
            answer: 1,
            why: "The overlay gives the VMs one flat Ethernet network, so VM A addresses VM B's MAC directly.",
          },
          events: [
            pkt("vmA", "leaf1", "amber", "PING", ["to 10.10.0.12", "plain Ethernet"], {
              time: 0, info: `Echo (ping) request id=0x2b1c, seq=1/256, ttl=64`,
              packet: build(...innerReq()),
            }),
          ],
        },
        {
          title: "Leaf 1 wraps the frame",
          desc: "Ethernet inside VXLAN inside UDP inside IP",
          detail:
            `Leaf 1 is a VTEP: a VXLAN tunnel endpoint. It has learned (usually through BGP EVPN) that VM B's MAC sits behind Leaf 2 at ${VTEP2}. It puts the whole frame behind an 8-byte VXLAN header with VNI ${VNI_RED} for the Red tenant, then adds UDP, IP and Ethernet headers addressed to Leaf 2.`,
          facts: [["Outer IPs", `${VTEP1} → ${VTEP2}`], ["UDP", "random source → 4789"], ["VNI", `${VNI_RED} (Red)`]],
          quiz: {
            q: "Why does the outer UDP source port change from flow to flow?",
            options: ["It is a security token", "It is a hash of the inner frame, so routers spread flows across links", "It counts frames", "It carries the VNI"],
            answer: 1,
            why: "Routers balance traffic by hashing the outer headers. A per-flow source port lets different inner flows take different equal-cost paths.",
          },
          events: [
            pkt("leaf1", "leaf2", "teal", "VXLAN", [`VNI ${VNI_RED}`, `${VTEP1} → ${VTEP2}`], {
              time: 0.000004, info: `VXLAN VNI ${VNI_RED}: Echo (ping) request ${VM_A} → ${VM_B}`,
              packet: build(...outer(1, 52814, VNI_RED, 0x0e11), ...innerReq()),
            }),
            note("spine", "JUST AN IP PACKET HERE", "blue"),
          ],
        },
        {
          title: "Leaf 2 unwraps it",
          desc: "Strip 50 bytes, deliver the original frame",
          detail:
            "The spine routed the packet like any other UDP packet; it never looked inside. Leaf 2 sees UDP port 4789, reads VNI 10010, removes the outer 50 bytes and hands the original frame to VM B, byte for byte the same as VM A sent it.",
          facts: [["Removed", "14 + 20 + 8 + 8 = 50 bytes"], ["VNI", `${VNI_RED} → Red network`], ["Delivered", "Original 98-byte frame"]],
          events: [
            pkt("leaf2", "vmB", "amber", "PING", ["unwrapped", "same frame as before"], {
              time: 0.000009, info: `Echo (ping) request id=0x2b1c, seq=1/256, ttl=64`,
              packet: build(...innerReq()),
            }),
          ],
        },
        {
          title: "The reply comes back",
          desc: "The same trip in reverse",
          detail:
            "VM B answers with an echo reply. Leaf 2 wraps it with the same VNI and sends it to Leaf 1, which unwraps it and delivers it to VM A. The whole round trip inside the data centre takes about 20 microseconds.",
          facts: [["Outer IPs", `${VTEP2} → ${VTEP1}`], ["VNI", String(VNI_RED)], ["Round trip", "≈ 20 µs"]],
          events: [
            pkt("vmB", "leaf2", "violet", "REPLY", ["to 10.10.0.11"], {
              time: 0.000012, info: `Echo (ping) reply id=0x2b1c, seq=1/256, ttl=64`,
              packet: build(...innerRep()),
            }),
            pkt("leaf2", "leaf1", "teal", "VXLAN", [`VNI ${VNI_RED}`, `${VTEP2} → ${VTEP1}`], {
              time: 0.000016, info: `VXLAN VNI ${VNI_RED}: Echo (ping) reply ${VM_B} → ${VM_A}`,
              packet: build(...outer(2, 61207, VNI_RED, 0x2f40), ...innerRep()),
            }),
            pkt("leaf1", "vmA", "violet", "REPLY", ["unwrapped"], {
              time: 0.00002, info: `Echo (ping) reply id=0x2b1c, seq=1/256, ttl=64`,
              packet: build(...innerRep()),
            }),
            note("vmA", "REPLY IN 20 µs", "green"),
          ],
        },
        {
          title: "Same IPs, other tenant",
          desc: "The VNI keeps tenants apart",
          detail:
            `VM C belongs to the Blue tenant, which happens to use the very same address, ${VM_A}. Leaf 1 wraps its frames with VNI ${VNI_BLUE} instead. Leaf 2 only delivers VNI ${VNI_BLUE} frames to Blue machines, so Red and Blue never see each other even though their addresses clash.`,
          facts: [["Blue VNI", String(VNI_BLUE)], ["Same inner IPs", "No problem"], ["Old VLAN limit", "4094 networks"]],
          quiz: {
            q: "Why do clouds use VXLAN instead of ordinary VLANs to separate tenants?",
            options: ["VLANs can't carry IP", "A VLAN ID has only 12 bits (4094 networks); a VNI has 24 bits", "VXLAN is encrypted", "VLANs need fibre"],
            answer: 1,
            why: "12 bits give 4094 usable VLANs, far too few for a big cloud. 24 bits give about 16 million.",
          },
          events: [
            pkt("vmC", "leaf1", "pink", "PING", ["Blue 10.10.0.11"], {
              time: 0.5, info: `Echo (ping) request id=0x2b1c, seq=1/256, ttl=64`,
              packet: build(...innerReq(VM_C_MAC, VM_C2_MAC)),
            }),
            pkt("leaf1", "leaf2", "pink", "VXLAN", [`VNI ${VNI_BLUE}`, "Blue tenant"], {
              time: 0.500004, info: `VXLAN VNI ${VNI_BLUE}: Echo (ping) request ${VM_A} → ${VM_B}`,
              packet: build(...outer(1, 50377, VNI_BLUE, 0x0e12), ...innerReq(VM_C_MAC, VM_C2_MAC)),
            }),
            note("leaf2", `VNI ${VNI_BLUE}: BLUE ONLY`, "blue"),
          ],
        },
      ],
      outro: {
        title: "One flat network, many racks",
        text: "VXLAN carried an ordinary Ethernet frame across a routed data-centre network by wrapping it in UDP. The spine only saw IP packets between two VTEPs, and the VNI kept two tenants with the same addresses apart.",
        facts: [["Overhead", "50 bytes per frame"], ["UDP port", "4789"], ["Tenants", "Up to 16 million VNIs"], ["Control plane", "Usually BGP EVPN"]],
      },
    },
    {
      id: "mtu",
      name: "Big packets vanish (MTU)",
      summary: "The 50-byte VXLAN overhead pushes a full-size frame past the underlay's 1500-byte MTU, so big packets are silently dropped.",
      kind: "failure",
      steps: [
        {
          title: "A full-size segment",
          desc: "VM A sends 1500 bytes of IP",
          detail:
            "VM A has a normal Ethernet MTU of 1500, so its database replies go out as full 1500-byte IP packets: 20 bytes IP, 20 bytes TCP and 1460 bytes of data. Small packets like the ping earlier worked fine.",
          facts: [["Inner IP packet", "1500 bytes"], ["VM MTU", "1500"], ["DF bit", "Set"]],
          events: [
            pkt("vmA", "leaf1", "amber", "DATA", ["1500-byte IP packet"], {
              time: 0, info: "44120 → 5432 [PSH, ACK] Seq=1 Ack=1 Win=502 Len=1460",
              packet: build(...seg(1460, 1)),
            }),
          ],
        },
        {
          title: "Too big for the underlay",
          desc: "1500 + 50 = 1550 bytes",
          detail:
            "Leaf 1 adds 50 bytes of outer headers. The outer IP packet is now 1550 bytes, but the links between leaf and spine were left at MTU 1500. VTEPs must not fragment VXLAN packets, so the oversized packet is dropped.",
          facts: [["Outer IP packet", "1550 bytes"], ["Underlay MTU", "1500"], ["Result", "Dropped"]],
          quiz: {
            q: "The underlay sends an ICMP “too big” message back. Why doesn't VM A shrink its packets?",
            options: ["The ICMP goes to Leaf 1's VTEP address, not to VM A", "VM A ignores all ICMP", "ICMP can't cross VXLAN", "The message is encrypted"],
            answer: 0,
            why: "The dropped packet's source was the VTEP, so any error goes there. VM A never learns its packets are too big.",
          },
          events: [
            pkt("leaf1", "leaf2", "red", "VXLAN", ["1550 bytes", "MTU is 1500"], {
              time: 0.000004, lost: true, info: `VXLAN VNI ${VNI_RED}: 44120 → 5432 [PSH, ACK] Len=1460`,
              packet: build(...outer(1, 55102, VNI_RED, 0x0f01), ...seg(1460, 1)),
            }),
            note("spine", "1550 > MTU 1500: DROPPED", "red"),
          ],
        },
        {
          title: "Small works, big vanishes",
          desc: "A classic black hole",
          detail:
            "TCP retransmits the same 1500-byte packet after its timer runs out, and it is dropped again. Pings and small requests still work, which makes this bug confusing: the connection opens, then hangs as soon as real data flows.",
          facts: [["Pings", "Work"], ["Big transfers", "Hang"], ["Symptom", "Retransmissions, then timeout"]],
          events: [
            pkt("vmA", "leaf1", "amber", "RESEND", ["same 1500 bytes"], {
              time: 0.204, info: "[TCP Retransmission] 44120 → 5432 [PSH, ACK] Seq=1 Ack=1 Len=1460",
              packet: build(...seg(1460, 1)),
            }),
            pkt("leaf1", "leaf2", "red", "VXLAN", ["1550 bytes"], {
              time: 0.204004, lost: true, info: `VXLAN VNI ${VNI_RED}: [TCP Retransmission] Len=1460`,
              packet: build(...outer(1, 55102, VNI_RED, 0x0f02), ...seg(1460, 1)),
            }),
            note("vmA", "CONNECTION HANGS", "red"),
          ],
        },
        {
          title: "The fix",
          desc: "Room for 50 more bytes",
          detail:
            "There are two fixes. The usual one is to raise the underlay MTU to 9000 or more (jumbo frames), so a 1550-byte packet fits easily. The other is to give the VMs an MTU of 1450, which is what many clouds do. Here the VM uses 1450: the inner packet is 1450 bytes and the outer one exactly 1500.",
          facts: [["VM MTU", "1450 (MSS 1410)"], ["Outer packet", "1500 bytes: fits"], ["Better fix", "Underlay MTU 9000+"]],
          quiz: {
            q: "With a VM MTU of 1450, how large is the outer IP packet?",
            options: ["1450 bytes", "1486 bytes", "1500 bytes", "1550 bytes"],
            answer: 2,
            why: "The outer IP header (20), UDP (8), VXLAN (8) and inner Ethernet (14) add 50 bytes above the inner IP packet: 1450 + 50 = 1500. The outer Ethernet header is not counted in the IP MTU.",
          },
          events: [
            pkt("leaf1", "leaf2", "teal", "VXLAN", ["1500 bytes", "fits"], {
              time: 1.5, info: `VXLAN VNI ${VNI_RED}: 44120 → 5432 [PSH, ACK] Len=1410`,
              packet: build(...outer(1, 55102, VNI_RED, 0x0f03), ...seg(1410, 1)),
            }),
            pkt("leaf2", "vmB", "amber", "DATA", ["1450-byte IP packet"], {
              time: 1.500009, info: "44120 → 5432 [PSH, ACK] Seq=1 Ack=1 Win=502 Len=1410",
              packet: build(...seg(1410, 1)),
            }),
            note("vmB", "DATA ARRIVES", "green"),
          ],
        },
      ],
      outro: {
        title: "Mind the 50 bytes",
        text: "VXLAN adds 50 bytes to every frame. If the underlay MTU isn't raised, or the VMs' MTU lowered, full-size packets are silently dropped while small ones work, which looks like a mysterious hang.",
        facts: [["Overhead", "50 bytes (IPv4 underlay)"], ["Fix 1", "Underlay MTU 9000+"], ["Fix 2", "VM MTU 1450"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "The VXLAN stack",
      items: [["Outer Ethernet", "14 bytes, leaf → spine"], ["Outer IPv4", "20 bytes, VTEP → VTEP"], ["Outer UDP", "8 bytes, dst port 4789, checksum 0"], ["VXLAN", "8 bytes: flags 0x08, 24-bit VNI"], ["Inner frame", "The VM's original Ethernet frame"]],
    },
    {
      title: "Words to know",
      items: [["Underlay", "The real routed network"], ["Overlay", "The virtual network the VMs see"], ["VTEP", "Switch or host that wraps and unwraps"], ["VNI", "Tenant network number"], ["EVPN", "BGP that tells VTEPs where each MAC lives"]],
    },
    {
      title: "Numbers",
      items: [["UDP port", "4789"], ["VNI size", "24 bits (≈16.7 million)"], ["Overhead", "50 bytes"], ["Safe VM MTU", "1450 on a 1500 underlay"]],
    },
  ],
});
