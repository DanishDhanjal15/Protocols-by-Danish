import { defineLesson, Device, note, pkt, PacketEvent } from "@/lib/lesson";
import { build } from "@/lib/packet";
import { arp, BROADCAST_MAC, eth, ipv4, tcp, TcpOpt } from "@/lib/proto";
import { ADDR } from "./_common";

const LAPTOP = ADDR.laptop;
const NAS = "192.168.1.50";
const PRINTER = "192.168.1.60";
const LMAC = ADDR.laptopMac;
const NMAC = "00:11:32:c4:5e:07";
const PMAC = "00:80:77:3b:c2:19";
const RMAC = ADDR.routerMac;
const XMAC = "02:42:de:ad:be:ef";

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: "port 1", x: 10, y: 62 },
  { id: "switch", kind: "switch", label: "Switch", sub: "4 ports", x: 46, y: 50 },
  { id: "printer", kind: "printer", label: "Printer", sub: "port 2", x: 46, y: 15 },
  { id: "nas", kind: "nas", label: "NAS", sub: "port 3", x: 88, y: 62 },
  { id: "router", kind: "router", label: "Router", sub: "port 4", x: 46, y: 85 },
];
const links: [string, string][] = [["client", "switch"], ["switch", "printer"], ["switch", "nas"], ["switch", "router"]];

const attackDevices: Device[] = [...devices, { id: "attacker", kind: "attacker", label: "Attacker", sub: "port 5", x: 12, y: 20 }];
const attackLinks: [string, string][] = [...links, ["switch", "attacker"]];

const synOpts: TcpOpt[] = [{ mss: 1460 }, "sackOk", { ts: [902211, 0] }, "nop", { ws: 7 }];
const SEQ_L = 0x61a0b000;
const SEQ_N = 0x0c3d2200;

const synFrame = () => build(eth({ src: LMAC, dst: NMAC }), ipv4({ src: LAPTOP, dst: NAS, ttl: 64, id: 0x1201 }), tcp({ sport: 50110, dport: 445, seq: 0, flags: "S", opts: synOpts, seqBase: SEQ_L }));
const synAck = () => build(eth({ src: NMAC, dst: LMAC }), ipv4({ src: NAS, dst: LAPTOP, ttl: 64, id: 0 }), tcp({ sport: 445, dport: 50110, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1460 }, "sackOk", { ts: [4410021, 902211] }, "nop", { ws: 7 }], seqBase: SEQ_N, ackBase: SEQ_L }));
const ackFrame = (id: number) => build(eth({ src: LMAC, dst: NMAC }), ipv4({ src: LAPTOP, dst: NAS, ttl: 64, id }), tcp({ sport: 50110, dport: 445, seq: 1, ack: 1, flags: "A", win: 502, seqBase: SEQ_L, ackBase: SEQ_N }));
const SYN_INFO = "50110 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128";

/** copies of one frame leaving the switch on several ports */
const flood = (to: string[], label: string, lines: string[], color: PacketEvent["color"], time: number, info: string, packet: PacketEvent["packet"]) =>
  to.map((d, i) => pkt("switch", d, color, label, lines, { time, parallel: i > 0, info, packet }));

const fakeMac = (i: number) => `${(0x02 + ((i * 0x34) & 0xfc)).toString(16).padStart(2, "0")}:${["7f", "1c", "e3", "5a"][i % 4]}:${(0x10 + i * 37).toString(16).slice(-2).padStart(2, "0")}:9b:${(i * 61 + 3).toString(16).slice(-2).padStart(2, "0")}:${(i * 13 + 0x40).toString(16).slice(-2)}`;
const junk = (i: number, time: number, lost = false) =>
  pkt("attacker", "switch", "red", "JUNK", [`src ${fakeMac(i)}`, lost ? "port shut down" : "fake MAC"], {
    time, lost, info: `${40000 + i} → ${1000 + i} [SYN] Seq=0 Win=512 Len=0`,
    packet: build(eth({ src: fakeMac(i), dst: fakeMac(i + 50) }), ipv4({ src: `198.18.${i}.${i * 7}`, dst: `198.19.${i * 3}.${i + 9}`, ttl: 64, id: 0x0100 + i, df: false }), tcp({ sport: 40000 + i, dport: 1000 + i, seq: 0, flags: "S", win: 512, seqBase: 0x01010101 * (i + 1) })),
  });

export default defineLesson({
  id: "ethernet",
  name: "Ethernet",
  full: "Ethernet (IEEE 802.3) and switch learning",
  group: "lan",
  layer: 2,
  difficulty: 1,
  tagline: "How a switch learns who sits on which port.",
  description:
    "Ethernet frames carry a destination MAC, a source MAC and a type. A switch reads the source MAC of every frame to learn which port each device is on, then sends later frames only out of the right port. Frames to unknown or broadcast addresses are copied to every port.",
  facts: [
    ["Layer", "Data link (Layer 2)"],
    ["Header", "14 bytes: dst, src, type"],
    ["Frame size", "60–1514 bytes (+4 FCS)"],
    ["MAC address", "48 bits, e.g. 3c:22:fb:7a:91:0e"],
    ["Switch table aging", "300 s by default"],
    ["Defined in", "IEEE 802.3, 802.1D (bridging)"],
  ],
  ports: "None: EtherType says what’s inside (0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6)",
  rfc: "IEEE 802.3",
  keywords: ["ethernet", "switch", "mac address", "mac table", "cam table", "flooding", "broadcast", "frame", "mac flooding", "port security", "ethertype"],
  related: ["arp", "vlan", "stp", "ip"],
  devices,
  links,
  legend: [
    ["amber", "Frames from the laptop"],
    ["violet", "Frames from the NAS"],
    ["slate", "Flooded copies"],
    ["blue", "Broadcast"],
    ["red", "Attack frames"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A switch learns its ports",
      summary: "The first frame is flooded, the switch learns from the reply, and later frames go out of one port only.",
      kind: "normal",
      steps: [
        {
          title: "Empty table, first frame",
          desc: "Learn the source, flood the unknown destination",
          detail:
            "The switch has just powered on and its MAC table is empty. The laptop sends a frame to the NAS. The switch notes that 3c:22:fb:7a:91:0e lives on port 1. It doesn’t know where the NAS is yet, so it floods a copy out of every other port.",
          facts: [["Learned", `${LMAC} → port 1`], ["Destination", `${NMAC} (unknown)`], ["Action", "Flood to ports 2, 3, 4"]],
          quiz: {
            q: "Which ports get a copy of this frame?",
            options: ["Only port 3 (the NAS)", "Ports 2, 3 and 4: all except where it came in", "All ports including port 1", "None, it is dropped"],
            answer: 1,
            why: "An unknown destination is flooded to every port except the one it arrived on. Sending it back to the sender would be pointless.",
          },
          events: [
            pkt("client", "switch", "amber", "FRAME", [`to ${NMAC}`, "dst unknown"], { time: 0, info: SYN_INFO, packet: synFrame() }),
            note("switch", "LEARN: LAPTOP = PORT 1", "blue"),
            ...flood(["nas", "printer", "router"], "COPY", ["flooded"], "slate", 0.00002, SYN_INFO, synFrame()),
          ],
        },
        {
          title: "The NAS answers",
          desc: "Only the owner keeps the frame",
          detail:
            "The printer and router see a destination MAC that isn’t theirs and throw the frame away in hardware. The NAS replies. Now the switch learns the NAS is on port 3, and it already knows the laptop is on port 1, so the reply goes out of port 1 only.",
          facts: [["Learned", `${NMAC} → port 3`], ["Reply goes to", "Port 1 only"], ["Others", "Dropped the copy"]],
          events: [
            note("printer", "NOT MY MAC", "blue"),
            pkt("nas", "client", "violet", "FRAME", [`to ${LMAC}`, "port 1 only"], {
              time: 0.0003, info: "445 → 50110 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128", packet: synAck(),
            }),
            note("switch", "LEARN: NAS = PORT 3", "blue"),
          ],
        },
        {
          title: "Straight to the right port",
          desc: "No more flooding",
          detail:
            "From now on, frames between the laptop and the NAS travel only between ports 1 and 3. The printer never sees them. This is what makes a switch faster and more private than an old hub, which copied every frame everywhere.",
          facts: [["MAC table", "Port 1: laptop, port 3: NAS"], ["Frames to printer", "None"], ["Hub would", "Copy everything everywhere"]],
          quiz: {
            q: "The laptop sends another frame to the NAS. How many ports does it go out of?",
            options: ["1", "3", "4", "It depends on the size"],
            answer: 0,
            why: "The NAS’s MAC is now in the table on port 3, so the switch forwards it there and nowhere else.",
          },
          events: [pkt("client", "nas", "amber", "FRAME", ["known: port 3"], { time: 0.0004, info: "50110 → 445 [ACK] Seq=1 Ack=1 Win=502 Len=0", packet: ackFrame(0x1202) })],
        },
        {
          title: "Broadcast goes everywhere",
          desc: "ff:ff:ff:ff:ff:ff is always flooded",
          detail:
            "Now the laptop wants to print and asks with ARP who has 192.168.1.60. The destination is the broadcast MAC, which means everyone, so the switch always floods it, no matter what its table says. That is why very large Layer 2 networks get slowed down by broadcasts.",
          facts: [["Destination", "ff:ff:ff:ff:ff:ff"], ["Type", "0x0806 (ARP)"], ["Flooded to", "Ports 2, 3, 4"]],
          events: [
            pkt("client", "switch", "blue", "BROADCAST", ["ARP: who has .60?"], {
              time: 5.0, info: `Who has ${PRINTER}? Tell ${LAPTOP}`,
              packet: build(eth({ src: LMAC, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: LMAC, senderIp: LAPTOP, targetIp: PRINTER })),
            }),
            ...flood(["printer", "nas", "router"], "BROADCAST", ["to everyone"], "blue", 5.00002, `Who has ${PRINTER}? Tell ${LAPTOP}`,
              build(eth({ src: LMAC, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: LMAC, senderIp: LAPTOP, targetIp: PRINTER }))),
          ],
        },
        {
          title: "Aging out",
          desc: "Unused entries are forgotten after 300 s",
          detail:
            "The printer answers, and the switch learns it is on port 2. Every entry has a timer that resets whenever that MAC sends a frame. If a device is silent for 300 seconds, or is moved to another port, the old entry disappears and the switch learns again.",
          facts: [["Learned", `${PMAC} → port 2`], ["Aging time", "300 s"], ["Moved device", "Re-learned on its new port"]],
          quiz: {
            q: "The NAS is unplugged and moved to port 4. What happens to its next frame?",
            options: ["It is dropped forever", "The switch sees its MAC on port 4 and updates the table", "The switch floods it to every port forever", "The NAS must reboot the switch"],
            answer: 1,
            why: "Learning happens on every frame. A source MAC seen on a new port simply replaces the old entry.",
          },
          events: [
            pkt("printer", "client", "green", "ARP REPLY", [`${PRINTER} is at`, PMAC], {
              time: 5.0004, info: `${PRINTER} is at ${PMAC}`,
              packet: build(eth({ src: PMAC, dst: LMAC }), arp({ op: 2, senderMac: PMAC, senderIp: PRINTER, targetMac: LMAC, targetIp: LAPTOP })),
            }),
            note("switch", "LEARN: PRINTER = PORT 2", "blue"),
          ],
        },
      ],
      outro: {
        title: "A switch that knows its ports",
        text: "The switch learned each device’s port from the source MAC of its frames. Unknown and broadcast destinations were flooded; known ones went out of exactly one port. No configuration was needed.",
        facts: [["Learn from", "Source MAC"], ["Forward by", "Destination MAC"], ["Unknown / broadcast", "Flood"], ["Aging", "300 s"]],
      },
    },
    {
      id: "mac-flood",
      name: "MAC flooding and port security",
      summary: "An attacker fills the MAC table with fake addresses so the switch floods everything; port security shuts the port.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "Thousands of fake MACs",
          desc: "A tool like macof sends random source addresses",
          detail:
            "The attacker plugs into port 5 and runs a tool that sends frames with a new random source MAC each time, tens of thousands per second. The switch dutifully learns every one of them on port 5.",
          facts: [["Rate", "~100,000 frames/s"], ["Source MACs", "Random, all different"], ["Goal", "Fill the MAC table"]],
          events: [junk(1, 0), junk(2, 0.00001), junk(3, 0.00002), note("switch", "TABLE FILLING…", "amber")],
        },
        {
          title: "The table is full",
          desc: "Real devices no longer fit",
          detail:
            "The switch has room for 8,192 entries, and they are all fake now. When the NAS’s entry ages out, there is no room to learn it again. Frames to the NAS now have an unknown destination, so the switch floods them out of every port, including the attacker’s.",
          facts: [["Table size", "8,192 entries"], ["Free", "0"], ["Laptop → NAS frames", "Flooded to all ports"]],
          quiz: {
            q: "Why does the attacker now see the laptop’s frames to the NAS?",
            options: ["The switch forwards everything to port 5 on purpose", "The NAS’s MAC isn’t in the full table, so its frames are flooded", "The attacker changed the NAS’s IP", "The laptop sends to the attacker by mistake"],
            answer: 1,
            why: "With no room to learn the NAS, the switch treats it as unknown and floods. The switch behaves like a hub and the attacker can capture traffic.",
          },
          events: [
            pkt("client", "switch", "amber", "FRAME", [`to ${NMAC}`], { time: 1.0, info: "50110 → 445 [ACK] Seq=1 Ack=1 Win=502 Len=0", packet: ackFrame(0x1210) }),
            ...flood(["nas", "printer", "router", "attacker"], "COPY", ["flooded"], "slate", 1.00002, "50110 → 445 [ACK] Seq=1 Ack=1 Win=502 Len=0", ackFrame(0x1210)),
            note("attacker", "CAPTURING", "red"),
          ],
        },
        {
          title: "Port security",
          desc: "At most 2 MACs per port, then shut down",
          detail:
            "The admin enables port security: each access port may learn at most two MAC addresses. When a third source MAC shows up on port 5, the switch counts it as a violation and puts the port into an error-disabled state. The attacker’s frames go nowhere.",
          facts: [["Limit", "2 MACs per port"], ["Violation action", "Shut down the port"], ["Port 5", "err-disabled"]],
          quiz: {
            q: "Which signal tells the switch this port is misbehaving?",
            options: ["The frames are too big", "More source MACs than allowed on one port", "The frames are broadcasts", "The IP addresses are wrong"],
            answer: 1,
            why: "A laptop or printer has one MAC. Hundreds of source MACs on a single access port can only mean something is wrong.",
          },
          events: [junk(4, 30.0), junk(5, 30.00001), junk(6, 30.00002, true), note("switch", "PORT 5 ERR-DISABLED", "green")],
        },
        {
          title: "Back to normal",
          desc: "The table empties and real devices are learned",
          detail:
            "The fake entries age out. The NAS sends a frame, the switch learns it on port 3 again, and laptop-to-NAS traffic goes out of one port only. Port 5 stays down until an admin checks it and turns it back on.",
          facts: [["Fake entries", "Aged out"], ["NAS", "Port 3 again"], ["Port 5", "Down until reset"]],
          events: [
            pkt("nas", "client", "violet", "FRAME", ["learned again"], { time: 330.0, info: "445 → 50110 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128", packet: synAck() }),
            pkt("client", "nas", "amber", "FRAME", ["port 3 only"], { time: 330.0004, info: "50110 → 445 [ACK] Seq=1 Ack=1 Win=502 Len=0", packet: ackFrame(0x1220) }),
          ],
        },
      ],
      outro: {
        title: "The table is a resource too",
        text: "MAC flooding turns a switch into a hub by filling its table with fake addresses. Port security caps how many MACs each port may use and shuts down a port that breaks the rule.",
        facts: [["Attack", "MAC flooding (CAM overflow)"], ["Effect", "Unknown-unicast flooding"], ["Defence", "Port security, 802.1X"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Frame layout",
      items: [["Preamble + SFD", "8 bytes of sync (not captured)"], ["Destination MAC", "6 bytes"], ["Source MAC", "6 bytes"], ["EtherType", "2 bytes"], ["Payload", "46–1500 bytes (padded)"], ["FCS", "4-byte CRC (usually not captured)"]],
    },
    {
      title: "Switch rules",
      items: [["Learn", "Source MAC → incoming port"], ["Known unicast", "Forward to one port"], ["Unknown unicast", "Flood"], ["Broadcast / multicast", "Flood (unless snooping)"]],
    },
    {
      title: "Special MACs",
      items: [["ff:ff:ff:ff:ff:ff", "Broadcast"], ["01:00:5e:…", "IPv4 multicast"], ["33:33:…", "IPv6 multicast"], ["2nd bit of byte 1 set", "Locally administered (often random)"]],
    },
  ],
});
