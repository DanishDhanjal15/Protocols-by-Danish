import { defineLesson, Device, note, pkt, PacketEvent } from "@/lib/lesson";
import { build, BuiltPacket, FieldSpec, proto } from "@/lib/packet";
import { arp, BROADCAST_MAC, eth, icmp, ipv4 } from "@/lib/proto";
import { Bytes, mac } from "@/lib/bytes";
import { ADDR } from "./_common";

// ---------------------------------------------------------------- the bridges
// All three keep the default priority 32768, so the lowest MAC decides the root.
interface Bridge { prio: number; mac: string; name: string }
const SW1: Bridge = { prio: 32768, mac: "00:1a:a1:00:00:10", name: "SW1" };
const SW2: Bridge = { prio: 32768, mac: "00:1a:a1:00:00:20", name: "SW2" };
const SW3: Bridge = { prio: 32768, mac: "00:1a:a1:00:00:30", name: "SW3" };
/** each switch port has its own MAC, used as the frame's source */
const portMac = (b: Bridge, port: number) => b.mac.slice(0, -1) + String(port);

const STP_MAC = "01:80:c2:00:00:00";
const COST = 4; // 1 Gb/s link, 802.1D-1998 short cost
const LAPTOP = ADDR.laptop;
const NAS = "192.168.1.50";
const LMAC = ADDR.laptopMac;
const NMAC = "00:11:32:c4:5e:07";

const devices: Device[] = [
  { id: "sw1", kind: "switch", label: "SW1", sub: `32768 · ${SW1.mac}`, x: 50, y: 17 },
  { id: "sw2", kind: "switch", label: "SW2", sub: `32768 · ${SW2.mac}`, x: 27, y: 70 },
  { id: "sw3", kind: "switch", label: "SW3", sub: `32768 · ${SW3.mac}`, x: 73, y: 70 },
  { id: "client", kind: "laptop", label: "Laptop", sub: LAPTOP, x: 7, y: 42 },
  { id: "nas", kind: "nas", label: "NAS", sub: NAS, x: 93, y: 42 },
];
// SW1: port 1 → SW2, port 2 → SW3. SW2: port 1 → SW1, port 2 → SW3, port 3 → laptop.
// SW3: port 1 → SW1, port 2 → SW2, port 3 → NAS.
const links: [string, string][] = [["sw1", "sw2"], ["sw1", "sw3"], ["sw2", "sw3"], ["client", "sw2"], ["nas", "sw3"]];

// ---------------------------------------------------------------- frame builders

/** 802.3 frames carry a length where Ethernet II has a type. Relabel that field after building. */
const dot3 = (p: BuiltPacket, src: string): BuiltPacket => {
  const l = p.layers[0];
  const len = (l.fields[2].bytes[0] << 8) | l.fields[2].bytes[1];
  l.name = "IEEE 802.3 Ethernet";
  l.summary = `IEEE 802.3 Ethernet, Src: ${src}, Dst: ${STP_MAC}`;
  l.fields[2] = {
    ...l.fields[2],
    name: "Length",
    value: `${len} bytes`,
    note: "A number of 1500 or less here is a length, not an EtherType. It marks an old-style 802.3 frame, and an LLC header follows to say what is inside. Padding is not counted.",
  };
  return p;
};

const llc = () =>
  proto({
    id: "llc", name: "Logical-Link Control", osi: 2, summary: "Logical-Link Control, DSAP: STP (0x42), SSAP: STP (0x42)",
    fields: [
      { name: "DSAP", u8: 0x42, value: "0x42 (Spanning Tree BPDU)", note: "Destination service access point: who should read this. 0x42 means spanning tree." },
      { name: "SSAP", u8: 0x42, value: "0x42 (Spanning Tree BPDU)", note: "Source service access point: who sent it. Also spanning tree." },
      { name: "Control", u8: 0x03, value: "0x03 (Unnumbered Information)", note: "A simple one-shot message, no connection." },
    ],
  });

const bid = (name: string, b: Bridge, note: string): FieldSpec => ({
  name, value: `${b.prio} / ${b.mac} (${b.name})`, note,
  fields: [
    { name: "Priority", u16: b.prio, note: "Set by the admin, 32768 by default, in steps of 4096. Lower wins." },
    { name: "MAC address", bytes: mac(b.mac), value: b.mac, note: "Breaks ties when priorities are equal. Lower wins." },
  ],
});

const t256 = (name: string, sec: number, note: string): FieldSpec => ({ name, u16: Math.round(sec * 256), value: `${sec} s`, note: `${note} Counted in 1/256 of a second, so ${sec} s is ${Math.round(sec * 256)}.` });

const flagName = (f: number) => [f & 0x80 ? "TCA" : "", f & 0x01 ? "TC" : ""].filter(Boolean).join(", ") || "none";

/** A 35-byte 802.1D configuration BPDU */
const configBpdu = (o: { root: Bridge; cost: number; bridge: Bridge; port: number; age: number; flags?: number }) => {
  const flags = o.flags ?? 0;
  return proto({
    id: "stp", name: "Spanning Tree Protocol", osi: 2,
    summary: `Spanning Tree Protocol: Configuration BPDU, Root ${o.root.name}, cost ${o.cost}, from ${o.bridge.name} port ${o.port}`,
    fields: [
      { name: "Protocol identifier", u16: 0, value: "0x0000 (Spanning Tree)" },
      { name: "Protocol version", u8: 0, value: "0 (802.1D STP)", note: "RSTP sends 2 and MSTP 3. Version 0 is classic spanning tree." },
      { name: "BPDU type", u8: 0x00, value: "0x00 (Configuration)", note: "A configuration BPDU: the regular hello that carries the election data." },
      { name: "Flags", u8: flags, value: `0x${flags.toString(16).padStart(2, "0")} (${flagName(flags)})`, note: "Bit 0 is TC (topology change: flush MAC tables quickly). Bit 7 is TCA (I got your change notice)." },
      bid("Root identifier", o.root, "Who the sender thinks the root bridge is."),
      { name: "Root path cost", u32: o.cost, note: o.cost ? `The sender’s total cost to reach the root. Each 1 Gb/s link adds ${COST}.` : "0: the sender is the root itself." },
      bid("Bridge identifier", o.bridge, "The switch that sent this BPDU."),
      { name: "Port identifier", u16: 0x8000 | o.port, value: `0x${(0x8000 | o.port).toString(16)} (priority 128, port ${o.port})`, note: "Port priority (1 byte) and port number. The last tie-breaker." },
      t256("Message age", o.age, "How old the root’s information is. Each switch adds about 1 s when it passes it on."),
      t256("Max age", 20, "Throw this information away if no fresh BPDU arrives for this long."),
      t256("Hello time", 2, "The root sends a new BPDU this often."),
      t256("Forward delay", 15, "Time spent in listening, then again in learning, before a port forwards."),
    ],
  });
};

const tcnBpdu = () =>
  proto({
    id: "stp", name: "Spanning Tree Protocol", osi: 2, summary: "Spanning Tree Protocol: Topology Change Notification",
    fields: [
      { name: "Protocol identifier", u16: 0, value: "0x0000 (Spanning Tree)" },
      { name: "Protocol version", u8: 0, value: "0 (802.1D STP)" },
      { name: "BPDU type", u8: 0x80, value: "0x80 (Topology Change Notification)", note: "Just 4 bytes: something changed, please tell the root. It goes up the root port, hop by hop." },
    ],
  });

const LLC_LEN = 3;
const bpduFrame = (from: Bridge, port: number, o: Parameters<typeof configBpdu>[0]) => {
  const src = portMac(from, port);
  return dot3(build(eth({ src, dst: STP_MAC, type: LLC_LEN + 35 }), llc(), configBpdu(o)), src);
};
const tcnFrame = (from: Bridge, port: number) => {
  const src = portMac(from, port);
  return dot3(build(eth({ src, dst: STP_MAC, type: LLC_LEN + 4 }), llc(), tcnBpdu()), src);
};

const confInfo = (o: { root: Bridge; cost: number; port: number; flags?: number }) =>
  `Conf. ${o.flags ? `${flagName(o.flags).replace(", ", " + ")} + ` : ""}Root = ${o.root.prio}/0/${o.root.mac}  Cost = ${o.cost}  Port = 0x${(0x8000 | o.port).toString(16)}`;

/** a BPDU event: `fromId`/`toId` are device ids */
const bpdu = (
  fromId: string, toId: string, from: Bridge, port: number,
  o: { root: Bridge; cost: number; age: number; flags?: number },
  ev: { time: number; color?: PacketEvent["color"]; lines: string[]; label?: string; parallel?: boolean; lost?: boolean },
) =>
  pkt(fromId, toId, ev.color ?? "blue", ev.label ?? "BPDU", ev.lines, {
    time: ev.time, parallel: ev.parallel, lost: ev.lost, proto: "STP",
    info: confInfo({ ...o, port }),
    packet: bpduFrame(from, port, { ...o, bridge: from, port }),
  });

// ---------------------------------------------------------------- data frames

const pingData: Bytes = Array.from({ length: 32 }, (_, i) => 0x61 + (i % 23));
const ping = (seq: number) =>
  build(eth({ src: LMAC, dst: NMAC }), ipv4({ src: LAPTOP, dst: NAS, ttl: 128, id: 0x2200 + seq, df: false }),
    icmp({
      type: 8, name: "Echo (ping) request",
      restFields: [{ name: "Identifier", u16: 1 }, { name: "Sequence number", u16: seq }],
      data: pingData, dataName: "Data",
    }));
const PING_INFO = (seq: number) => `Echo (ping) request id=0x0001, seq=${seq}/${seq << 8}, ttl=128`;

const arpReq = () => build(eth({ src: LMAC, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: LMAC, senderIp: LAPTOP, targetIp: NAS }));
const ARP_INFO = `Who has ${NAS}? Tell ${LAPTOP}`;

const ROOT1 = { root: SW1 };

export default defineLesson({
  id: "stp",
  name: "STP",
  full: "Spanning Tree Protocol (IEEE 802.1D / RSTP)",
  group: "lan",
  layer: 2,
  difficulty: 3,
  tagline: "Spare cables without endless loops: switches agree what to block.",
  description:
    "Extra links between switches give you a backup path, but they also create loops that Ethernet cannot survive. Spanning Tree lets switches elect a root, work out the cheapest path to it, and block just enough ports to leave a loop-free tree. When a link fails, a blocked port wakes up and takes over.",
  facts: [
    ["Layer", "Data link (Layer 2)"],
    ["Messages", "BPDUs to 01:80:c2:00:00:00"],
    ["Framing", "802.3 + LLC 0x42 0x42 0x03"],
    ["Config BPDU", "35 bytes"],
    ["Timers", "Hello 2 s, max age 20 s, forward delay 15 s"],
    ["Defined in", "IEEE 802.1D (RSTP: 802.1w)"],
  ],
  ports: "None: LLC SAP 0x42",
  rfc: "IEEE 802.1D",
  keywords: ["spanning tree", "stp", "rstp", "bpdu", "root bridge", "root port", "designated port", "blocked port", "alternate port", "broadcast storm", "loop", "topology change", "tcn", "802.1d", "802.1w"],
  related: ["ethernet", "vlan", "arp"],
  devices,
  links,
  legend: [
    ["blue", "BPDUs (hellos)"],
    ["pink", "Topology change"],
    ["amber", "Laptop data"],
    ["red", "Failures and loops"],
    ["slate", "Flooded copies"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Electing a root and blocking one port",
      summary: "Three switches in a triangle elect SW1 as root, pick root ports, and block one port to break the loop.",
      kind: "normal",
      steps: [
        {
          title: "Everyone claims root",
          desc: "At power-on each switch thinks it is the root",
          detail:
            "When the switches start, each one assumes it is the root and sends BPDUs out of every port saying so, with a cost of 0. A BPDU carries a bridge ID: a 2-byte priority followed by the switch’s MAC. Until the election is over, every port stays blocked for user traffic.",
          facts: [["Destination", STP_MAC], ["Each says", "Root = me, cost 0"], ["Priorities", "All 32768 (default)"]],
          quiz: {
            q: "All three priorities are 32768. Which switch becomes the root?",
            options: ["SW1, lowest MAC 00:1a:a1:00:00:10", "SW3, highest MAC", "The one that booted first", "The one with the most ports"],
            answer: 0,
            why: "The lowest bridge ID wins. Priority is compared first; when it ties, the lower MAC address wins, so SW1 is the root.",
          },
          events: [
            bpdu("sw1", "sw2", SW1, 1, { root: SW1, cost: 0, age: 0 }, { time: 0, lines: ["root = SW1"] }),
            bpdu("sw1", "sw3", SW1, 2, { root: SW1, cost: 0, age: 0 }, { time: 0.0001, parallel: true, lines: ["root = SW1"] }),
            bpdu("sw2", "sw1", SW2, 1, { root: SW2, cost: 0, age: 0 }, { time: 0.0002, parallel: true, lines: ["root = SW2?"] }),
            bpdu("sw2", "sw3", SW2, 2, { root: SW2, cost: 0, age: 0 }, { time: 0.0003, parallel: true, lines: ["root = SW2?"] }),
            bpdu("sw3", "sw1", SW3, 1, { root: SW3, cost: 0, age: 0 }, { time: 0.0004, parallel: true, lines: ["root = SW3?"] }),
            bpdu("sw3", "sw2", SW3, 2, { root: SW3, cost: 0, age: 0 }, { time: 0.0005, parallel: true, lines: ["root = SW3?"] }),
          ],
        },
        {
          title: "SW1 wins",
          desc: "Better BPDUs win, worse ones go quiet",
          detail:
            "SW2 and SW3 each hear a BPDU naming SW1, which has a lower bridge ID than their own. They stop claiming to be root and accept SW1. From now on only the root starts new BPDUs, every 2 seconds (the hello time), always with a root path cost of 0.",
          facts: [["Root bridge", `SW1 (${SW1.mac})`], ["Root sends", "Hellos every 2 s"], ["Root path cost", "0 at the root"]],
          events: [
            bpdu("sw1", "sw2", SW1, 1, { root: SW1, cost: 0, age: 0 }, { time: 2.0, lines: ["root = SW1", "cost 0"] }),
            bpdu("sw1", "sw3", SW1, 2, { root: SW1, cost: 0, age: 0 }, { time: 2.0, parallel: true, lines: ["root = SW1", "cost 0"] }),
            note("sw1", "ROOT BRIDGE", "green"),
          ],
        },
        {
          title: "Pick a root port",
          desc: "Each switch keeps its cheapest way to the root",
          detail:
            `SW2 and SW3 each pick one root port: the port with the lowest total cost to the root. For both it is port 1, straight to SW1, cost ${COST}. They then pass the root’s BPDU on through their other ports, adding their own cost and about 1 s of message age.`,
          facts: [["SW2 root port", `Port 1, cost ${COST}`], ["SW3 root port", `Port 1, cost ${COST}`], ["Relayed cost", `${COST} (0 + one 1 Gb/s link)`]],
          quiz: {
            q: `SW2 could also reach SW1 through SW3. What would that path cost?`,
            options: [String(COST), String(COST * 2), "0", "It has no cost"],
            answer: 1,
            why: `Two 1 Gb/s links at ${COST} each make ${COST * 2}. The direct link costs ${COST}, so port 1 is the root port.`,
          },
          events: [
            note("sw2", "ROOT PORT: 1", "blue"),
            note("sw3", "ROOT PORT: 1", "blue"),
            bpdu("sw2", "sw3", SW2, 2, { ...ROOT1, cost: COST, age: 1 }, { time: 2.001, lines: ["root SW1", `cost ${COST}, from SW2`] }),
            bpdu("sw3", "sw2", SW3, 2, { ...ROOT1, cost: COST, age: 1 }, { time: 2.001, parallel: true, lines: ["root SW1", `cost ${COST}, from SW3`] }),
          ],
        },
        {
          title: "A tie on the last link",
          desc: "Lower bridge ID wins, the other port blocks",
          detail:
            `On the SW2–SW3 link both sides offer the root at cost ${COST}. To break the tie they compare bridge IDs. SW2 is lower, so SW2’s port 2 becomes the designated port for that link, and SW3’s port 2 is blocked. It drops user frames but keeps listening to BPDUs.`,
          facts: [["Designated", "SW2 port 2"], ["Blocked", "SW3 port 2"], ["Tie-breakers", "Cost, then bridge ID, then port ID"]],
          quiz: {
            q: "Which port blocks to break the loop?",
            options: ["SW1 port 2", "SW2 port 2", "SW3 port 2", "SW2 port 1"],
            answer: 2,
            why: "Both offer the same cost, so the switch with the higher bridge ID (SW3) loses and blocks its port on that link. Root ports and the root’s ports are never blocked.",
          },
          events: [
            note("sw3", "PORT 2 BLOCKED", "red"),
            bpdu("sw2", "sw3", SW2, 2, { ...ROOT1, cost: COST, age: 1 }, { time: 4.001, lines: ["hello", "still heard"] }),
          ],
        },
        {
          title: "30 seconds, then forward",
          desc: "Listening, learning, forwarding",
          detail:
            "Classic 802.1D makes each new forwarding port wait 15 s in listening and 15 s in learning (MAC addresses only), so a loop cannot form while BPDUs are still spreading. After that the laptop’s ping to the NAS flows SW2 → SW1 → SW3, around the blocked link. RSTP (802.1w) does the same job in about a second using handshakes between neighbours.",
          facts: [["Listening", "15 s"], ["Learning", "15 s"], ["Laptop → NAS path", "SW2 → SW1 → SW3"]],
          quiz: {
            q: "Why does the ping go through SW1 even though SW2 and SW3 have a direct cable?",
            options: ["SW1 is faster", "The direct cable goes through SW3’s blocked port", "Pings always go via the root", "The NAS asked for it"],
            answer: 1,
            why: "SW3 port 2 drops user frames, so the only open path between SW2 and SW3 is through the root.",
          },
          events: [
            note("sw2", "FORWARDING", "green"),
            pkt("client", "nas", "amber", "PING", ["via SW1", "around the block"], {
              time: 31.0, via: ["sw2", "sw1", "sw3"], info: PING_INFO(1), packet: ping(1),
            }),
          ],
        },
      ],
      outro: {
        title: "A loop-free tree",
        text: "The switches elected the lowest bridge ID as root, each picked its cheapest port towards it, and the one port that would close the loop was blocked. The spare link is still there, waiting, with BPDUs arriving every 2 seconds.",
        facts: [["Root", "SW1"], ["Root ports", "SW2 port 1, SW3 port 1"], ["Blocked", "SW3 port 2"], ["BPDU size", "35 bytes + 3 LLC"]],
      },
    },
    {
      id: "link-fail",
      name: "A link breaks, the blocked port takes over",
      summary: "The SW1–SW3 cable fails; a topology change is announced and SW3’s blocked port starts forwarding.",
      kind: "failure",
      steps: [
        {
          title: "The cable is cut",
          desc: "SW3 loses its root port",
          detail:
            "Someone unplugs the cable between SW1 and SW3. SW1’s next hello never reaches SW3. Both switches see the link go down at once, so they don’t have to wait 20 s (max age) for old information to expire.",
          facts: [["Failed link", "SW1 port 2 – SW3 port 1"], ["SW3 root port", "Gone"], ["Detected", "At once (link down)"]],
          quiz: {
            q: "Which port should SW3 now use to reach the root?",
            options: ["None, it is cut off", "Port 2, through SW2", "Port 3, through the NAS", "It becomes the root itself"],
            answer: 1,
            why: `Port 2 still hears BPDUs from SW2 saying the root is SW1 at cost ${COST}. Through it SW3 reaches the root at cost ${COST * 2}.`,
          },
          events: [
            bpdu("sw1", "sw3", SW1, 2, { ...ROOT1, cost: 0, age: 0 }, { time: 0, lost: true, color: "red", lines: ["link down"] }),
            note("sw3", "PORT 1 DOWN", "red"),
          ],
        },
        {
          title: "New root port",
          desc: "The blocked port becomes the way out",
          detail:
            `SW3 makes port 2 its new root port, at cost ${COST * 2}, using the BPDUs SW2 keeps sending. In classic 802.1D it must still go through listening and learning before forwarding. In RSTP this port was already marked as the alternate, so it would switch to forwarding almost at once.`,
          facts: [["New root port", "SW3 port 2"], ["Cost to root", `${COST * 2}`], ["State", "Listening (802.1D)"]],
          events: [
            bpdu("sw2", "sw3", SW2, 2, { ...ROOT1, cost: COST, age: 1 }, { time: 0.001, lines: ["root SW1", `cost ${COST}`] }),
            note("sw3", "ROOT PORT: 2 (LISTENING)", "amber"),
          ],
        },
        {
          title: "Tell the root",
          desc: "TCN up the tree, TCA back down",
          detail:
            "SW3 sends a tiny Topology Change Notification BPDU out of its root port. SW2 confirms it with the TCA flag and passes the notice up to SW1, which confirms it too. Only the root can announce a change to the whole network.",
          facts: [["TCN BPDU", "4 bytes, type 0x80"], ["Ack flag", "TCA (bit 7)"], ["Path", "SW3 → SW2 → SW1"]],
          quiz: {
            q: "Why does the notice go to the root instead of straight to every switch?",
            options: ["The root is the only one allowed to set the TC flag for everyone", "Other switches ignore BPDUs", "The root stores all MAC addresses", "It is faster"],
            answer: 0,
            why: "All BPDUs flow down the tree from the root. Getting the root to set TC in its hellos is the simplest way to reach every switch.",
          },
          events: [
            pkt("sw3", "sw2", "pink", "TCN", ["something changed"], { time: 0.002, proto: "STP", info: "Topology Change Notification", packet: tcnFrame(SW3, 2) }),
            bpdu("sw2", "sw3", SW2, 2, { ...ROOT1, cost: COST, age: 1, flags: 0x80 }, { time: 0.003, color: "green", label: "TCA", lines: ["got it"] }),
            pkt("sw2", "sw1", "pink", "TCN", ["passed up"], { time: 0.004, proto: "STP", info: "Topology Change Notification", packet: tcnFrame(SW2, 1) }),
            bpdu("sw1", "sw2", SW1, 1, { ...ROOT1, cost: 0, age: 0, flags: 0x80 }, { time: 0.005, color: "green", label: "TCA", lines: ["got it"] }),
          ],
        },
        {
          title: "TC flag everywhere",
          desc: "Forget old MAC entries quickly",
          detail:
            "For the next 35 s (max age plus forward delay) the root sets the TC flag in its hellos, and every switch passes it on. A switch that sees TC shortens its MAC table aging from 300 s to 15 s. Entries that point down the dead link vanish fast, so frames are not sent into a hole.",
          facts: [["Flags", "0x01 (TC)"], ["TC lasts", "35 s"], ["MAC aging", "300 s → 15 s"]],
          quiz: {
            q: "Why must switches flush MAC entries after a topology change?",
            options: ["To save memory", "Some devices are now reached through different ports, and old entries point the wrong way", "To make BPDUs smaller", "To reset the root election"],
            answer: 1,
            why: "SW1 still thinks the NAS is out of port 2, which is dead. Fast aging lets it relearn the NAS on port 1, via SW2.",
          },
          events: [
            bpdu("sw1", "sw2", SW1, 1, { ...ROOT1, cost: 0, age: 0, flags: 0x01 }, { time: 2.0, color: "pink", label: "BPDU TC", lines: ["topology changed"] }),
            bpdu("sw2", "sw3", SW2, 2, { ...ROOT1, cost: COST, age: 1, flags: 0x01 }, { time: 2.001, color: "pink", label: "BPDU TC", lines: ["passed on"] }),
            note("sw1", "FAST AGING 15 s", "amber"),
          ],
        },
        {
          title: "Port 2 forwards",
          desc: "The backup link carries traffic",
          detail:
            "After 15 s of listening and 15 s of learning, SW3 port 2 starts forwarding. The laptop’s pings now take the short way, SW2 → SW3, over the link that was blocked. When the broken cable comes back, the switches will run the same rules and block a port again.",
          facts: [["SW3 port 2", "Forwarding"], ["Outage (802.1D)", "About 30 s"], ["Outage (RSTP)", "Under 1 s"]],
          events: [
            note("sw3", "PORT 2 FORWARDING", "green"),
            pkt("client", "nas", "amber", "PING", ["via the backup link"], { time: 30.0, via: ["sw2", "sw3"], info: PING_INFO(31), packet: ping(31) }),
          ],
        },
      ],
      outro: {
        title: "The spare link saved the day",
        text: "When SW3 lost its root port, its blocked port became the new root port. A TCN told the root, the root’s TC flag made every switch flush old MAC entries, and after the forward delay timers the backup link carried traffic.",
        facts: [["Trigger", "Root port link down"], ["Messages", "TCN, TCA, TC"], ["Recovery time", "~30 s STP, <1 s RSTP"]],
      },
    },
    {
      id: "storm",
      name: "No spanning tree: a broadcast storm",
      summary: "With STP turned off, one ARP broadcast loops around the triangle forever and swamps every link.",
      kind: "failure",
      steps: [
        {
          title: "One innocent broadcast",
          desc: "The laptop asks: who has the NAS?",
          detail:
            "Someone has turned spanning tree off. The laptop sends a single ARP broadcast. SW2 floods it, as switches always do with broadcasts, out of every port except the one it came in on: to SW1 and to SW3.",
          facts: [["Destination", BROADCAST_MAC], ["STP", "Disabled"], ["Copies from SW2", "2"]],
          events: [
            pkt("client", "sw2", "blue", "ARP", ["who has .50?"], { time: 0, info: ARP_INFO, packet: arpReq() }),
            pkt("sw2", "sw1", "slate", "COPY", ["flooded"], { time: 0.00002, info: ARP_INFO, packet: arpReq() }),
            pkt("sw2", "sw3", "slate", "COPY", ["flooded"], { time: 0.00002, parallel: true, info: ARP_INFO, packet: arpReq() }),
          ],
        },
        {
          title: "Round and round",
          desc: "Each switch floods it again",
          detail:
            "SW1 floods its copy to SW3, and SW3 floods its copy to SW1 and the NAS. Each copy then comes back to SW2, which floods it again. The copies go round the triangle in both directions and never stop.",
          facts: [["Directions", "Clockwise and anticlockwise"], ["Ends when", "Never"], ["MAC table", "Laptop seen on many ports"]],
          quiz: {
            q: "An IP packet in a loop dies when its TTL reaches 0. Why doesn’t this frame die?",
            options: ["It is too small", "The Ethernet header has no TTL or hop count", "Switches renew the TTL", "ARP frames are protected"],
            answer: 1,
            why: "Ethernet has nothing like a TTL. A switch has no way to tell it has seen the frame before, so it floods it again forever.",
          },
          events: [
            pkt("sw1", "sw3", "red", "COPY", ["again"], { time: 0.00004, info: ARP_INFO, packet: arpReq() }),
            pkt("sw3", "sw1", "red", "COPY", ["again"], { time: 0.00004, parallel: true, info: ARP_INFO, packet: arpReq() }),
            pkt("sw3", "nas", "slate", "COPY", ["flooded"], { time: 0.00004, parallel: true, info: ARP_INFO, packet: arpReq() }),
            pkt("sw3", "sw2", "red", "COPY", ["back again"], { time: 0.00006, info: ARP_INFO, packet: arpReq() }),
            pkt("sw1", "sw2", "red", "COPY", ["back again"], { time: 0.00006, parallel: true, info: ARP_INFO, packet: arpReq() }),
            note("sw2", "MAC FLAPPING", "red"),
          ],
        },
        {
          title: "The network melts",
          desc: "Links full, CPUs busy, nothing works",
          detail:
            "Within a second the looping copies fill every link. Every device on the network must read every broadcast, so laptops and switch CPUs get swamped, and MAC tables change port constantly. Real traffic can’t get through. The fix is to turn spanning tree back on, or unplug a cable.",
          facts: [["Link use", "~100%"], ["Frames per second", "Hundreds of thousands"], ["Fix", "STP blocks one port"]],
          events: [
            pkt("sw2", "client", "red", "COPY", ["again and again"], { time: 0.5, info: ARP_INFO, packet: arpReq() }),
            pkt("sw2", "sw1", "red", "COPY", ["storm"], { time: 0.5, parallel: true, info: ARP_INFO, packet: arpReq() }),
            pkt("sw2", "sw3", "red", "COPY", ["storm"], { time: 0.5, parallel: true, info: ARP_INFO, packet: arpReq() }),
            note("sw1", "BROADCAST STORM", "red"),
          ],
        },
      ],
      outro: {
        title: "Why spanning tree exists",
        text: "Ethernet frames carry no hop count, so a single loop lets one broadcast multiply until the network stops. Spanning Tree keeps the spare cables but blocks just enough ports that frames can never come back round.",
        facts: [["Cause", "A loop and no STP"], ["Ethernet TTL", "None"], ["Defence", "STP/RSTP, BPDU guard, storm control"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Port roles",
      items: [["Root port", "Each switch’s best path to the root"], ["Designated port", "The one port per link that forwards towards the leaves"], ["Blocked / alternate", "Drops data, still listens to BPDUs"], ["Edge port (PortFast)", "Goes to a PC: forwards at once"]],
    },
    {
      title: "Election order",
      items: [["1", "Lowest root bridge ID"], ["2", "Lowest root path cost"], ["3", "Lowest sender bridge ID"], ["4", "Lowest sender port ID"]],
    },
    {
      title: "Numbers to know",
      items: [["Hello", "2 s"], ["Max age", "20 s"], ["Forward delay", "15 s (twice: listening, learning)"], ["Default priority", "32768, steps of 4096"], ["Cost (short)", "100 Mb/s = 19, 1 Gb/s = 4, 10 Gb/s = 2"]],
    },
    {
      title: "BPDU types and flags",
      items: [["0x00", "Configuration BPDU (35 bytes)"], ["0x80", "Topology Change Notification (4 bytes)"], ["0x02", "RST BPDU (RSTP, 36 bytes)"], ["Flag 0x01 / 0x80", "TC / TCA"]],
    },
  ],
});
