import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { inetChecksum } from "@/lib/bytes";
import { eth, ipv4, udp } from "@/lib/proto";
import { ADDR } from "./_common";

const STB = "192.168.1.40";
const STB_MAC = "a4:08:f5:3c:11:40";
const LAPTOP = ADDR.laptop;
const ROUTER = ADDR.router;
const ROUTER_MAC = ADDR.routerMac;
const HEADEND = "198.51.100.50";
const CH1 = "239.1.1.5";
const CH2 = "239.1.1.7";
const ALL_V3_ROUTERS = "224.0.0.22";
const ALL_HOSTS = "224.0.0.1";
const RTP_PORT = 5000;

/** Map an IPv4 multicast group to its Ethernet MAC: 01:00:5e + the low 23 bits. */
const mcastMac = (ip: string) => {
  const [, b, c, d] = ip.split(".").map(Number);
  return ["01", "00", "5e", (b & 0x7f).toString(16), c.toString(16), d.toString(16)].map((h) => h.padStart(2, "0")).join(":");
};

const ROUTER_ALERT = [0x94, 0x04, 0x00, 0x00];
const RA_NOTE = "Router Alert (option 148, length 4): tells every router to look inside this packet even though it isn't addressed to it.";

/** IGMP message with a correct checksum over the whole message. */
function igmpMsg(name: string, summary: string, type: number, second: FieldSpec, rest: FieldSpec[]): LayerSpec {
  const typeF: FieldSpec = { name: "Type", u8: type, value: `0x${type.toString(16)} (${name})` };
  const bytes = [type, ...field(second).bytes, 0, 0, ...rest.map(field).flatMap((f) => f.bytes)];
  const cs = inetChecksum(bytes);
  return proto({
    id: "igmp", name: "IGMPv3", osi: 3, ipProto: 2, summary: `Internet Group Management Protocol v3: ${summary}`,
    fields: [typeF, second, { name: "Checksum", u16: cs, value: `0x${cs.toString(16).padStart(4, "0")}`, note: "Covers the whole IGMP message." }, ...rest],
  });
}

const REC_TYPES: Record<number, string> = {
  1: "MODE_IS_INCLUDE", 2: "MODE_IS_EXCLUDE", 3: "CHANGE_TO_INCLUDE_MODE", 4: "CHANGE_TO_EXCLUDE_MODE", 5: "ALLOW_NEW_SOURCES", 6: "BLOCK_OLD_SOURCES",
};
const REC_NOTES: Record<number, string> = {
  2: "Answer to a query: I still want this group from any source.",
  3: "Include no sources at all: this is how IGMPv3 says “leave”.",
  4: "Exclude no sources = accept every source: this is a join.",
};

const record = (type: number, group: string): FieldSpec => ({
  name: `Group record: ${group}`,
  value: `${REC_TYPES[type]}, ${group}`,
  note: REC_NOTES[type],
  fields: [
    { name: "Record type", u8: type, value: `${type} (${REC_TYPES[type]})` },
    { name: "Aux data length", u8: 0 },
    { name: "Number of sources", u16: 0, note: "No source list: the meaning comes from the record type." },
    { name: "Multicast address", bytes: group.split(".").map(Number), value: group },
  ],
});

const report = (recs: [number, string][]) =>
  igmpMsg(
    "Membership Report", `Membership Report / ${recs.map(([t, g]) => `${REC_TYPES[t]} ${g}`).join(", ")}`, 0x22,
    { name: "Reserved", u8: 0 },
    [{ name: "Reserved", u16: 0 }, { name: "Number of group records", u16: recs.length }, ...recs.map(([t, g]) => record(t, g))],
  );

const query = (group: string, maxResp: number) =>
  igmpMsg(
    "Membership Query", group === "0.0.0.0" ? "Membership Query, general" : `Membership Query, specific for group ${group}`, 0x11,
    { name: "Max resp code", u8: maxResp, value: `${maxResp} (${maxResp / 10} s)`, note: "Answer within this time, in tenths of a second. Hosts pick a random delay up to it." },
    [
      { name: "Group address", bytes: group.split(".").map(Number), value: group === "0.0.0.0" ? "0.0.0.0 (general query: all groups)" : group },
      { name: "Resv, S, QRV", u8: 0x02, value: "S=0, QRV=2", note: "QRV is the robustness variable: how many times messages are repeated in case one is lost." },
      { name: "QQIC", u8: 125, value: "125 s", note: "Querier's query interval: the router asks again every 125 seconds." },
      { name: "Number of sources", u16: 0 },
    ],
  );

const igmpIp = (src: string, dst: string, id: number) =>
  ipv4({ src, dst, ttl: 1, dscp: 48, id, options: ROUTER_ALERT, optionNote: RA_NOTE });

const joinPkt = (recs: [number, string][], id: number) =>
  build(eth({ src: STB_MAC, dst: mcastMac(ALL_V3_ROUTERS) }), igmpIp(STB, ALL_V3_ROUTERS, id), report(recs));

const queryPkt = (group: string, maxResp: number, id: number) => {
  const dst = group === "0.0.0.0" ? ALL_HOSTS : group;
  return build(eth({ src: ROUTER_MAC, dst: mcastMac(dst) }), igmpIp(ROUTER, dst, id), query(group, maxResp));
};

/** One RTP packet carrying seven 188-byte MPEG transport stream packets. */
const rtp = (seq: number, ts: number): LayerSpec =>
  proto({
    id: "rtp", name: "RTP", osi: 7, summary: `Real-Time Transport Protocol, PT=MPEG-II transport streams, Seq=${seq}, Time=${ts}`,
    fields: [
      { name: "Version, P, X, CC", u8: 0x80, value: "2, no padding, no extension, 0 CSRCs" },
      { name: "Marker, payload type", u8: 33, value: "M=0, PT=33 (MP2T)", note: "33 means MPEG-2 transport stream: the usual format for TV channels." },
      { name: "Sequence number", u16: seq, note: "Goes up by one per packet, so the box can spot losses." },
      { name: "Timestamp", u32: ts, note: "90 kHz clock, used to play the video at the right pace." },
      { name: "SSRC", u32: 0x1f2e3d4c, value: "0x1f2e3d4c", note: "Identifies this stream's sender." },
      {
        name: "MPEG-TS packets", value: "7 × 188 bytes", note: "Seven transport stream packets fill one 1316-byte payload, the usual IPTV packing.",
        fields: Array.from({ length: 7 }, (_, i) => ({
          name: `TS packet ${i + 1}`, value: "188 bytes",
          fields: [{ name: "Sync byte", u8: 0x47, value: "0x47", note: "Every TS packet starts with 0x47." }, { name: "Video/audio data", random: 187, opaque: true, seed: 300 + i + seq }],
        })),
      },
    ],
  });

const stream = (group: string, seq: number, ts: number, dst = STB_MAC) =>
  build(eth({ src: ROUTER_MAC, dst: dst === STB_MAC ? mcastMac(group) : dst }), ipv4({ src: HEADEND, dst: group, ttl: 58, dscp: 32, df: false, id: seq & 0xffff }), udp({ sport: RTP_PORT, dport: RTP_PORT }), rtp(seq, ts));

const devices: Device[] = [
  { id: "stb", kind: "tv", label: "Set-top box", sub: STB, x: 8, y: 30 },
  { id: "laptop", kind: "laptop", label: "Laptop", sub: LAPTOP, x: 8, y: 78 },
  { id: "switch", kind: "switch", label: "Switch", sub: "IGMP snooping on", x: 32, y: 55 },
  { id: "router", kind: "router", label: "ISP router", sub: `${ROUTER} (querier)`, x: 60, y: 55 },
  { id: "headend", kind: "server", label: "IPTV head-end", sub: HEADEND, x: 90, y: 30 },
];
const links: [string, string][] = [["stb", "switch"], ["laptop", "switch"], ["switch", "router"], ["router", "headend"]];

const floodDevices: Device[] = [
  ...devices.map((d) => (d.id === "switch" ? { ...d, sub: "IGMP snooping off" } : d)),
  { id: "printer", kind: "printer", label: "Printer", sub: "192.168.1.60", x: 40, y: 85 },
];
const floodLinks: [string, string][] = [...links, ["switch", "printer"]];

export default defineLesson({
  id: "igmp",
  name: "IGMP",
  full: "Internet Group Management Protocol (IPTV multicast)",
  group: "realtime",
  layer: 3,
  difficulty: 2,
  tagline: "How a TV box tells the network which channel to send it.",
  description:
    "IPTV sends each channel once as a multicast stream, and the network copies it only towards homes that are watching. IGMP is how a set-top box says “I want channel 239.1.1.5” or “I'm done with it” to its local router. The router checks every couple of minutes who is still watching, and stops a stream nobody wants.",
  facts: [
    ["Layer", "Network (Layer 3)"],
    ["IP protocol", "2"],
    ["Reports go to", "224.0.0.22 (IGMPv3)"],
    ["Queries go to", "224.0.0.1 (all hosts)"],
    ["TTL", "1, with Router Alert option"],
    ["Defined in", "RFC 3376 (IGMPv3)"],
  ],
  ports: "None (IP protocol 2); streams on UDP, e.g. 5000",
  rfc: "RFC 3376",
  keywords: ["igmp", "multicast", "iptv", "join", "leave", "query", "snooping", "224.0.0.22", "239", "rtp", "mpeg-ts"],
  related: ["rtp", "udp", "ip", "ethernet", "pim"],
  devices,
  links,
  legend: [
    ["blue", "IGMP reports (join, leave, still here)"],
    ["slate", "Queries from the router"],
    ["pink", "Multicast TV stream"],
    ["red", "Unwanted flooding"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Watch a channel, then switch",
      summary: "The set-top box joins a TV channel, answers the router's periodic check, and switches channels by leaving one group and joining another.",
      kind: "normal",
      steps: [
        {
          title: "Join a channel",
          desc: "IGMPv3 Membership Report to 224.0.0.22",
          detail:
            `You pick channel 1 on the remote. Channel 1 is the multicast group ${CH1}, so the box sends an IGMPv3 Membership Report with one group record: CHANGE_TO_EXCLUDE_MODE with no sources, which means “send me ${CH1} from anyone”. It goes to ${ALL_V3_ROUTERS}, the address every IGMPv3 router listens on, with TTL 1 so it never leaves the local network.`,
          facts: [["Group", `${CH1} (channel 1)`], ["Sent to", `${ALL_V3_ROUTERS}, MAC ${mcastMac(ALL_V3_ROUTERS)}`], ["IP options", "Router Alert (94 04 00 00)"]],
          quiz: {
            q: "Why is the TTL of an IGMP message set to 1?",
            options: ["To save bandwidth", "IGMP only talks to the local router; it must never be forwarded further", "TTL 1 means high priority", "Routers ignore TTL for IGMP"],
            answer: 1,
            why: "IGMP is a conversation between hosts and their first router. TTL 1 guarantees no router passes it on.",
          },
          events: [
            pkt("stb", "router", "blue", "JOIN", [CH1, "to 224.0.0.22"], {
              time: 0, info: `Membership Report / Join group ${CH1} for any sources`,
              packet: joinPkt([[4, CH1]], 0x0001),
            }),
          ],
        },
        {
          title: "The stream starts",
          desc: "UDP/RTP to the group address",
          detail:
            `The router adds the box's network to its list for ${CH1} and, if it isn't already receiving that channel, asks upstream for it (with PIM). Packets start flowing: UDP to ${CH1}, port ${RTP_PORT}, each carrying an RTP header and seven 188-byte MPEG-TS packets. An HD channel is about 8 Mbit/s, roughly 750 of these packets a second.`,
          facts: [["Destination", `${CH1}:${RTP_PORT}`], ["Ethernet dst", mcastMac(CH1)], ["Payload", "RTP + 7 × 188-byte TS"]],
          quiz: {
            q: `What destination MAC does a frame for group ${CH1} use?`,
            options: ["ff:ff:ff:ff:ff:ff", `The set-top box's own MAC`, mcastMac(CH1), "01:00:5e:00:00:01"],
            answer: 2,
            why: "IPv4 multicast MACs are 01:00:5e followed by the low 23 bits of the group address: 1.1.5 → 01:01:05.",
          },
          events: [
            pkt("headend", "stb", "pink", "RTP", [CH1, "channel 1"], {
              time: 0.012, info: `PT=MPEG-II transport streams, SSRC=0x1F2E3D4C, Seq=40112, Time=1800000`,
              packet: stream(CH1, 40112, 1800000),
            }),
            pkt("headend", "stb", "pink", "RTP", [CH1, "next packet"], {
              time: 0.0133, info: `PT=MPEG-II transport streams, SSRC=0x1F2E3D4C, Seq=40113, Time=1800117`,
              packet: stream(CH1, 40113, 1800117),
            }),
            note("stb", "CHANNEL 1 PLAYING", "green"),
          ],
        },
        {
          title: "Is anyone still watching?",
          desc: "General Query to 224.0.0.1",
          detail:
            `Every 125 seconds the router, acting as the querier, sends a General Query to ${ALL_HOSTS}, the all-hosts group. Every multicast-capable device receives it. Group address 0.0.0.0 means “tell me about every group you want”. Max resp code 100 gives everyone up to 10 seconds to answer.`,
          facts: [["Sent to", `${ALL_HOSTS} (all hosts)`], ["Max response", "10 s"], ["Interval", "125 s"]],
          events: [
            pkt("router", "stb", "slate", "QUERY", ["general", "who wants what?"], {
              time: 125.0, info: "Membership Query, general",
              packet: queryPkt("0.0.0.0", 100, 0x2001),
            }),
            pkt("router", "laptop", "slate", "QUERY", ["general"], {
              time: 125.0, parallel: true, info: "Membership Query, general",
              packet: queryPkt("0.0.0.0", 100, 0x2001),
            }),
            note("laptop", "NOT IN ANY GROUP: SILENT", "blue"),
          ],
        },
        {
          title: "Yes, still here",
          desc: "Report: MODE_IS_EXCLUDE",
          detail:
            `The box waits a random time (here 3.4 s) so that many boxes don't answer at once, then reports its current state: MODE_IS_EXCLUDE for ${CH1}, meaning “still want it from any source”. The router resets its timer for the group.`,
          facts: [["Record type", "2 (MODE_IS_EXCLUDE)"], ["Random delay", "3.4 s"], ["Timer", "Reset to 260 s"]],
          quiz: {
            q: "If the box had been switched off, how long until the router stops the stream?",
            options: ["At once", "About 260 s (2 queries × 125 s + 10 s)", "Never", "One day"],
            answer: 1,
            why: "The group membership interval is robustness × query interval + max response time: 2 × 125 + 10 = 260 seconds.",
          },
          events: [
            pkt("stb", "router", "blue", "REPORT", ["still want", CH1], {
              time: 128.4, info: `Membership Report / Report state of group ${CH1}: exclude no sources`,
              packet: joinPkt([[2, CH1]], 0x0002),
            }),
          ],
        },
        {
          title: "Switch channels",
          desc: "Leave one group, join another, in one report",
          detail:
            `You press channel up. The box sends one report with two records: CHANGE_TO_INCLUDE_MODE with no sources for ${CH1} (leave) and CHANGE_TO_EXCLUDE_MODE for ${CH2} (join). The new channel starts arriving within milliseconds, which is why IPTV channel changes feel quick.`,
          facts: [["Leave", `${CH1} (record type 3)`], ["Join", `${CH2} (record type 4)`], ["Records", "2 in one message"]],
          events: [
            pkt("stb", "router", "blue", "ZAP", [`leave ${CH1}`, `join ${CH2}`], {
              time: 200.0, info: `Membership Report / Leave group ${CH1} / Join group ${CH2} for any sources`,
              packet: joinPkt([[3, CH1], [4, CH2]], 0x0003),
            }),
            pkt("headend", "stb", "pink", "RTP", [CH2, "channel 2"], {
              time: 200.018, info: `PT=MPEG-II transport streams, SSRC=0x1F2E3D4C, Seq=9051, Time=36000000`,
              packet: stream(CH2, 9051, 36000000),
            }),
          ],
        },
        {
          title: "Last one out?",
          desc: "Group-specific query, then silence",
          detail:
            `Before stopping ${CH1}, the router checks that nobody else on this network still watches it. It sends a query just for ${CH1}, twice, one second apart. Nobody answers, so the router stops forwarding channel 1 here and tells upstream it no longer needs it.`,
          facts: [["Query to", CH1], ["Max response", "1 s"], ["Then", "Stream 1 stops"]],
          quiz: {
            q: "Why doesn't the router stop channel 1 the moment it hears the leave?",
            options: ["It is slow", "Another device on the same network might still be watching it", "Leaves are often forged", "The stream must finish its current show"],
            answer: 1,
            why: "Reports from other members may have been suppressed or not sent yet, so the router asks specifically about that group before cutting it.",
          },
          events: [
            pkt("router", "stb", "slate", "QUERY", [`only ${CH1}`, "anyone?"], {
              time: 200.019, info: `Membership Query, specific for group ${CH1}`,
              packet: queryPkt(CH1, 10, 0x2002),
            }),
            pkt("router", "stb", "slate", "QUERY", [`only ${CH1}`, "again"], {
              time: 201.019, info: `Membership Query, specific for group ${CH1}`,
              packet: queryPkt(CH1, 10, 0x2003),
            }),
            note("router", `${CH1} STOPPED`, "blue"),
          ],
        },
      ],
      outro: {
        title: "Only the channels being watched",
        text: "The box joined a group with a report, kept it alive by answering the router's queries, and changed channel with a single report that left one group and joined another. The router forwards each channel only where someone wants it.",
        facts: [["Join / leave", "Membership Report to 224.0.0.22"], ["Keep-alive", "General Query every 125 s"], ["Channel change", "One report, two records"], ["Stream", "RTP over UDP to 239.x.x.x"]],
      },
    },
    {
      id: "snooping-off",
      name: "Snooping off: TV floods the LAN",
      summary: "A switch without IGMP snooping treats multicast like broadcast and sends the 8 Mbit/s channel out of every port.",
      kind: "failure",
      devices: floodDevices,
      links: floodLinks,
      steps: [
        {
          title: "The box joins as usual",
          desc: "Same report, but the switch isn't listening",
          detail:
            "The set-top box sends the same join report. This cheaper switch has IGMP snooping turned off, so it does not read IGMP at all. It just forwards the report to the router like any other frame.",
          facts: [["Group", CH1], ["Switch", "Snooping off"], ["Router", "Starts the stream"]],
          events: [
            pkt("stb", "router", "blue", "JOIN", [CH1], {
              time: 0, info: `Membership Report / Join group ${CH1} for any sources`,
              packet: joinPkt([[4, CH1]], 0x0011),
            }),
          ],
        },
        {
          title: "Flooded everywhere",
          desc: "Multicast treated like broadcast",
          detail:
            `When the stream arrives, the switch has no table saying which port wants ${mcastMac(CH1)}. A plain switch handles unknown multicast like broadcast and sends it out of every port. The laptop and the printer now each receive 8 Mbit/s of TV they never asked for. Their network cards drop it, but on Wi-Fi it can choke the whole network.`,
          facts: [["Copies", "Every port"], ["Wasted", "8 Mbit/s per idle device"], ["Worst on", "Wi-Fi access points"]],
          quiz: {
            q: "How does an IGMP-snooping switch know which port wants the stream?",
            options: ["It asks the router", "It listens to the IGMP reports passing through it and notes their ports", "It reads the RTP header", "The set-top box registers with the switch by DHCP"],
            answer: 1,
            why: "Snooping means peeking at IGMP joins and leaves on their way to the router, and building a group-to-port table from them.",
          },
          events: [
            pkt("headend", "stb", "red", "RTP", [CH1, "wanted"], {
              time: 0.012, info: `PT=MPEG-II transport streams, SSRC=0x1F2E3D4C, Seq=40112, Time=1800000`,
              packet: stream(CH1, 40112, 1800000),
            }),
            pkt("switch", "laptop", "red", "RTP", [CH1, "not wanted"], {
              time: 0.012, parallel: true, info: `PT=MPEG-II transport streams, SSRC=0x1F2E3D4C, Seq=40112, Time=1800000`,
              packet: stream(CH1, 40112, 1800000),
            }),
            pkt("switch", "printer", "red", "RTP", [CH1, "not wanted"], {
              time: 0.012, parallel: true, info: `PT=MPEG-II transport streams, SSRC=0x1F2E3D4C, Seq=40112, Time=1800000`,
              packet: stream(CH1, 40112, 1800000),
            }),
            note("switch", "FLOODING 8 MBIT/S", "red"),
          ],
        },
        {
          title: "Turn snooping on",
          desc: "The switch learns from the next report",
          detail:
            `With IGMP snooping enabled, the switch reads the box's next report and records “${CH1} wanted on the set-top box port”. From then on it sends channel 1 only there. The laptop and printer go quiet again.`,
          facts: [["Learned", `${CH1} → set-top box port`], ["Laptop, printer", "No more stream"], ["Router port", "Always gets reports"]],
          events: [
            pkt("stb", "router", "blue", "REPORT", ["still want", CH1], {
              time: 30.0, info: `Membership Report / Report state of group ${CH1}: exclude no sources`,
              packet: joinPkt([[2, CH1]], 0x0012),
            }),
            note("switch", `${CH1} → PORT 1 ONLY`, "green"),
            pkt("headend", "stb", "pink", "RTP", [CH1, "only here"], {
              time: 30.012, info: `PT=MPEG-II transport streams, SSRC=0x1F2E3D4C, Seq=62611, Time=4500000`,
              packet: stream(CH1, 62611, 4500000),
            }),
          ],
        },
      ],
      outro: {
        title: "Snooping keeps multicast on a leash",
        text: "Without IGMP snooping a switch floods multicast to every port, wasting bandwidth on every device. With snooping it reads the joins and leaves itself and sends each stream only to ports that asked for it.",
        facts: [["Snooping off", "Flood to all ports"], ["Snooping on", "Only member ports + router port"], ["Needs", "A querier on the network"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Message types",
      items: [["0x11", "Membership Query (general or group-specific)"], ["0x22", "IGMPv3 Membership Report"], ["0x16", "IGMPv2 Report (older)"], ["0x17", "IGMPv2 Leave Group (older)"]],
    },
    {
      title: "Group record types",
      items: [["1 / 2", "MODE_IS_INCLUDE / EXCLUDE (answers)"], ["3", "CHANGE_TO_INCLUDE (no sources = leave)"], ["4", "CHANGE_TO_EXCLUDE (no sources = join)"], ["5 / 6", "ALLOW_NEW / BLOCK_OLD sources"]],
    },
    {
      title: "Addresses and numbers",
      items: [["224.0.0.1", "All hosts (queries)"], ["224.0.0.22", "All IGMPv3 routers (reports)"], ["239.0.0.0/8", "Organisation-local groups (IPTV)"], ["MAC", "01:00:5e + low 23 bits"], ["Query interval", "125 s"], ["Router Alert", "IP option 94 04 00 00"]],
    },
  ],
});
