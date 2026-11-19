import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build } from "@/lib/packet";
import { arp, BROADCAST_MAC, eth, icmp, ipv4 } from "@/lib/proto";
import { Bytes, u32le } from "@/lib/bytes";
import { ADDR } from "./_common";

const LAPTOP = ADDR.laptop;
const HOME = ADDR.router;
const ISP = "198.51.100.1";
const CORE = "203.0.113.1";
const S = ADDR.web;
const DEAD = "203.0.113.99";

const L2 = { src: ADDR.laptopMac, dst: ADDR.routerMac };
const L2back = { src: ADDR.routerMac, dst: ADDR.laptopMac };
const CORE_MAC = "5c:5e:ab:20:00:02";

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: LAPTOP, x: 8, y: 64 },
  { id: "router", kind: "router", label: "Home router", sub: HOME, x: 28, y: 64 },
  { id: "isp", kind: "isp", label: "ISP router", sub: ISP, x: 48, y: 30 },
  { id: "core", kind: "router", label: "Core router", sub: CORE, x: 69, y: 64 },
  { id: "server", kind: "web", label: "Web server", sub: S, x: 91, y: 36 },
];
const links: [string, string][] = [["client", "router"], ["router", "isp"], ["isp", "core"], ["core", "server"]];

/** Linux ping payload: 16-byte timestamp then counting bytes 0x10.. (56 bytes by default) */
const pingData = (sec: number, usec: number, len = 56): Bytes => {
  const out: Bytes = [...u32le(sec), 0, 0, 0, 0, ...u32le(usec), 0, 0, 0, 0];
  for (let i = 16; i < len; i++) out.push(i);
  return out;
};
/** traceroute -I payload: 32 bytes 0x40, 0x41, ... */
const traceData: Bytes = Array.from({ length: 32 }, (_, i) => 0x40 + i);

const PING_ID = 0x1a2b;
const TR_ID = 0x4d10;
const T0 = 1763548800;

const echo = (type: 0 | 8, id: number, seq: number, data: Bytes) =>
  icmp({
    type, name: type === 8 ? "Echo (ping) request" : "Echo (ping) reply",
    restFields: [
      { name: "Identifier", u16: id, value: `0x${id.toString(16)}`, note: "Picked by the ping program so it can match replies to itself." },
      { name: "Sequence number", u16: seq, note: "Counts up by one per ping, so lost ones show as gaps." },
    ],
    data, dataName: "Data", dataNote: type === 8 ? "Whatever the sender likes. ping puts a timestamp first so it can work out the round-trip time." : "Copied back unchanged from the request.",
  });

const req = (seq: number, time: number, usec: number) =>
  pkt("client", "server", "amber", "ECHO REQ", [`seq=${seq}`, "are you there?"], {
    time, info: `Echo (ping) request id=0x${PING_ID.toString(16)}, seq=${seq}/${seq << 8}, ttl=64`,
    packet: build(eth(L2), ipv4({ src: LAPTOP, dst: S, ttl: 64, id: 0x6100 + seq }), echo(8, PING_ID, seq, pingData(T0 + seq - 1, usec))),
  });
const rep = (seq: number, time: number, usec: number) =>
  pkt("server", "client", "green", "ECHO REPLY", [`seq=${seq}`, "yes!"], {
    time, info: `Echo (ping) reply id=0x${PING_ID.toString(16)}, seq=${seq}/${seq << 8}, ttl=61`,
    packet: build(eth(L2back), ipv4({ src: S, dst: LAPTOP, ttl: 61, id: 0xc200 + seq, df: false }), echo(0, PING_ID, seq, pingData(T0 + seq - 1, usec))),
  });

// ---------------------------------------------------------------- traceroute
const probe = (ttl: number, seq: number, to: string, time: number) =>
  pkt("client", to, "amber", "PROBE", [`TTL ${ttl}`], {
    time, info: `Echo (ping) request id=0x${TR_ID.toString(16)}, seq=${seq}/${seq << 8}, ttl=${ttl}`,
    packet: build(eth(L2), ipv4({ src: LAPTOP, dst: S, ttl, id: 0x7000 + seq, df: false }), echo(8, TR_ID, seq, traceData)),
  });
const quoteProbe = (seq: number) =>
  build(ipv4({ src: LAPTOP, dst: S, ttl: 1, id: 0x7000 + seq, df: false }), echo(8, TR_ID, seq, traceData)).bytes.slice(0, 28);
const timeExceeded = (from: string, fromIp: string, ttlSeen: number, seq: number, time: number) =>
  pkt(from, "client", "blue", "TTL EXCEEDED", [`from ${fromIp}`], {
    time, info: "Time-to-live exceeded (Time to live exceeded in transit)",
    packet: build(
      eth(L2back),
      ipv4({ src: fromIp, dst: LAPTOP, ttl: ttlSeen, id: 0x1e00 + seq, df: false, dscp: 48 }),
      icmp({
        type: 11, code: 0, name: "Time-to-live exceeded",
        data: quoteProbe(seq), dataName: "Original packet (start)",
        dataNote: "The probe’s IP header (TTL 1 when it died) and its first 8 ICMP bytes, including the identifier and sequence number traceroute uses to match it.",
      })
    ),
  });

const t = (n: number) => Number(n.toFixed(4));

const failDevices: Device[] = [
  ...devices,
  { id: "dead", kind: "server", label: "Old server (off)", sub: DEAD, x: 90, y: 80 },
];
const failLinks: [string, string][] = [...links, ["core", "dead"]];

export default defineLesson({
  id: "icmp",
  name: "ICMP",
  full: "Internet Control Message Protocol",
  group: "foundations",
  layer: 3,
  difficulty: 1,
  tagline: "The internet’s error messages, and the tool behind ping.",
  description:
    "ICMP is how routers and hosts report problems with IP packets: “too many hops”, “can’t reach that host”, “packet too big”. It also has a simple echo request and reply, which ping uses to test whether a host answers and how long it takes. Traceroute builds on the error messages to map the path.",
  facts: [
    ["Layer", "Network (Layer 3), rides inside IP"],
    ["IP protocol", "1"],
    ["Header", "8 bytes"],
    ["Common types", "0 reply, 3 unreachable, 8 request, 11 time exceeded"],
    ["Tools", "ping, traceroute / tracert"],
    ["Defined in", "RFC 792"],
  ],
  ports: "None: identified by IP protocol 1",
  rfc: "RFC 792",
  keywords: ["ping", "traceroute", "tracert", "echo", "time exceeded", "destination unreachable", "rtt", "firewall"],
  related: ["ip", "udp", "ipv6", "tcp"],
  devices,
  links,
  legend: [
    ["amber", "Requests and probes from the laptop"],
    ["green", "Echo replies"],
    ["blue", "ICMP errors from routers"],
    ["red", "Failures and drops"],
  ],
  scenarios: [
    {
      id: "ping",
      name: "ping example.com",
      summary: "Three echo requests and three replies measure whether the server answers and how fast.",
      kind: "normal",
      steps: [
        {
          title: "Echo request",
          desc: "Type 8, id 0x1a2b, seq 1, 56 bytes of data",
          detail:
            "ping sends an ICMP Echo Request: type 8, code 0, an identifier that marks this ping run, and sequence number 1. The 56 data bytes start with the send time, which ping reads back from the reply to measure the round trip.",
          facts: [["Type / code", "8 / 0"], ["Size", "56 data + 8 ICMP + 20 IP = 84 bytes"], ["Identifier", "0x1a2b"]],
          events: [req(1, 0, 104211)],
        },
        {
          title: "Echo reply",
          desc: "Type 0, same id, same seq, same data",
          detail:
            "The server’s operating system answers by itself; no program has to be running. It turns the message into type 0, swaps the addresses and sends back the very same identifier, sequence number and data. ping matches the identifier and prints the time.",
          facts: [["Type / code", "0 / 0"], ["Round trip", "24.1 ms"], ["TTL seen", "61 (3 routers away)"]],
          quiz: {
            q: "How does ping know this reply belongs to its own request?",
            options: ["By the TTL", "By the identifier and sequence number", "By the reply’s size alone", "By the server’s MAC address"],
            answer: 1,
            why: "The reply copies the identifier and sequence number. The identifier picks out this ping run; the sequence number says which request it answers.",
          },
          events: [rep(1, 0.0241, 104211)],
        },
        {
          title: "Once a second",
          desc: "seq 2 and 3 follow",
          detail:
            "ping keeps sending one request per second, with the sequence number going up each time. A missing number in the replies means that request or its reply was lost. The round-trip times wobble a little because router queues change.",
          facts: [["Interval", "1 second"], ["seq 2", "23.8 ms"], ["seq 3", "25.0 ms"]],
          events: [req(2, 1.0, 105033), rep(2, 1.0238, 105033), req(3, 2.0, 104870), rep(3, 2.025, 104870)],
        },
        {
          title: "The summary",
          desc: "3 sent, 3 received, 0% loss",
          detail:
            "When you press Ctrl+C, ping prints how many replies came back and the minimum, average and maximum round-trip time. That answers two questions at once: is the host reachable, and how far away is it in time.",
          facts: [["Loss", "0%"], ["rtt min/avg/max", "23.8 / 24.3 / 25.0 ms"], ["Bytes per ping", "98 on the wire"]],
          quiz: {
            q: "ping shows 3 sent, 2 received. What can you say?",
            options: ["The server is down", "One request or its reply was lost", "The server refused one ping", "DNS failed"],
            answer: 1,
            why: "ICMP is not resent, so a missing reply just means one of the two packets was lost on the way. A down server would answer none.",
          },
          events: [note("client", "3 SENT, 3 RECEIVED", "green")],
        },
      ],
      outro: {
        title: "Reachable, 24 ms away",
        text: "ping used just two ICMP types: echo request and echo reply. The identifier, sequence number and timestamp in the data are all it needs to find loss and measure the round trip.",
        facts: [["Types used", "8 and 0"], ["Data size", "56 bytes"], ["Average RTT", "24.3 ms"]],
      },
    },
    {
      id: "traceroute",
      name: "traceroute: map the path",
      summary: "Probes with TTL 1, 2, 3 make each router on the way reveal itself with Time Exceeded.",
      kind: "normal",
      steps: [
        {
          title: "TTL 1",
          desc: "Dies at the first router",
          detail:
            "traceroute sends a probe with TTL 1. The home router lowers it to 0, must drop it, and sends back ICMP Time Exceeded from its own address. Now the laptop knows hop 1. Real traceroute sends three probes per hop; one is shown here.",
          facts: [["Probe", "Echo request, TTL 1"], ["Answer from", `${HOME} (hop 1)`], ["Time", "0.9 ms"]],
          quiz: {
            q: "Which address does the Time Exceeded come from?",
            options: ["The web server", "The home router", "The laptop", "The ISP’s DNS server"],
            answer: 1,
            why: "The router where TTL hits zero sends the error from its own address. That address is what traceroute prints for the hop.",
          },
          events: [probe(1, 1, "router", 0), timeExceeded("router", HOME, 64, 1, 0.0009)],
        },
        {
          title: "TTL 2",
          desc: "One router further",
          detail:
            "The next probe has TTL 2. The home router lowers it to 1 and forwards it; the ISP router lowers it to 0 and reports back. The reply crosses one router on the way home, so it arrives with TTL 63.",
          facts: [["Probe", "TTL 2"], ["Answer from", `${ISP} (hop 2)`], ["Time", "8.2 ms"]],
          events: [probe(2, 4, "isp", 0.01), timeExceeded("isp", ISP, 63, 4, 0.0182)],
        },
        {
          title: "TTL 3",
          desc: "The core router reveals itself",
          detail:
            "With TTL 3 the probe gets as far as the core router before it runs out. Each hop’s time is a full round trip to that router, so the numbers grow as the probes go further.",
          facts: [["Probe", "TTL 3"], ["Answer from", `${CORE} (hop 3)`], ["Time", "17.6 ms"]],
          quiz: {
            q: "What will the probe with TTL 4 get back?",
            options: ["Another Time Exceeded", "An Echo Reply from the server", "Nothing, TTL 4 is too high", "A TCP RST"],
            answer: 1,
            why: "The server is 4 hops away, so TTL 4 is just enough. The probe reaches the server, which answers the echo request normally, and traceroute stops.",
          },
          events: [probe(3, 7, "core", 0.03), timeExceeded("core", CORE, 62, 7, 0.0476)],
        },
        {
          title: "TTL 4 reaches the server",
          desc: "An echo reply ends the trace",
          detail:
            "The fourth probe survives all three routers and reaches the server, which answers with a normal echo reply. traceroute sees the destination answer and prints the finished list of hops.",
          facts: [["Answer", "Echo reply from server"], ["Hops", "4"], ["Time", "24.0 ms"]],
          events: [
            probe(4, 10, "server", 0.06),
            pkt("server", "client", "green", "ECHO REPLY", ["destination!"], {
              time: t(0.084), info: `Echo (ping) reply id=0x${TR_ID.toString(16)}, seq=10/2560, ttl=61`,
              packet: build(eth(L2back), ipv4({ src: S, dst: LAPTOP, ttl: 61, id: 0xc301, df: false }), echo(0, TR_ID, 10, traceData)),
            }),
            note("client", "TRACE COMPLETE: 4 HOPS", "green"),
          ],
        },
      ],
      outro: {
        title: "The path, hop by hop",
        text: "traceroute turned a safety feature into a map. By raising the TTL one step at a time, it made every router on the path send a Time Exceeded message from its own address. Windows tracert works the same way with echo requests; Linux traceroute uses UDP probes by default.",
        facts: [["Hop 1", HOME], ["Hop 2", ISP], ["Hop 3", CORE], ["Hop 4", `${S} (done)`]],
      },
    },
    {
      id: "unreachable",
      name: "No reply: unreachable host and a firewall",
      summary: "One ping gets Destination Host Unreachable; another gets nothing because a firewall drops it.",
      kind: "failure",
      devices: failDevices,
      links: failLinks,
      steps: [
        {
          title: "Ping a switched-off host",
          desc: "The last router can’t find it",
          detail:
            "The laptop pings 203.0.113.99, an old server that has been switched off. The request reaches the core router, which is directly connected to that network. It asks with ARP for the host’s MAC address, but nobody answers.",
          facts: [["Target", DEAD], ["ARP tries", "3, one per second"], ["Answer", "None"]],
          events: [
            pkt("client", "core", "amber", "ECHO REQ", [`to ${DEAD}`], {
              time: 0, info: `Echo (ping) request id=0x${PING_ID.toString(16)}, seq=1/256, ttl=64`,
              packet: build(eth(L2), ipv4({ src: LAPTOP, dst: DEAD, ttl: 64, id: 0x6201 }), echo(8, PING_ID, 1, pingData(T0, 300112))),
            }),
            pkt("core", "dead", "blue", "ARP", [`who has ${DEAD}?`], {
              time: 0.014, lost: true, info: `Who has ${DEAD}? Tell ${CORE}`,
              packet: build(eth({ src: CORE_MAC, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: CORE_MAC, senderIp: CORE, targetIp: DEAD })),
            }),
            note("core", "ARP: NO ANSWER", "amber"),
          ],
        },
        {
          title: "Host unreachable",
          desc: "ICMP type 3, code 1",
          detail:
            "After about three seconds of silence the core router gives up and drops the ping. It sends ICMP Destination Unreachable, code 1 (host unreachable), quoting the start of the ping. ping prints “From 203.0.113.1 icmp_seq=1 Destination Host Unreachable”.",
          facts: [["ICMP", "Type 3, code 1"], ["From", `${CORE} (core router)`], ["After", "About 3 s"]],
          quiz: {
            q: "Who sends the Destination Unreachable message?",
            options: ["The switched-off host", "The router that could not deliver it", "The laptop to itself", "The home router"],
            answer: 1,
            why: "The host is off and can’t say anything. The last router, which failed to find it with ARP, reports the problem.",
          },
          events: [
            pkt("core", "client", "red", "UNREACH", ["host unreachable", `from ${CORE}`], {
              time: 3.015, info: "Destination unreachable (Host unreachable)",
              packet: build(
                eth(L2back),
                ipv4({ src: CORE, dst: LAPTOP, ttl: 62, id: 0x2a10, df: false, dscp: 48 }),
                icmp({
                  type: 3, code: 1, name: "Destination unreachable (Host unreachable)",
                  data: build(ipv4({ src: LAPTOP, dst: DEAD, ttl: 62, id: 0x6201 }), echo(8, PING_ID, 1, pingData(T0, 300112))).bytes.slice(0, 28),
                  dataName: "Original packet (start)", dataNote: "The IP header and first 8 bytes of the ping that could not be delivered.",
                })
              ),
            }),
            note("client", "DESTINATION HOST UNREACHABLE", "red"),
          ],
        },
        {
          title: "Ping a firewalled server",
          desc: "Silence: request timed out",
          detail:
            "Next the laptop pings the web server. Its firewall is set to drop ICMP echo requests without a word. No reply and no error come back, so ping just waits and reports a timeout. Yet the website on port 443 works fine.",
          facts: [["Target", S], ["Firewall rule", "Drop ICMP echo"], ["ping says", "Request timed out"]],
          quiz: {
            q: "ping to the server times out, but the website loads. Why?",
            options: ["The server is down", "A firewall drops pings but allows HTTPS", "DNS is broken", "ICMP is faster than TCP"],
            answer: 1,
            why: "Many servers and firewalls block ping. A timeout only means no echo reply came back; it doesn’t prove the host is down.",
          },
          events: [
            pkt("client", "server", "amber", "ECHO REQ", [`to ${S}`, "dropped"], {
              time: 5.0, lost: true, info: `Echo (ping) request id=0x${PING_ID.toString(16)}, seq=1/256, ttl=64 (no response found!)`,
              packet: build(eth(L2), ipv4({ src: LAPTOP, dst: S, ttl: 64, id: 0x6301 }), echo(8, PING_ID, 1, pingData(T0 + 5, 120443))),
            }),
            note("server", "FIREWALL: DROP ICMP", "red"),
            note("client", "REQUEST TIMED OUT", "amber"),
          ],
        },
      ],
      outro: {
        title: "An error, or just silence",
        text: "When a router can’t deliver a packet it usually says so with ICMP Destination Unreachable. A firewall that drops pings says nothing at all. So an error message tells you where the problem is, while silence only tells you that something on the path is not answering.",
        facts: [["Host unreachable", "ICMP 3/1"], ["Port unreachable", "ICMP 3/3"], ["Filtered", "No reply"], ["Ping timeout", "Not proof the host is down"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Message types",
      items: [["0", "Echo reply"], ["3", "Destination unreachable"], ["5", "Redirect"], ["8", "Echo request"], ["11", "Time exceeded"]],
    },
    {
      title: "Type 3 codes",
      items: [["0", "Network unreachable"], ["1", "Host unreachable"], ["3", "Port unreachable"], ["4", "Fragmentation needed (with MTU)"], ["13", "Blocked by policy"]],
    },
    {
      title: "Commands",
      items: [["ping host", "Echo requests, one per second"], ["traceroute -I host", "Linux, ICMP probes"], ["tracert host", "Windows"], ["mtr host", "ping + traceroute live"]],
    },
  ],
});
