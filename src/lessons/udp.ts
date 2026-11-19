import { defineLesson, note, pkt } from "@/lib/lesson";
import { build, proto } from "@/lib/packet";
import { icmp, ipv4, udp } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

const S = ADDR.server2; // voice relay
const LP = 50004; // laptop's port
const SPORT = 5004; // relay's port
const SSRC_UP = 0x5a1c33e0;
const SSRC_DOWN = 0x1d07a9b4;
const TS_UP = 160000;
const TS_DOWN = 92160;

/** RTP header (RFC 3550) carrying one 20 ms Opus frame. */
const rtp = (o: { seq: number; ts: number; ssrc: number; marker?: boolean; bytes?: number }) =>
  proto({
    id: "rtp", name: "RTP (voice)", osi: 7,
    summary: `Real-Time Transport Protocol, Seq=${o.seq}, Time=${o.ts}, PT=111 (Opus)`,
    fields: [
      { name: "Version, flags", u8: 0x80, value: "Version 2, no padding, no extension", note: "RTP version 2. RTP adds a sequence number and timestamp on top of UDP." },
      { name: "Marker, payload type", u8: (o.marker ? 0x80 : 0) | 111, value: `${o.marker ? "Marker, " : ""}111 (Opus)`, note: o.marker ? "Marker set: the start of a talk spurt." : "111 is the number both sides agreed on for the Opus voice codec." },
      { name: "Sequence number", u16: o.seq, note: "Goes up by one per packet, so the receiver can spot gaps and reorder." },
      { name: "Timestamp", u32: o.ts, note: "Sample clock (48 kHz). 20 ms of audio = 960 ticks." },
      { name: "SSRC", u32: o.ssrc, value: `0x${o.ssrc.toString(16)}`, note: "Random number that names this audio stream." },
      { name: "Opus audio frame", random: o.bytes ?? 80, opaque: true, seed: o.seq, value: `${o.bytes ?? 80} bytes`, note: "20 ms of compressed speech." },
    ],
  });

const voiceUp = (n: number, time: number, extra: { lost?: boolean; parallel?: boolean } = {}) =>
  pkt("client", "server", "amber", "RTP", [`seq ${1000 + n}`, extra.lost ? "lost, never resent" : "20 ms of voice"], {
    time, ...extra,
    info: `PT=opus, SSRC=0x${SSRC_UP.toString(16).toUpperCase()}, Seq=${1000 + n}, Time=${TS_UP + 960 * n}${n === 0 ? ", Mark" : ""}`,
    proto: "RTP",
    packet: build(...up(S, { id: 0x3100 + n }), udp({ sport: LP, dport: SPORT }), rtp({ seq: 1000 + n, ts: TS_UP + 960 * n, ssrc: SSRC_UP, marker: n === 0 })),
  });

const voiceDown = (n: number, time: number, parallel = false) =>
  pkt("server", "client", "violet", "RTP", [`seq ${7700 + n}`, "friend’s voice"], {
    time, parallel,
    info: `PT=opus, SSRC=0x${SSRC_DOWN.toString(16).toUpperCase()}, Seq=${7700 + n}, Time=${TS_DOWN + 960 * n}`,
    proto: "RTP",
    packet: build(...down(S, { id: 0x9200 + n }), udp({ sport: SPORT, dport: LP }), rtp({ seq: 7700 + n, ts: TS_DOWN + 960 * n, ssrc: SSRC_DOWN, bytes: 72 })),
  });

const devs = homeToServer({ kind: "server", label: "Voice relay", sub: S });

export default defineLesson({
  id: "udp",
  name: "UDP",
  full: "User Datagram Protocol",
  group: "foundations",
  layer: 4,
  difficulty: 1,
  tagline: "Fire and forget: fast datagrams with no promises.",
  description:
    "UDP adds just port numbers, a length and a checksum to IP, then sends each message on its own. There is no handshake, no acknowledgment and no resending. That makes it ideal for voice, video, games and DNS, where late data is worse than missing data.",
  facts: [
    ["Layer", "Transport (Layer 4)"],
    ["Connection", "None, no handshake"],
    ["Reliability", "None; the app decides"],
    ["Header", "8 bytes"],
    ["Used by", "DNS, DHCP, VoIP, games, QUIC"],
    ["Defined in", "RFC 768"],
  ],
  ports: "Any: 53 DNS, 67/68 DHCP, 123 NTP, 443 QUIC, 5004 RTP…",
  rfc: "RFC 768",
  keywords: ["datagram", "connectionless", "voip", "rtp", "games", "port unreachable", "packet loss", "jitter"],
  related: ["tcp", "ip", "icmp", "quic", "dns"],
  ...devs,
  legend: [
    ["amber", "Voice from the laptop"],
    ["violet", "Voice from the other side"],
    ["blue", "ICMP messages"],
    ["red", "Errors"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A voice call, one packet lost",
      summary: "A call app streams 20 ms voice packets over UDP. One goes missing and nobody resends it.",
      kind: "normal",
      steps: [
        {
          title: "Just start talking",
          desc: "The first datagram leaves with no handshake",
          detail:
            "The call app already knows the relay’s address and port from its signalling. It simply sends the first voice packet. There is no SYN, no setup round trip: the very first UDP datagram already carries 20 ms of speech.",
          facts: [["To", `${S}:${SPORT}`], ["From port", String(LP)], ["Setup time", "0 round trips"]],
          quiz: {
            q: "How many round trips does UDP need before the first voice data can be sent?",
            options: ["0", "1, like TCP’s handshake", "2", "3"],
            answer: 0,
            why: "UDP has no connection to set up. The first datagram already carries data; compare TCP, which needs a full round trip first.",
          },
          events: [voiceUp(0, 0)],
        },
        {
          title: "A steady stream",
          desc: "One datagram every 20 ms",
          detail:
            "Each datagram stands alone: 8 bytes of UDP header, 12 bytes of RTP header and about 80 bytes of compressed voice. UDP itself has no idea these belong together. The RTP sequence number and timestamp inside are what let the other side play them in order.",
          facts: [["Interval", "20 ms"], ["UDP header", "8 bytes"], ["Per packet", "~142 bytes on the wire"]],
          events: [voiceUp(1, 0.02), voiceUp(2, 0.04)],
        },
        {
          title: "One goes missing",
          desc: "Nobody notices at the UDP level",
          detail:
            "Datagram 1003 is dropped by a busy router. The laptop has no idea, because nothing is ever acknowledged. The next one, 1004, leaves 20 ms later as if nothing happened.",
          facts: [["Lost", "seq 1003"], ["Sender knows?", "No"], ["Resent?", "Never"]],
          quiz: {
            q: "What does UDP do about the lost datagram?",
            options: ["Resends it after a timeout", "Asks the receiver for a NACK", "Nothing at all", "Slows down the stream"],
            answer: 2,
            why: "UDP has no acknowledgments and no timers. If the application cares, it must notice and react itself.",
          },
          events: [voiceUp(3, 0.06, { lost: true }), note("internet", "DATAGRAM 1003 LOST", "amber"), voiceUp(4, 0.08)],
        },
        {
          title: "The receiver hides the gap",
          desc: "Sequence numbers reveal it, the codec covers it",
          detail:
            "The relay sees 1002 then 1004, so it knows 1003 is missing. Asking for it again would be pointless: by the time a copy arrived, that moment of speech should already have been played. The voice decoder fills the 20 ms gap with a guess, and the listener rarely hears it.",
          facts: [["Gap found by", "RTP sequence number"], ["Fix", "Loss concealment in the codec"], ["Audible?", "Rarely, at 1 lost in 50"]],
          events: [note("server", "GAP AT 1003: CONCEAL", "blue"), voiceUp(5, 0.1)],
        },
        {
          title: "Both ways at once",
          desc: "The other side streams on its own",
          detail:
            "The friend’s voice flows back as a completely separate stream of datagrams. There is no shared state between the two directions and nothing ties them together except the ports. Each side just sends when it has audio.",
          facts: [["Direction", "Relay → laptop"], ["Ports", `${SPORT} → ${LP}`], ["Shared state", "None"]],
          events: [voiceDown(0, 0.105), voiceUp(6, 0.12), voiceDown(1, 0.125)],
        },
        {
          title: "Why not TCP?",
          desc: "Waiting for a resend would freeze the call",
          detail:
            "Over TCP, the lost packet would hold back everything behind it until a resend arrived, so the voice would stall for a round trip or more. TCP also needs a handshake first and has a 20-byte header. For live audio, a small gap now is better than perfect audio late.",
          facts: [["TCP header", "20+ bytes vs UDP 8"], ["TCP after loss", "Waits, then catches up"], ["UDP after loss", "Skips and keeps going"]],
          quiz: {
            q: "Over TCP, packet 1003 is lost. What happens to 1004 and 1005 at the receiver?",
            options: ["They are played straight away", "They wait in a buffer until 1003 is resent", "They are thrown away", "They are sent back"],
            answer: 1,
            why: "TCP delivers bytes strictly in order, so later data waits for the missing piece. This is called head-of-line blocking.",
          },
          events: [voiceUp(7, 0.14), voiceDown(2, 0.145)],
        },
      ],
      outro: {
        title: "Fast beats perfect",
        text: "UDP sent every voice packet the moment it was ready, with an 8-byte header and no handshake. One packet was lost and never came back, and that was fine: RTP noticed the gap and the codec covered it.",
        facts: [["Handshake", "None"], ["Lost / resent", "1 / 0"], ["Header", "8 bytes"], ["Order and loss", "Handled by RTP and the app"]],
      },
    },
    {
      id: "closed-port",
      name: "Nobody is listening (port unreachable)",
      summary: "The relay program has crashed, so the server’s OS answers with ICMP Port Unreachable.",
      kind: "failure",
      steps: [
        {
          title: "Send to a closed port",
          desc: "The datagram leaves like any other",
          detail:
            "The relay program has crashed, but the server itself is up. The laptop sends a voice datagram to port 5004 as usual. With UDP it can’t know in advance whether anyone is listening.",
          facts: [["To", `${S}:${SPORT}`], ["Listener", "None (program crashed)"], ["Sender knows?", "Not yet"]],
          events: [voiceUp(0, 0)],
        },
        {
          title: "Port unreachable",
          desc: "The server’s OS answers with ICMP type 3, code 3",
          detail:
            "The server’s operating system finds no socket on UDP port 5004. Instead of silence, it sends ICMP Destination Unreachable, code 3 (port unreachable). Inside, it quotes the original IP header and the 8-byte UDP header so the laptop can tell which socket it belongs to.",
          facts: [["ICMP", "Type 3, code 3"], ["Quoted", "IP header + UDP header"], ["Took", "32 ms"]],
          quiz: {
            q: "What does the ICMP message quote so the laptop knows which socket failed?",
            options: ["Nothing, just the server’s address", "The original IP header and UDP ports", "The full voice audio", "The laptop’s MAC address"],
            answer: 1,
            why: "ICMP errors carry the start of the packet that caused them: the IP header plus 8 bytes, which for UDP is the whole header with both ports.",
          },
          events: [
            pkt("server", "client", "red", "ICMP 3/3", ["port unreachable", `port ${SPORT}`], {
              time: 0.032, info: "Destination unreachable (Port unreachable)",
              packet: build(
                ...down(S, { id: 0x0f11 }),
                icmp({
                  type: 3, code: 3, name: "Destination unreachable (Port unreachable)",
                  data: build(ipv4({ src: ADDR.laptop, dst: S, ttl: 54, id: 0x3100 }), udp({ sport: LP, dport: SPORT }), rtp({ seq: 1000, ts: TS_UP, ssrc: SSRC_UP, marker: true })).bytes.slice(0, 28),
                  dataName: "Original packet (start)", dataNote: "The IP header and UDP header of the datagram that was refused. The home router fixes the addresses back for the laptop.",
                })
              ),
            }),
            note("client", "ECONNREFUSED", "red"),
          ],
        },
        {
          title: "The app reacts",
          desc: "Report the error, or retry with backoff",
          detail:
            "If the app’s UDP socket is “connected” to the relay, the next receive call fails with “connection refused”. The call app shows “Reconnecting…” and tries another relay. Many firewalls drop such datagrams silently instead, so UDP apps must also use their own timeouts.",
          facts: [["Socket error", "ECONNREFUSED"], ["App does", "Switch relay"], ["If filtered", "Silence, app times out"]],
          quiz: {
            q: "If a firewall silently dropped the datagram instead, how would the app find out?",
            options: ["From an ICMP message", "From a TCP RST", "Only by its own timeout", "The datagram would bounce back"],
            answer: 2,
            why: "With no reply of any kind, UDP gives the app nothing. The app must notice that answers stopped coming.",
          },
          events: [voiceUp(1, 1.0), note("client", "RECONNECTING…", "amber")],
        },
      ],
      outro: {
        title: "Closed is not the same as silent",
        text: "A host with no listener answers UDP with ICMP Port Unreachable, quoting the datagram it refused. A firewall usually says nothing. UDP scanners and apps tell the two apart by whether that ICMP comes back.",
        facts: [["Closed port", "ICMP 3/3"], ["Filtered port", "Silence"], ["TCP’s version", "RST"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "UDP header (8 bytes)",
      items: [["Source port", "2 bytes"], ["Destination port", "2 bytes"], ["Length", "Header + data"], ["Checksum", "Header, data, IP pseudo-header"]],
    },
    {
      title: "UDP vs TCP",
      items: [["Setup", "None vs 3-way handshake"], ["Order", "Not kept vs always in order"], ["Loss", "Ignored vs resent"], ["Header", "8 vs 20–60 bytes"]],
    },
    {
      title: "Common UDP ports",
      items: [["53", "DNS"], ["67 / 68", "DHCP server / client"], ["123", "NTP"], ["443", "QUIC (HTTP/3)"], ["5004", "RTP media"]],
    },
  ],
});
