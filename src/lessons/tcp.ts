import { defineLesson, note, pkt, Step } from "@/lib/lesson";
import { build, textLayer } from "@/lib/packet";
import { eth, ipv4, tcp } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

const S = ADDR.web;
const SP = 51234; // laptop's ephemeral port
const MSS = 1460;
const REQ = ["GET / HTTP/1.1", "Host: example.com", "User-Agent: curl/8.9.1", "Accept: */*"];
const REQ_LEN = REQ.join("\r\n").length + 4; // + final CRLF CRLF
const httpReq = () => textLayer({ id: "http", name: "HTTP", lines: REQ, blankLine: true });
const chunk = (from: number) =>
  textLayer({ id: "http", name: "HTTP (part of the page)", lines: [], body: { opaque: MSS, what: `Page bytes ${from}–${from + MSS - 1}` }, summary: `HTTP response data, bytes ${from}–${from + MSS - 1}` });

const ISN_C = 0; // relative numbers
const synOpts = [{ mss: 1460 }, "sackOk" as const, { ts: [3021111, 0] as [number, number] }, "nop" as const, { ws: 7 }];

const t = (n: number) => Number(n.toFixed(3));

// three-way handshake shared by every scenario
const handshake = (sport: number, base = 0): Step["events"] => [
  pkt("client", "server", "green", "SYN", ["seq=0", "I’d like to talk"], {
    time: t(base), info: `${sport} → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
    packet: build(...up(S), tcp({ sport, dport: 80, seq: ISN_C, flags: "S", opts: synOpts, seqBase: 0x6a1f2c00 })),
  }),
  pkt("server", "client", "green", "SYN-ACK", ["seq=0 ack=1", "me too, go ahead"], {
    time: t(base + 0.017), info: `80 → ${sport} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128`,
    packet: build(...down(S), tcp({ sport: 80, dport: sport, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1460 }, "sackOk", { ts: [918273, 3021111] }, "nop", { ws: 7 }], seqBase: 0x1b33e800, ackBase: 0x6a1f2c00 })),
  }),
  pkt("client", "server", "green", "ACK", ["ack=1", "connected"], {
    time: t(base + 0.034), info: `${sport} → 80 [ACK] Seq=1 Ack=1 Win=502 Len=0`,
    packet: build(...up(S), tcp({ sport, dport: 80, seq: 1, ack: 1, flags: "A", win: 502, seqBase: 0x6a1f2c00, ackBase: 0x1b33e800 })),
  }),
];

const devs = homeToServer();

// forged SYN as it arrives at the server (captured at the server this time)
const forged = (src: string, sport: number, seqBase: number) =>
  build(eth({ src: "00:1b:21:aa:00:01", dst: ADDR.serverMac }), ipv4({ src, dst: S, ttl: 241, id: sport }), tcp({ sport, dport: 80, seq: 0, flags: "S", win: 1024, seqBase }));

const attackDevices = [
  ...devs.devices,
  { id: "attacker", kind: "attacker" as const, label: "Botnet", sub: "forged sources", x: 30, y: 20 },
];
const attackLinks: [string, string][] = [...devs.links, ["attacker", "internet"]];

export default defineLesson({
  id: "tcp",
  name: "TCP",
  full: "Transmission Control Protocol",
  group: "foundations",
  layer: 4,
  difficulty: 2,
  tagline: "Reliable, ordered delivery over an unreliable internet.",
  description:
    "TCP turns the internet’s best-effort packet delivery into a reliable, ordered stream of bytes. It numbers every byte, acknowledges what arrives, resends what goes missing, and paces the sender so neither the receiver nor the network gets overwhelmed.",
  facts: [
    ["Layer", "Transport (Layer 4)"],
    ["Connection", "Three-way handshake"],
    ["Reliability", "Sequence numbers + ACKs"],
    ["Recovery", "Retransmission, SACK"],
    ["Header", "20–60 bytes"],
    ["Defined in", "RFC 9293"],
  ],
  ports: "Any: 80 HTTP, 443 HTTPS, 22 SSH, 25 SMTP…",
  rfc: "RFC 9293",
  keywords: ["handshake", "syn", "ack", "retransmission", "sack", "fin", "rst", "syn flood", "congestion"],
  related: ["udp", "quic", "ip", "http"],
  ...devs,
  legend: [
    ["green", "Handshake and ACKs"],
    ["amber", "Data from the laptop"],
    ["violet", "Data from the server"],
    ["slate", "Closing (FIN)"],
    ["red", "Reset or attack"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A page download with one lost packet",
      summary: "curl fetches a page; one segment is lost on the way and TCP quietly repairs it.",
      kind: "normal",
      steps: [
        {
          title: "Open the connection",
          desc: "Three-way handshake: SYN, SYN-ACK, ACK",
          detail:
            "Before any data moves, both sides pick a starting sequence number and confirm the other’s. The laptop sends SYN, the server answers SYN-ACK, the laptop confirms with ACK. The numbers shown are relative; real ones start at a random value so attackers can’t guess them.",
          facts: [["Server", `${S}, port 80`], ["Laptop port", `${SP} (temporary)`], ["Takes", "1 round trip (34 ms)"]],
          quiz: {
            q: "What does the server send in reply to the laptop’s SYN?",
            options: ["ACK", "SYN-ACK", "FIN", "Data straight away"],
            answer: 1,
            why: "The server acknowledges the laptop’s SYN and sends its own SYN in the same segment: SYN-ACK.",
          },
          events: handshake(SP),
        },
        {
          title: "Send the request",
          desc: "Every byte gets a number",
          detail: `curl sends its ${REQ_LEN}-byte HTTP request as bytes 1 to ${REQ_LEN}. The server’s ACK number, ${REQ_LEN + 1}, is the next byte it expects, which tells the laptop everything before it has arrived.`,
          facts: [["Sent", `${REQ_LEN} bytes (seq 1–${REQ_LEN})`], ["ACK", `${REQ_LEN + 1} = next byte expected`], ["Flags", "PSH, ACK"]],
          quiz: {
            q: `The laptop sends bytes 1–${REQ_LEN}. What ACK number does the server send back?`,
            options: [String(REQ_LEN), String(REQ_LEN + 1), "1", "0"],
            answer: 1,
            why: "TCP acknowledges the next byte it expects, which is one past the last byte received.",
          },
          events: [
            pkt("client", "server", "amber", "DATA", [`seq=1 len=${REQ_LEN}`, "GET / HTTP/1.1"], {
              time: 0.035, info: `${SP} → 80 [PSH, ACK] Seq=1 Ack=1 Len=${REQ_LEN}`,
              packet: build(...up(S), tcp({ sport: SP, dport: 80, seq: 1, ack: 1, flags: "PA", win: 502, seqBase: 0x6a1f2c00, ackBase: 0x1b33e800 }), httpReq()),
            }),
            pkt("server", "client", "green", "ACK", [`ack=${REQ_LEN + 1}`], {
              time: 0.052, info: `80 → ${SP} [ACK] Seq=1 Ack=${REQ_LEN + 1} Win=509 Len=0`,
              packet: build(...down(S), tcp({ sport: 80, dport: SP, seq: 1, ack: REQ_LEN + 1, flags: "A", win: 509, seqBase: 0x1b33e800, ackBase: 0x6a1f2c00 })),
            }),
          ],
        },
        {
          title: "Two segments back, one lost",
          desc: "Packets can vanish on the internet",
          detail: `The server answers with two full segments of ${MSS} bytes each, sent back to back. The first one is dropped by a busy router somewhere on the internet; the second gets through.`,
          facts: [["Segment 1", `bytes 1–${MSS} (lost)`], ["Segment 2", `bytes ${MSS + 1}–${2 * MSS}`], ["Segment size", `${MSS} bytes (MSS)`]],
          events: [
            pkt("server", "client", "violet", "DATA", ["seq=1", "lost on the way"], {
              time: 0.053, lost: true, info: `80 → ${SP} [ACK] Seq=1 Ack=${REQ_LEN + 1} Len=${MSS}`,
              packet: build(...down(S), tcp({ sport: 80, dport: SP, seq: 1, ack: REQ_LEN + 1, flags: "A", win: 509, seqBase: 0x1b33e800, ackBase: 0x6a1f2c00 }), chunk(1)),
            }),
            pkt("server", "client", "violet", "DATA", [`seq=${MSS + 1}`], {
              time: 0.053, parallel: true, info: `80 → ${SP} [PSH, ACK] Seq=${MSS + 1} Ack=${REQ_LEN + 1} Len=${MSS}`,
              packet: build(...down(S), tcp({ sport: 80, dport: SP, seq: MSS + 1, ack: REQ_LEN + 1, flags: "PA", win: 509, seqBase: 0x1b33e800, ackBase: 0x6a1f2c00 }), chunk(MSS + 1)),
            }),
            note("internet", "SEGMENT 1 LOST", "amber"),
          ],
        },
        {
          title: "A gap is noticed",
          desc: "Duplicate ACK with a SACK block",
          detail: `Bytes ${MSS + 1}–${2 * MSS} arrived but 1–${MSS} did not. A normal ACK can only count bytes received in order, so the laptop repeats ACK 1 straight away and adds a SACK block that says “I already have ${MSS + 1}–${2 * MSS}”.`,
          facts: [["ACK", "1 (still waiting for byte 1)"], ["SACK", `holds ${MSS + 1}–${2 * MSS}`], ["Sent", "At once, not delayed"]],
          quiz: {
            q: "Which bytes will the server resend?",
            options: ["Everything from byte 1", `Only bytes 1–${MSS}`, `Only bytes ${MSS + 1}–${2 * MSS}`, "Nothing; the laptop asks again later"],
            answer: 1,
            why: "SACK tells the server exactly which bytes already arrived, so only the gap is resent.",
          },
          events: [
            pkt("client", "server", "green", "DUP ACK", ["ack=1", `SACK ${MSS + 1}–${2 * MSS}`], {
              time: 0.07, info: `${SP} → 80 [ACK] Seq=${REQ_LEN + 1} Ack=1 Win=502 SLE=${MSS + 1} SRE=${2 * MSS + 1}`,
              packet: build(...up(S), tcp({ sport: SP, dport: 80, seq: REQ_LEN + 1, ack: 1, flags: "A", win: 502, opts: ["nop", "nop", { sack: [[0x1b33e800 + MSS + 1, 0x1b33e800 + 2 * MSS + 1]] }], seqBase: 0x6a1f2c00, ackBase: 0x1b33e800 })),
            }),
          ],
        },
        {
          title: "Resend just the gap",
          desc: "Fast retransmission",
          detail: "Thanks to SACK the server resends only segment 1, and the laptop acknowledges everything at once. If no ACK had come back at all, a retransmission timer (at least 200 ms on Linux) would have fired instead, which is much slower.",
          facts: [["Resent", `bytes 1–${MSS} only`], ["Next ACK", `${2 * MSS + 1} (everything)`], ["curl saw", "Every byte, in order"]],
          events: [
            pkt("server", "client", "violet", "RESEND", ["seq=1", "only the missing part"], {
              time: 0.087, info: `[TCP Retransmission] 80 → ${SP} [ACK] Seq=1 Ack=${REQ_LEN + 1} Len=${MSS}`,
              packet: build(...down(S), tcp({ sport: 80, dport: SP, seq: 1, ack: REQ_LEN + 1, flags: "A", win: 509, seqBase: 0x1b33e800, ackBase: 0x6a1f2c00 }), chunk(1)),
            }),
            pkt("client", "server", "green", "ACK", [`ack=${2 * MSS + 1}`], {
              time: 0.104, info: `${SP} → 80 [ACK] Seq=${REQ_LEN + 1} Ack=${2 * MSS + 1} Win=501 Len=0`,
              packet: build(...up(S), tcp({ sport: SP, dport: 80, seq: REQ_LEN + 1, ack: 2 * MSS + 1, flags: "A", win: 501, seqBase: 0x6a1f2c00, ackBase: 0x1b33e800 })),
            }),
            note("client", "ALL BYTES IN ORDER", "green"),
          ],
        },
        {
          title: "Close the connection",
          desc: "Each side says goodbye separately",
          detail: "Each direction closes on its own. The laptop sends FIN and the server acknowledges it; then the server sends its own FIN and the laptop acknowledges that. The laptop then keeps the connection’s details for a while (TIME-WAIT) in case a late packet turns up.",
          facts: [["Order", "FIN → ACK → FIN → ACK"], ["Then", "Laptop waits (TIME-WAIT)"], ["Total time", "0.141 s"]],
          events: [
            pkt("client", "server", "slate", "FIN", [`seq=${REQ_LEN + 1}`], {
              time: 0.105, info: `${SP} → 80 [FIN, ACK] Seq=${REQ_LEN + 1} Ack=${2 * MSS + 1}`,
              packet: build(...up(S), tcp({ sport: SP, dport: 80, seq: REQ_LEN + 1, ack: 2 * MSS + 1, flags: "FA", win: 501, seqBase: 0x6a1f2c00, ackBase: 0x1b33e800 })),
            }),
            pkt("server", "client", "green", "ACK", [`ack=${REQ_LEN + 2}`], {
              time: 0.122, info: `80 → ${SP} [ACK] Seq=${2 * MSS + 1} Ack=${REQ_LEN + 2}`,
              packet: build(...down(S), tcp({ sport: 80, dport: SP, seq: 2 * MSS + 1, ack: REQ_LEN + 2, flags: "A", win: 509, seqBase: 0x1b33e800, ackBase: 0x6a1f2c00 })),
            }),
            pkt("server", "client", "slate", "FIN", [`seq=${2 * MSS + 1}`], {
              time: 0.123, parallel: true, info: `80 → ${SP} [FIN, ACK] Seq=${2 * MSS + 1} Ack=${REQ_LEN + 2}`,
              packet: build(...down(S), tcp({ sport: 80, dport: SP, seq: 2 * MSS + 1, ack: REQ_LEN + 2, flags: "FA", win: 509, seqBase: 0x1b33e800, ackBase: 0x6a1f2c00 })),
            }),
            pkt("client", "server", "green", "ACK", [`ack=${2 * MSS + 2}`], {
              time: 0.141, info: `${SP} → 80 [ACK] Seq=${REQ_LEN + 2} Ack=${2 * MSS + 2}`,
              packet: build(...up(S), tcp({ sport: SP, dport: 80, seq: REQ_LEN + 2, ack: 2 * MSS + 2, flags: "A", win: 501, seqBase: 0x6a1f2c00, ackBase: 0x1b33e800 })),
            }),
          ],
        },
      ],
      outro: {
        title: "Connection closed",
        text: "TCP opened a connection, numbered and acknowledged every byte, spotted a gap and resent only the missing segment, then closed both directions. curl received every byte in order and never knew a packet was lost.",
        facts: [["Segments", "13 (1 lost, 1 resent)"], ["Bytes delivered", `${REQ_LEN} up, ${2 * MSS} down`], ["Loss found by", "Duplicate ACK + SACK"], ["Total time", "0.141 s"]],
      },
    },
    {
      id: "closed-port",
      name: "Nobody is listening (RST)",
      summary: "The laptop knocks on a port with no service behind it and gets an instant reset.",
      kind: "failure",
      steps: [
        {
          title: "Knock on port 8080",
          desc: "A SYN to a closed port",
          detail: "This time curl tries port 8080, where nothing is running on the server. The SYN looks exactly like a normal one.",
          facts: [["Server", `${S}, port 8080`], ["Laptop port", "51240"], ["Flags", "SYN"]],
          events: [
            pkt("client", "server", "green", "SYN", ["seq=0", "port 8080?"], {
              time: 0, info: "51240 → 8080 [SYN] Seq=0 Win=64240 Len=0 MSS=1460",
              packet: build(...up(S), tcp({ sport: 51240, dport: 8080, seq: 0, flags: "S", opts: synOpts, seqBase: 0x51aa0000 })),
            }),
          ],
        },
        {
          title: "Reset",
          desc: "RST, ACK: nothing here",
          detail: "The server’s operating system has no program listening on 8080, so it answers at once with RST. curl reports “Connection refused”. A firewall that silently drops the SYN instead would make curl wait and retry until it times out, which is how you can tell the two apart.",
          facts: [["Flags", "RST, ACK"], ["curl says", "Connection refused"], ["Took", "17 ms"]],
          quiz: {
            q: "If a firewall silently dropped the SYN instead, what would curl see?",
            options: ["Connection refused at once", "A timeout after several retries", "An HTTP 404", "A TLS error"],
            answer: 1,
            why: "With no answer at all, the laptop retransmits the SYN with growing gaps and eventually gives up with a timeout.",
          },
          events: [
            pkt("server", "client", "red", "RST", ["ack=1", "connection refused"], {
              time: 0.017, info: "8080 → 51240 [RST, ACK] Seq=0 Ack=1 Win=0 Len=0",
              packet: build(...down(S), tcp({ sport: 8080, dport: 51240, seq: 0, ack: 1, flags: "RA", win: 0, ackBase: 0x51aa0000 })),
            }),
            note("client", "CONNECTION REFUSED", "red"),
          ],
        },
      ],
      outro: {
        title: "Refused in one round trip",
        text: "A closed port answers SYN with RST straight away. Port scanners use exactly this difference (RST = closed, SYN-ACK = open, silence = filtered) to map a server.",
        facts: [["Packets", "2"], ["Result", "Connection refused"], ["Closed vs filtered", "RST vs silence"]],
      },
    },
    {
      id: "syn-flood",
      name: "SYN flood attack and SYN cookies",
      summary: "An attacker sends thousands of SYNs from fake addresses; SYN cookies keep the server alive.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "The flood begins",
          desc: "SYNs from addresses that don’t exist",
          detail: "An attacker sends SYN after SYN with forged source addresses. Each one asks the server to remember a half-open connection while it waits for the final ACK, which never comes because the forged senders never asked.",
          facts: [["Rate", "Tens of thousands per second"], ["Source IPs", "Forged (random)"], ["Goal", "Fill the half-open queue"]],
          events: [
            pkt("attacker", "server", "red", "SYN", ["from 198.18.4.7 (fake)"], {
              time: 0, info: "40001 → 80 [SYN] Seq=0 Win=1024 Len=0",
              packet: forged("198.18.4.7", 40001, 0x0badf00d),
            }),
            pkt("attacker", "server", "red", "SYN", ["from 198.18.9.41 (fake)"], {
              time: 0.0001, parallel: true, info: "40002 → 80 [SYN] Seq=0 Win=1024 Len=0",
              packet: forged("198.18.9.41", 40002, 0x0badf11d),
            }),
            pkt("attacker", "server", "red", "SYN", ["from 198.18.200.3 (fake)"], {
              time: 0.0002, parallel: true, info: "40003 → 80 [SYN] Seq=0 Win=1024 Len=0",
              packet: forged("198.18.200.3", 40003, 0x0badf22d),
            }),
            note("server", "HALF-OPEN QUEUE FILLING", "red"),
          ],
        },
        {
          title: "SYN cookies switch on",
          desc: "Remember nothing, encode it in the sequence number",
          detail: "When the queue is full, the server stops storing half-open connections. Instead it builds its starting sequence number from a secret hash of the connection’s addresses, ports and time: a SYN cookie. It sends SYN-ACK and forgets about it.",
          facts: [["Stored per SYN", "Nothing"], ["Cookie", "Hash in the sequence number"], ["Defined in", "RFC 4987"]],
          events: [
            pkt("server", "attacker", "green", "SYN-ACK", ["seq=cookie", "nothing stored"], {
              time: 0.002, info: "80 → 40001 [SYN, ACK] Seq=0 Ack=1 (SYN cookie)",
              packet: build(eth({ src: ADDR.serverMac, dst: "00:1b:21:aa:00:01" }), ipv4({ src: S, dst: "198.18.4.7" }), tcp({ sport: 80, dport: 40001, seq: 0, ack: 1, flags: "SA", win: 65160, seqBase: 0x9c3e1f07, ackBase: 0x0badf00d })),
            }),
            note("server", "SYN COOKIES ON", "green"),
          ],
        },
        {
          title: "Real users still get in",
          desc: "The cookie comes back in the ACK",
          detail: "A real visitor completes the handshake. Its ACK number is the cookie plus one, so the server can recompute the hash, check it, and rebuild the connection from that alone. The flood costs the server almost nothing.",
          facts: [["Check", "ACK − 1 = valid cookie?"], ["Result", "Real users connect"], ["Attacker gets", "Nothing"]],
          events: handshake(51300, 0.01),
        },
      ],
      outro: {
        title: "The server survived",
        text: "A SYN flood tries to exhaust the memory for half-open connections. SYN cookies move that state into the sequence number, so the server stores nothing until a real ACK proves the sender is genuine.",
        facts: [["Attack", "SYN flood (DoS)"], ["Defence", "SYN cookies, rate limits, upstream scrubbing"], ["Stored per fake SYN", "0 bytes"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Flags",
      items: [["SYN", "Start, sync sequence numbers"], ["ACK", "Acknowledgment field is valid"], ["PSH", "Hand data to the app now"], ["FIN", "No more data from me"], ["RST", "Abort the connection"], ["URG", "Urgent pointer valid (rare)"]],
    },
    {
      title: "States",
      items: [["LISTEN", "Server waiting"], ["SYN-SENT / SYN-RCVD", "Handshake in progress"], ["ESTABLISHED", "Data flowing"], ["FIN-WAIT / CLOSE-WAIT", "Closing one side"], ["TIME-WAIT", "2×MSL wait after close"]],
    },
    {
      title: "Numbers to know",
      items: [["Header", "20 bytes min, 60 max"], ["Typical MSS", "1460 bytes on Ethernet"], ["Min RTO (Linux)", "200 ms"], ["Port range", "0–65535; ephemeral 32768–60999 (Linux)"]],
    },
  ],
});
