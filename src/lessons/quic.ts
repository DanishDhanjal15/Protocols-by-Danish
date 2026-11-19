import { defineLesson, note, pkt, Device } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, udp } from "@/lib/proto";
import { Bytes, u16, u32 } from "@/lib/bytes";
import { ADDR, down, homeToServer, up } from "./_common";

// HTTP/3 over QUIC: Initial / Handshake long-header packets, then 1-RTT short-header packets.

const S = ADDR.web;
const CP = 52844; // laptop's UDP port
const DCID0 = "8394c8f03e515708"; // client-chosen first destination CID (as in RFC 9001 appendix A)
const CCID = "c3a1f05b7e2d9a14"; // client's own CID
const SCID = "f067a5502a4262b5"; // CID the server picks for itself

const t = (n: number) => Number(n.toFixed(4));

/** QUIC variable-length integer (RFC 9000 §16) */
const varint = (n: number): Bytes => (n < 64 ? [n] : n < 16384 ? u16(0x4000 | n) : u32((0x80000000 | n) >>> 0));
const vi = (name: string, n: number, note?: string): FieldSpec => ({
  name, bytes: varint(n), value: String(n),
  note: note ?? `Variable-length integer: the top two bits say it is ${varint(n).length} byte(s) long.`,
});

let seed = 900;
type Part = [string, number, string?];
/** Encrypted payload described by what is inside it. Sizes include the 16-byte AEAD tag as its own part. */
const encPayload = (parts: Part[]): FieldSpec => {
  const all: Part[] = [...parts, ["AEAD tag", 16, "16-byte authentication tag. Any change to the packet makes decryption fail."]];
  const total = all.reduce((n, p) => n + p[1], 0);
  return {
    name: "Protected payload",
    value: `${total} bytes (encrypted)`,
    opaque: true,
    fields: all.map(([name, n, note]) => ({ name, random: n, seed: seed++, opaque: true, value: `${n} bytes`, note: note ?? "Encrypted: shown by what it contains." })),
  };
};
const partsLen = (parts: Part[]) => parts.reduce((n, p) => n + p[1], 0) + 16;

/** Long header packet: Initial (type 0) or Handshake (type 2). Packet number is 1 byte. */
function longHdr(o: { type: "Initial" | "Handshake"; firstByte: number; dcid: string; scid: string; pn: number; parts: Part[] }): FieldSpec[] {
  const len = 1 + partsLen(o.parts);
  const f: FieldSpec[] = [
    {
      name: "Header form, fixed bit, type, protected bits",
      u8: o.firstByte,
      value: `0x${o.firstByte.toString(16)} (long header, ${o.type})`,
      note: `Bit 7 = 1 long header, bit 6 = 1 fixed, bits 5–4 = ${o.type === "Initial" ? "00 Initial" : "10 Handshake"}. The low 4 bits (incl. packet number length) are hidden by header protection.`,
    },
    { name: "Version", u32: 1, value: "0x00000001 (QUIC v1)", note: "RFC 9000." },
    { name: "Destination CID length", u8: 8 },
    { name: "Destination connection ID", bytes: o.dcid, value: o.dcid, note: "Who this packet is for. It, not the IP address, identifies the connection." },
    { name: "Source CID length", u8: 8 },
    { name: "Source connection ID", bytes: o.scid, value: o.scid, note: "The ID the sender wants the other side to use when replying." },
  ];
  if (o.type === "Initial") f.push(vi("Token length", 0, "No token: this is a fresh connection (no Retry, no resumption)."));
  f.push(vi("Length", len, "Bytes after this field: packet number plus encrypted payload."));
  f.push({ name: "Packet number (protected)", u8: (o.pn * 0x5b + 0x2e) & 0xff, value: `${o.pn} (masked on the wire)`, opaque: true, note: "Header protection XORs the packet number with a mask made from the encrypted payload." });
  f.push(encPayload(o.parts));
  return f;
}

const longPkt = (o: Parameters<typeof longHdr>[0]): LayerSpec =>
  proto({ id: "quic", name: `QUIC ${o.type}`, osi: 4, summary: `QUIC ${o.type}, DCID=${o.dcid}, SCID=${o.scid}, PKN: ${o.pn}`, fields: longHdr(o) });

const shortPkt = (o: { dcid: string; pn: number; parts: Part[]; firstByte?: number }): LayerSpec =>
  proto({
    id: "quic", name: "QUIC 1-RTT", osi: 4, summary: `QUIC Protected Payload (KP0), DCID=${o.dcid}, PKN: ${o.pn}`,
    fields: [
      { name: "Header form, fixed bit, spin, protected bits", u8: o.firstByte ?? 0x4e, value: `0x${(o.firstByte ?? 0x4e).toString(16)} (short header)`, note: "Bit 7 = 0: short header, used once the handshake is done. Key phase and packet number length are masked." },
      { name: "Destination connection ID", bytes: o.dcid, value: o.dcid, note: "No length byte: each side knows how long its own IDs are." },
      { name: "Packet number (protected)", u8: (o.pn * 0x5b + 0x2e) & 0xff, value: `${o.pn} (masked on the wire)`, opaque: true },
      encPayload(o.parts),
    ],
  });

// ------------------------------------------------------------ normal flow packets

const fromLaptop = (...l: LayerSpec[]) => build(...up(S), udp({ sport: CP, dport: 443 }), ...l);
const toLaptop = (...l: LayerSpec[]) => build(...down(S), udp({ sport: 443, dport: CP }), ...l);

// client Initial: 27-byte header + 1173 payload = 1200 bytes of UDP payload
const clientInitial = () =>
  longPkt({
    type: "Initial", firstByte: 0xcd, dcid: DCID0, scid: CCID, pn: 0,
    parts: [
      ["CRYPTO frame: TLS 1.3 ClientHello", 290, "Offset 0. Holds the ClientHello with key_share, ALPN \"h3\", SNI example.com and QUIC transport parameters."],
      ["PADDING frames", 867, "Zeros before encryption. They make the datagram 1200 bytes, so a server never answers a tiny spoofed packet with a big reply."],
    ],
  });
const serverInitial = () =>
  longPkt({
    type: "Initial", firstByte: 0xc2, dcid: CCID, scid: SCID, pn: 0,
    parts: [["ACK frame (client packet 0)", 5], ["CRYPTO frame: ServerHello", 97, "The server’s key share. After this both sides can derive Handshake keys."]],
  });
const serverHs1 = () =>
  longPkt({ type: "Handshake", firstByte: 0xe7, dcid: CCID, scid: SCID, pn: 0, parts: [["CRYPTO frame: EncryptedExtensions + Certificate (start)", 1013]] });
const serverHs2 = () =>
  longPkt({ type: "Handshake", firstByte: 0xe1, dcid: CCID, scid: SCID, pn: 1, parts: [["CRYPTO frame: Certificate (rest), CertificateVerify, Finished", 938]] });
const clientInitial2 = () =>
  longPkt({ type: "Initial", firstByte: 0xc9, dcid: SCID, scid: CCID, pn: 1, parts: [["ACK frame (server Initial 0)", 5], ["PADDING frames", 1065, "Any datagram holding a client Initial must be at least 1200 bytes."]] });
const clientHs = () =>
  longPkt({ type: "Handshake", firstByte: 0xe4, dcid: SCID, scid: CCID, pn: 0, parts: [["ACK frame (Handshake 0–1)", 5], ["CRYPTO frame: client Finished", 41]] });
const request = () =>
  shortPkt({
    dcid: SCID, pn: 0,
    parts: [
      ["STREAM frame, stream 2 (control): SETTINGS", 12, "HTTP/3 control stream: a client-opened one-way stream that starts with a SETTINGS frame."],
      ["STREAM frame, stream 0, FIN: HEADERS (GET /)", 48, "HTTP/3 HEADERS frame with QPACK-compressed :method GET, :scheme https, :authority example.com, :path /."],
    ],
  });
const response = () =>
  shortPkt({
    dcid: CCID, pn: 0, firstByte: 0x5a,
    parts: [
      ["HANDSHAKE_DONE frame", 1, "Tells the client the handshake is confirmed, so it can drop its Handshake keys."],
      ["ACK frame (1-RTT 0)", 5],
      ["STREAM frame, stream 0, FIN: HEADERS (200) + DATA", 1128, "HEADERS frame with :status 200, then a DATA frame with the page. FIN closes the stream."],
    ],
  });
const ackOnly = (pn: number, what: string) => shortPkt({ dcid: SCID, pn, parts: [[`ACK frame (${what})`, 5]] });

// ------------------------------------------------------------ head-of-line scenario packets
const twoRequests = () =>
  shortPkt({
    dcid: SCID, pn: 3,
    parts: [
      ["STREAM frame, stream 4, FIN: HEADERS (GET /style.css)", 44],
      ["STREAM frame, stream 8, FIN: HEADERS (GET /photo.jpg)", 44],
    ],
  });
const respCss = (pn: number) => shortPkt({ dcid: CCID, pn, firstByte: 0x59, parts: [["STREAM frame, stream 4, offset 0, FIN: style.css", 1150]] });
const respJpg = () => shortPkt({ dcid: CCID, pn: 6, firstByte: 0x5b, parts: [["STREAM frame, stream 8, offset 0: photo.jpg (first part)", 1150]] });
const ackGap = () =>
  shortPkt({ dcid: SCID, pn: 4, parts: [["ACK frame: largest 6, ranges 6 and ≤4 (5 missing)", 7, "Largest Acknowledged 6, First ACK Range 0, then a Gap that skips packet 5."]] });

// ------------------------------------------------------------ migration scenario (captured on the server)
const UPSTREAM_MAC = "00:1b:21:aa:00:01";
const MOBILE_IP = "198.51.100.200";
const atServerIn = (srcIp: string, sport: number, ...l: LayerSpec[]) =>
  build(eth({ src: UPSTREAM_MAC, dst: ADDR.serverMac }), ipv4({ src: srcIp, dst: S, ttl: 52 }), udp({ sport, dport: 443 }), ...l);
const atServerOut = (dstIp: string, dport: number, ...l: LayerSpec[]) =>
  build(eth({ src: ADDR.serverMac, dst: UPSTREAM_MAC }), ipv4({ src: S, dst: dstIp, ttl: 64 }), udp({ sport: 443, dport }), ...l);
const WIFI_PORT = 40122;
const MOB_PORT = 61003;

const base = homeToServer();
const migDevices: Device[] = [
  { id: "client", kind: "phone", label: "Phone", sub: "Wi-Fi, then 4G", x: 9, y: 55 },
  { id: "router", kind: "router", label: "Home Wi-Fi", sub: ADDR.routerWan, x: 32, y: 76 },
  { id: "tower", kind: "tower", label: "Mobile network", sub: MOBILE_IP, x: 32, y: 24 },
  { id: "internet", kind: "cloud", label: "Internet", x: 60, y: 45 },
  { id: "server", kind: "web", label: "Video server", sub: S, x: 88, y: 55 },
];
const migLinks: [string, string][] = [["client", "router"], ["client", "tower"], ["router", "internet"], ["tower", "internet"], ["internet", "server"]];
const viaWifi = ["router", "internet"];
const viaMobile = ["tower", "internet"];
const viaWifiBack = ["internet", "router"];
const viaMobileBack = ["internet", "tower"];

export default defineLesson({
  id: "quic",
  name: "QUIC",
  full: "QUIC and HTTP/3",
  group: "foundations",
  layer: 4,
  difficulty: 3,
  tagline: "Encrypted, multiplexed transport over UDP that powers HTTP/3.",
  description:
    "QUIC is a transport protocol built on UDP. It merges the TCP and TLS handshakes into one round trip, encrypts almost every header bit, carries many independent streams in one connection, and identifies the connection by an ID instead of IP addresses so it survives a network change.",
  facts: [
    ["Layer", "Transport (Layer 4), runs on UDP"],
    ["Port", "UDP 443"],
    ["Handshake", "TLS 1.3 inside QUIC, 1 RTT"],
    ["Streams", "Many, independent"],
    ["Min client Initial", "1200 bytes"],
    ["Defined in", "RFC 9000, 9001, 9114 (HTTP/3)"],
  ],
  ports: "UDP 443",
  rfc: "RFC 9000",
  keywords: ["http3", "http/3", "udp", "connection id", "0-rtt", "head of line blocking", "migration", "initial packet", "tls 1.3", "streams"],
  related: ["tcp", "udp", "tls", "http2", "webrtc"],
  devices: base.devices,
  links: base.links,
  legend: [
    ["teal", "Handshake (Initial / Handshake packets)"],
    ["amber", "Requests from the laptop"],
    ["violet", "Data from the server"],
    ["green", "ACKs and confirmations"],
    ["blue", "Path checks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Load a page over HTTP/3",
      summary: "One round trip sets up an encrypted QUIC connection, then GET / goes out on stream 0.",
      kind: "normal",
      steps: [
        {
          title: "Client Initial",
          desc: "ClientHello in a 1200-byte UDP datagram",
          detail:
            "The browser sends a long-header Initial packet. Its CRYPTO frame holds a normal TLS 1.3 ClientHello. Initial packets are encrypted with keys derived from the destination connection ID, so anyone can decrypt them, but routers still can’t tamper unnoticed. Padding makes the datagram 1200 bytes so the server never sends back more than three times what it received from an unverified address.",
          facts: [["UDP payload", "1200 bytes (27 header + 1173 encrypted)"], ["DCID", `${DCID0} (random)`], ["Inside", "CRYPTO(ClientHello) + PADDING"]],
          quiz: {
            q: "Why is the client Initial padded to 1200 bytes?",
            options: ["Ethernet needs it", "To limit amplification: the server may send only 3× what it receives before the address is verified", "To hide the ClientHello length", "Because TLS needs it"],
            answer: 1,
            why: "A big first packet gives the server a larger anti-amplification budget, so its certificate fits, while spoofed tiny packets can’t trigger huge replies.",
          },
          events: [
            pkt("client", "server", "teal", "INITIAL", ["ClientHello", "1200 bytes"], { time: 0, info: `Initial, DCID=${DCID0}, SCID=${CCID}, PKN: 0, CRYPTO, PADDING`, packet: fromLaptop(clientInitial()) }),
          ],
        },
        {
          title: "Server Initial + Handshake",
          desc: "ServerHello, then the certificate",
          detail:
            "The server answers with its own Initial (ServerHello, plus an ACK) and, in the same UDP datagram, a Handshake packet encrypted with the new handshake keys. Putting several QUIC packets in one datagram is called coalescing. The certificate does not fit, so a second datagram finishes it along with CertificateVerify and Finished. Note the server picked its own connection ID.",
          facts: [["Datagram 1", "Initial (145 B) + Handshake (1055 B)"], ["Datagram 2", "Handshake (980 B)"], ["New server CID", SCID]],
          events: [
            pkt("server", "client", "teal", "INIT+HS", ["ServerHello", "certificate (start)"], { time: 0.034, info: `Initial, DCID=${CCID}, SCID=${SCID}, PKN: 0, ACK, CRYPTO; Handshake, PKN: 0, CRYPTO`, packet: toLaptop(serverInitial(), serverHs1()) }),
            pkt("server", "client", "teal", "HANDSHAKE", ["certificate (end)", "Finished"], { time: 0.0341, parallel: true, info: `Handshake, DCID=${CCID}, SCID=${SCID}, PKN: 1, CRYPTO`, packet: toLaptop(serverHs2()) }),
          ],
        },
        {
          title: "Finish and ask at once",
          desc: "Client Finished and GET / together",
          detail:
            "The client checks the certificate, sends its Finished in a Handshake packet, and in the very same moment sends the HTTP/3 request in a 1-RTT packet. That packet has a short header: no version, no lengths, just the server’s connection ID and a protected packet number. The request is a HEADERS frame on stream 0, the first client-opened two-way stream.",
          facts: [["Handshake cost", "1 round trip (TCP + TLS needs 2)"], ["Request on", "Stream 0"], ["Header", "Short: 1 + 8 + 1 bytes"]],
          quiz: {
            q: "How many round trips pass before the laptop can send its GET?",
            options: ["0", "1", "2", "3"],
            answer: 1,
            why: "QUIC does the transport and TLS 1.3 handshakes together, so the request goes out after one round trip. TCP + TLS 1.3 takes two.",
          },
          events: [
            pkt("client", "server", "green", "INIT+HS", ["ACKs", "client Finished"], { time: 0.035, info: `Initial, PKN: 1, ACK, PADDING; Handshake, PKN: 0, ACK, CRYPTO`, packet: fromLaptop(clientInitial2(), clientHs()) }),
            pkt("client", "server", "amber", "GET /", ["1-RTT, stream 0", "HEADERS"], { time: 0.0351, parallel: true, info: `Protected Payload (KP0), DCID=${SCID}, PKN: 0, STREAM(2), STREAM(0)`, packet: fromLaptop(request()) }),
          ],
        },
        {
          title: "The response",
          desc: "HANDSHAKE_DONE, 200 OK and the page",
          detail:
            "The server confirms the handshake with a HANDSHAKE_DONE frame and returns the page on stream 0: a HEADERS frame (status 200) then a DATA frame. The FIN bit on the STREAM frame closes stream 0. Everything after the first byte and the connection ID is encrypted, even the packet number.",
          facts: [["Status", "200"], ["Stream 0", "Closed with FIN"], ["Visible to routers", "Connection ID only"]],
          quiz: {
            q: "What can a router on the path read in this 1-RTT packet?",
            options: ["The URL", "The packet number and ACKs", "Only the first byte, the connection ID and the UDP/IP headers", "Everything, QUIC is plain text"],
            answer: 2,
            why: "Short header packets expose just the flags byte and destination CID. Frames, including ACKs and stream data, are encrypted, and the packet number is masked.",
          },
          events: [
            pkt("server", "client", "violet", "200 OK", ["HANDSHAKE_DONE", "page on stream 0"], { time: 0.069, info: `Protected Payload (KP0), DCID=${CCID}, PKN: 0, DONE, ACK, STREAM(0)`, packet: toLaptop(response()) }),
          ],
        },
        {
          title: "Acknowledge",
          desc: "ACKs are frames, and encrypted",
          detail:
            "The laptop acknowledges packet 0 with an ACK frame in a small 1-RTT packet. Unlike TCP, QUIC acknowledges packet numbers, not byte offsets, and never reuses a packet number, so it always knows whether an ACK is for an original or a resent packet.",
          facts: [["Acknowledges", "1-RTT packet 0"], ["Size", "31-byte QUIC packet"], ["Packet numbers", "Never reused"]],
          events: [
            pkt("client", "server", "green", "ACK", ["ack 1-RTT 0"], { time: 0.07, info: `Protected Payload (KP0), DCID=${SCID}, PKN: 1, ACK`, packet: fromLaptop(ackOnly(1, "1-RTT 0")) }),
            note("client", "PAGE LOADED IN 70 MS", "green"),
          ],
        },
      ],
      outro: {
        title: "HTTP/3 in one round trip",
        text: "QUIC carried the TLS 1.3 handshake in CRYPTO frames, switched to short-header packets after one round trip, and sent the request on stream 0. Almost nothing is visible on the wire except connection IDs, which keeps middleboxes from freezing the protocol in place.",
        facts: [["Datagrams", "7"], ["Round trips to first byte", "2 (1 handshake + 1 request)"], ["Connection IDs", `${CCID} / ${SCID}`], ["Total", "70 ms"]],
      },
    },
    {
      id: "loss",
      name: "One lost packet, one stalled stream",
      summary: "Two files load on two streams. A packet for one is lost; the other keeps flowing.",
      kind: "failure",
      steps: [
        {
          title: "Two requests",
          desc: "style.css on stream 4, photo.jpg on stream 8",
          detail:
            "The connection is already open. The browser asks for two files at once, each on its own stream: stream 4 for style.css and stream 8 for photo.jpg. Both requests fit in one 1-RTT packet.",
          facts: [["Stream 4", "GET /style.css"], ["Stream 8", "GET /photo.jpg"], ["Packet", "1-RTT, PKN 3"]],
          events: [
            pkt("client", "server", "amber", "GET ×2", ["stream 4: css", "stream 8: jpg"], { time: 0, info: `Protected Payload (KP0), DCID=${SCID}, PKN: 3, STREAM(4), STREAM(8)`, packet: fromLaptop(twoRequests()) }),
          ],
        },
        {
          title: "Packet 5 is lost",
          desc: "Only stream 4 is affected",
          detail:
            "The server sends packet 5 (style.css) and packet 6 (first part of photo.jpg). Packet 5 is dropped on the internet. Packet 6 arrives, and QUIC hands its photo bytes to the browser straight away, because stream 8 has no gap. Only stream 4 has to wait.",
          facts: [["Lost", "PKN 5 (stream 4)"], ["Delivered", "PKN 6 (stream 8)"], ["Stream 8", "Keeps going"]],
          quiz: {
            q: "Over HTTP/2 on TCP, what would happen to the photo bytes in this situation?",
            options: ["Delivered at once, like QUIC", "Held back by TCP until the lost bytes are resent", "Dropped and requested again", "Sent on a new TCP connection"],
            answer: 1,
            why: "TCP is one ordered byte stream. Bytes after a gap wait in the buffer even if they belong to a different HTTP/2 stream: head-of-line blocking.",
          },
          events: [
            pkt("server", "client", "violet", "PKN 5", ["stream 4: style.css"], { time: 0.034, lost: true, info: `Protected Payload (KP0), DCID=${CCID}, PKN: 5, STREAM(4)`, packet: toLaptop(respCss(5)) }),
            pkt("server", "client", "violet", "PKN 6", ["stream 8: photo.jpg"], { time: 0.0341, parallel: true, info: `Protected Payload (KP0), DCID=${CCID}, PKN: 6, STREAM(8)`, packet: toLaptop(respJpg()) }),
            note("internet", "PKN 5 LOST", "amber"),
            note("client", "PHOTO BYTES DELIVERED", "green"),
          ],
        },
        {
          title: "ACK with a gap",
          desc: "Got 6, missing 5",
          detail:
            "The laptop sends an ACK frame: largest acknowledged 6, then a gap that skips 5. When the server sees a later packet acknowledged and 5 still missing (and time has passed), it declares 5 lost.",
          facts: [["Largest acked", "6"], ["Missing", "5"], ["Loss rule", "3 later packets acked, or about 9/8 RTT passed"]],
          events: [
            pkt("client", "server", "green", "ACK", ["got 6", "missing 5"], { time: 0.035, info: `Protected Payload (KP0), DCID=${SCID}, PKN: 4, ACK`, packet: fromLaptop(ackGap()) }),
          ],
        },
        {
          title: "Resend in a new packet",
          desc: "Same data, new packet number",
          detail:
            "The server sends the style.css bytes again. QUIC resends frames, not packets, so the data goes in a brand-new packet with a new number. There is never confusion about which copy an ACK refers to, which makes round-trip measurements exact.",
          facts: [["Resent", "Stream 4, offset 0"], ["New PKN", "7"], ["Stream 8", "Was never paused"]],
          quiz: {
            q: "Which packet number carries the resent style.css data?",
            options: ["5 again", "7, the next new number", "0", "It reuses the TCP sequence number"],
            answer: 1,
            why: "QUIC packet numbers only go up. Lost frames are put into the next new packet.",
          },
          events: [
            pkt("server", "client", "violet", "PKN 7", ["stream 4 again", "new number"], { time: 0.069, info: `Protected Payload (KP0), DCID=${CCID}, PKN: 7, STREAM(4)`, packet: toLaptop(respCss(7)) }),
            pkt("client", "server", "green", "ACK", ["got 7"], { time: 0.07, info: `Protected Payload (KP0), DCID=${SCID}, PKN: 5, ACK`, packet: fromLaptop(ackOnly(5, "largest 7")) }),
          ],
        },
      ],
      outro: {
        title: "No head-of-line blocking",
        text: "Because QUIC tracks ordering per stream, one lost packet only delays the stream whose data it carried. With TCP, every HTTP/2 stream would have stalled until the gap was filled.",
        facts: [["Stalled", "Stream 4 for one RTT"], ["Unaffected", "Stream 8"], ["Retransmits", "Frames in new packets"]],
      },
    },
    {
      id: "migration",
      name: "Wi-Fi to mobile data, same connection",
      summary: "A phone walks out of Wi-Fi range mid-video. The QUIC connection moves to mobile data without restarting.",
      kind: "normal",
      devices: migDevices,
      links: migLinks,
      steps: [
        {
          title: "Watching over Wi-Fi",
          desc: "Captured on the server this time",
          detail:
            `This capture is taken on the video server. The phone’s packets arrive from the home router’s public address ${ADDR.routerWan}, port ${WIFI_PORT}. The server knows the connection by its connection ID ${SCID}, not by that address.`,
          facts: [["From", `${ADDR.routerWan}:${WIFI_PORT}`], ["DCID", SCID], ["Stream", "Video segments"]],
          events: [
            pkt("client", "server", "green", "ACK", ["via Wi-Fi"], { time: 0, via: viaWifi, info: `Protected Payload (KP0), DCID=${SCID}, PKN: 40, ACK`, packet: atServerIn(ADDR.routerWan, WIFI_PORT, ackOnly(40, "largest 81")) }),
            pkt("server", "client", "violet", "VIDEO", ["stream 12"], { time: 0.03, via: viaWifiBack, info: `Protected Payload (KP0), DCID=${CCID}, PKN: 82, STREAM(12)`, packet: atServerOut(ADDR.routerWan, WIFI_PORT, respCss(82)) }),
          ],
        },
        {
          title: "Switch to mobile data",
          desc: "New IP and port, same connection",
          detail:
            `The phone leaves Wi-Fi and its next packet goes out over 4G from ${MOBILE_IP}:${MOB_PORT}. A TCP connection would be dead: its identity is the address/port pair. QUIC looks up the destination connection ID instead and finds the existing connection. (Phones may also switch to a spare ID the server handed out earlier, so watchers can’t link the two paths; the idea is the same.)`,
          facts: [["New source", `${MOBILE_IP}:${MOB_PORT}`], ["DCID", `${SCID} (unchanged)`], ["TCP would", "Reset and start over"]],
          quiz: {
            q: "How does the server know this packet from a new address belongs to the old connection?",
            options: ["The IP address", "The destination connection ID", "A cookie in the HTTP header", "It doesn’t; it starts a new handshake"],
            answer: 1,
            why: "QUIC routes packets to connections by connection ID, so a change of address or port is just a new path.",
          },
          events: [
            note("router", "WI-FI LOST", "amber"),
            pkt("client", "server", "green", "ACK", ["via 4G", "same CID"], { time: 2.1, via: viaMobile, info: `Protected Payload (KP0), DCID=${SCID}, PKN: 41, ACK`, packet: atServerIn(MOBILE_IP, MOB_PORT, ackOnly(41, "largest 82")) }),
            note("server", "SAME CONNECTION ID", "green"),
          ],
        },
        {
          title: "Check the new path",
          desc: "PATH_CHALLENGE and PATH_RESPONSE",
          detail:
            "Before trusting the new address, the server sends a PATH_CHALLENGE frame with 8 random bytes. Only a phone that really sits at that address can read it and echo the bytes in a PATH_RESPONSE. Until then, the server limits how much it sends there, so an attacker can’t redirect traffic onto a victim.",
          facts: [["Challenge", "8 random bytes"], ["Response", "Same 8 bytes"], ["Until checked", "3× amplification limit"]],
          events: [
            pkt("server", "client", "blue", "CHALLENGE", ["8 random bytes"], { time: 2.101, via: viaMobileBack, info: `Protected Payload (KP0), DCID=${CCID}, PKN: 83, PATH_CHALLENGE`, packet: atServerOut(MOBILE_IP, MOB_PORT, shortPkt({ dcid: CCID, pn: 83, firstByte: 0x58, parts: [["PATH_CHALLENGE frame", 9, "Type 0x1a + 8 random bytes."], ["PADDING frames", 1165, "Padded to 1200 bytes to check the path carries full-size packets."]] })) }),
            pkt("client", "server", "blue", "RESPONSE", ["same 8 bytes"], { time: 2.161, via: viaMobile, info: `Protected Payload (KP0), DCID=${SCID}, PKN: 42, PATH_RESPONSE`, packet: atServerIn(MOBILE_IP, MOB_PORT, shortPkt({ dcid: SCID, pn: 42, parts: [["PATH_RESPONSE frame", 9, "Type 0x1b + the same 8 bytes."], ["PADDING frames", 1165]] })) }),
          ],
        },
        {
          title: "Video keeps playing",
          desc: "Data now flows over 4G",
          detail:
            "The path is confirmed and the server sends the next video data to the new address. Streams, encryption keys and congestion state from before carry on (the sender resets its congestion estimate for the new path). The viewer sees, at most, a short pause.",
          facts: [["Handshakes redone", "0"], ["Streams kept", "All"], ["Gap", "About one RTT"]],
          events: [
            pkt("server", "client", "violet", "VIDEO", ["stream 12", "via 4G"], { time: 2.162, via: viaMobileBack, info: `Protected Payload (KP0), DCID=${CCID}, PKN: 84, STREAM(12)`, packet: atServerOut(MOBILE_IP, MOB_PORT, respCss(84)) }),
            note("client", "NO REBUFFERING", "green"),
          ],
        },
      ],
      outro: {
        title: "Connection migration",
        text: "Identifying the connection by an ID instead of the IP/port pair lets QUIC survive network changes. Path validation makes sure the new address is real before sending much data to it.",
        facts: [["Identity", "Connection ID"], ["Path check", "PATH_CHALLENGE / RESPONSE"], ["TCP equivalent", "Would need a new connection"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Packet types",
      items: [["Initial", "Long header, ClientHello / ServerHello"], ["Handshake", "Long header, rest of TLS"], ["0-RTT", "Early data on resumption"], ["Retry", "Server asks client to prove its address"], ["1-RTT", "Short header, all app data"]],
    },
    {
      title: "Common frames",
      items: [["0x00 / 0x01", "PADDING / PING"], ["0x02", "ACK"], ["0x06", "CRYPTO"], ["0x08–0x0f", "STREAM"], ["0x1a / 0x1b", "PATH_CHALLENGE / PATH_RESPONSE"], ["0x1e", "HANDSHAKE_DONE"]],
    },
    {
      title: "Numbers to know",
      items: [["Client Initial", "≥ 1200 bytes"], ["Amplification limit", "3× before address is validated"], ["Stream IDs", "0, 4, 8… client bidirectional"], ["Varint sizes", "1, 2, 4 or 8 bytes (top 2 bits)"]],
    },
  ],
});
