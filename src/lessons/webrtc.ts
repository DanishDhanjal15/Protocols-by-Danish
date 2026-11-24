import { defineLesson, note, pkt, Device } from "@/lib/lesson";
import { build, field, Field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ext, ipv4, tcp, tls, udp, vec } from "@/lib/proto";
import { Bytes, crc32, hex, ip4, u16, u32 } from "@/lib/bytes";
import { ADDR, down, up } from "./_common";

// ---------------------------------------------------------------- addresses

const SIG = "203.0.113.10"; // signalling server (WebSocket over TLS)
const STUN_IP = "192.0.2.19";
const TURN_IP = "192.0.2.30";
const PEER_PUB = "203.0.113.77"; // friend's home router (public side)
const PEER_LAN = "192.168.0.20";
const PEER_MAC = "a4:83:e7:12:9b:40";
const PEER_GW = "00:1e:58:a1:22:07";
const TURN_MAC = "00:16:3e:77:30:01";
const TURN_GW = "00:00:5e:00:01:01";
const LP = 54321; // laptop's UDP port for media
const MAPPED_PORT = 61001; // what the home router turns it into
const PP = 50000; // friend's public (mapped) port
const WSP = 50112; // laptop's TCP port to the signalling server
const RELAY_PORT = 49170;

const hex4 = (n: number) => n.toString(16).padStart(4, "0");

// ---------------------------------------------------------------- STUN (RFC 8489)

const COOKIE = 0x2112a442;
const COOKIE_B = u32(COOKIE);

const STUN_TYPES: Record<number, string> = {
  0x0001: "Binding Request",
  0x0101: "Binding Success Response",
  0x0003: "Allocate Request",
  0x0103: "Allocate Success Response",
  0x0113: "Allocate Error Response",
  0x0009: "ChannelBind Request",
  0x0109: "ChannelBind Success Response",
};

interface Attr {
  type: number;
  name: string;
  fields: FieldSpec[];
  value?: string;
  note?: string;
}

/** A full STUN message. Lengths and the FINGERPRINT CRC are computed from the real bytes. */
function stun(type: number, tx: string, attrs: Attr[], fingerprint = true): LayerSpec {
  return {
    kind: "stun",
    build: () => {
      const attrFields: Field[] = [];
      const attrBytes: Bytes = [];
      for (const a of attrs) {
        const data = a.fields.map(field).flatMap((f) => f.bytes);
        const pad = (4 - (data.length % 4)) % 4;
        const f = field({
          name: `Attribute: ${a.name}`,
          value: a.value ?? `${data.length} bytes`,
          note: a.note,
          fields: [
            { name: "Type", u16: a.type, value: `0x${hex4(a.type)} (${a.name})` },
            { name: "Length", u16: data.length, note: "Length of the value, not counting padding." },
            ...a.fields,
            ...(pad ? [{ name: "Padding", zero: pad, note: "Every attribute is padded to a multiple of 4 bytes." }] : []),
          ],
        });
        attrFields.push(f);
        attrBytes.push(...f.bytes);
      }
      const len = attrBytes.length + (fingerprint ? 8 : 0);
      const txb = hex(tx);
      const header = [...u16(type), ...u16(len), ...COOKIE_B, ...txb];
      if (fingerprint) {
        const crc = (crc32([...header, ...attrBytes]) ^ 0x5354554e) >>> 0;
        attrFields.push(
          field({
            name: "Attribute: FINGERPRINT",
            value: `0x${crc.toString(16).padStart(8, "0")}`,
            note: "CRC-32 of the whole message before this attribute, XORed with 0x5354554e. It lets a receiver tell STUN apart from RTP or DTLS on the same port.",
            fields: [
              { name: "Type", u16: 0x8028, value: "0x8028 (FINGERPRINT)" },
              { name: "Length", u16: 4 },
              { name: "CRC-32 XOR 0x5354554e", u32: crc, value: `0x${crc.toString(16).padStart(8, "0")}` },
            ],
          })
        );
      }
      const fields: Field[] = [
        field({ name: "Message type", u16: type, value: `0x${hex4(type)} (${STUN_TYPES[type] ?? "?"})`, note: "The first two bits are always 0. The rest mixes the method (Binding, Allocate…) and the class (request, success, error)." }),
        field({ name: "Message length", u16: len, value: `${len} bytes`, note: "Length of all attributes after the 20-byte header." }),
        field({ name: "Magic cookie", bytes: COOKIE_B, value: "0x2112a442", note: "Fixed value. It marks a modern STUN message and is the key for the XOR tricks below." }),
        field({ name: "Transaction ID", bytes: txb, value: `0x${tx}`, note: "12 random bytes. The response copies them so the client can match it to the request." }),
        ...attrFields,
      ];
      return { id: "stun", name: "STUN", osi: 7, summary: `Session Traversal Utilities for NAT: ${STUN_TYPES[type] ?? "?"}`, fields };
    },
  };
}

/** XOR-MAPPED-ADDRESS style value: port XOR 0x2112, address XOR magic cookie. */
const xorAddr = (ip: string, port: number): FieldSpec[] => [
  { name: "Reserved", u8: 0 },
  { name: "Family", u8: 1, value: "IPv4 (0x01)" },
  { name: "X-Port", u16: port ^ 0x2112, value: `0x${hex4(port ^ 0x2112)} → port ${port}`, note: `The real port XORed with 0x2112 (the top half of the cookie): ${port} ^ 0x2112 = ${port ^ 0x2112}.` },
  {
    name: "X-Address",
    bytes: ip4(ip).map((b, i) => b ^ COOKIE_B[i]),
    value: `→ ${ip}`,
    note: "The real address XORed with the magic cookie. Some old NAT boxes rewrite any IP they see inside packets; scrambling it stops them breaking the answer.",
  },
];

const A = {
  xorMapped: (ip: string, port: number, note = "Your address and port as the other side saw them, after your router’s NAT changed them."): Attr => ({ type: 0x0020, name: "XOR-MAPPED-ADDRESS", fields: xorAddr(ip, port), value: `${ip}:${port}`, note }),
  xorRelayed: (ip: string, port: number): Attr => ({ type: 0x0016, name: "XOR-RELAYED-ADDRESS", fields: xorAddr(ip, port), value: `${ip}:${port}`, note: "The public address the TURN server opened for you. Anything sent here is passed on to you." }),
  xorPeer: (ip: string, port: number): Attr => ({ type: 0x0012, name: "XOR-PEER-ADDRESS", fields: xorAddr(ip, port), value: `${ip}:${port}`, note: "The friend’s address, as the TURN server will see it." }),
  username: (u: string, note?: string): Attr => ({ type: 0x0006, name: "USERNAME", fields: [{ name: "Username", text: u }], value: u, note }),
  priority: (p: number): Attr => ({ type: 0x0024, name: "PRIORITY", fields: [{ name: "Priority", u32: p }], value: String(p), note: "The priority this path would have if it is learned from this check." }),
  controlling: (): Attr => ({ type: 0x802a, name: "ICE-CONTROLLING", fields: [{ name: "Tie breaker", bytes: "6b2f90c1d4e8a713", value: "0x6b2f90c1d4e8a713" }], value: "tie breaker", note: "This side (the caller) picks the final path." }),
  controlled: (): Attr => ({ type: 0x8029, name: "ICE-CONTROLLED", fields: [{ name: "Tie breaker", bytes: "1c55e2a09b3f7d48", value: "0x1c55e2a09b3f7d48" }], value: "tie breaker", note: "This side follows the caller’s choice." }),
  candidateFlag: (): Attr => ({ type: 0x0025, name: "USE-CANDIDATE", fields: [], value: "(flag)", note: "The controlling side says: if this check works, use this path." }),
  integrity: (seed: number): Attr => ({ type: 0x0008, name: "MESSAGE-INTEGRITY", fields: [{ name: "HMAC-SHA1", random: 20, seed, opaque: true }], value: "20-byte HMAC", note: "A keyed hash using the password from the SDP (or the TURN password). A stranger cannot forge a check." }),
  transport: (): Attr => ({ type: 0x0019, name: "REQUESTED-TRANSPORT", fields: [{ name: "Protocol", u8: 17, value: "17 (UDP)" }, { name: "Reserved", zero: 3 }], value: "UDP" }),
  error401: (): Attr => ({ type: 0x0009, name: "ERROR-CODE", fields: [{ name: "Reserved", zero: 2 }, { name: "Class", u8: 4 }, { name: "Number", u8: 1 }, { name: "Reason", text: "Unauthorized" }], value: "401 Unauthorized", note: "Class 4 and number 01 make 401: prove who you are first." }),
  realm: (): Attr => ({ type: 0x0014, name: "REALM", fields: [{ name: "Realm", text: "example.com" }], value: "example.com" }),
  nonce: (): Attr => ({ type: 0x0015, name: "NONCE", fields: [{ name: "Nonce", text: "8f3c1a6e2b9d4f70" }], value: "8f3c1a6e2b9d4f70", note: "A fresh value the client must use in its next request, so old requests can’t be replayed." }),
  lifetime: (s: number): Attr => ({ type: 0x000d, name: "LIFETIME", fields: [{ name: "Seconds", u32: s }], value: `${s} s`, note: "The relay closes unless the client refreshes it before then." }),
  channel: (n: number): Attr => ({ type: 0x000c, name: "CHANNEL-NUMBER", fields: [{ name: "Channel", u16: n, value: `0x${hex4(n)}` }, { name: "Reserved", zero: 2 }], value: `0x${hex4(n)}`, note: "A 2-byte nickname for the friend’s address, so relayed media needs only a 4-byte header." }),
};

// ICE priority = 2^24 * type pref + 2^8 * local pref + (256 - component)
const PRFLX_PRIO = 110 * 2 ** 24 + 65535 * 2 ** 8 + 255;

// ---------------------------------------------------------------- DTLS 1.2 (RFC 6347)

const DTLS_CT: Record<number, string> = { 20: "Change Cipher Spec", 22: "Handshake", 23: "Application Data" };

const dtlsRec = (ct: number, epoch: number, seq: number, body: FieldSpec[], note?: string): FieldSpec => {
  const len = body.map(field).flatMap((f) => f.bytes).length;
  return {
    name: `DTLS record: ${DTLS_CT[ct]}`,
    value: `${len + 13} bytes`,
    note,
    fields: [
      { name: "Content type", u8: ct, value: `${ct} (${DTLS_CT[ct]})` },
      { name: "Version", u16: 0xfefd, value: "DTLS 1.2 (0xfefd)" },
      { name: "Epoch", u16: epoch, note: epoch ? "Epoch 1: protected with the new keys." : "Epoch 0: nothing is encrypted yet." },
      { name: "Sequence number", bytes: [0, 0, ...u32(seq)], value: String(seq), note: "UDP can reorder or lose datagrams, so DTLS numbers every record." },
      { name: "Length", u16: len },
      ...body,
    ],
  };
};

const HS: Record<number, string> = { 1: "ClientHello", 2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateVerify", 16: "ClientKeyExchange" };

const dtlsHs = (type: number, msgSeq: number, body: FieldSpec[], note?: string): FieldSpec => {
  const len = body.map(field).flatMap((f) => f.bytes).length;
  return {
    name: HS[type],
    value: `${len + 12} bytes`,
    note,
    fields: [
      { name: "Handshake type", u8: type, value: `${type} (${HS[type]})` },
      { name: "Length", u24: len },
      { name: "Message sequence", u16: msgSeq, note: "Lets the receiver put handshake messages back in order." },
      { name: "Fragment offset", u24: 0 },
      { name: "Fragment length", u24: len, note: "The whole message fits in one record, so no fragmenting." },
      ...body,
    ],
  };
};

const hsRec = (epochSeq: number, type: number, msgSeq: number, body: FieldSpec[], note?: string) => dtlsRec(22, 0, epochSeq, [dtlsHs(type, msgSeq, body, note)]);

const dtls = (records: FieldSpec[], summary: string): LayerSpec =>
  proto({ id: "dtls", name: "DTLS", osi: 6, summary: `Datagram Transport Layer Security: ${summary}`, fields: records });

const clientHello = hsRec(0, 1, 0, [
  { name: "Version", u16: 0xfefd, value: "DTLS 1.2" },
  { name: "Random", random: 32, seed: 501, note: "32 fresh random bytes, mixed into the keys." },
  { name: "Session ID length", u8: 0 },
  { name: "Cookie length", u8: 0 },
  vec("Cipher suites", 2, [
    { name: "Suite", u16: 0xc02b, value: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { name: "Suite", u16: 0xc02f, value: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
    { name: "Suite", u16: 0xcca9, value: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" },
  ], "3 suites"),
  vec("Compression methods", 1, [{ name: "Method", u8: 0, value: "null" }], "null"),
  vec("Extensions", 2, [
    ext(10, "supported_groups", [0, 4, 0, 0x1d, 0, 0x17], "x25519, secp256r1"),
    ext(11, "ec_point_formats", [1, 0], "uncompressed"),
    ext(13, "signature_algorithms", [0, 4, 4, 3, 8, 4], "ecdsa_secp256r1_sha256, rsa_pss_sha256"),
    ext(14, "use_srtp", [0, 4, 0, 7, 0, 1, 0], "SRTP_AEAD_AES_128_GCM, SRTP_AES128_CM_HMAC_SHA1_80", "Asks to derive keys for SRTP from this handshake. This is the reason WebRTC runs DTLS at all."),
    ext(23, "extended_master_secret", []),
  ]),
], "The friend’s phone is the DTLS client here because its answer said a=setup:active.");

const serverFlight = [
  hsRec(0, 2, 0, [
    { name: "Version", u16: 0xfefd, value: "DTLS 1.2" },
    { name: "Random", random: 32, seed: 502 },
    { name: "Session ID length", u8: 0 },
    { name: "Cipher suite", u16: 0xc02b, value: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" },
    { name: "Compression", u8: 0 },
    vec("Extensions", 2, [
      ext(14, "use_srtp", [0, 2, 0, 1, 0], "SRTP_AES128_CM_HMAC_SHA1_80", "The laptop picks the SRTP profile."),
      ext(23, "extended_master_secret", []),
    ]),
  ]),
  hsRec(1, 11, 1, [
    { name: "Certificates length", u24: 287 },
    { name: "Certificate length", u24: 284 },
    { name: "Self-signed certificate (DER)", random: 284, seed: 503, opaque: true, note: "Made by the browser for this call. Nobody signed it; instead its SHA-256 fingerprint was sent in the SDP, and the friend checks that it matches." },
  ]),
  hsRec(2, 12, 2, [
    { name: "Curve type", u8: 3, value: "named_curve" },
    { name: "Named curve", u16: 0x001d, value: "x25519" },
    { name: "Public key length", u8: 32 },
    { name: "Public key", random: 32, seed: 504, note: "The laptop’s half of the key exchange." },
    { name: "Signature algorithm", u16: 0x0403, value: "ecdsa_secp256r1_sha256" },
    { name: "Signature length", u16: 71 },
    { name: "Signature", random: 71, seed: 505, opaque: true, note: "Signed with the certificate’s key, so the key share is tied to the fingerprint in the SDP." },
  ]),
  hsRec(3, 13, 3, [
    vec("Certificate types", 1, [{ name: "Type", u8: 64, value: "ecdsa_sign" }], "ecdsa_sign"),
    vec("Signature algorithms", 2, [{ name: "Algorithm", u16: 0x0403, value: "ecdsa_secp256r1_sha256" }], "ecdsa_secp256r1_sha256"),
    { name: "Distinguished names length", u16: 0 },
  ], "Both ends must show a certificate: each checks the other against the fingerprint in the SDP."),
  hsRec(4, 14, 4, []),
];

const clientFlight = [
  hsRec(1, 11, 1, [
    { name: "Certificates length", u24: 287 },
    { name: "Certificate length", u24: 284 },
    { name: "Self-signed certificate (DER)", random: 284, seed: 506, opaque: true, note: "The friend’s browser certificate. Its fingerprint was in the SDP answer." },
  ]),
  hsRec(2, 16, 2, [{ name: "Public key length", u8: 32 }, { name: "Public key", random: 32, seed: 507, note: "The friend’s half of the key exchange." }]),
  hsRec(3, 15, 3, [{ name: "Signature algorithm", u16: 0x0403, value: "ecdsa_secp256r1_sha256" }, { name: "Signature length", u16: 70 }, { name: "Signature", random: 70, seed: 508, opaque: true }]),
  dtlsRec(20, 0, 4, [{ name: "Change cipher spec", u8: 1, note: "From now on this side encrypts." }]),
  dtlsRec(22, 1, 0, [{ name: "Encrypted Finished", random: 48, seed: 509, opaque: true, note: "A hash of the whole handshake, encrypted. Proves nobody changed anything on the way." }]),
];

const serverFinish = [
  dtlsRec(20, 0, 5, [{ name: "Change cipher spec", u8: 1 }]),
  dtlsRec(22, 1, 0, [{ name: "Encrypted Finished", random: 48, seed: 510, opaque: true }]),
];

// ---------------------------------------------------------------- RTP / SRTP

const rtpHeader = (o: { pt: number; seq: number; ts: number; ssrc: number; marker?: boolean }): FieldSpec[] => [
  { name: "V, P, X, CC", u8: 0x80, value: "V=2, no padding, no extension, 0 CSRC", note: "Version 2 is the only RTP version in use." },
  { name: "Marker, payload type", u8: ((o.marker ? 1 : 0) << 7) | o.pt, value: `M=${o.marker ? 1 : 0}, PT=${o.pt}`, note: `Payload type ${o.pt} was mapped to a codec in the SDP (${o.pt === 96 ? "96 = VP8 video" : o.pt === 111 ? "111 = Opus audio" : "dynamic"}). The marker bit flags the last packet of a video frame.` },
  { name: "Sequence number", u16: o.seq, note: "Goes up by one per packet, so the receiver can spot loss and reordering." },
  { name: "Timestamp", u32: o.ts, note: o.pt === 111 ? "Audio clock, 48 000 ticks per second." : "Video clock, 90 000 ticks per second. All packets of one frame share it." },
  { name: "SSRC", u32: o.ssrc, value: `0x${o.ssrc.toString(16)}`, note: "A random number naming this media stream." },
];

const srtp = (o: { pt: number; seq: number; ts: number; ssrc: number; marker?: boolean; len: number; seed: number }) =>
  proto({
    id: "srtp",
    name: "SRTP",
    osi: 7,
    summary: `Secure Real-time Transport Protocol: PT=${o.pt}, SSRC=0x${o.ssrc.toString(16)}, Seq=${o.seq}, Time=${o.ts}${o.marker ? ", Mark" : ""}`,
    fields: [
      ...rtpHeader(o),
      { name: "Encrypted payload", random: o.len, seed: o.seed, opaque: true, note: o.pt === 111 ? "20 ms of Opus audio, encrypted with AES." : "A slice of a VP8 video frame, encrypted with AES." },
      { name: "Authentication tag", random: 10, seed: o.seed + 1, opaque: true, note: "HMAC-SHA1-80. Covers the header and the payload, so nobody can change either." },
    ],
  });

const VIDEO_SSRC = 0x3a9c51e2;
const AUDIO_SSRC = 0x7f20b415;
const PEER_VIDEO_SSRC = 0x58c1d07a;

/** TURN ChannelData message: 2-byte channel, 2-byte length, then the data. */
const channelData = (ch: number): LayerSpec => ({
  kind: "channeldata",
  build: (payload) => ({
    id: "turn-channel",
    name: "TURN ChannelData",
    osi: 7,
    summary: `TURN ChannelData: channel 0x${hex4(ch)}, ${payload.length} bytes`,
    fields: [
      field({ name: "Channel number", u16: ch, value: `0x${hex4(ch)}`, note: "Starts with 0x4… so the TURN server knows this is not a STUN message. It stands for the friend’s address." }),
      field({ name: "Length", u16: payload.length, value: `${payload.length} bytes`, note: "Only 4 bytes of overhead, compared with 36+ for a full STUN Send indication." }),
    ],
  }),
});

// ---------------------------------------------------------------- packet shortcuts

const toPeer = () => [...up(PEER_PUB), udp({ sport: LP, dport: PP })];
const fromPeer = () => [...down(PEER_PUB), udp({ sport: PP, dport: LP })];
const peerSide = (src: string, ttl = 52) => [eth({ src: PEER_GW, dst: PEER_MAC }), ipv4({ src, dst: PEER_LAN, ttl })];

const OFFER_LEN = 1214;
const ANSWER_LEN = 1102;

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: ADDR.laptop, x: 8, y: 66 },
  { id: "router", kind: "router", label: "Home router", sub: ADDR.routerWan, x: 26, y: 66 },
  { id: "internet", kind: "cloud", label: "Internet", x: 50, y: 48 },
  { id: "signal", kind: "web", label: "Signalling server", sub: SIG, x: 34, y: 18 },
  { id: "stun", kind: "server", label: "STUN server", sub: STUN_IP, x: 66, y: 18 },
  { id: "peerRouter", kind: "router", label: "Friend’s router", sub: PEER_PUB, x: 74, y: 66 },
  { id: "peer", kind: "phone", label: "Friend’s phone", sub: PEER_LAN, x: 92, y: 66 },
];
const links: [string, string][] = [
  ["client", "router"],
  ["router", "internet"],
  ["internet", "signal"],
  ["internet", "stun"],
  ["internet", "peerRouter"],
  ["peerRouter", "peer"],
];

const turnDevices: Device[] = [
  ...devices.map((d) =>
    d.id === "router" ? { ...d, sub: `${ADDR.routerWan} (symmetric NAT)` } : d.id === "peerRouter" ? { ...d, sub: `${PEER_PUB} (symmetric NAT)` } : d
  ),
  { id: "turn", kind: "server", label: "TURN relay", sub: TURN_IP, x: 50, y: 85 },
];
const turnLinks: [string, string][] = [...links, ["internet", "turn"]];

const t = (n: number) => Number(n.toFixed(4));

export default defineLesson({
  id: "webrtc",
  name: "WebRTC",
  full: "Web Real-Time Communication",
  group: "realtime",
  layer: 7,
  difficulty: 3,
  tagline: "Video calls straight from one browser to another.",
  description:
    "WebRTC lets two browsers or apps send audio and video directly to each other. A server only helps them swap descriptions of the call; then STUN and ICE find a path through home routers, DTLS agrees on keys, and SRTP carries the encrypted media.",
  facts: [
    ["Layer", "Application (7), media over UDP"],
    ["Path finding", "ICE with STUN and TURN"],
    ["Keys", "DTLS handshake → SRTP keys"],
    ["Media", "RTP, encrypted as SRTP"],
    ["STUN header", "20 bytes + attributes"],
    ["Defined in", "RFC 8825–8835, RFC 8489, RFC 8445"],
  ],
  ports: "UDP (any port) for media, 3478 STUN/TURN, 443 for signalling",
  rfc: "RFC 8825, RFC 8445 (ICE), RFC 8489 (STUN), RFC 8656 (TURN), RFC 5764 (DTLS-SRTP)",
  keywords: ["video call", "stun", "turn", "ice", "nat traversal", "sdp", "offer", "answer", "dtls", "srtp", "rtp", "peer to peer", "candidate"],
  related: ["sip", "rtsp", "udp", "tls", "quic"],
  devices,
  links,
  legend: [
    ["blue", "Signalling and STUN lookups"],
    ["green", "ICE checks and replies"],
    ["teal", "DTLS key exchange"],
    ["amber", "Media from the laptop"],
    ["violet", "Media from the friend"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A video call between two homes",
      summary: "The laptop calls a friend’s phone; both sit behind ordinary home routers, so a direct path works.",
      kind: "normal",
      steps: [
        {
          title: "Ask STUN: who am I?",
          desc: "Learn the public address the router gives you",
          detail: `The laptop only knows its private address, ${ADDR.laptop}, which nobody on the internet can reach. It sends a tiny STUN Binding Request to a public STUN server. The server replies with the address and port it saw the request come from: the home router’s public side.`,
          facts: [["Request", "Binding, 20-byte header, no attributes"], ["Answer", `${ADDR.routerWan}:${MAPPED_PORT}`], ["Server port", "UDP 3478"]],
          quiz: {
            q: `The laptop sent from ${ADDR.laptop}:${LP}. Which address will the STUN server report back?`,
            options: [`${ADDR.laptop}:${LP}`, `${ADDR.routerWan}:${MAPPED_PORT}`, `${STUN_IP}:3478`, "No address, just OK"],
            answer: 1,
            why: "The home router rewrote the source to its own public address and a new port (NAT). That rewritten address is what the STUN server sees and reports.",
          },
          events: [
            pkt("client", "stun", "blue", "STUN REQ", ["Binding Request", "who am I?"], {
              time: 0, info: "Binding Request",
              packet: build(...up(STUN_IP), udp({ sport: LP, dport: 3478 }), stun(0x0001, "b7e7a701bc34d686fa87dfae", [], false)),
            }),
            pkt("stun", "client", "blue", "STUN RESP", [`you are ${ADDR.routerWan}`, `port ${MAPPED_PORT}`], {
              time: 0.018, info: `Binding Success Response XOR-MAPPED-ADDRESS: ${ADDR.routerWan}:${MAPPED_PORT}`,
              packet: build(...down(STUN_IP), udp({ sport: 3478, dport: LP }), stun(0x0101, "b7e7a701bc34d686fa87dfae", [A.xorMapped(ADDR.routerWan, MAPPED_PORT)])),
            }),
            note("client", "SRFLX CANDIDATE FOUND", "green"),
          ],
        },
        {
          title: "Send the offer",
          desc: "SDP offer over a WebSocket",
          detail:
            "The browser writes an SDP offer: which codecs it can use (Opus audio, VP8 video), the ICE username fragment and password, its certificate fingerprint, and its candidate addresses, including the public one STUN just found. WebRTC does not say how to deliver this text, so the app sends it over its own WebSocket, inside TLS, and the server passes it to the friend.",
          facts: [["Offer holds", "Codecs, candidates, ice-ufrag, fingerprint"], ["Carried by", "WebSocket over TLS (port 443)"], ["Candidates", `host ${ADDR.laptop}, srflx ${ADDR.routerWan}`]],
          quiz: {
            q: "Which part of WebRTC decides how the offer reaches the friend?",
            options: ["The STUN server", "Nothing in WebRTC: the app picks any channel it likes", "The DTLS handshake", "RTP"],
            answer: 1,
            why: "Signalling is left to the app. A WebSocket is common, but HTTP polling, a chat message or even a QR code would work.",
          },
          events: [
            pkt("client", "signal", "blue", "OFFER", ["SDP offer", "inside WebSocket + TLS"], {
              time: 0.03, info: "Application Data (WebSocket text frame: SDP offer)",
              packet: build(...up(SIG), tcp({ sport: WSP, dport: 443, seq: 1, ack: 1, flags: "PA", win: 502, seqBase: 0x2c41a900, ackBase: 0x77e01300 }), tls({ records: [{ type: "appdata", encrypted: OFFER_LEN, what: "WebSocket frame: SDP offer" }] })),
            }),
            pkt("signal", "peer", "blue", "OFFER", ["passed on to", "the friend"], {
              time: 0.052, info: "Application Data (WebSocket text frame: SDP offer)",
              packet: build(...peerSide(SIG), tcp({ sport: 443, dport: 41822, seq: 1, ack: 1, flags: "PA", win: 501, seqBase: 0x5130c200, ackBase: 0x0de17700 }), tls({ records: [{ type: "appdata", encrypted: OFFER_LEN, what: "WebSocket frame: SDP offer" }] })),
            }),
            note("peer", "INCOMING CALL", "blue"),
          ],
        },
        {
          title: "The answer comes back",
          desc: "The friend accepts and sends an SDP answer",
          detail:
            "The friend taps Accept. Their browser picks the codecs both sides support and writes an SDP answer with its own candidates, ICE credentials and certificate fingerprint. It also says a=setup:active, which means the friend’s phone will start the DTLS handshake later.",
          facts: [["Answer holds", "Chosen codecs, candidates, fingerprint"], ["Friend’s candidate", `${PEER_PUB}:${PP}`], ["DTLS role", "Friend = client (setup:active)"]],
          events: [
            pkt("peer", "signal", "blue", "ANSWER", ["SDP answer"], {
              time: 2.4, info: "Application Data (WebSocket text frame: SDP answer)",
              packet: build(eth({ src: PEER_MAC, dst: PEER_GW }), ipv4({ src: PEER_LAN, dst: SIG }), tcp({ sport: 41822, dport: 443, seq: 1, ack: OFFER_LEN + 6, flags: "PA", win: 502, seqBase: 0x0de17700, ackBase: 0x5130c200 }), tls({ records: [{ type: "appdata", encrypted: ANSWER_LEN, what: "WebSocket frame: SDP answer" }] })),
            }),
            pkt("signal", "client", "blue", "ANSWER", ["SDP answer", "for the laptop"], {
              time: 2.421, info: "Application Data (WebSocket text frame: SDP answer)",
              packet: build(...down(SIG), tcp({ sport: 443, dport: WSP, seq: 1, ack: OFFER_LEN + 6, flags: "PA", win: 501, seqBase: 0x77e01300, ackBase: 0x2c41a900 }), tls({ records: [{ type: "appdata", encrypted: ANSWER_LEN, what: "WebSocket frame: SDP answer" }] })),
            }),
          ],
        },
        {
          title: "ICE connectivity checks",
          desc: "Both sides knock on each other’s doors",
          detail:
            "Now each side sends STUN Binding Requests straight to the other’s candidate addresses. Sending out also opens a hole in your own router, so the other side’s check can get in. Each check is signed with the ICE password from the SDP. The laptop is in control and adds USE-CANDIDATE to pick this path.",
          facts: [["Check", "STUN Binding with USERNAME, PRIORITY, MESSAGE-INTEGRITY"], ["Chosen path", `${ADDR.routerWan}:${MAPPED_PORT} ⇄ ${PEER_PUB}:${PP}`], ["Server involved", "None: direct"]],
          quiz: {
            q: "Why must both sides send checks, not just the laptop?",
            options: [
              "To double the speed",
              "Sending out opens a mapping in your own NAT, so the other side’s packets are let in",
              "STUN only works in one direction",
              "The signalling server requires it",
            ],
            answer: 1,
            why: "A home router only lets in replies from addresses you have already sent to. When both send at about the same time, both routers open holes. This is called hole punching.",
          },
          events: [
            pkt("client", "peer", "green", "ICE CHECK", ["Binding Request", "USE-CANDIDATE"], {
              time: 2.43, info: "Binding Request user: Pq7v:a9Xk",
              packet: build(...toPeer(), stun(0x0001, "4d1fa1e05c9b23b8e6f0aa12", [A.username("Pq7v:a9Xk", "Friend’s ufrag : my ufrag, both from the SDP."), A.priority(PRFLX_PRIO), A.controlling(), A.candidateFlag(), A.integrity(521)])),
            }),
            pkt("peer", "client", "green", "ICE CHECK", ["Binding Request", "from the friend"], {
              time: 2.431, parallel: true, info: "Binding Request user: a9Xk:Pq7v",
              packet: build(...fromPeer(), stun(0x0001, "9e02b5c4113d7f6a0c88e231", [A.username("a9Xk:Pq7v", "My ufrag : friend’s ufrag."), A.priority(PRFLX_PRIO), A.controlled(), A.integrity(522)])),
            }),
            pkt("peer", "client", "green", "ICE OK", ["Success", `you are ${ADDR.routerWan}`], {
              time: 2.47, info: `Binding Success Response XOR-MAPPED-ADDRESS: ${ADDR.routerWan}:${MAPPED_PORT}`,
              packet: build(...fromPeer(), stun(0x0101, "4d1fa1e05c9b23b8e6f0aa12", [A.xorMapped(ADDR.routerWan, MAPPED_PORT), A.integrity(523)])),
            }),
            pkt("client", "peer", "green", "ICE OK", ["Success", `you are ${PEER_PUB}`], {
              time: 2.471, info: `Binding Success Response XOR-MAPPED-ADDRESS: ${PEER_PUB}:${PP}`,
              packet: build(...toPeer(), stun(0x0101, "9e02b5c4113d7f6a0c88e231", [A.xorMapped(PEER_PUB, PP), A.integrity(524)])),
            }),
            note("client", "DIRECT PATH WORKS", "green"),
          ],
        },
        {
          title: "DTLS handshake",
          desc: "Agree on keys over the new path",
          detail:
            "On the same UDP path the two browsers run a DTLS handshake, which is TLS made to survive lost and reordered datagrams. Each shows a self-signed certificate, and each checks it against the fingerprint the other put in its SDP. The use_srtp extension makes the handshake also produce the keys for SRTP.",
          facts: [["Version", "DTLS 1.2 (0xfefd)"], ["Trust", "Certificate fingerprint from the SDP"], ["Output", "SRTP keys (AES-128, HMAC-SHA1-80)"]],
          quiz: {
            q: "The certificates are self-signed. What stops a man in the middle from showing its own?",
            options: [
              "Nothing, DTLS is not secure",
              "Each side compares the certificate with the fingerprint that arrived in the SDP over the TLS-protected signalling channel",
              "The STUN server signs them",
              "The router checks them",
            ],
            answer: 1,
            why: "The fingerprint travelled through the signalling server over TLS. A different certificate would not match it and the call would fail. The trust rests on the signalling server.",
          },
          events: [
            pkt("peer", "client", "teal", "CLIENTHELLO", ["DTLS ClientHello", "use_srtp"], {
              time: 2.48, info: "Client Hello",
              packet: build(...fromPeer(), dtls([clientHello], "Client Hello")),
            }),
            pkt("client", "peer", "teal", "SERVER HELLO", ["ServerHello, cert,", "key share, done"], {
              time: 2.481, info: "Server Hello, Certificate, Server Key Exchange, Certificate Request, Server Hello Done",
              packet: build(...toPeer(), dtls(serverFlight, "Server Hello, Certificate, Server Key Exchange, Certificate Request, Server Hello Done")),
            }),
            pkt("peer", "client", "teal", "KEYS+FIN", ["cert, key share,", "Finished"], {
              time: 2.522, info: "Certificate, Client Key Exchange, Certificate Verify, Change Cipher Spec, Encrypted Handshake Message",
              packet: build(...fromPeer(), dtls(clientFlight, "Certificate, Client Key Exchange, Certificate Verify, Change Cipher Spec, Finished")),
            }),
            pkt("client", "peer", "teal", "FINISHED", ["Change Cipher Spec", "Finished"], {
              time: 2.523, info: "Change Cipher Spec, Encrypted Handshake Message",
              packet: build(...toPeer(), dtls(serverFinish, "Change Cipher Spec, Finished")),
            }),
            note("client", "SRTP KEYS READY", "green"),
          ],
        },
        {
          title: "Video and voice flow",
          desc: "RTP packets, encrypted as SRTP",
          detail:
            "Media now flows both ways on the same UDP path. Each packet has a readable 12-byte RTP header with the codec number, a sequence number and a timestamp, so the receiver can reorder, spot loss and play at the right moment. The payload is encrypted, and a 10-byte tag at the end proves nothing was changed.",
          facts: [["Video", "VP8, PT 96, 90 kHz clock"], ["Audio", "Opus, PT 111, 48 kHz clock, 20 ms per packet"], ["Overhead", "12-byte header + 10-byte tag"]],
          quiz: {
            q: "A video frame is split over 3 packets. What do those 3 packets share?",
            options: ["The sequence number", "The timestamp", "The authentication tag", "Nothing"],
            answer: 1,
            why: "Each packet gets the next sequence number, but all pieces of one frame carry the same timestamp, because they belong to the same moment in the video. The last one also sets the marker bit.",
          },
          events: [
            pkt("client", "peer", "amber", "SRTP", ["video, PT 96", "seq 18233"], {
              time: 2.56, info: `PT=DynamicRTP-Type-96, SSRC=0x${VIDEO_SSRC.toString(16)}, Seq=18233, Time=3201450000, Mark`,
              packet: build(...toPeer(), srtp({ pt: 96, seq: 18233, ts: 3201450000, ssrc: VIDEO_SSRC, marker: true, len: 1100, seed: 530 })),
            }),
            pkt("client", "peer", "amber", "SRTP", ["voice, PT 111", "seq 4410"], {
              time: 2.561, parallel: true, info: `PT=DynamicRTP-Type-111, SSRC=0x${AUDIO_SSRC.toString(16)}, Seq=4410, Time=1922880`,
              packet: build(...toPeer(), srtp({ pt: 111, seq: 4410, ts: 1922880, ssrc: AUDIO_SSRC, len: 96, seed: 532 })),
            }),
            pkt("peer", "client", "violet", "SRTP", ["video from", "the friend"], {
              time: 2.58, info: `PT=DynamicRTP-Type-96, SSRC=0x${PEER_VIDEO_SSRC.toString(16)}, Seq=771, Time=118400, Mark`,
              packet: build(...fromPeer(), srtp({ pt: 96, seq: 771, ts: 118400, ssrc: PEER_VIDEO_SSRC, marker: true, len: 980, seed: 534 })),
            }),
            note("peer", "CALL CONNECTED", "green"),
          ],
        },
      ],
      outro: {
        title: "Call connected, peer to peer",
        text: "A server only carried the offer and answer. STUN found the public address, ICE checks proved a direct path, DTLS checked the fingerprints and made keys, and now SRTP carries the voice and video straight between the two homes.",
        facts: [["Setup time", "About 0.15 s after the answer"], ["Servers in the media path", "None"], ["Encryption", "Always on (DTLS-SRTP)"], ["Transport", "One UDP port pair for everything"]],
      },
    },
    {
      id: "turn",
      name: "Both behind symmetric NAT: use TURN",
      summary: "Direct checks fail because each router picks a new port for every destination, so the call goes through a TURN relay.",
      kind: "failure",
      devices: turnDevices,
      links: turnLinks,
      steps: [
        {
          title: "Checks go nowhere",
          desc: "Symmetric NAT breaks hole punching",
          detail:
            "This time both routers are symmetric NATs, common on mobile networks and in offices. They pick a new public port for every new destination. The port STUN reported is only valid towards the STUN server, so checks sent to it are dropped by the other router.",
          facts: [["NAT type", "Symmetric (new port per destination)"], ["STUN said", `${ADDR.routerWan}:${MAPPED_PORT}`], ["Used towards the friend", `${ADDR.routerWan}:61377 (different)`]],
          quiz: {
            q: "With symmetric NAT on both sides, what can still connect the call?",
            options: ["Retrying the checks faster", "A relay with a public address that both sides send to (TURN)", "A bigger STUN server", "Turning off encryption"],
            answer: 1,
            why: "Each side can always send out to a fixed public server. A TURN server relays between the two, so neither side has to guess the other’s port.",
          },
          events: [
            pkt("client", "peer", "green", "ICE CHECK", ["to " + PEER_PUB, "dropped"], {
              time: 0, lost: true, info: "Binding Request user: Pq7v:a9Xk",
              packet: build(...toPeer(), stun(0x0001, "61aa0c3e9f12d4b7c58e0f01", [A.username("Pq7v:a9Xk"), A.priority(PRFLX_PRIO), A.controlling(), A.integrity(541)])),
            }),
            pkt("peer", "client", "green", "ICE CHECK", ["from the friend", "dropped"], {
              time: 0.001, parallel: true, lost: true, info: "Binding Request user: a9Xk:Pq7v",
              packet: build(...fromPeer(), stun(0x0001, "d3027b81aa6f0e5c94b21c77", [A.username("a9Xk:Pq7v"), A.priority(PRFLX_PRIO), A.controlled(), A.integrity(542)])),
            }),
            note("router", "NEW PORT PER DESTINATION", "red"),
            note("peerRouter", "UNKNOWN SENDER: DROP", "red"),
          ],
        },
        {
          title: "Ask for a relay",
          desc: "TURN Allocate, first without a password",
          detail:
            "The laptop asks the TURN server to allocate a relay address. TURN servers cost bandwidth, so they need a login. The first request carries no credentials, and the server answers 401 with a realm and a nonce to use in the next try.",
          facts: [["Request", "Allocate, REQUESTED-TRANSPORT = UDP"], ["Answer", "401 Unauthorized + REALM + NONCE"], ["Server port", "UDP 3478"]],
          events: [
            pkt("client", "turn", "blue", "ALLOCATE", ["Allocate Request", "UDP relay please"], {
              time: 0.5, info: "Allocate Request UDP",
              packet: build(...up(TURN_IP), udp({ sport: LP, dport: 3478 }), stun(0x0003, "0f5b7a92c1e8d3346a9e2b10", [A.transport()])),
            }),
            pkt("turn", "client", "red", "401", ["Unauthorized", "here is a nonce"], {
              time: 0.52, info: "Allocate Error Response error-code: 401 (Unauthorized) realm: example.com",
              packet: build(...down(TURN_IP), udp({ sport: 3478, dport: LP }), stun(0x0113, "0f5b7a92c1e8d3346a9e2b10", [A.error401(), A.realm(), A.nonce()])),
            }),
          ],
        },
        {
          title: "Relay granted",
          desc: "Allocate again, signed with the password",
          detail:
            "The laptop repeats the request with a username, the realm, the nonce and a MESSAGE-INTEGRITY hash made from the password. The app got these short-lived credentials from its own server. The TURN server opens a public relay port for the laptop and reports it.",
          facts: [["Relay address", `${TURN_IP}:${RELAY_PORT}`], ["Lifetime", "600 s, refreshed while the call lasts"], ["New candidate", "type relay, lowest priority"]],
          quiz: {
            q: "Where does the laptop put its new relay address so the friend can use it?",
            options: ["In a new ICE candidate sent via the signalling server", "In the RTP header", "Nowhere, the friend guesses it", "In the DTLS certificate"],
            answer: 0,
            why: "It is just another ICE candidate (type relay). It is trickled to the friend over signalling, and ICE checks run through it like any other path.",
          },
          events: [
            pkt("client", "turn", "blue", "ALLOCATE", ["with username", "and HMAC"], {
              time: 0.53, info: "Allocate Request UDP user: 1763600000:caller realm: example.com",
              packet: build(...up(TURN_IP), udp({ sport: LP, dport: 3478 }), stun(0x0003, "77c20e4b18f5a0d39c6e2f84", [A.transport(), A.username("1763600000:caller", "A time-limited username issued by the app’s server."), A.realm(), A.nonce(), A.integrity(551)])),
            }),
            pkt("turn", "client", "green", "ALLOCATED", [`relay ${TURN_IP}`, `port ${RELAY_PORT}`], {
              time: 0.55, info: `Allocate Success Response XOR-RELAYED-ADDRESS: ${TURN_IP}:${RELAY_PORT} lifetime: 600`,
              packet: build(...down(TURN_IP), udp({ sport: 3478, dport: LP }), stun(0x0103, "77c20e4b18f5a0d39c6e2f84", [A.xorRelayed(TURN_IP, RELAY_PORT), A.xorMapped(ADDR.routerWan, 61004), A.lifetime(600), A.integrity(552)])),
            }),
          ],
        },
        {
          title: "Bind a channel",
          desc: "Give the friend’s address a short number",
          detail:
            "TURN only relays to addresses the client has given permission for. ChannelBind does that and also assigns channel 0x4000 to the friend’s address. From now on the laptop can wrap media in a tiny 4-byte ChannelData header instead of a full STUN message.",
          facts: [["Channel", "0x4000"], ["Peer", `${PEER_PUB}:50022`], ["Overhead after this", "4 bytes per packet"]],
          events: [
            pkt("client", "turn", "blue", "CHANBIND", ["channel 0x4000", `→ ${PEER_PUB}`], {
              time: 0.56, info: `ChannelBind Request Channel: 0x4000 XOR-PEER-ADDRESS: ${PEER_PUB}:50022`,
              packet: build(...up(TURN_IP), udp({ sport: LP, dport: 3478 }), stun(0x0009, "a3f1092e7bd45c60e81f3b2d", [A.channel(0x4000), A.xorPeer(PEER_PUB, 50022), A.username("1763600000:caller"), A.realm(), A.nonce(), A.integrity(561)])),
            }),
            pkt("turn", "client", "green", "BOUND", ["ChannelBind", "Success"], {
              time: 0.58, info: "ChannelBind Success Response",
              packet: build(...down(TURN_IP), udp({ sport: 3478, dport: LP }), stun(0x0109, "a3f1092e7bd45c60e81f3b2d", [A.integrity(562)])),
            }),
          ],
        },
        {
          title: "Media through the relay",
          desc: "ICE, DTLS and SRTP all ride the relay",
          detail:
            "ICE checks through the relay succeed, DTLS runs over it, and then SRTP flows. The laptop sends each packet to the TURN server with channel 0x4000, and the server forwards the inner bytes from its relay port to the friend. The relay can’t read the media: it is still SRTP, encrypted end to end.",
          facts: [["Extra delay", "One detour via the relay"], ["Relay can read media?", "No, it only sees SRTP"], ["Cost", "The relay pays for all the bandwidth"]],
          quiz: {
            q: "The TURN server forwards every packet. Can it watch the video?",
            options: ["Yes, it has the keys", "No, the DTLS keys exist only in the two browsers", "Only the audio", "Only if it is in the same country"],
            answer: 1,
            why: "The DTLS handshake runs end to end through the relay, so the SRTP keys never reach the TURN server. It just moves encrypted bytes.",
          },
          events: [
            pkt("client", "turn", "amber", "CHANDATA", ["channel 0x4000", "SRTP video"], {
              time: 0.6, info: `ChannelData 0x4000, PT=DynamicRTP-Type-96, Seq=18233`,
              packet: build(...up(TURN_IP), udp({ sport: LP, dport: 3478 }), channelData(0x4000), srtp({ pt: 96, seq: 18233, ts: 3201450000, ssrc: VIDEO_SSRC, marker: true, len: 1100, seed: 570 })),
            }),
            pkt("turn", "peer", "amber", "SRTP", [`from ${TURN_IP}:${RELAY_PORT}`, "header removed"], {
              time: 0.611, info: `PT=DynamicRTP-Type-96, SSRC=0x${VIDEO_SSRC.toString(16)}, Seq=18233, Mark`,
              packet: build(eth({ src: TURN_MAC, dst: TURN_GW }), ipv4({ src: TURN_IP, dst: PEER_PUB }), udp({ sport: RELAY_PORT, dport: 50022 }), srtp({ pt: 96, seq: 18233, ts: 3201450000, ssrc: VIDEO_SSRC, marker: true, len: 1100, seed: 570 })),
            }),
            pkt("turn", "client", "violet", "CHANDATA", ["friend’s video", "via the relay"], {
              time: 0.66, info: `ChannelData 0x4000, PT=DynamicRTP-Type-96, Seq=771`,
              packet: build(...down(TURN_IP), udp({ sport: 3478, dport: LP }), channelData(0x4000), srtp({ pt: 96, seq: 771, ts: 118400, ssrc: PEER_VIDEO_SSRC, marker: true, len: 980, seed: 574 })),
            }),
            note("turn", "RELAYING (CAN’T DECRYPT)", "blue"),
          ],
        },
      ],
      outro: {
        title: "Connected through a relay",
        text: "When both sides sit behind symmetric NAT, hole punching fails. ICE falls back to a relay candidate: the TURN server gives each side a public address and forwards packets. The call works with slightly more delay, and the media stays encrypted end to end.",
        facts: [["Calls needing TURN", "Roughly 10–20% in practice"], ["TURN messages", "Allocate, CreatePermission, ChannelBind, Refresh"], ["ChannelData header", "4 bytes"], ["Defined in", "RFC 8656"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Building blocks",
      items: [["SDP", "Text describing codecs, keys fingerprint, candidates"], ["ICE", "Tries every address pair, keeps the best working one"], ["STUN", "Tells you your public address; also used for checks"], ["TURN", "Relay when no direct path works"], ["DTLS", "TLS over UDP; makes the SRTP keys"], ["SRTP", "RTP with encrypted payload + auth tag"]],
    },
    {
      title: "Candidate types",
      items: [["host", "Your own interface address"], ["srflx", "Public address learned from STUN"], ["prflx", "Learned during a check"], ["relay", "Address on a TURN server"]],
    },
    {
      title: "Numbers to know",
      items: [["STUN header", "20 bytes; magic cookie 0x2112A442"], ["STUN/TURN port", "3478 (5349 over TLS)"], ["RTP header", "12 bytes, V=2"], ["FINGERPRINT", "CRC-32 XOR 0x5354554E"], ["Video clock", "90 000 Hz; Opus 48 000 Hz"]],
    },
  ],
});
