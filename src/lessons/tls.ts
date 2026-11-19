import { defineLesson, note, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec } from "@/lib/packet";
import { ext, hsMsg, tcp, tls, TlsRecord, vec } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

const S = ADDR.web;
const t = (n: number) => Number(n.toFixed(4));
const size = (spec: LayerSpec) => build(spec).bytes.length;

// ---------------------------------------------------------------- TCP connection helper
// Tracks relative sequence numbers for one TCP connection so every segment is consistent.
function conn(sport: number, cBase: number, sBase: number) {
  let c = 0;
  let s = 0;
  const seg = (fromClient: boolean, flags: string, payload?: LayerSpec) => {
    const len = payload ? size(payload) : 0;
    const seq = fromClient ? c : s;
    const ack = fromClient ? s : c;
    const hasAck = flags.includes("A");
    const spec = tcp({
      sport: fromClient ? sport : 443, dport: fromClient ? 443 : sport, seq, ack: hasAck ? ack : 0, flags,
      win: fromClient ? 502 : 509, seqBase: fromClient ? cBase : sBase, ackBase: hasAck ? (fromClient ? sBase : cBase) : undefined,
      opts: flags.includes("S") ? [{ mss: 1460 }, "sackOk", "nop", "nop", "nop", { ws: 7 }] : undefined,
    });
    const adv = len + (flags.includes("S") ? 1 : 0) + (flags.includes("F") ? 1 : 0);
    if (fromClient) c += adv; else s += adv;
    const packet = build(...(fromClient ? up(S) : down(S)), spec, ...(payload ? [payload] : []));
    return { packet, seq, ack, len };
  };
  return {
    up: (flags: string, payload?: LayerSpec) => seg(true, flags, payload),
    down: (flags: string, payload?: LayerSpec) => seg(false, flags, payload),
  };
}

// ---------------------------------------------------------------- TLS building blocks

const suite = (code: number, name: string, note?: string): FieldSpec => ({ name: "Cipher suite", u16: code, value: `${name} (0x${code.toString(16).padStart(4, "0")})`, note });
const u16v = (name: string, code: number, label: string, note?: string): FieldSpec => ({ name, u16: code, value: `${label} (0x${code.toString(16).padStart(4, "0")})`, note });

const SESSION_SEED = 4242;

const clientHello = (o: { psk?: boolean; early?: boolean; keySeed?: number } = {}) => {
  const exts: FieldSpec[] = [
    ext(0, "server_name", [
      vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name (0)" }, vec("Host name", 2, [{ name: "Name", text: "example.com" }], "example.com")]),
    ], "example.com", "Server Name Indication (SNI): which website the browser wants, so one IP address can host many sites. It travels in clear text."),
    ext(11, "ec_point_formats", [vec("Formats", 1, [{ name: "Format", u8: 0, value: "uncompressed (0)" }])], "uncompressed", "Only used by TLS 1.2 servers. Kept so an old server can still answer."),
    ext(10, "supported_groups", [
      vec("Named groups", 2, [u16v("Group", 0x001d, "x25519"), u16v("Group", 0x0017, "secp256r1"), u16v("Group", 0x0018, "secp384r1")]),
    ], "x25519, secp256r1, secp384r1", "Which key exchange curves the browser can use, best first."),
    ext(13, "signature_algorithms", [
      vec("Algorithms", 2, [
        u16v("Algorithm", 0x0403, "ecdsa_secp256r1_sha256"), u16v("Algorithm", 0x0804, "rsa_pss_rsae_sha256"),
        u16v("Algorithm", 0x0401, "rsa_pkcs1_sha256"), u16v("Algorithm", 0x0807, "ed25519"),
      ]),
    ], "4 algorithms", "Which kinds of signature the browser can check on the server's certificate and handshake."),
    ext(16, "application_layer_protocol_negotiation", [
      vec("Protocol list", 2, [vec("Protocol", 1, [{ name: "Name", text: "h2" }], "h2"), vec("Protocol", 1, [{ name: "Name", text: "http/1.1" }], "http/1.1")]),
    ], "h2, http/1.1", "ALPN: which application protocol to speak once the tunnel is up. Saves a round trip later."),
    ext(23, "extended_master_secret", [], "", "TLS 1.2 fix that ties the keys to the whole handshake."),
    ext(65281, "renegotiation_info", [{ name: "Renegotiated connection", u8: 0, value: "empty" }], "empty", "TLS 1.2 safety signal. Ignored by TLS 1.3."),
    ext(43, "supported_versions", [
      vec("Versions", 1, [u16v("Version", 0x0304, "TLS 1.3"), u16v("Version", 0x0303, "TLS 1.2")]),
    ], "TLS 1.3, TLS 1.2", "The real version list. The old version field above is frozen at 1.2, so TLS 1.3 is offered here instead."),
    ext(45, "psk_key_exchange_modes", [vec("Modes", 1, [{ name: "Mode", u8: 1, value: "psk_dhe_ke (1)" }])], "psk_dhe_ke", "If we ever resume with a ticket, still do a fresh key exchange so old traffic stays safe."),
    ext(51, "key_share", [
      vec("Client key shares", 2, [u16v("Group", 0x001d, "x25519"), vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: o.keySeed ?? 1301, note: "The browser's x25519 public key. The private half never leaves the laptop." }], "32 bytes")]),
    ], "x25519, 32 bytes", "The browser guesses the server will pick x25519 and sends its public key right away. This is what lets TLS 1.3 finish in one round trip."),
  ];
  if (o.early) exts.push(ext(42, "early_data", [], "", "The browser is about to send a request before the handshake finishes (0-RTT)."));
  if (o.psk)
    exts.push(ext(41, "pre_shared_key", [
      vec("Identities", 2, [vec("Identity", 2, [{ name: "Session ticket", random: 192, seed: 777, opaque: true, note: "The ticket the server gave us last time. Only the server can open it." }], "192-byte ticket"), { name: "Obfuscated ticket age", u32: 0x5c1a77e3, value: "0x5c1a77e3", note: "How old the ticket is, scrambled with a secret from the ticket so watchers can't link visits." }]),
      vec("Binders", 2, [vec("Binder", 1, [{ name: "HMAC", random: 32, seed: 778, opaque: true }], "32 bytes")], undefined, "Proves the browser really holds the secret that goes with the ticket."),
    ], "1 identity", "Resume with a ticket. Must be the last extension."));
  return hsMsg("client_hello", "Client Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "Frozen at 1.2 so old middleboxes don't choke. The real offer is in supported_versions." },
    { name: "Random", random: 32, seed: 1001, note: "32 fresh random bytes. They make every handshake's keys unique." },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: SESSION_SEED }], "32 bytes", "Not needed by TLS 1.3, but filled in so the handshake looks like a TLS 1.2 resumption to middleboxes."),
    vec("Cipher suites", 2, [
      suite(0x1301, "TLS_AES_128_GCM_SHA256", "TLS 1.3 suite."), suite(0x1302, "TLS_AES_256_GCM_SHA384", "TLS 1.3 suite."), suite(0x1303, "TLS_CHACHA20_POLY1305_SHA256", "TLS 1.3 suite."),
      suite(0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "TLS 1.2 suite."), suite(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS 1.2 suite."),
      suite(0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "TLS 1.2 suite."),
    ], "6 suites"),
    vec("Compression methods", 1, [{ name: "Method", u8: 0, value: "null (0)", note: "Compression is always off; it leaked secrets (the CRIME attack)." }], "null"),
    vec("Extensions", 2, exts, `${exts.length} extensions`),
  ]);
};

const chRecord = (o: Parameters<typeof clientHello>[0] = {}): TlsRecord => ({ type: "handshake", version: 0x0301, fields: [clientHello(o)] });

const serverHello13 = (psk = false) =>
  hsMsg("server_hello", "Server Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
    { name: "Random", random: 32, seed: 2002, note: "The server's own 32 random bytes." },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: SESSION_SEED, note: "An echo of the browser's session ID." }], "echo"),
    suite(0x1301, "TLS_AES_128_GCM_SHA256", "The server picked AES-128 in GCM mode with SHA-256."),
    { name: "Compression method", u8: 0, value: "null (0)" },
    vec("Extensions", 2, [
      ext(43, "supported_versions", [u16v("Selected version", 0x0304, "TLS 1.3")], "TLS 1.3", "This is how the server says 'we are speaking TLS 1.3'."),
      ext(51, "key_share", [u16v("Group", 0x001d, "x25519"), vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: 2303, note: "The server's x25519 public key. Combined with the browser's, both sides now compute the same secret." }], "32 bytes")], "x25519, 32 bytes"),
      ...(psk ? [ext(41, "pre_shared_key", [{ name: "Selected identity", u16: 0, value: "0 (the first ticket)" }], "ticket 0 accepted")] : []),
    ], psk ? "3 extensions" : "2 extensions"),
  ]);

const ccs: TlsRecord = { type: "ccs", fields: [{ name: "Change cipher spec message", u8: 1, note: "A dummy record in TLS 1.3. It is sent only so old middleboxes see something familiar. It changes nothing." }] };
const enc = (plain: number, what: string, note: string): TlsRecord => ({ type: "appdata", encrypted: plain + 1 + 16, what, note });

// Plaintext sizes of the encrypted handshake messages (handshake header included)
const EE = 15; // 4 header + 2 list length + ALPN "h2" (9)
const CERT = 4 + 1 + 3 + (3 + 650 + 2) + (3 + 700 + 2); // two certs, empty extensions each
const CV = 4 + 2 + 2 + 71; // ECDSA P-256 signature
const FIN = 4 + 32; // HMAC-SHA256
const NST = 4 + 4 + 4 + (1 + 8) + (2 + 192) + 2;

const devs = homeToServer({ label: "example.com", sub: S });

// ---------------------------------------------------------------- normal flow (TLS 1.3)
const a = conn(51500, 0x3a10c000, 0x88e10000);
const syn = a.up("S");
const synack = a.down("SA");
const ack = a.up("A");
const chSpec = tls({ records: [chRecord()], summary: "TLS 1.3 Client Hello" });
const ch = a.up("PA", chSpec);
const sf1 = a.down("A", tls({
  records: [
    { type: "handshake", fields: [serverHello13()] },
    ccs,
    enc(EE, "Encrypted Extensions (encrypted)", "Inside: EncryptedExtensions with ALPN = h2. From here on everything is encrypted with handshake keys."),
  ],
  summary: "TLS: Server Hello, Change Cipher Spec, Application Data",
}));
const sf2 = a.down("A", tls({ records: [enc(CERT, "Certificate (encrypted)", "Inside: the server's certificate for example.com plus the intermediate CA certificate. Hidden from anyone on the path, unlike TLS 1.2.")], summary: "TLS: Application Data (Certificate)" }));
const sf3 = a.down("PA", tls({
  records: [
    enc(CV, "CertificateVerify (encrypted)", "Inside: an ECDSA signature over the whole handshake so far, made with the certificate's private key. Proves the server owns the certificate."),
    enc(FIN, "Finished (encrypted)", "Inside: an HMAC over the whole handshake. Proves nothing was changed on the way."),
  ],
  summary: "TLS: Application Data (CertificateVerify, Finished)",
}));
const cfin = a.up("PA", tls({ records: [ccs, enc(FIN, "Finished (encrypted)", "Inside: the browser's own Finished HMAC. The handshake is complete.")], summary: "TLS: Change Cipher Spec, Application Data (Finished)" }));
const REQ_H2 = 24 + 27 + 13 + 9 + 52; // preface, SETTINGS, WINDOW_UPDATE, HEADERS
const req = a.up("PA", tls({ records: [enc(REQ_H2, "HTTP/2 request (encrypted)", "Inside: the HTTP/2 connection preface, a SETTINGS frame and a HEADERS frame for GET / on example.com.")], summary: "TLS: Application Data (HTTP/2 GET /)" }));
const nst = a.down("PA", tls({
  records: [
    enc(NST, "NewSessionTicket (encrypted)", "Inside: a session ticket valid for 7 days. Next time the browser can skip the certificate and resume."),
    enc(NST, "NewSessionTicket (encrypted)", "A second ticket, so the browser can open two connections later without reusing one."),
  ],
  summary: "TLS: Application Data (NewSessionTicket x2)",
}));
const resp = a.down("PA", tls({ records: [enc(1180, "HTTP/2 response (encrypted)", "Inside: HEADERS (:status 200, content-type text/html) and DATA frames with the page.")], summary: "TLS: Application Data (HTTP/2 200 OK)" }));

// ---------------------------------------------------------------- TLS 1.2 for comparison
const b = conn(51510, 0x5b220000, 0x91f00000);
const chB = b.up("PA", tls({ records: [chRecord({ keySeed: 1401 })], summary: "TLS Client Hello" }));
const sh12 = hsMsg("server_hello", "Server Hello", [
  { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "No supported_versions extension in the reply, so this really is TLS 1.2." },
  { name: "Random", random: 32, seed: 3003 },
  vec("Session ID", 1, [{ name: "Session ID", random: 32, seed: 3004 }], "32 bytes"),
  suite(0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE key exchange, RSA certificate, AES-128-GCM, SHA-256."),
  { name: "Compression method", u8: 0, value: "null (0)" },
  vec("Extensions", 2, [
    ext(65281, "renegotiation_info", [{ name: "Renegotiated connection", u8: 0, value: "empty" }], "empty"),
    ext(11, "ec_point_formats", [vec("Formats", 1, [{ name: "Format", u8: 0, value: "uncompressed (0)" }])], "uncompressed"),
    ext(23, "extended_master_secret", [], ""),
    ext(16, "application_layer_protocol_negotiation", [vec("Protocol list", 2, [vec("Protocol", 1, [{ name: "Name", text: "h2" }], "h2")])], "h2"),
  ], "4 extensions"),
]);
const cert12 = hsMsg("certificate", "Certificate", [
  vec("Certificate list", 3, [
    vec("Certificate", 3, [{ name: "DER bytes", random: 600, seed: 3100, opaque: true, note: "An X.509 certificate: subject example.com, issuer, validity dates and an RSA public key. Sent in clear in TLS 1.2." }], "example.com (600 bytes)"),
    vec("Certificate", 3, [{ name: "DER bytes", random: 650, seed: 3101, opaque: true, note: "The intermediate CA certificate that signed the server's certificate." }], "Intermediate CA (650 bytes)"),
  ], "2 certificates"),
], "In TLS 1.2 the certificate travels unencrypted, so anyone on the path can read which site you visit.");
const ske = hsMsg("server_key_exchange", "Server Key Exchange", [
  { name: "Curve type", u8: 3, value: "named_curve (3)" },
  u16v("Named curve", 0x001d, "x25519"),
  vec("Public key", 1, [{ name: "Point", random: 32, seed: 3200 }], "32 bytes", "The server's ECDHE public key for this connection only."),
  u16v("Signature algorithm", 0x0804, "rsa_pss_rsae_sha256"),
  vec("Signature", 2, [{ name: "Signature", random: 256, seed: 3201, opaque: true }], "256 bytes", "RSA-2048 signature over both randoms and the public key, made with the certificate's private key."),
], "Only needed in TLS 1.2: the server's key exchange share arrives in its own message, after the certificate.");
const shd = hsMsg("server_hello_done", "Server Hello Done", [], "Empty message: 'your turn'.");
const sB1 = b.down("A", tls({ records: [{ type: "handshake", fields: [sh12] }, { type: "handshake", fields: [cert12] }], summary: "TLS: Server Hello, Certificate" }));
const sB2 = b.down("PA", tls({ records: [{ type: "handshake", fields: [ske, shd] }], summary: "TLS: Server Key Exchange, Server Hello Done" }));
const cke = hsMsg("client_key_exchange", "Client Key Exchange", [vec("Public key", 1, [{ name: "Point", random: 32, seed: 3300 }], "32 bytes", "The browser's ECDHE public key. Only now can both sides compute the shared secret.")]);
const ccs12: TlsRecord = { type: "ccs", fields: [{ name: "Change cipher spec message", u8: 1, note: "In TLS 1.2 this is real: 'everything I send after this is encrypted'." }] };
const fin12: TlsRecord = { type: "handshake", encrypted: 40, what: "Encrypted Finished", note: "8-byte explicit nonce + 16-byte Finished message + 16-byte tag. The record type still says Handshake in TLS 1.2." };
const cB = b.up("PA", tls({ records: [{ type: "handshake", fields: [cke] }, ccs12, fin12], summary: "TLS: Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message" }));
const sB3 = b.down("PA", tls({ records: [ccs12, fin12], summary: "TLS: Change Cipher Spec, Encrypted Handshake Message" }));
const reqB = b.up("PA", tls({ records: [{ type: "appdata", encrypted: 8 + REQ_H2 + 16, what: "HTTP/2 request (encrypted)" }], summary: "TLS: Application Data" }));

// ---------------------------------------------------------------- expired certificate
const e = conn(51520, 0x1e440000, 0x7d330000);
const chE = e.up("PA", tls({ records: [chRecord({ keySeed: 1501 })], summary: "TLS 1.3 Client Hello" }));
const sE = e.down("PA", tls({
  records: [
    { type: "handshake", fields: [serverHello13()] }, ccs,
    enc(EE, "Encrypted Extensions (encrypted)", "ALPN = h2."),
    enc(CERT - 1350 + 600, "Certificate (encrypted)", "Inside: a certificate for example.com whose 'Not After' date was 3 days ago."),
    enc(CV, "CertificateVerify (encrypted)", "A valid signature. The key is fine, only the date is wrong."),
    enc(FIN, "Finished (encrypted)", "Server's Finished."),
  ],
  summary: "TLS: Server Hello, Change Cipher Spec, Application Data x4",
}));
const alertE = e.up("PA", tls({ records: [enc(2, "Alert (encrypted)", "Inside: level 2 (fatal), description 45 (certificate_expired). Bytes 02 2d, then inner content type 0x15 (alert).")], summary: "TLS: Application Data (Alert: certificate_expired)" }));
const finE = e.up("FA");

// ---------------------------------------------------------------- 0-RTT resumption
const r = conn(51530, 0x2c550000, 0x6e770000);
const syn0 = r.up("S");
const synack0 = r.down("SA");
const ack0 = r.up("A");
const EARLY = 24 + 27 + 9 + 45; // HTTP/2 preface, SETTINGS, WINDOW_UPDATE, HEADERS GET /news
const ch0 = r.up("PA", tls({
  records: [chRecord({ psk: true, early: true, keySeed: 1601 }), enc(EARLY, "Early data: HTTP/2 GET /news (encrypted)", "0-RTT data, encrypted with keys made from the ticket's secret. The request leaves before the server has said anything.")],
  summary: "TLS: Client Hello (PSK, early_data), Application Data (0-RTT)",
}));
const s0 = r.down("PA", tls({
  records: [
    { type: "handshake", fields: [serverHello13(true)] }, ccs,
    enc(EE + 4, "Encrypted Extensions (encrypted)", "Inside: ALPN = h2 and an empty early_data extension, which means 'I accepted your 0-RTT request'."),
    enc(FIN, "Finished (encrypted)", "No Certificate or CertificateVerify: the ticket already proves who the server is."),
    enc(1180, "HTTP/2 response (encrypted)", "Inside: 200 OK for /news. The server answered the early request in its very first flight."),
  ],
  summary: "TLS: Server Hello, Change Cipher Spec, Application Data x3",
}));
const c0 = r.up("PA", tls({
  records: [ccs, enc(4, "EndOfEarlyData (encrypted)", "Inside: EndOfEarlyData, 'no more 0-RTT data from me'."), enc(FIN, "Finished (encrypted)", "The browser's Finished.")],
  summary: "TLS: Change Cipher Spec, Application Data x2",
}));

const fl = (f: string) => ({ S: "SYN", SA: "SYN, ACK", A: "ACK", PA: "PSH, ACK", FA: "FIN, ACK" } as Record<string, string>)[f] ?? f;
const tcpInfo = (sport: number, toServer: boolean, flags: string, s: { seq: number; ack: number; len: number }) =>
  `${toServer ? sport : 443} → ${toServer ? 443 : sport} [${fl(flags)}] Seq=${s.seq} Ack=${s.ack} Len=${s.len}`;

export default defineLesson({
  id: "tls",
  name: "TLS 1.3",
  full: "Transport Layer Security 1.3",
  group: "security",
  layer: 6,
  difficulty: 3,
  tagline: "The padlock: private, tamper-proof connections in one round trip.",
  description:
    "TLS wraps a TCP connection in encryption so nobody on the path can read or change the data, and it uses certificates so the browser knows it reached the real website. TLS 1.3 agrees on keys in a single round trip and encrypts almost the whole handshake, including the certificate.",
  facts: [
    ["Layer", "Between TCP and the app (5–6)"],
    ["Port", "443 for HTTPS (runs over TCP)"],
    ["Handshake", "1 round trip (0 with resumption)"],
    ["Key exchange", "ECDHE, usually x25519"],
    ["Ciphers", "AES-GCM, ChaCha20-Poly1305"],
    ["Defined in", "RFC 8446"],
  ],
  ports: "443 (HTTPS), 853 (DoT), 993 (IMAPS), 465 (SMTPS)",
  rfc: "RFC 8446",
  keywords: ["https", "ssl", "handshake", "client hello", "server hello", "certificate", "x25519", "sni", "alpn", "0-rtt", "session ticket", "padlock", "cipher suite"],
  related: ["tcp", "mtls", "http", "quic", "oauth"],
  ...devs,
  legend: [
    ["green", "TCP handshake"],
    ["blue", "TLS hello messages (clear text)"],
    ["teal", "Encrypted handshake and keys"],
    ["amber", "Encrypted data from the laptop"],
    ["violet", "Encrypted data from the server"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A TLS 1.3 handshake to example.com",
      summary: "The browser opens https://example.com: one round trip of hellos, then everything is encrypted.",
      kind: "normal",
      steps: [
        {
          title: "TCP first",
          desc: "TLS rides on an open TCP connection",
          detail: "TLS does not open its own connection. The browser first makes an ordinary TCP connection to port 443. Nothing is secret yet: these three packets are the same as for plain HTTP.",
          facts: [["Server", `${S}:443`], ["Laptop port", "51500"], ["Takes", "1 round trip (34 ms)"]],
          events: [
            pkt("client", "server", "green", "SYN", ["port 443"], { time: 0, info: tcpInfo(51500, true, "S", syn), packet: syn.packet }),
            pkt("server", "client", "green", "SYN-ACK", [], { time: 0.034, info: tcpInfo(51500, false, "SA", synack), packet: synack.packet }),
            pkt("client", "server", "green", "ACK", [], { time: 0.0342, info: tcpInfo(51500, true, "A", ack), packet: ack.packet }),
          ],
        },
        {
          title: "Client Hello",
          desc: "Here's what I support, and here's my key",
          detail: "The browser lists its cipher suites and extensions. Three extensions matter most: server_name says which site it wants, supported_versions offers TLS 1.3, and key_share already carries a 32-byte x25519 public key. Sending the key now, before the server has chosen anything, is the trick that saves a whole round trip.",
          facts: [["Size", `${ch.len} bytes`], ["SNI", "example.com (visible to the network)"], ["Key share", "x25519, 32 bytes"]],
          quiz: {
            q: "The legacy version field says TLS 1.2. Where does the browser actually offer TLS 1.3?",
            options: ["In the record header", "In the supported_versions extension", "In the cipher suite list only", "It can't; the server decides"],
            answer: 1,
            why: "The old version fields are frozen at 1.2 because some middleboxes broke on new values. The real list of versions lives in the supported_versions extension.",
          },
          events: [
            pkt("client", "server", "blue", "CLIENT HELLO", ["SNI example.com", "x25519 key share"], { time: 0.035, info: "Client Hello (SNI=example.com)", packet: ch.packet }),
          ],
        },
        {
          title: "Server Hello",
          desc: "Picking the cipher and sending its key",
          detail: "The server picks TLS 1.3 and TLS_AES_128_GCM_SHA256, and sends back its own x25519 public key. Now each side combines its private key with the other's public key and gets the same shared secret, which no one watching can compute. From this secret both derive the handshake keys.",
          facts: [["Version", "TLS 1.3 (in supported_versions)"], ["Cipher", "TLS_AES_128_GCM_SHA256"], ["Shared secret", "x25519 (ECDHE)"]],
          quiz: {
            q: "Right after the Server Hello, what can the server already do?",
            options: ["Nothing until the client answers", "Encrypt the rest of its messages", "Send the page in clear text", "Ask the client for a password"],
            answer: 1,
            why: "Both public keys are now known, so both sides have the shared secret. The server encrypts everything after the Server Hello, including its certificate.",
          },
          events: [
            pkt("server", "client", "blue", "SERVER HELLO", ["TLS 1.3, AES-128-GCM", "x25519 key share"], { time: 0.069, info: "Server Hello, Change Cipher Spec, Application Data", packet: sf1.packet }),
            note("client", "SHARED SECRET READY", "green"),
          ],
        },
        {
          title: "Encrypted server flight",
          desc: "Certificate, signature and Finished, all hidden",
          detail: "The rest of the server's first flight is already encrypted, so it shows up as Application Data records. Inside are EncryptedExtensions (ALPN chose h2), the Certificate chain, CertificateVerify (a signature over the handshake with the certificate's key) and Finished (a MAC over everything so far). The browser checks the chain against its trusted roots, the name, and the dates.",
          facts: [["Certificate", `${CERT} bytes, encrypted`], ["CertificateVerify", "ECDSA P-256 signature"], ["Finished", "HMAC-SHA256 over the handshake"]],
          quiz: {
            q: "Why does CertificateVerify matter? Anyone can copy a public certificate.",
            options: ["It makes the certificate smaller", "It proves the server holds the certificate's private key", "It tells the browser the expiry date", "It picks the cipher suite"],
            answer: 1,
            why: "A certificate is public. Only a signature made with the matching private key, over this very handshake, proves the server is the real owner.",
          },
          events: [
            pkt("server", "client", "teal", "CERT", ["encrypted"], { time: 0.0691, parallel: true, info: "Application Data (Certificate)", packet: sf2.packet }),
            pkt("server", "client", "teal", "CV + FIN", ["encrypted"], { time: 0.0692, parallel: true, info: "Application Data (CertificateVerify, Finished)", packet: sf3.packet }),
            note("client", "CERT CHAIN OK", "green"),
          ],
        },
        {
          title: "Client Finished",
          desc: "The browser confirms, and may speak at once",
          detail: "The browser sends its own Finished, proving it saw the same handshake. A dummy Change Cipher Spec goes first only to keep old middleboxes calm. Both sides now switch from handshake keys to application keys.",
          facts: [["Round trips used", "1"], ["Keys", "Application traffic secrets"], ["Change Cipher Spec", "Dummy, for middleboxes"]],
          events: [
            pkt("client", "server", "teal", "FINISHED", ["encrypted"], { time: 0.071, info: "Change Cipher Spec, Application Data (Finished)", packet: cfin.packet }),
          ],
        },
        {
          title: "Encrypted HTTP",
          desc: "The request and page travel inside TLS",
          detail: "Now HTTP/2 frames go inside encrypted records. On the wire every record says Application Data and has a 16-byte tag at the end; if anyone changes a single bit, the tag check fails and the connection is dropped. The first request left only one round trip after the Client Hello.",
          facts: [["Request", "GET / over HTTP/2"], ["Record overhead", "5-byte header + 1 type byte + 16-byte tag"], ["Response", "200 OK"]],
          events: [
            pkt("client", "server", "amber", "GET /", ["HTTP/2, encrypted"], { time: 0.0711, info: "Application Data (HTTP/2)", packet: req.packet }),
            pkt("server", "client", "violet", "200 OK", ["HTTP/2, encrypted"], { time: 0.106, info: "Application Data (HTTP/2)", packet: resp.packet }),
          ],
        },
        {
          title: "Session tickets",
          desc: "A ticket for next time",
          detail: "After the handshake the server sends two NewSessionTicket messages, encrypted like everything else. Each ticket lets the browser resume later without the certificate exchange, and even send its first request in the Client Hello (0-RTT).",
          facts: [["Tickets", "2"], ["Lifetime", "7 days (604800 s) at most"], ["Used for", "Resumption and 0-RTT"]],
          events: [
            pkt("server", "client", "teal", "TICKET", ["NewSessionTicket x2"], { time: 0.1061, info: "Application Data (NewSessionTicket)", packet: nst.packet }),
            note("client", "PADLOCK SHOWN", "green"),
          ],
        },
      ],
      outro: {
        title: "Secure in one round trip",
        text: "The browser and server swapped key shares in their hellos, so the server could encrypt its certificate straight away. After one round trip the browser sent its request, protected by keys nobody else can compute.",
        facts: [["Round trips before data", "1"], ["Visible in clear", "Hellos, SNI"], ["Encrypted", "Certificate onwards"], ["Total time", "0.106 s"]],
      },
    },
    {
      id: "tls12",
      name: "The same thing in TLS 1.2",
      summary: "An older server only speaks TLS 1.2: two round trips, a visible certificate and a real Change Cipher Spec.",
      kind: "normal",
      steps: [
        {
          title: "Same Client Hello",
          desc: "The browser offers 1.3 and 1.2",
          detail: "The browser sends the same Client Hello as before; it doesn't know yet how old the server is. It offers TLS 1.3 and 1.2 suites. The TCP handshake has already happened.",
          facts: [["Offered", "TLS 1.3 and 1.2"], ["Server", "Supports only 1.2"], ["Time", "starts after TCP"]],
          events: [pkt("client", "server", "blue", "CLIENT HELLO", ["TLS 1.3 + 1.2 offered"], { time: 0, info: "Client Hello (SNI=example.com)", packet: chB.packet })],
        },
        {
          title: "Hello, certificate in clear",
          desc: "Server Hello, Certificate, Server Key Exchange",
          detail: "The server ignores supported_versions and key_share and picks ECDHE-RSA with AES-128-GCM. Its certificate travels in clear text. Then comes Server Key Exchange: a separate message with its ECDHE public key, signed with the certificate's key. Server Hello Done says 'your turn'.",
          facts: [["Cipher", "ECDHE-RSA-AES128-GCM-SHA256"], ["Certificate", "Readable by anyone on the path"], ["Extra message", "Server Key Exchange"]],
          quiz: {
            q: "Why can't the TLS 1.2 server encrypt its certificate like TLS 1.3 does?",
            options: ["The certificate is too big", "No shared key exists yet: the client hasn't sent its key share", "RSA can't encrypt", "Certificates must be public by law"],
            answer: 1,
            why: "In TLS 1.2 the client sends its key share only after it sees the server's. So at this point there is nothing to encrypt with.",
          },
          events: [
            pkt("server", "client", "blue", "SERVER HELLO", ["+ Certificate (clear)"], { time: 0.034, info: "Server Hello, Certificate", packet: sB1.packet }),
            pkt("server", "client", "blue", "KEY EXCH", ["Server Key Exchange", "Server Hello Done"], { time: 0.0341, parallel: true, info: "Server Key Exchange, Server Hello Done", packet: sB2.packet }),
          ],
        },
        {
          title: "Client key, then switch",
          desc: "Client Key Exchange, Change Cipher Spec, Finished",
          detail: "Now the browser sends its public key in Client Key Exchange. Then a Change Cipher Spec, which in TLS 1.2 really means 'from now on I encrypt', followed by an encrypted Finished. The record type of that Finished still says Handshake.",
          facts: [["Client key", "32 bytes x25519"], ["Change Cipher Spec", "Real meaning in 1.2"], ["Finished", "40 bytes encrypted"]],
          events: [pkt("client", "server", "teal", "KEY + CCS", ["Client Key Exchange", "Finished (encrypted)"], { time: 0.036, info: "Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message", packet: cB.packet })],
        },
        {
          title: "Second round trip",
          desc: "Server's Change Cipher Spec and Finished",
          detail: "The server answers with its own Change Cipher Spec and Finished. Only now, two round trips after the Client Hello, can the browser send its request. On a 34 ms path that is 34 ms slower than TLS 1.3 for every new connection.",
          facts: [["Round trips", "2 before data"], ["Extra delay", "34 ms vs TLS 1.3"], ["Forward secrecy", "Yes, thanks to ECDHE"]],
          quiz: {
            q: "How many round trips after the Client Hello before the first request goes out in TLS 1.2?",
            options: ["0", "1", "2", "3"],
            answer: 2,
            why: "Client Hello → server flight is one; Client Key Exchange/Finished → server Finished is the second. TLS 1.3 needs only one.",
          },
          events: [
            pkt("server", "client", "teal", "CCS + FIN", ["encrypted Finished"], { time: 0.070, info: "Change Cipher Spec, Encrypted Handshake Message", packet: sB3.packet }),
            pkt("client", "server", "amber", "GET /", ["HTTP/2, encrypted"], { time: 0.0705, info: "Application Data", packet: reqB.packet }),
          ],
        },
      ],
      outro: {
        title: "Two round trips, more in the open",
        text: "TLS 1.2 waits for the server's key before the client sends its own, so it needs a second round trip. The certificate and more handshake details travel unencrypted. TLS 1.3 fixed both and removed old, weak options.",
        facts: [["TLS 1.2", "2 RTT, certificate visible"], ["TLS 1.3", "1 RTT, certificate encrypted"], ["Removed in 1.3", "RSA key exchange, CBC, SHA-1, compression"]],
      },
    },
    {
      id: "expired",
      name: "Expired certificate",
      summary: "The server's certificate ran out three days ago; the browser refuses with a fatal alert.",
      kind: "failure",
      steps: [
        {
          title: "Hello as usual",
          desc: "Nothing looks wrong yet",
          detail: "The browser sends a normal Client Hello. Nothing in the hellos tells it about the certificate; that arrives encrypted in the server's flight.",
          facts: [["Site", "example.com"], ["Version", "TLS 1.3"], ["Problem", "Not visible yet"]],
          events: [pkt("client", "server", "blue", "CLIENT HELLO", ["SNI example.com"], { time: 0, info: "Client Hello (SNI=example.com)", packet: chE.packet })],
        },
        {
          title: "An old certificate",
          desc: "The server sends a certificate past its date",
          detail: "The server's flight looks exactly like a good one. Inside the encrypted Certificate message, the certificate's Not After date passed three days ago. Somebody forgot to renew it.",
          facts: [["Not After", "3 days ago"], ["Signature", "Valid"], ["Chain", "Trusted root"]],
          quiz: {
            q: "The signature checks out and the name matches. What will the browser do?",
            options: ["Accept it; the key is still good", "Reject it with a fatal alert", "Ask the server for a new one", "Downgrade to TLS 1.2"],
            answer: 1,
            why: "An expired certificate is no longer vouched for by its CA, and could have been revoked without anyone tracking it. Browsers treat it as a hard failure.",
          },
          events: [pkt("server", "client", "teal", "SERVER FLIGHT", ["Server Hello", "Certificate (expired)"], { time: 0.034, info: "Server Hello, Change Cipher Spec, Application Data", packet: sE.packet })],
        },
        {
          title: "Fatal alert 45",
          desc: "certificate_expired, then close",
          detail: "The browser sends an alert with level 2 (fatal) and description 45 (certificate_expired). Because handshake keys already exist, even the alert is encrypted, so on the wire it is a tiny 24-byte Application Data record. Then it closes TCP. The user sees an error page like NET::ERR_CERT_DATE_INVALID.",
          facts: [["Alert level", "2 (fatal)"], ["Description", "45 certificate_expired"], ["Browser shows", "Your connection is not private"]],
          events: [
            pkt("client", "server", "red", "ALERT 45", ["fatal", "certificate_expired"], { time: 0.036, info: "Application Data (Alert: certificate_expired)", packet: alertE.packet }),
            pkt("client", "server", "slate", "FIN", [], { time: 0.0361, info: tcpInfo(51520, true, "FA", finE), packet: finE.packet }),
            note("client", "CERT EXPIRED", "red"),
          ],
        },
      ],
      outro: {
        title: "Refused, as it should be",
        text: "TLS checks dates, names and the chain of trust on every connection. An expired certificate ends the handshake with a fatal alert before any data moves. Automatic renewal (for example with ACME) prevents this outage.",
        facts: [["Alert", "45 certificate_expired"], ["Related alerts", "42 bad_certificate, 48 unknown_ca"], ["Fix", "Renew; automate with ACME"]],
      },
    },
    {
      id: "zero-rtt",
      name: "Resumption with 0-RTT",
      summary: "The browser comes back the next day with a ticket and sends its request inside the very first flight.",
      kind: "normal",
      steps: [
        {
          title: "Ticket and request together",
          desc: "Client Hello with pre_shared_key and early data",
          detail: "After the TCP handshake, the browser sends a Client Hello carrying yesterday's ticket in pre_shared_key, plus a fresh x25519 key share. Right behind it, in the same segment, comes an encrypted HTTP request: early data keyed from the ticket's secret. The binder proves the browser really owns the ticket.",
          facts: [["Ticket", "From the earlier visit"], ["Early data", "GET /news"], ["Still sends", "A fresh key share"]],
          quiz: {
            q: "The early data is encrypted before the server has answered. Which secret makes that possible?",
            options: ["The new x25519 shared secret", "The secret stored with the session ticket", "The server's certificate key", "None; early data is clear text"],
            answer: 1,
            why: "The new key exchange isn't finished yet. Early data uses keys derived from the resumption secret that came with the ticket.",
          },
          events: [
            pkt("client", "server", "green", "SYN", [], { time: 0, info: tcpInfo(51530, true, "S", syn0), packet: syn0.packet }),
            pkt("server", "client", "green", "SYN-ACK", [], { time: 0.034, info: tcpInfo(51530, false, "SA", synack0), packet: synack0.packet }),
            pkt("client", "server", "green", "ACK", [], { time: 0.0342, info: tcpInfo(51530, true, "A", ack0), packet: ack0.packet }),
            pkt("client", "server", "amber", "HELLO+DATA", ["ticket + key share", "GET /news (0-RTT)"], { time: 0.0343, info: "Client Hello, Application Data (early data)", packet: ch0.packet }),
          ],
        },
        {
          title: "Accepted, no certificate",
          desc: "Server Hello picks the ticket and answers the request",
          detail: "The server opens the ticket, accepts it (selected identity 0) and says yes to early data in EncryptedExtensions. No Certificate or CertificateVerify this time. Because it already has the request, the first flight also carries the response.",
          facts: [["Certificate", "Skipped"], ["Response", "In the first server flight"], ["Time to first byte", "1 RTT after TCP"]],
          events: [pkt("server", "client", "violet", "HELLO+PAGE", ["ticket accepted", "200 OK /news"], { time: 0.0683, info: "Server Hello, Change Cipher Spec, Application Data", packet: s0.packet })],
        },
        {
          title: "End of early data",
          desc: "The browser finishes the handshake",
          detail: "The browser sends EndOfEarlyData and its Finished. There is a catch: an attacker who recorded the first flight could send it again, and the server might run the request twice. So browsers and servers only allow 0-RTT for safe requests like GET, never for 'pay now'.",
          facts: [["Risk", "Replay of early data"], ["Allowed for", "Idempotent requests (GET)"], ["Defence", "Single-use tickets, replay caches"]],
          quiz: {
            q: "Which request is unsafe to send as 0-RTT early data?",
            options: ["GET /news", "GET /logo.png", "POST /transfer?amount=5000", "HEAD /"],
            answer: 2,
            why: "Early data can be replayed by an attacker. Repeating a money transfer would be harmful; repeating a page load is not.",
          },
          events: [
            pkt("client", "server", "teal", "FINISHED", ["EndOfEarlyData", "Finished"], { time: 0.0685, info: "Change Cipher Spec, Application Data", packet: c0.packet }),
            note("client", "RESUMED, 0-RTT", "green"),
          ],
        },
      ],
      outro: {
        title: "Zero round trips for the request",
        text: "With a session ticket, the browser sent its request alongside the Client Hello and got the page back in the first server flight. The price is replay risk, so 0-RTT is kept for requests that are safe to repeat.",
        facts: [["Handshake RTTs", "0 for early data"], ["Certificate sent", "No"], ["Replay protection", "Up to the server"], ["Extensions", "pre_shared_key (41), early_data (42)"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Handshake messages",
      items: [["1 ClientHello", "Offers versions, suites, key share"], ["2 ServerHello", "Picks them, sends its key share"], ["8 EncryptedExtensions", "Rest of the choices (ALPN)"], ["11 Certificate", "The server's chain"], ["15 CertificateVerify", "Signature proving key ownership"], ["20 Finished", "MAC over the handshake"], ["4 NewSessionTicket", "Ticket for resumption"]],
    },
    {
      title: "Extensions",
      items: [["0 server_name", "Which site (SNI)"], ["10 supported_groups", "Key exchange curves"], ["13 signature_algorithms", "Accepted signatures"], ["16 ALPN", "h2 or http/1.1"], ["43 supported_versions", "Real version negotiation"], ["51 key_share", "Public key for ECDHE"], ["41 pre_shared_key", "Resumption ticket (last)"]],
    },
    {
      title: "Alerts and numbers",
      items: [["Record types", "20 CCS, 21 Alert, 22 Handshake, 23 Application Data"], ["Alert 40", "handshake_failure"], ["Alert 42 / 45 / 48", "bad / expired / unknown CA certificate"], ["Alert 116", "certificate_required (mTLS)"], ["Record limit", "16 KB plaintext + 256 bytes"]],
    },
  ],
});
