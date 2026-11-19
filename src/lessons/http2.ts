import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { ext, hsMsg, tcp, TcpOpt, tls, vec } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

// ---------------------------------------------------------------- TCP connection helper

type Seg = { flags?: string; data?: LayerSpec[]; info?: string; lost?: boolean; parallel?: boolean; via?: string[]; seq?: number; ack?: number; win?: number; opts?: TcpOpt[] };
const SYN_OPTS: TcpOpt[] = [{ mss: 1460 }, "nop", { ws: 7 }, "nop", "nop", "sackOk"];
const FLAG_ORDER: [string, string][] = [["F", "FIN"], ["S", "SYN"], ["R", "RST"], ["P", "PSH"], ["A", "ACK"]];

/** One TCP connection: keeps the relative seq/ack numbers right for every segment. */
function conn(o: { a: string; b: string; cport: number; sport: number; cBase: number; sBase: number; cl: LayerSpec[]; sv: LayerSpec[] }) {
  const next = { a: 0, b: 0 };
  const seg = (fromA: boolean, time: number, color: Color, label: string, lines: string[], x: Seg = {}): PacketEvent => {
    const data = x.data ?? [];
    const len = data.length ? build(...data).bytes.length : 0;
    const flags = x.flags ?? (len ? "PA" : "A");
    const me = fromA ? "a" : "b", peer = fromA ? "b" : "a";
    const seq = x.seq ?? next[me];
    const ack = x.ack ?? next[peer];
    const hasAck = flags.includes("A"), syn = flags.includes("S");
    const win = x.win ?? (syn ? (fromA ? 64240 : 65160) : fromA ? 502 : 509);
    const sport = fromA ? o.cport : o.sport, dport = fromA ? o.sport : o.cport;
    const packet = build(...(fromA ? o.cl : o.sv), tcp({ sport, dport, seq, ack: hasAck ? ack : 0, flags, win, opts: x.opts ?? (syn ? SYN_OPTS : undefined), seqBase: fromA ? o.cBase : o.sBase, ackBase: hasAck ? (fromA ? o.sBase : o.cBase) : 0 }), ...data);
    if (x.seq === undefined) next[me] += len + (syn || flags.includes("F") ? 1 : 0);
    const names = FLAG_ORDER.filter(([c]) => flags.includes(c)).map(([, n]) => n).join(", ");
    const info = x.info ?? `${sport} → ${dport} [${names}] Seq=${seq}${hasAck ? ` Ack=${ack}` : ""} Win=${win} Len=${len}${syn ? " MSS=1460 WS=128 SACK_PERM" : ""}`;
    return pkt(fromA ? o.a : o.b, fromA ? o.b : o.a, color, label, lines, { time: Number(time.toFixed(4)), info, packet, lost: x.lost, parallel: x.parallel, via: x.via });
  };
  const c = (time: number, color: Color, label: string, lines: string[], x?: Seg) => seg(true, time, color, label, lines, x);
  const s = (time: number, color: Color, label: string, lines: string[], x?: Seg) => seg(false, time, color, label, lines, x);
  const open = (t: number, rtt: number): PacketEvent[] => [
    c(t, "green", "SYN", ["seq=0", `to port ${o.sport}`], { flags: "S" }),
    s(t + rtt, "green", "SYN-ACK", ["seq=0 ack=1"], { flags: "SA" }),
    c(t + rtt + 0.0002, "green", "ACK", ["ack=1", "connected"]),
  ];
  return { c, s, open, next };
}

// ---------------------------------------------------------------- TLS 1.3 hellos

function clientHello(host: string, alpn: string[], seed: number): LayerSpec {
  const hello = hsMsg("client_hello", "Client Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "Frozen at 1.2; the real versions are in supported_versions." },
    { name: "Random", random: 32, seed },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: seed + 1 }], "32 bytes"),
    vec("Cipher suites", 2, [
      { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256 (0x1301)" },
      { name: "Cipher suite", u16: 0x1302, value: "TLS_AES_256_GCM_SHA384 (0x1302)" },
      { name: "Cipher suite", u16: 0x1303, value: "TLS_CHACHA20_POLY1305_SHA256 (0x1303)" },
    ], "3 suites"),
    vec("Compression methods", 1, [{ name: "Method", u8: 0, value: "null (0)" }], "null only"),
    vec("Extensions", 2, [
      ext(0, "server_name", [vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name (0)" }, vec("Host name", 2, [{ name: "Name", text: host }], host)])], host),
      ext(10, "supported_groups", [vec("Groups", 2, [{ name: "Group", u16: 0x001d, value: "x25519 (0x001d)" }, { name: "Group", u16: 0x0017, value: "secp256r1 (0x0017)" }])], "x25519, secp256r1"),
      ext(13, "signature_algorithms", [vec("Algorithms", 2, [
        { name: "Algorithm", u16: 0x0403, value: "ecdsa_secp256r1_sha256 (0x0403)" },
        { name: "Algorithm", u16: 0x0804, value: "rsa_pss_rsae_sha256 (0x0804)" },
        { name: "Algorithm", u16: 0x0401, value: "rsa_pkcs1_sha256 (0x0401)" },
      ])], "3 algorithms"),
      ext(16, "application_layer_protocol_negotiation", [vec("Protocols", 2, alpn.map((p) => vec("Protocol", 1, [{ name: "Name", text: p }], p)))], alpn.join(", "),
        "ALPN: the browser offers h2 first. The server's choice comes back inside the encrypted EncryptedExtensions message."),
      ext(43, "supported_versions", [vec("Versions", 1, [{ name: "Version", u16: 0x0304, value: "TLS 1.3 (0x0304)" }, { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)" }])], "TLS 1.3, TLS 1.2"),
      ext(45, "psk_key_exchange_modes", [vec("Modes", 1, [{ name: "Mode", u8: 1, value: "psk_dhe_ke (1)" }])], "psk_dhe_ke"),
      ext(51, "key_share", [vec("Client key shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 2 }], "32 bytes")])], "x25519 public key"),
    ]),
  ]);
  return tls({ records: [{ type: "handshake", version: 0x0301, fields: [hello] }], summary: `TLS 1.3 Client Hello (SNI=${host}, ALPN=${alpn.join(",")})` });
}

const serverHello = (seed: number): FieldSpec =>
  hsMsg("server_hello", "Server Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
    { name: "Random", random: 32, seed: seed + 50 },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: seed + 1 }], "32 bytes (echo)"),
    { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256 (0x1301)" },
    { name: "Compression method", u8: 0, value: "null (0)" },
    vec("Extensions", 2, [
      ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3 (0x0304)" }], "TLS 1.3"),
      ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 51 }], "32 bytes")], "x25519 public key"),
    ]),
  ]);

// ---------------------------------------------------------------- HTTP/2 frames and HPACK

const FT = { DATA: 0, HEADERS: 1, PRIORITY: 2, RST_STREAM: 3, SETTINGS: 4, PUSH_PROMISE: 5, PING: 6, GOAWAY: 7, WINDOW_UPDATE: 8, CONTINUATION: 9 } as const;
const sizeOf = (fs: FieldSpec[]) => fs.map(field).reduce((n, f) => n + f.bytes.length, 0);

/** One HTTP/2 frame: 9-byte header (length 3, type 1, flags 1, R + stream id 4) + payload. */
function frame(type: keyof typeof FT, flags: number, flagText: string, stream: number, payload: FieldSpec[], note?: string): FieldSpec {
  const len = sizeOf(payload);
  return {
    name: `${type} frame (stream ${stream})`, value: `${len + 9} bytes`, note,
    fields: [
      { name: "Length", u24: len, value: `${len} bytes`, note: "3 bytes: size of the payload after this 9-byte header." },
      { name: "Type", u8: FT[type], value: `${FT[type]} (${type})` },
      { name: "Flags", u8: flags, value: `0x${flags.toString(16).padStart(2, "0")}${flagText ? ` (${flagText})` : ""}` },
      { name: "Stream identifier", u32: stream, value: String(stream), note: stream === 0 ? "Stream 0 means the connection as a whole." : "1 reserved bit + 31-bit stream number. Browser streams are odd: 1, 3, 5…" },
      ...payload,
    ],
  };
}

const hstr = (label: string, s: string): FieldSpec[] => {
  if (s.length > 126) throw new Error("hpack string too long for 1-byte length");
  return [{ name: `${label} length`, u8: s.length, value: `${s.length} (H=0, not Huffman-coded)` }, { name: label, text: s }];
};
const hIdx = (i: number, what: string): FieldSpec => ({ name: `Indexed: ${what}`, u8: 0x80 | i, value: `0x${(0x80 | i).toString(16)} → entry ${i}`, note: i > 61 ? `One byte: entry ${i} is in the dynamic table, added by an earlier request.` : `One byte: entry ${i} of the static table.` });
const hLit = (nameIdx: number, hname: string, value: string): FieldSpec => ({
  name: `Literal + add to table: ${hname}: ${value}`, value: `${hname}: ${value}`, note: `Name from table entry ${nameIdx}, value spelled out, then saved in the dynamic table for next time.`,
  fields: [{ name: "Prefix 01 + name index", u8: 0x40 | nameIdx, value: `0x${(0x40 | nameIdx).toString(16)} (index ${nameIdx})` }, ...hstr("Value", value)],
});
const hLitNoIdx = (nameIdx: number, hname: string, value: string): FieldSpec => ({
  name: `Literal, not indexed: ${hname}: ${value}`, value: `${hname}: ${value}`, note: `Name from table entry ${nameIdx}; value spelled out and not saved, because it will not repeat.`,
  fields: [{ name: "Prefix 0000 + name index", u8: nameIdx, value: `0x0${nameIdx.toString(16)} (index ${nameIdx})` }, ...hstr("Value", value)],
});
const block = (items: FieldSpec[]): FieldSpec => ({ name: "Header block (HPACK)", value: `${sizeOf(items)} bytes`, fields: items });

const settings = (pairs: [number, string, number][]): FieldSpec[] =>
  pairs.map(([id, n, v]) => ({ name: `Setting: ${n}`, value: `${n} = ${v}`, fields: [{ name: "Identifier", u16: id, value: `${id} (${n})` }, { name: "Value", u32: v }] }));

/** A TLS record shown decrypted, as Wireshark shows it with the browser's SSLKEYLOGFILE. */
function dec(frames: FieldSpec[], summary: string): LayerSpec[] {
  const inner = sizeOf(frames);
  return [
    proto({
      id: "tls", name: "TLS (decrypted view)", osi: 6, summary: "Transport Layer Security: Application Data (decrypted with logged keys)",
      fields: [
        { name: "Content type", u8: 23, value: "23 (Application Data)" },
        { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
        { name: "Length", u16: inner + 17, value: `${inner + 17} bytes`, note: "HTTP/2 bytes + 1 inner type byte + 16-byte tag." },
      ],
      trailer: [
        { name: "Inner content type", u8: 23, value: "23 (Application Data)", note: "TLS 1.3 hides the real record type here, inside the encryption." },
        { name: "Authentication tag", random: 16, opaque: true, note: "AES-GCM tag: proves the record was not changed." },
      ],
    }),
    proto({ id: "http2", name: "HTTP/2 (decrypted)", osi: 7, summary, fields: frames }),
  ];
}

// ---------------------------------------------------------------- content

const S = ADDR.web;
const RTT = 0.034;
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0";
const HTML = `<!doctype html>
<html><head><title>Example</title>
<link rel="stylesheet" href="/style.css">
<script src="/app.js" defer></script>
</head><body><h1>Hello over HTTP/2</h1></body></html>
`;
const CSS = "body { font-family: sans-serif; margin: 2em; }\n";
const JS = "document.querySelector('h1').title = 'served over h2';\n";
const blen = (s: string) => new TextEncoder().encode(s).length;
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const reqFirst = frame("HEADERS", 0x05, "END_STREAM, END_HEADERS", 1, [block([
  hIdx(2, ":method: GET"), hIdx(7, ":scheme: https"), hIdx(4, ":path: /"),
  hLit(1, ":authority", "example.com"), hLit(58, "user-agent", UA), hLit(19, "accept", "*/*"),
])], "GET / on stream 1. END_STREAM: no body follows.");
const reqNext = (stream: number, path: string) => frame("HEADERS", 0x05, "END_STREAM, END_HEADERS", stream, [block([
  hIdx(2, ":method: GET"), hIdx(7, ":scheme: https"), hLitNoIdx(4, ":path", path),
  hIdx(64, ":authority: example.com"), hIdx(63, "user-agent"), hIdx(62, "accept: */*"),
])], `GET ${path} on stream ${stream}. Most headers are single bytes pointing at the dynamic table.`);
const respHeaders = (stream: number, type: string, body: string) => frame("HEADERS", 0x04, "END_HEADERS", stream, [block([
  hIdx(8, ":status: 200"), hLit(31, "content-type", type), hLit(28, "content-length", String(blen(body))),
])]);
const dataFrame = (stream: number, body: string, what: string) => frame("DATA", 0x01, "END_STREAM", stream, [{ name: what, text: body, value: `${blen(body)} bytes` }], "END_STREAM: this response is complete.");
const dataOpaque = (stream: number, n: number, what: string, end = true) => frame("DATA", end ? 0x01 : 0, end ? "END_STREAM" : "", stream, [{ name: what, random: n, opaque: true, value: `${n} bytes`, note: "File contents." }]);

const devs = homeToServer({ label: "example.com", sub: S });

export default defineLesson({
  id: "http2",
  name: "HTTP/2",
  full: "Hypertext Transfer Protocol version 2",
  group: "web",
  layer: 7,
  difficulty: 3,
  tagline: "Many requests at once over one connection, in binary frames.",
  description:
    "HTTP/2 keeps HTTP's meaning (methods, headers, status codes) but changes how it travels. Messages are cut into binary frames, each tagged with a stream number, so many requests and responses share one TCP connection at the same time. Headers are compressed with HPACK.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TLS over TCP, port 443"],
    ["Negotiated by", "ALPN \"h2\""],
    ["Frame header", "9 bytes"],
    ["Header compression", "HPACK (RFC 7541)"],
    ["Defined in", "RFC 9113"],
  ],
  ports: "443 (h2 over TLS)",
  rfc: "RFC 9113, RFC 7541",
  keywords: ["h2", "frames", "streams", "multiplexing", "hpack", "alpn", "settings", "head-of-line blocking", "preface"],
  related: ["http", "https", "grpc", "tcp", "quic"],
  ...devs,
  legend: [
    ["green", "TCP handshake and ACKs"],
    ["teal", "TLS handshake"],
    ["blue", "Connection setup (SETTINGS)"],
    ["amber", "Requests (HEADERS)"],
    ["violet", "Responses (HEADERS + DATA)"],
  ],
  scenarios: [
    (() => {
      const k = conn({ a: "client", b: "server", cport: 52410, sport: 443, cBase: 0x30c0ffee, sBase: 0x7e57ab1e, cl: up(S), sv: down(S) });
      return {
        id: "normal",
        name: "A page with CSS and JavaScript",
        summary: "TLS picks h2, both sides exchange SETTINGS, and three files come back over one connection. Frames are shown decrypted.",
        kind: "normal" as const,
        steps: [
          {
            title: "TCP, then Client Hello",
            desc: "ALPN offers h2 first",
            detail: "The browser connects to port 443 and starts TLS. In the Client Hello's ALPN extension it lists the protocols it can speak inside TLS: h2 first, then http/1.1. This is how both sides agree on HTTP/2 without an extra round trip.",
            facts: [["ALPN offer", "h2, http/1.1"], ["Port", "443"], ["Extra round trips", "None"]],
            events: [...k.open(0, RTT), k.c(0.0345, "teal", "HELLO", ["ALPN: h2", "SNI example.com"], { data: [clientHello("example.com", ["h2", "http/1.1"], 5200)], info: "Client Hello (SNI=example.com)" })],
          },
          {
            title: "Server picks h2",
            desc: "The answer is inside the encrypted part",
            detail: "The server's choice of h2 is in EncryptedExtensions, which TLS 1.3 encrypts. From here on this lesson shows the decrypted view, as Wireshark does when the browser writes its TLS keys to an SSLKEYLOGFILE. On the real wire these records are unreadable.",
            facts: [["Chosen", "h2"], ["Where", "EncryptedExtensions"], ["Decrypted with", "SSLKEYLOGFILE"]],
            quiz: {
              q: "What happens if the server only supports HTTP/1.1?",
              options: ["The connection fails", "ALPN picks http/1.1 and the browser speaks HTTP/1.1", "The browser retries on port 80", "The server upgrades later"],
              answer: 1,
              why: "ALPN is a negotiation: the server picks one protocol from the browser's list. http/1.1 is the fallback.",
            },
            events: [
              k.s(0.0692, "teal", "S.HELLO", ["ALPN: h2 (encrypted)"], {
                info: "Server Hello, Change Cipher Spec, Application Data, Application Data",
                data: [tls({ records: [
                  { type: "handshake", fields: [serverHello(5200)] },
                  { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] },
                  { type: "appdata", encrypted: 42, what: "EncryptedExtensions (encrypted)", note: "Encrypted: contains ALPN = h2." },
                  { type: "appdata", encrypted: 1180, what: "Certificate, CertificateVerify, Finished (encrypted)" },
                ] })],
              }),
              k.c(0.0711, "teal", "FINISHED", [], { info: "Change Cipher Spec, Application Data", data: [tls({ records: [{ type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] }, { type: "appdata", encrypted: 53, what: "Finished (encrypted)" }] })] }),
            ],
          },
          {
            title: "Preface and SETTINGS",
            desc: "PRI * HTTP/2.0, then the browser's limits",
            detail: "The browser starts with a fixed 24-byte preface, PRI * HTTP/2.0 then SM. An HTTP/1.1 server would reject it, so a mismatch is caught at once. Then comes a SETTINGS frame with the browser's limits and a WINDOW_UPDATE that gives the server a bigger flow-control window.",
            facts: [["Preface", "24 bytes, fixed"], ["Frame header", "Length 3, Type 1, Flags 1, Stream 4"], ["Stream", "0 = whole connection"]],
            quiz: {
              q: "The SETTINGS frame has 4 settings of 6 bytes each. What does its 3-byte Length field say?",
              options: ["4", "24", "33", "9"],
              answer: 1,
              why: "Length counts only the payload after the 9-byte header: 4 × 6 = 24.",
            },
            events: [
              k.c(0.0713, "blue", "PREFACE", ["PRI * HTTP/2.0", "SETTINGS"], {
                info: "Magic, SETTINGS[0], WINDOW_UPDATE[0]",
                data: dec([
                  { name: "Connection preface", text: PREFACE, value: "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n", note: "A fixed string. It looks like a broken HTTP/1 request on purpose, so old servers fail fast." },
                  frame("SETTINGS", 0, "", 0, settings([[1, "HEADER_TABLE_SIZE", 65536], [2, "ENABLE_PUSH", 0], [4, "INITIAL_WINDOW_SIZE", 131072], [5, "MAX_FRAME_SIZE", 16384]]), "The browser's limits and preferences."),
                  frame("WINDOW_UPDATE", 0, "", 0, [{ name: "Window size increment", u32: 12517377, note: "Lets the server send about 12 MB more on the connection before waiting." }]),
                ], "Magic, SETTINGS, WINDOW_UPDATE"),
              }),
            ],
          },
          {
            title: "Server SETTINGS and ACKs",
            desc: "Both sides confirm the other's settings",
            detail: "The server sends its own SETTINGS, for example at most 128 streams at once, and acknowledges the browser's SETTINGS with an empty SETTINGS frame that has the ACK flag. The browser does the same back.",
            facts: [["Max streams", "128 at once"], ["ACK", "Empty SETTINGS, flag 0x01"], ["Applies to", "The whole connection"]],
            events: [
              k.s(0.1054, "blue", "SETTINGS", ["max 128 streams", "+ ACK"], {
                info: "SETTINGS[0], SETTINGS[0] (ACK)",
                data: dec([
                  frame("SETTINGS", 0, "", 0, settings([[3, "MAX_CONCURRENT_STREAMS", 128], [4, "INITIAL_WINDOW_SIZE", 65536], [5, "MAX_FRAME_SIZE", 16777215]])),
                  frame("SETTINGS", 0x01, "ACK", 0, [], "Empty SETTINGS with the ACK flag: \"got your settings\"."),
                ], "SETTINGS, SETTINGS ACK"),
              }),
              k.c(0.1056, "blue", "ACK", ["SETTINGS ACK"], { info: "SETTINGS[0] (ACK)", data: dec([frame("SETTINGS", 0x01, "ACK", 0, [])], "SETTINGS ACK") }),
            ],
          },
          {
            title: "GET / on stream 1",
            desc: "A HEADERS frame, compressed with HPACK",
            detail: "The request is a HEADERS frame on stream 1. Common headers like :method GET are a single byte pointing into HPACK's built-in static table. New values such as the user-agent are spelled out once and saved in a dynamic table, so later requests can refer to them with one byte.",
            facts: [["Stream", "1 (odd = browser-started)"], [":method GET", "1 byte (0x82)"], ["Flags", "END_STREAM, END_HEADERS"]],
            quiz: {
              q: "The next request also has user-agent with the same value. How many bytes will that header take?",
              options: ["About 85, spelled out again", "1 byte, pointing at the dynamic table", "0, headers are not resent", "2 bytes"],
              answer: 1,
              why: "HPACK added it to the dynamic table, so next time a single indexed byte is enough.",
            },
            events: [k.c(0.1058, "amber", "HEADERS", ["stream 1", "GET /"], { info: "HEADERS[1]: GET /", data: dec([reqFirst], "HEADERS[1]: GET /") })],
          },
          {
            title: "Response on stream 1",
            desc: "HEADERS then DATA",
            detail: "The server answers on the same stream number: a HEADERS frame with :status 200, then a DATA frame with the HTML and the END_STREAM flag. The browser reads the HTML and finds two more files to fetch.",
            facts: [[":status 200", "1 byte (0x88)"], ["Body", `${blen(HTML)} bytes in DATA`], ["Found", "/style.css, /app.js"]],
            events: [
              k.s(0.1402, "violet", "200 OK", ["stream 1", "HEADERS + DATA"], { info: "HEADERS[1]: 200 OK, DATA[1]", data: dec([respHeaders(1, "text/html; charset=utf-8", HTML), dataFrame(1, HTML, "HTML")], "HEADERS[1]: 200 OK, DATA[1]") }),
            ],
          },
          {
            title: "Two requests at once",
            desc: "Streams 3 and 5 in one packet",
            detail: "Instead of waiting, or opening more connections like HTTP/1.1, the browser sends both requests together on streams 3 and 5. Thanks to the dynamic table each HEADERS frame is tiny. The server may answer in any order, and it can even interleave frames from different streams.",
            facts: [["Streams", "3 (/style.css), 5 (/app.js)"], ["Connections", "Still 1"], ["Header block", "Under 25 bytes each"]],
            quiz: {
              q: "app.js is ready before style.css. Can the server send it first?",
              options: ["No, responses must follow request order", "Yes, frames carry the stream number so order does not matter", "Only if the browser asks", "Only with HTTP/3"],
              answer: 1,
              why: "Each frame names its stream, so responses can arrive in any order and even be interleaved. HTTP/1.1 could not do this.",
            },
            events: [
              k.c(0.1406, "amber", "HEADERS", ["streams 3 + 5", "CSS and JS"], { info: "HEADERS[3]: GET /style.css, HEADERS[5]: GET /app.js", data: dec([reqNext(3, "/style.css"), reqNext(5, "/app.js")], "HEADERS[3], HEADERS[5]") }),
              k.s(0.1751, "violet", "DATA", ["stream 5 then 3", "out of order"], {
                info: "HEADERS[5], DATA[5], HEADERS[3], DATA[3]",
                data: dec([respHeaders(5, "text/javascript", JS), dataFrame(5, JS, "JavaScript"), respHeaders(3, "text/css", CSS), dataFrame(3, CSS, "CSS")], "HEADERS[5], DATA[5], HEADERS[3], DATA[3]"),
              }),
              k.c(0.1753, "green", "ACK", []),
              note("client", "3 FILES, 1 CONNECTION", "green"),
            ],
          },
        ],
        outro: {
          title: "Multiplexed",
          text: "ALPN chose h2 inside the TLS handshake, the preface and SETTINGS set up the connection, and three requests shared one TCP connection as frames on streams 1, 3 and 5. HPACK shrank repeated headers to single bytes. One weakness remains: all streams share one TCP byte stream.",
          facts: [["Streams used", "1, 3, 5"], ["TCP connections", "1"], ["Frame header", "9 bytes"], ["Page ready", "~175 ms"]],
        },
      };
    })(),
    (() => {
      const k = conn({ a: "client", b: "server", cport: 52410, sport: 443, cBase: 0x30c0ffee, sBase: 0x7e57ab1e, cl: up(S), sv: down(S) });
      // continue an already-open connection: pretend earlier bytes were exchanged
      k.next.a = 1201; k.next.b = 6533;
      const req3 = dec([reqNext(7, "/hero.jpg"), reqNext(9, "/font.woff2"), reqNext(11, "/logo.svg")], "HEADERS[7], HEADERS[9], HEADERS[11]");
      const seg7 = dec([dataOpaque(7, 1200, "hero.jpg (part)", false)], "DATA[7]");
      const seg9 = dec([dataOpaque(9, 1200, "font.woff2")], "DATA[9]");
      const seg11 = dec([dataOpaque(11, 1200, "logo.svg")], "DATA[11]");
      const lostSeq = 6533; // relative seq of the lost segment
      return {
        id: "hol",
        name: "One lost segment stalls every stream",
        summary: "A single dropped TCP segment carrying stream 7 holds back streams 9 and 11 too: TCP head-of-line blocking.",
        kind: "failure" as const,
        steps: [
          {
            title: "Three requests",
            desc: "Streams 7, 9 and 11",
            detail: "Later on the same connection, the browser asks for an image, a font and a logo on three new streams. They travel together in one TLS record.",
            facts: [["Streams", "7, 9, 11"], ["Connection", "The same one as before"], ["Sent", "In one segment"]],
            events: [k.c(0, "amber", "HEADERS", ["streams 7, 9, 11"], { info: "HEADERS[7], HEADERS[9], HEADERS[11]", data: req3 })],
          },
          {
            title: "Segment with stream 7 is lost",
            desc: "Streams 9 and 11 arrive fine",
            detail: "The server sends three TCP segments, one per stream. A busy router drops the first one, which carries stream 7's data. The segments with stream 9 and stream 11 arrive safely.",
            facts: [["Lost", "Segment with DATA[7]"], ["Arrived", "DATA[9], DATA[11]"], ["Each segment", "~1290 bytes"]],
            quiz: {
              q: "The font (stream 9) has fully arrived at the laptop. Can the browser use it now?",
              options: ["Yes, it is a separate stream", "No, TCP holds all later bytes until the gap is filled", "Yes, but only after a second", "No, fonts need stream 7"],
              answer: 1,
              why: "HTTP/2 streams are independent, but TCP only hands over bytes in order. Everything after the gap waits.",
            },
            events: [
              k.s(0.035, "violet", "DATA 7", ["hero.jpg", "lost"], { lost: true, data: seg7, info: "DATA[7]" }),
              k.s(0.0351, "violet", "DATA 9", ["font.woff2"], { parallel: true, data: seg9, info: "DATA[9]" }),
              k.s(0.0352, "violet", "DATA 11", ["logo.svg"], { parallel: true, data: seg11, info: "DATA[11]" }),
              note("internet", "SEGMENT LOST", "amber"),
            ],
          },
          {
            title: "Everything waits",
            desc: "TCP head-of-line blocking",
            detail: "TCP sees a gap before the stream 9 and stream 11 bytes. It must deliver bytes in order, so it keeps them in its buffer and tells the server with duplicate ACKs and a SACK block. The browser gets nothing at all until the gap is filled, even for streams that are complete.",
            facts: [["Held back", "Streams 9 and 11"], ["Signal", "Duplicate ACK + SACK"], ["Browser sees", "Nothing yet"]],
            events: (() => {
              const sackL = 0x7e57ab1e + lostSeq + build(...seg7).bytes.length;
              const sackR = sackL + build(...seg9).bytes.length + build(...seg11).bytes.length;
              return [
                k.c(0.0353, "green", "DUP ACK", [`ack=${lostSeq}`, "SACK 9 + 11"], { ack: lostSeq, opts: ["nop", "nop", { sack: [[sackL >>> 0, sackR >>> 0]] }], info: `[TCP Dup ACK] 52410 → 443 [ACK] Seq=1201 Ack=${lostSeq} SLE=${sackL - 0x7e57ab1e} SRE=${sackR - 0x7e57ab1e}` }),
                note("client", "STREAMS 9 + 11 STUCK", "red"),
              ];
            })(),
          },
          {
            title: "Resend and release",
            desc: "All three streams arrive together",
            detail: "The server resends the missing segment. Now TCP has every byte in order and hands streams 7, 9 and 11 to the browser at once. One lost packet delayed three unrelated files by a full round trip. HTTP/3 fixes this by running over QUIC, where each stream has its own ordering.",
            facts: [["Delay added", "~1 round trip"], ["Streams hurt", "3 (only 1 was lost)"], ["Real fix", "HTTP/3 over QUIC"]],
            quiz: {
              q: "Why does HTTP/3 not have this problem?",
              options: ["It never loses packets", "QUIC orders each stream separately, so a loss only delays its own stream", "It uses bigger packets", "It sends everything twice"],
              answer: 1,
              why: "QUIC knows about streams. A lost packet blocks only the streams whose data was in it.",
            },
            events: [
              k.s(0.0705, "violet", "RESEND", ["DATA 7"], { seq: lostSeq, data: seg7, info: "[TCP Retransmission] DATA[7]" }),
              k.c(0.0707, "green", "ACK", ["all bytes in order"]),
              note("client", "7, 9, 11 DELIVERED", "green"),
            ],
          },
        ],
        outro: {
          title: "Head-of-line blocking moved down a layer",
          text: "HTTP/2 removed head-of-line blocking between requests, but all streams still ride one TCP byte stream. When a segment is lost, every stream waits for it. On lossy mobile networks this can make HTTP/2 slower than several HTTP/1.1 connections, which is why HTTP/3 moved to QUIC.",
          facts: [["Cause", "TCP delivers bytes strictly in order"], ["Hurts most", "Lossy Wi-Fi and mobile"], ["Fix", "HTTP/3 (QUIC)"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "Frame types",
      items: [["0 DATA", "Body bytes"], ["1 HEADERS", "Request or response headers"], ["3 RST_STREAM", "Cancel one stream"], ["4 SETTINGS", "Connection parameters"], ["6 PING", "Liveness and RTT"], ["7 GOAWAY", "Shutting down"], ["8 WINDOW_UPDATE", "Flow control credit"]],
    },
    {
      title: "Frame header (9 bytes)",
      items: [["Length", "3 bytes"], ["Type", "1 byte"], ["Flags", "1 byte (END_STREAM 0x1, END_HEADERS 0x4, ACK 0x1)"], ["Stream ID", "4 bytes (1 reserved bit)"]],
    },
    {
      title: "HPACK",
      items: [["Static table", "61 common headers"], ["Dynamic table", "Entries 62+, per connection"], ["0x82", ":method GET"], ["0x88", ":status 200"]],
    },
  ],
});
