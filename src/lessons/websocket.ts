import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, proto, textLayer } from "@/lib/packet";
import { eth, ipv4, tcp, TcpOpt } from "@/lib/proto";
import { toHex } from "@/lib/bytes";
import { ADDR, down, up } from "./_common";

// ---------------------------------------------------------------- TCP connection helper

type Seg = { flags?: string; data?: LayerSpec[]; info?: string; lost?: boolean; parallel?: boolean; via?: string[]; seq?: number; ack?: number; win?: number };
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
    const packet = build(...(fromA ? o.cl : o.sv), tcp({ sport, dport, seq, ack: hasAck ? ack : 0, flags, win, opts: syn ? SYN_OPTS : undefined, seqBase: fromA ? o.cBase : o.sBase, ackBase: hasAck ? (fromA ? o.sBase : o.cBase) : 0 }), ...data);
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

// ---------------------------------------------------------------- WebSocket frames (RFC 6455)

// Sec-WebSocket-Key is 16 random bytes in base64 (here the ASCII bytes "ProtocolsByDanis").
// Accept = base64(SHA-1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")), computed with node:crypto.
const WS_KEY = "UHJvdG9jb2xzQnlEYW5pcw==";
const WS_ACCEPT = "bBg45Fje81XX4xvOWUFa04onpGI=";

const OPS: Record<number, string> = { 0x1: "Text", 0x2: "Binary", 0x8: "Close", 0x9: "Ping", 0xa: "Pong" };
const enc = (s: string) => Array.from(new TextEncoder().encode(s));

/** One WebSocket frame. Client frames must be masked; server frames must not be. Payload < 126 bytes. */
function wsFrame(opcode: number, payload: number[], shown: string, mask?: number[], inner?: FieldSpec[]): LayerSpec {
  const len = payload.length;
  const fields: FieldSpec[] = [
    { name: "FIN, RSV, opcode", u8: 0x80 | opcode, value: `FIN=1, opcode ${opcode} (${OPS[opcode]})`, note: "FIN=1: this is the whole message. The low 4 bits say what kind of frame it is." },
    { name: "MASK, payload length", u8: (mask ? 0x80 : 0) | len, value: `MASK=${mask ? 1 : 0}, ${len} bytes`, note: mask ? "Client-to-server frames must be masked (MASK=1)." : "Server-to-client frames are never masked." },
  ];
  if (mask) {
    const masked = payload.map((b, i) => b ^ mask[i % 4]);
    fields.push({ name: "Masking key", bytes: mask, value: `0x${toHex(mask, "")}`, note: "4 random bytes, new for every frame." });
    fields.push({ name: "Masked payload", bytes: masked, value: `${len} bytes → ${shown}`, note: `Each byte is XORed with key byte (i mod 4). Unmasked: ${toHex(payload)}. Masking stops old proxies from mistaking the bytes for HTTP.` });
  } else if (len) {
    fields.push(inner ? { name: "Payload", fields: inner, value: shown } : { name: "Payload", bytes: payload, value: shown });
  }
  return proto({ id: "websocket", name: "WebSocket", osi: 7, summary: `WebSocket ${OPS[opcode]} [FIN]${mask ? " [MASKED]" : ""}: ${shown}`, fields });
}

const closeBody = (code: number, reason: string) => [(code >> 8) & 255, code & 255, ...enc(reason)];
const closeFields = (code: number, reason: string): FieldSpec[] => [{ name: "Status code", u16: code, value: `${code} (Normal Closure)` }, { name: "Reason", text: reason }];

// ---------------------------------------------------------------- content

const S = ADDR.web;
const RTT = 0.034;
const MSG1 = "Namaste!";
const MSG2 = '{"from":"Asha","text":"Hi Danish, welcome to the room"}';

const upgradeLines = [
  "GET /chat HTTP/1.1",
  "Host: example.com",
  "Upgrade: websocket",
  "Connection: Upgrade",
  `Sec-WebSocket-Key: ${WS_KEY}`,
  "Sec-WebSocket-Version: 13",
  "Origin: http://example.com",
];
const upgradeReq = () => textLayer({
  id: "http", name: "HTTP", lines: upgradeLines, blankLine: true,
  notes: {
    2: "Asks the server to switch this connection to the WebSocket protocol.",
    3: "Says the Upgrade header is meant for this hop. Proxies treat both as hop-by-hop and may drop them.",
    4: "16 random bytes in base64. The server must prove it read them.",
    5: "The only version in use today.",
    6: "Which page opened the socket, so the server can refuse other sites.",
  },
});

const devices = [
  { id: "client", kind: "laptop" as const, label: "Browser", sub: ADDR.laptop, x: 9, y: 62 },
  { id: "router", kind: "router" as const, label: "Home router", sub: ADDR.router, x: 32, y: 62 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 58, y: 40 },
  { id: "server", kind: "server" as const, label: "Chat server", sub: S, x: 87, y: 62 },
];
const links: [string, string][] = [["client", "router"], ["router", "internet"], ["internet", "server"]];

const PROXY_MAC = "00:50:56:a1:31:28";
const GW_MAC = "00:00:5e:00:01:07";
const proxyDevices = [
  { id: "client", kind: "laptop" as const, label: "Office laptop", sub: ADDR.laptop, x: 9, y: 62 },
  { id: "proxy", kind: "proxy" as const, label: "Transparent proxy", sub: ADDR.routerWan, x: 33, y: 62 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 60, y: 40 },
  { id: "server", kind: "server" as const, label: "Chat server", sub: S, x: 87, y: 62 },
];
const proxyLinks: [string, string][] = [["client", "proxy"], ["proxy", "internet"], ["internet", "server"]];

export default defineLesson({
  id: "websocket",
  name: "WebSocket",
  full: "The WebSocket Protocol",
  group: "web",
  layer: 7,
  difficulty: 2,
  tagline: "Turn one HTTP request into a two-way, always-open pipe.",
  description:
    "WebSocket starts as an ordinary HTTP request that asks to upgrade. Once the server agrees with 101 Switching Protocols, the same TCP connection carries small frames in both directions, whenever either side wants. Chat, live scores and multiplayer games use it.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Starts as", "HTTP/1.1 GET with Upgrade"],
    ["Ports", "80 (ws://), 443 (wss://)"],
    ["Frame header", "2–14 bytes"],
    ["Client frames", "Always masked"],
    ["Defined in", "RFC 6455"],
  ],
  ports: "80 (ws), 443 (wss)",
  rfc: "RFC 6455",
  keywords: ["ws", "wss", "upgrade", "101", "sec-websocket-key", "masking", "ping", "pong", "close", "real-time", "chat"],
  related: ["http", "https", "tcp", "proxy"],
  devices,
  links,
  legend: [
    ["green", "TCP handshake and ACKs"],
    ["blue", "HTTP upgrade"],
    ["amber", "Frames from the browser"],
    ["violet", "Frames from the server"],
    ["slate", "Ping, pong and close"],
  ],
  scenarios: [
    (() => {
      const k = conn({ a: "client", b: "server", cport: 52510, sport: 80, cBase: 0x11aa2200, sBase: 0x55cc6600, cl: up(S), sv: down(S) });
      const resp = textLayer({
        id: "http", name: "HTTP", blankLine: true,
        lines: ["HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade", `Sec-WebSocket-Accept: ${WS_ACCEPT}`],
        notes: { 0: "101: from the next byte on, this connection speaks WebSocket, not HTTP.", 3: "base64(SHA-1(key + 258EAFA5-E914-47DA-95CA-C5AB0DC85B11)). Proves the server really understood the WebSocket request." },
      });
      return {
        id: "normal",
        name: "A chat room",
        summary: "The browser upgrades an HTTP request, sends and receives messages, answers a ping and closes cleanly.",
        kind: "normal" as const,
        steps: [
          {
            title: "Ask to upgrade",
            desc: "GET with Upgrade: websocket",
            detail: "JavaScript runs new WebSocket(\"ws://example.com/chat\"). The browser opens a TCP connection and sends a normal-looking GET with Upgrade: websocket, Connection: Upgrade and a random Sec-WebSocket-Key.",
            facts: [["URL", "ws://example.com/chat"], ["Key", WS_KEY], ["Version", "13"]],
            events: [...k.open(0, RTT), k.c(0.0345, "blue", "UPGRADE", ["GET /chat", "Upgrade: websocket"], { data: [upgradeReq()], info: "GET /chat HTTP/1.1 (Upgrade: websocket)" })],
          },
          {
            title: "101 Switching Protocols",
            desc: "The server agrees and proves it",
            detail: "The server glues the key to a fixed GUID, hashes it with SHA-1 and sends the base64 result as Sec-WebSocket-Accept. The browser does the same sum; if it matches, the connection is now a WebSocket. HTTP is finished on this connection.",
            facts: [["Status", "101 Switching Protocols"], ["Accept", WS_ACCEPT], ["Formula", "base64(SHA-1(key + GUID))"]],
            quiz: {
              q: "Why does the server have to send Sec-WebSocket-Accept at all?",
              options: ["To encrypt the connection", "To prove it understood the WebSocket request, not just any HTTP", "To log the user in", "To choose a port"],
              answer: 1,
              why: "Only a server that read the key and knows the WebSocket GUID can produce the right value. A confused HTTP server or cache cannot fake a valid upgrade.",
            },
            events: [k.s(0.0692, "blue", "101", ["Switching", "Protocols"], { data: [resp], info: "HTTP/1.1 101 Switching Protocols" }), note("client", "SOCKET OPEN", "green")],
          },
          {
            title: "Browser sends a message",
            desc: "A masked text frame",
            detail: `The browser sends "${MSG1}" as a text frame. The header is just 2 bytes plus a 4-byte masking key. Every payload byte is XORed with the key, so the bytes on the wire look random. This is not encryption: the key is right there. It stops badly written proxies from treating the bytes as HTTP.`,
            facts: [["Opcode", "1 (text)"], ["Header", "2 bytes + 4-byte mask"], ["Payload", `${enc(MSG1).length} bytes, masked`]],
            quiz: {
              q: `The first payload byte is "N" (0x4e) and the first key byte is 0x37. What byte goes on the wire?`,
              options: ["0x4e", "0x37", "0x79", "0x85"],
              answer: 2,
              why: "0x4e XOR 0x37 = 0x79. The server XORs again with 0x37 to get 0x4e back.",
            },
            events: [
              k.c(0.072, "amber", "TEXT", [`"${MSG1}"`, "masked"], { data: [wsFrame(0x1, enc(MSG1), `"${MSG1}"`, [0x37, 0xfa, 0x21, 0x3d])], info: "WebSocket Text [FIN] [MASKED]" }),
              k.s(0.1062, "green", "ACK", []),
            ],
          },
          {
            title: "Server pushes a message",
            desc: "Unmasked, whenever it likes",
            detail: "Another user in the room writes something, and the server pushes it to the browser at once. The browser did not ask for it. Server frames are never masked, so the JSON text is readable on the wire.",
            facts: [["Direction", "Server → browser, unasked"], ["Masked", "No"], ["Payload", `${enc(MSG2).length} bytes of JSON`]],
            events: [
              k.s(1.204, "violet", "TEXT", ["from Asha", "pushed"], { data: [wsFrame(0x1, enc(MSG2), MSG2)], info: "WebSocket Text [FIN]" }),
              k.c(1.2042, "green", "ACK", []),
            ],
          },
          {
            title: "Ping and pong",
            desc: "Is anyone still there?",
            detail: "Every 30 seconds the server sends a ping frame. The browser must answer with a pong carrying the same bytes. This keeps NAT and firewall entries alive and lets the server notice dead clients.",
            facts: [["Ping opcode", "9"], ["Pong opcode", "10 (0xA)"], ["Pong payload", "Same as the ping"]],
            quiz: {
              q: "The ping carries the 2 bytes \"hb\". What must the pong carry?",
              options: ["Nothing", "\"hb\", masked because it comes from the browser", "\"hb\" unmasked", "The current time"],
              answer: 1,
              why: "A pong echoes the ping's payload. It goes from the browser, so like every client frame it is masked.",
            },
            events: [
              k.s(31.204, "slate", "PING", ["\"hb\""], { data: [wsFrame(0x9, enc("hb"), '"hb"')], info: "WebSocket Ping [FIN]" }),
              k.c(31.2045, "slate", "PONG", ["\"hb\"", "masked"], { data: [wsFrame(0xa, enc("hb"), '"hb"', [0x5a, 0x1c, 0x9e, 0x42])], info: "WebSocket Pong [FIN] [MASKED]" }),
            ],
          },
          {
            title: "Close cleanly",
            desc: "Close 1000, echoed, then TCP FIN",
            detail: "When the tab closes, the browser sends a close frame with status 1000 (normal closure) and a short reason. The server answers with its own close frame and then closes the TCP connection first, so the server is the one that waits in TIME-WAIT.",
            facts: [["Close opcode", "8"], ["Code", "1000 = normal"], ["Who closes TCP", "The server"]],
            events: [
              k.c(45.1, "slate", "CLOSE", ["1000", "\"bye\""], { data: [wsFrame(0x8, closeBody(1000, "bye"), '1000 "bye"', [0xc3, 0x07, 0x6b, 0xd8])], info: "WebSocket Connection Close [FIN] [MASKED]" }),
              k.s(45.135, "slate", "CLOSE", ["1000", "echo"], { data: [wsFrame(0x8, closeBody(1000, "bye"), '1000 "bye"', undefined, closeFields(1000, "bye"))], info: "WebSocket Connection Close [FIN]" }),
              k.s(45.1351, "slate", "FIN", [], { flags: "FA", parallel: true }),
              k.c(45.1353, "slate", "FIN", [], { flags: "FA" }),
              k.s(45.17, "green", "ACK", []),
            ],
          },
        ],
        outro: {
          title: "A two-way pipe",
          text: "One HTTP request with Upgrade turned a TCP connection into a WebSocket. After that, both sides sent tiny frames whenever they liked, kept the line alive with ping and pong, and closed with code 1000. In real sites use wss://, which is the same thing inside TLS.",
          facts: [["Handshake", "1 HTTP request + 101"], ["Smallest frame", "2 bytes (server), 6 (client)"], ["Close code", "1000 normal"], ["Secure version", "wss:// on port 443"]],
        },
      };
    })(),
    (() => {
      const k = conn({ a: "client", b: "proxy", cport: 52530, sport: 80, cBase: 0x21bb3300, sBase: 0x66dd7700, cl: up(S), sv: down(S) });
      // the proxy's own connection to the server (already open)
      const k2 = conn({
        a: "proxy", b: "server", cport: 40122, sport: 80, cBase: 0x3fe0a100, sBase: 0x77ee8800,
        cl: [eth({ src: PROXY_MAC, dst: GW_MAC }), ipv4({ src: ADDR.routerWan, dst: S })],
        sv: [eth({ src: GW_MAC, dst: PROXY_MAC }), ipv4({ src: S, dst: ADDR.routerWan, ttl: 55 })],
      });
      k2.next.a = 1; k2.next.b = 1;
      const stripped = textLayer({
        id: "http", name: "HTTP", blankLine: true,
        lines: ["GET /chat HTTP/1.1", "Host: example.com", `Sec-WebSocket-Key: ${WS_KEY}`, "Sec-WebSocket-Version: 13", "Origin: http://example.com", "Via: 1.1 office-proxy"],
        notes: { 0: "Upgrade and Connection are gone. The proxy treated them as hop-by-hop headers and removed them.", 5: "Added by the proxy." },
      });
      const r426 = (via: boolean) => textLayer({
        id: "http", name: "HTTP", blankLine: true,
        lines: ["HTTP/1.1 426 Upgrade Required", "Upgrade: websocket", "Connection: close", "Content-Length: 0", ...(via ? ["Via: 1.1 office-proxy"] : [])],
        notes: { 0: "The server only speaks WebSocket at /chat, and this request did not ask to upgrade." },
      });
      return {
        id: "proxy-strips",
        name: "A proxy that doesn't understand Upgrade",
        summary: "An old office proxy removes the Upgrade headers, the server refuses, and the socket never opens.",
        kind: "failure" as const,
        devices: proxyDevices,
        links: proxyLinks,
        steps: [
          {
            title: "Upgrade request",
            desc: "Caught by a transparent proxy",
            detail: "On an office network, all port 80 traffic is silently passed through a transparent proxy. The browser's Upgrade request looks exactly like before, but it lands at the proxy, which completes the TCP handshake in the server's name.",
            facts: [["URL", "ws://example.com/chat"], ["Intercepted by", "Office proxy"], ["Browser notices?", "No"]],
            events: [...k.open(0, 0.002), k.c(0.0025, "blue", "UPGRADE", ["GET /chat", "Upgrade: websocket"], { data: [upgradeReq()], info: "GET /chat HTTP/1.1 (Upgrade: websocket)" })],
          },
          {
            title: "Headers stripped",
            desc: "Upgrade and Connection are dropped",
            detail: "This proxy only knows plain HTTP. Upgrade and Connection are hop-by-hop headers, meant for one link only, so it removes them before forwarding. The server receives a normal GET /chat without any request to switch protocols.",
            facts: [["Removed", "Upgrade, Connection"], ["Added", "Via: 1.1 office-proxy"], ["Server sees", "A plain GET"]],
            quiz: {
              q: "What will the chat server answer to a GET /chat without Upgrade?",
              options: ["101 Switching Protocols", "An error such as 426 Upgrade Required", "200 with chat messages", "Nothing"],
              answer: 1,
              why: "Without Upgrade: websocket the server cannot switch protocols, so it refuses the plain request.",
            },
            events: [k2.c(0.003, "amber", "GET", ["no Upgrade!"], { data: [stripped], info: "GET /chat HTTP/1.1" }), note("proxy", "UPGRADE HEADER REMOVED", "red")],
          },
          {
            title: "426 Upgrade Required",
            desc: "The socket fails to open",
            detail: "The server answers 426 Upgrade Required and the proxy passes it back. The browser expected 101, so the WebSocket fails. JavaScript gets an error event and a close event with code 1006 (closed abnormally, no close frame).",
            facts: [["Server says", "426 Upgrade Required"], ["JS sees", "onerror, close code 1006"], ["Fix", "Use wss:// on port 443"]],
            quiz: {
              q: "Why does switching to wss:// usually fix this?",
              options: ["wss is faster", "Inside TLS the proxy cannot see or change headers; it only relays encrypted bytes", "Proxies are not allowed on port 443", "wss does not use HTTP"],
              answer: 1,
              why: "With TLS the Upgrade request is encrypted end to end. A proxy either tunnels it untouched (CONNECT) or cannot interfere at all.",
            },
            events: [
              k2.s(0.0372, "red", "426", ["Upgrade Required"], { data: [r426(false)], info: "HTTP/1.1 426 Upgrade Required" }),
              k.s(0.0375, "red", "426", ["Upgrade Required"], { data: [r426(true)], info: "HTTP/1.1 426 Upgrade Required" }),
              note("client", "WEBSOCKET ERROR 1006", "red"),
            ],
          },
        ],
        outro: {
          title: "Blocked by a middlebox",
          text: "WebSocket relies on two hop-by-hop headers surviving the trip. Old proxies that strip them break the upgrade. That is why real apps use wss://: inside TLS no middlebox can read or rewrite the handshake.",
          facts: [["Cause", "Proxy drops Upgrade/Connection"], ["Symptom", "426 or 400 instead of 101"], ["Close code", "1006 (abnormal)"], ["Fix", "wss:// or a proxy that supports Upgrade"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "Opcodes",
      items: [["0x0", "Continuation"], ["0x1", "Text (UTF-8)"], ["0x2", "Binary"], ["0x8", "Close"], ["0x9", "Ping"], ["0xA", "Pong"]],
    },
    {
      title: "Close codes",
      items: [["1000", "Normal closure"], ["1001", "Going away (page left)"], ["1006", "Abnormal, no close frame (never sent)"], ["1008", "Policy violation"], ["1011", "Server error"]],
    },
    {
      title: "Frame header",
      items: [["Byte 1", "FIN, RSV1-3, opcode"], ["Byte 2", "MASK bit + length (0–125)"], ["126 / 127", "16-bit / 64-bit length follows"], ["Masking key", "4 bytes, client frames only"]],
    },
  ],
});
