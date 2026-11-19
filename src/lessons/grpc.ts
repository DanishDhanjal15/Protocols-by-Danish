import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, tcp, TcpOpt } from "@/lib/proto";

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
    c(t + rtt + 0.0001, "green", "ACK", ["ack=1", "connected"]),
  ];
  return { c, s, open, next };
}

// ---------------------------------------------------------------- HTTP/2 frames and HPACK

const FT = { DATA: 0, HEADERS: 1, RST_STREAM: 3, SETTINGS: 4, PING: 6, WINDOW_UPDATE: 8 } as const;
const sizeOf = (fs: FieldSpec[]) => fs.map(field).reduce((n, f) => n + f.bytes.length, 0);

/** 9-byte HTTP/2 frame header. `len` is the payload length (payload may live in a later layer). */
const frameHeader = (type: keyof typeof FT, flags: number, flagText: string, stream: number, len: number): FieldSpec[] => [
  { name: "Length", u24: len, value: `${len} bytes`, note: "3 bytes: size of the payload after this 9-byte header." },
  { name: "Type", u8: FT[type], value: `${FT[type]} (${type})` },
  { name: "Flags", u8: flags, value: `0x${flags.toString(16).padStart(2, "0")}${flagText ? ` (${flagText})` : ""}` },
  { name: "Stream identifier", u32: stream, value: String(stream), note: stream === 0 ? "Stream 0 = the connection itself." : "Each gRPC call gets its own stream. Client streams are odd." },
];
const frame = (type: keyof typeof FT, flags: number, flagText: string, stream: number, payload: FieldSpec[], note?: string): FieldSpec => {
  const len = sizeOf(payload);
  return { name: `${type} frame (stream ${stream})`, value: `${len + 9} bytes`, note, fields: [...frameHeader(type, flags, flagText, stream, len), ...payload] };
};

const hstr = (label: string, s: string): FieldSpec[] => [{ name: `${label} length`, u8: s.length, value: `${s.length} (not Huffman-coded)` }, ...(s.length ? [{ name: label, text: s }] : [])];
const hIdx = (i: number, what: string): FieldSpec => ({ name: `Indexed: ${what}`, u8: 0x80 | i, value: `0x${(0x80 | i).toString(16)} → static entry ${i}`, note: "One byte stands for the whole header." });
const hLit = (nameIdx: number, hname: string, value: string): FieldSpec => ({
  name: `Literal: ${hname}: ${value}`, value: `${hname}: ${value}`, note: `Name from static table entry ${nameIdx}, value spelled out and added to the dynamic table.`,
  fields: [{ name: "Prefix 01 + name index", u8: 0x40 | nameIdx, value: `0x${(0x40 | nameIdx).toString(16)} (index ${nameIdx})` }, ...hstr("Value", value)],
});
const hNew = (hname: string, value: string, note?: string): FieldSpec => ({
  name: `Literal, new name: ${hname}: ${value}`, value: `${hname}: ${value}`, note: note ?? "A header the static table doesn't know: both name and value are spelled out.",
  fields: [{ name: "Prefix 01, new name", u8: 0x40, value: "0x40" }, ...hstr("Name", hname), ...hstr("Value", value)],
});
const block = (items: FieldSpec[]): FieldSpec => ({ name: "Header block (HPACK)", value: `${sizeOf(items)} bytes`, fields: items });
const settings = (pairs: [number, string, number][]): FieldSpec[] =>
  pairs.map(([id, n, v]) => ({ name: `Setting: ${n}`, value: `${n} = ${v}`, fields: [{ name: "Identifier", u16: id, value: `${id} (${n})` }, { name: "Value", u32: v }] }));

const h2 = (frames: FieldSpec[], summary: string) => proto({ id: "http2", name: "HTTP/2", osi: 7, summary, fields: frames });

// ---------------------------------------------------------------- Protobuf, written out by hand

/** varint field: tag byte = (field number << 3) | 0 */
const pbVarint = (num: number, fname: string, v: number): FieldSpec => {
  const vb: number[] = [];
  let x = v;
  do { let b = x & 0x7f; x >>>= 7; if (x) b |= 0x80; vb.push(b); } while (x);
  return {
    name: `Field ${num}: ${fname} = ${v}`, value: String(v),
    fields: [
      { name: "Tag", u8: (num << 3) | 0, value: `0x${((num << 3) | 0).toString(16).padStart(2, "0")} = field ${num}, wire type 0 (varint)`, note: `(${num} << 3) | 0. The name "${fname}" is never sent, only the number.` },
      { name: "Varint", bytes: vb, value: `${v}`, note: vb.length > 1 ? `7 bits per byte, low bits first; the top bit says "more bytes follow". 0x96 0x01 = 0x16 + (0x01 << 7) = 22 + 128 = 150.` : "Values under 128 fit in one byte." },
    ],
  };
};
/** length-delimited string field: tag = (n << 3) | 2, then length, then UTF-8 bytes */
const pbString = (num: number, fname: string, v: string): FieldSpec => ({
  name: `Field ${num}: ${fname} = "${v}"`, value: `"${v}"`,
  fields: [
    { name: "Tag", u8: (num << 3) | 2, value: `0x${((num << 3) | 2).toString(16).padStart(2, "0")} = field ${num}, wire type 2 (length-delimited)`, note: `(${num} << 3) | 2.` },
    { name: "Length", u8: v.length, value: `${v.length} bytes` },
    { name: "UTF-8 text", text: v },
  ],
});

/** gRPC message = 1-byte compressed flag + 4-byte length + protobuf bytes; returned as two layers. */
const grpcMsg = (msgName: string, pb: FieldSpec[]): LayerSpec[] => {
  const n = sizeOf(pb);
  return [
    proto({ id: "grpc", name: "gRPC", osi: 7, summary: `gRPC Message: ${msgName}, ${n} bytes`, fields: [
      { name: "Compressed flag", u8: 0, value: "0 (not compressed)" },
      { name: "Message length", u32: n, value: `${n} bytes`, note: "4 bytes, big-endian: how long the protobuf message is. This is gRPC's own framing inside the DATA frame." },
    ] }),
    proto({ id: "protobuf", name: `Protobuf (${msgName})`, osi: 6, summary: `Protocol Buffers: ${msgName}`, fields: pb }),
  ];
};

// ---------------------------------------------------------------- content

const CL = "10.0.5.21", SV = "10.0.5.40";
const CL_MAC = "02:42:0a:00:05:15", SV_MAC = "02:42:0a:00:05:28";
const PORT = 50051;
const METHOD = "/weather.Weather/GetForecast";
const cl = [eth({ src: CL_MAC, dst: SV_MAC }), ipv4({ src: CL, dst: SV })];
const sv = [eth({ src: SV_MAC, dst: CL_MAC }), ipv4({ src: SV, dst: CL })];
const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const REQ_PB = [pbString(1, "city", "Pune"), pbVarint(2, "days", 3)];
const RESP_PB = [pbString(1, "city", "Pune"), pbVarint(2, "temp_c", 31), pbString(3, "summary", "Sunny"), pbVarint(4, "aqi", 150)];

const reqHeaders = (timeout: string) => frame("HEADERS", 0x04, "END_HEADERS", 1, [block([
  hIdx(3, ":method: POST"), hIdx(6, ":scheme: http"), hLit(4, ":path", METHOD), hLit(1, ":authority", `weather:${PORT}`),
  hLit(31, "content-type", "application/grpc"), hLit(58, "user-agent", "grpc-go/1.68.0"),
  hNew("te", "trailers", "Required by gRPC: says the client accepts trailers (headers after the body)."),
  hNew("grpc-timeout", timeout, `The deadline: ${timeout === "1S" ? "1 second" : "200 milliseconds"}. The server can stop working once it passes.`),
])], `The call: POST ${METHOD}. The path is /package.Service/Method.`);
const reqPackets = (timeout: string): LayerSpec[] => {
  const n = 5 + sizeOf(REQ_PB);
  return [
    h2([reqHeaders(timeout), { name: "DATA frame (stream 1) header", value: `9 bytes + ${n} payload`, fields: frameHeader("DATA", 0x01, "END_STREAM", 1, n), note: "END_STREAM: the request message is complete. The payload is the gRPC message below." }], `HEADERS[1]: POST ${METHOD}, DATA[1]`),
    ...grpcMsg("ForecastRequest", REQ_PB),
  ];
};

const devices = [
  { id: "client", kind: "server" as const, label: "Checkout app", sub: CL, x: 12, y: 62 },
  { id: "switch", kind: "switch" as const, label: "Data-centre switch", x: 50, y: 40 },
  { id: "server", kind: "server" as const, label: "Weather service", sub: `${SV}:${PORT}`, x: 88, y: 62 },
];
const links: [string, string][] = [["client", "switch"], ["switch", "server"]];

export default defineLesson({
  id: "grpc",
  name: "gRPC",
  full: "gRPC Remote Procedure Calls",
  group: "web",
  layer: 7,
  difficulty: 3,
  tagline: "Call a function on another machine, over HTTP/2 with protobuf.",
  description:
    "gRPC lets one service call a function on another as if it were local. Each call is an HTTP/2 stream: a POST to /Service/Method, a length-prefixed protobuf message as the body, and the result status in trailers at the end. Deadlines travel with every call.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "HTTP/2 (usually inside TLS)"],
    ["Message format", "Protocol Buffers (binary)"],
    ["Framing", "1-byte flag + 4-byte length"],
    ["Result", "grpc-status in trailers"],
    ["Common port", "50051 (convention)"],
  ],
  ports: "Any; 50051 by convention, 443 with TLS",
  rfc: "gRPC over HTTP/2 spec (grpc.io), RFC 9113",
  keywords: ["rpc", "protobuf", "protocol buffers", "varint", "trailers", "grpc-status", "deadline", "microservices", "http2"],
  related: ["http2", "tcp", "https"],
  devices,
  links,
  legend: [
    ["green", "TCP handshake and ACKs"],
    ["blue", "HTTP/2 setup"],
    ["amber", "Request"],
    ["violet", "Response"],
    ["red", "Error status"],
  ],
  scenarios: [
    (() => {
      const k = conn({ a: "client", b: "server", cport: 41872, sport: PORT, cBase: 0x5eed0100, sBase: 0x5eed0900, cl, sv });
      return {
        id: "normal",
        name: "A unary call: GetForecast",
        summary: "The checkout app asks the weather service for a forecast. One request message, one response message, status OK.",
        kind: "normal" as const,
        steps: [
          {
            title: "Connect and start HTTP/2",
            desc: "TCP, preface, SETTINGS",
            detail: "Inside this data centre the two services talk plain HTTP/2 with no TLS (h2c), so we can see every byte. gRPC knows the server speaks HTTP/2, so the client sends the preface straight away instead of asking to upgrade. Over the internet the same frames would sit inside TLS.",
            facts: [["Server", `${SV}:${PORT}`], ["Mode", "HTTP/2 with prior knowledge"], ["Round trip", "~0.2 ms on a LAN"]],
            events: [
              ...k.open(0, 0.0002),
              k.c(0.0004, "blue", "PREFACE", ["PRI * HTTP/2.0", "SETTINGS"], {
                info: "Magic, SETTINGS[0], WINDOW_UPDATE[0]",
                data: [h2([
                  { name: "Connection preface", text: PREFACE, value: "PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n" },
                  frame("SETTINGS", 0, "", 0, settings([[2, "ENABLE_PUSH", 0], [4, "INITIAL_WINDOW_SIZE", 4194304]])),
                  frame("WINDOW_UPDATE", 0, "", 0, [{ name: "Window size increment", u32: 4128769 }]),
                ], "Magic, SETTINGS, WINDOW_UPDATE")],
              }),
              k.s(0.0006, "blue", "SETTINGS", ["+ ACK"], {
                info: "SETTINGS[0], SETTINGS[0] (ACK)",
                data: [h2([frame("SETTINGS", 0, "", 0, settings([[3, "MAX_CONCURRENT_STREAMS", 1000], [4, "INITIAL_WINDOW_SIZE", 4194304]])), frame("SETTINGS", 0x01, "ACK", 0, [])], "SETTINGS, SETTINGS ACK")],
              }),
            ],
          },
          {
            title: "The call goes out",
            desc: "HEADERS + DATA on stream 1",
            detail: `A gRPC call is an HTTP/2 POST. The path names the function: ${METHOD}. content-type is application/grpc, te: trailers is required, and grpc-timeout carries the deadline. The DATA frame holds the argument as a gRPC message.`,
            facts: [["Path", METHOD], ["Deadline", "grpc-timeout: 1S"], ["Stream", "1 (one call = one stream)"]],
            quiz: {
              q: "The checkout app makes 50 calls at the same time. How many TCP connections does it need?",
              options: ["50", "1, each call is its own HTTP/2 stream", "2, one per direction", "One per method"],
              answer: 1,
              why: "Every call is a separate stream on the same HTTP/2 connection, so many calls run at once over one connection.",
            },
            events: [
              k.c(0.0007, "blue", "ACK", ["SETTINGS ACK"], { info: "SETTINGS[0] (ACK)", data: [h2([frame("SETTINGS", 0x01, "ACK", 0, [])], "SETTINGS ACK")] }),
              k.c(0.0008, "amber", "CALL", ["GetForecast", "city=Pune days=3"], { data: reqPackets("1S"), info: `HEADERS[1]: POST ${METHOD}, DATA[1] (GRPC) (PROTOBUF) weather.ForecastRequest` }),
            ],
          },
          {
            title: "Inside the message",
            desc: "Protobuf: tags and varints",
            detail: "The 5-byte gRPC prefix says: not compressed, 8 bytes long. The protobuf is just 0a 04 50 75 6e 65 10 03. Byte 0x0a is a tag: field 1, wire type 2 (length-delimited), then length 4 and \"Pune\". Byte 0x10 is field 2, wire type 0 (varint), then the value 3. Field names never go on the wire; both sides share a .proto file that maps numbers to names.",
            facts: [["Tag byte", "(field number << 3) | wire type"], ["0x0a", "field 1, length-delimited"], ["0x10", "field 2, varint"]],
            quiz: {
              q: "What tag byte would field 3 with wire type 2 (a string) have?",
              options: ["0x03", "0x1a", "0x32", "0x0b"],
              answer: 1,
              why: "(3 << 3) | 2 = 24 + 2 = 26 = 0x1a.",
            },
            events: [note("server", "DECODE ForecastRequest", "blue"), k.s(0.0009, "green", "ACK", [])],
          },
          {
            title: "Response and trailers",
            desc: "HEADERS, DATA, then grpc-status: 0",
            detail: "The server replies on stream 1: HEADERS with :status 200 and content-type application/grpc, a DATA frame with the result message, and finally a second HEADERS frame called trailers with grpc-status: 0 (OK) and END_STREAM. The real result of the call is in the trailers, not in :status.",
            facts: [["HTTP status", "200 (always, if HTTP worked)"], ["grpc-status", "0 = OK"], ["aqi = 150", "varint 0x96 0x01"]],
            quiz: {
              q: "The varint for 150 is 0x96 0x01. Why does it need two bytes?",
              options: ["Every varint is 2 bytes", "Each byte holds 7 bits of value; 150 needs 8 bits", "Byte 2 is a checksum", "Negative numbers need 2 bytes"],
              answer: 1,
              why: "Values 0–127 fit in 7 bits. 150 needs more, so the first byte sets its top bit (0x80) to say \"more follows\".",
            },
            events: (() => {
              const n = 5 + sizeOf(RESP_PB);
              return [
                k.s(0.0124, "violet", "RESULT", ["31°C Sunny", "aqi 150"], {
                  info: "HEADERS[1]: 200 OK, DATA[1] (GRPC) (PROTOBUF) weather.Forecast",
                  data: [
                    h2([
                      frame("HEADERS", 0x04, "END_HEADERS", 1, [block([hIdx(8, ":status: 200"), hLit(31, "content-type", "application/grpc")])]),
                      { name: "DATA frame (stream 1) header", value: `9 bytes + ${n} payload`, fields: frameHeader("DATA", 0, "", 1, n), note: "No END_STREAM yet: trailers still have to come." },
                    ], "HEADERS[1]: 200 OK, DATA[1]"),
                    ...grpcMsg("Forecast", RESP_PB),
                  ],
                }),
                k.s(0.0125, "green", "TRAILERS", ["grpc-status: 0", "OK"], {
                  info: "HEADERS[1] (trailers): grpc-status: 0",
                  data: [h2([frame("HEADERS", 0x05, "END_STREAM, END_HEADERS", 1, [block([hNew("grpc-status", "0", "0 = OK. This, not :status 200, is the call's result."), hNew("grpc-message", "")])], "Trailers: headers sent after the body.")], "HEADERS[1]: trailers")],
                }),
                k.c(0.0126, "green", "ACK", []),
                note("client", "CALL OK IN 12 MS", "green"),
              ];
            })(),
          },
        ],
        outro: {
          title: "A function call over the network",
          text: "The call became a POST on its own HTTP/2 stream, the argument a 13-byte length-prefixed protobuf, and the outcome a grpc-status trailer. The connection stays open, ready for thousands more calls.",
          facts: [["Request body", `5 + ${sizeOf(REQ_PB)} bytes`], ["Response body", `5 + ${sizeOf(RESP_PB)} bytes`], ["Status", "grpc-status 0 (OK)"], ["Time", "~12 ms"]],
        },
      };
    })(),
    (() => {
      const k = conn({ a: "client", b: "server", cport: 41872, sport: PORT, cBase: 0x5eed0100, sBase: 0x5eed0900, cl, sv });
      k.next.a = 68; k.next.b = 31; // preface and SETTINGS already exchanged
      return {
        id: "deadline",
        name: "Deadline exceeded",
        summary: "The checkout page can only wait 200 ms. The weather service is stuck on a slow database and runs out of time.",
        kind: "failure" as const,
        steps: [
          {
            title: "A call with a tight deadline",
            desc: "grpc-timeout: 200m",
            detail: "The checkout page must render quickly, so the app gives the call a 200 millisecond deadline. It travels in the grpc-timeout header (200m means 200 milliseconds), so the server knows the limit too.",
            facts: [["grpc-timeout", "200m"], ["Units", "H M S m u n"], ["Stream", "1 (first call after setup)"]],
            events: [k.c(0, "amber", "CALL", ["GetForecast", "deadline 200 ms"], { data: reqPackets("200m"), info: `HEADERS[1]: POST ${METHOD}, DATA[1] (GRPC)` }), k.s(0.0002, "green", "ACK", [])],
          },
          {
            title: "The server is slow",
            desc: "Waiting on a database",
            detail: "The weather service asks its database, which is overloaded and takes seconds. Nothing goes on the wire while the clock runs.",
            facts: [["Database", "Overloaded"], ["Time used", "200 ms and counting"], ["Packets", "None"]],
            quiz: {
              q: "What should happen when the 200 ms deadline passes?",
              options: ["Keep waiting; the result is still useful", "Both sides give up and the call ends with DEADLINE_EXCEEDED", "The client retries on a new connection at once", "The server sends a partial result"],
              answer: 1,
              why: "After the deadline nobody wants the answer. Giving up frees the server and lets the client show a fallback.",
            },
            events: [note("server", "DATABASE SLOW", "amber")],
          },
          {
            title: "grpc-status 4",
            desc: "DEADLINE_EXCEEDED in trailers-only",
            detail: "At 200 ms the server stops and sends a trailers-only response: one HEADERS frame with :status 200, grpc-status: 4 and grpc-message: Deadline Exceeded, with END_STREAM. The client's own timer fires too and cancels the stream with RST_STREAM. The checkout page shows the order without the weather widget.",
            facts: [["grpc-status", "4 DEADLINE_EXCEEDED"], ["RST_STREAM", "Error 8 (CANCEL)"], ["Connection", "Still open for other calls"]],
            events: [
              k.s(0.2001, "red", "STATUS 4", ["DEADLINE_EXCEEDED"], {
                info: "HEADERS[1]: 200 OK, grpc-status: 4",
                data: [h2([frame("HEADERS", 0x05, "END_STREAM, END_HEADERS", 1, [block([
                  hIdx(8, ":status: 200"), hLit(31, "content-type", "application/grpc"),
                  hNew("grpc-status", "4", "4 = DEADLINE_EXCEEDED."), hNew("grpc-message", "Deadline Exceeded"),
                ])], "Trailers-only response: no body, just the status.")], "HEADERS[1]: trailers-only")],
              }),
              k.c(0.2002, "slate", "RST", ["RST_STREAM", "CANCEL"], { info: "RST_STREAM[1]: CANCEL", data: [h2([frame("RST_STREAM", 0, "", 1, [{ name: "Error code", u32: 8, value: "8 (CANCEL)", note: "The client no longer wants this stream." }])], "RST_STREAM[1]")] }),
              note("client", "DEADLINE_EXCEEDED", "red"),
            ],
          },
        ],
        outro: {
          title: "Failing fast, on purpose",
          text: "Deadlines stop a slow service from dragging down everything that calls it. The limit travels with the call, so the server can give up too. Only the stream is cancelled; the HTTP/2 connection carries on.",
          facts: [["Status", "4 DEADLINE_EXCEEDED"], ["Sent in", "Trailers"], ["Lost", "One call, not the connection"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "Status codes",
      items: [["0 OK", "Success"], ["1 CANCELLED", "Caller gave up"], ["3 INVALID_ARGUMENT", "Bad input"], ["4 DEADLINE_EXCEEDED", "Out of time"], ["5 NOT_FOUND", "No such thing"], ["14 UNAVAILABLE", "Server down, retry later"], ["16 UNAUTHENTICATED", "No valid credentials"]],
    },
    {
      title: "Protobuf wire types",
      items: [["0 varint", "int32, int64, bool, enum"], ["1 64-bit", "fixed64, double"], ["2 length-delimited", "string, bytes, nested messages"], ["5 32-bit", "fixed32, float"], ["Tag", "(field << 3) | wire type"]],
    },
    {
      title: "On the wire",
      items: [[":method", "Always POST"], [":path", "/package.Service/Method"], ["content-type", "application/grpc"], ["Message prefix", "1-byte flag + 4-byte length"]],
    },
  ],
});
