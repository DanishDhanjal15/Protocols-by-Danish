import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { Bytes, text } from "@/lib/bytes";
import { build, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, udp } from "@/lib/proto";
import { ADDR } from "./_common";

// ---------------------------------------------------------------- addresses

const NODE = "192.168.1.50";
const NODE_MAC = "00:12:4b:00:1c:aa";
const CPORT = 51000;
const r = (n: number) => Number(n.toFixed(4));

// ---------------------------------------------------------------- CoAP encoding (RFC 7252)

const TYPES = ["CON", "NON", "ACK", "RST"];
const TYPE_NAMES = ["Confirmable", "Non-confirmable", "Acknowledgement", "Reset"];
const CODE_NAMES: Record<number, string> = { 0x00: "Empty", 0x01: "GET", 0x45: "2.05 Content", 0x84: "4.04 Not Found" };
const codeStr = (c: number) => `${c >> 5}.${String(c & 31).padStart(2, "0")}`;

const OPT_NAMES: Record<number, string> = { 6: "Observe", 11: "Uri-Path", 12: "Content-Format", 14: "Max-Age" };
type Opt = [number, Bytes, string];
const uint = (n: number): Bytes => (n === 0 ? [] : n < 256 ? [n] : [n >> 8, n & 255]);
const path = (p: string): Opt[] => p.split("/").filter(Boolean).map((seg) => [11, text(seg), seg]);

const coap = (o: { type: number; code: number; mid: number; token: Bytes; options?: Opt[]; payload?: string }): LayerSpec => {
  const b0 = (1 << 6) | (o.type << 4) | o.token.length;
  let prev = 0;
  const optFields: FieldSpec[] = (o.options ?? []).map(([num, val, shown]) => {
    const delta = num - prev;
    prev = num;
    return {
      name: `Option: ${OPT_NAMES[num]}`,
      value: shown,
      fields: [
        { name: "Delta | Length", u8: (delta << 4) | val.length, value: `delta ${delta}, length ${val.length}`, note: `Option number = previous (${num - delta}) + delta ${delta} = ${num}. Options are sent in number order so deltas stay small.` },
        ...(val.length ? [{ name: "Value", bytes: val, value: shown }] : []),
      ],
    };
  });
  const fields: FieldSpec[] = [
    {
      name: "Ver | Type | Token length", u8: b0,
      value: `v1, ${TYPES[o.type]}, TKL ${o.token.length}`,
      note: `2 bits version (1), 2 bits type (${o.type} = ${TYPE_NAMES[o.type]}), 4 bits token length.`,
    },
    { name: "Code", u8: o.code, value: `${codeStr(o.code)} (${CODE_NAMES[o.code] ?? "?"})`, note: "class.detail: 0.xx requests, 2.xx success, 4.xx client error, 5.xx server error." },
    { name: "Message ID", u16: o.mid, value: `0x${o.mid.toString(16).padStart(4, "0")}`, note: "Matches a CON with its ACK, and catches duplicates." },
    ...(o.token.length ? [{ name: "Token", bytes: o.token, note: "Matches a response to its request, even when it comes in a different message." }] : []),
    ...optFields,
    ...(o.payload !== undefined ? [
      { name: "Payload marker", u8: 0xff, value: "0xFF", note: "End of options; the payload follows." },
      { name: "Payload", text: o.payload, value: JSON.stringify(o.payload) },
    ] : []),
  ];
  const tok = o.token.map((b) => b.toString(16).padStart(2, "0")).join("");
  const uri = (o.options ?? []).filter((x) => x[0] === 11).map((x) => x[2]).join("/");
  return proto({
    id: "coap", name: "Constrained Application Protocol",
    summary: `CoAP, ${TYPES[o.type]}, MID:${o.mid}, ${CODE_NAMES[o.code] ?? codeStr(o.code)}${uri ? `, /${uri}` : ""}${tok ? `, TKN:${tok}` : ""}`,
    fields,
  });
};

const toNode = (app: LayerSpec) => build(eth({ src: ADDR.laptopMac, dst: NODE_MAC }), ipv4({ src: ADDR.laptop, dst: NODE, ttl: 64 }), udp({ sport: CPORT, dport: 5683 }), app);
const toClient = (app: LayerSpec) => build(eth({ src: NODE_MAC, dst: ADDR.laptopMac }), ipv4({ src: NODE, dst: ADDR.laptop, ttl: 64 }), udp({ sport: 5683, dport: CPORT }), app);

const TEXT = (): Opt => [12, uint(0), "text/plain (0)"];
const MAXAGE = (s: number): Opt => [14, uint(s), `${s} s`];
const OBS = (n: number): Opt => [6, uint(n), n === 0 ? "0 (register)" : String(n)];

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Home app", sub: ADDR.laptop, x: 10, y: 60 },
  { id: "ap", kind: "ap", label: "Wi-Fi / border router", sub: ADDR.router, x: 46, y: 36 },
  { id: "server", kind: "iot", label: "Sensor node (CoAP server)", sub: `${NODE}:5683`, x: 86, y: 60 },
];
const links: [string, string][] = [["client", "ap"], ["ap", "server"]];

// ---------------------------------------------------------------- scenario 1

const T1: Bytes = [0x71, 0x3a];
const T2: Bytes = [0xc4, 0x09, 0x5e, 0x12];

const normalSteps = [
  {
    title: "GET, confirmable",
    desc: "GET /sensors/temp as a CON message over UDP",
    detail: "The home app wants the temperature from a tiny battery-powered sensor. CoAP is like HTTP for small devices, but runs over UDP port 5683 with a 4-byte header. The request is type CON (confirmable): the sender wants an acknowledgement. The path is sent as two Uri-Path options, \"sensors\" and \"temp\".",
    facts: [["Header", "4 bytes + token + options"], ["Type", "CON (needs an ACK)"], ["Code", "0.01 GET"]] as [string, string][],
    quiz: {
      q: "The first Uri-Path option byte is 0xB7. What does it mean?",
      options: ["Option 11, 7 bytes long", "Option 7, 11 bytes long", "Code 1.83", "Token B7"],
      answer: 0,
      why: "High nibble = delta 11 (Uri-Path, since the previous option was 0), low nibble = length 7 (\"sensors\").",
    },
    events: [
      pkt("client", "server", "amber", "GET CON", ["/sensors/temp", "MID 0x7d34"], {
        time: 0, info: "CON, MID:32052, GET, TKN:71 3a, /sensors/temp",
        packet: toNode(coap({ type: 0, code: 0x01, mid: 0x7d34, token: T1, options: path("sensors/temp") })),
      }),
    ],
  },
  {
    title: "Piggybacked ACK",
    desc: "ACK and 2.05 Content in one message",
    detail: "The sensor has the value ready, so it answers in the ACK itself: a piggybacked response. The ACK repeats the Message ID (so the CON is confirmed) and the token (so the app knows which request this answers). Code 2.05 Content, Content-Format text/plain, Max-Age 60 s, and the payload 22.5.",
    facts: [["Type", "ACK, same MID 0x7d34"], ["Code", "2.05 Content (0x45)"], ["Payload", "22.5 (°C), Max-Age 60 s"]] as [string, string][],
    quiz: {
      q: "Code 2.05 is sent as one byte. Which?",
      options: ["0x25", "0x45", "0x205", "0x05"],
      answer: 1,
      why: "3 bits class, 5 bits detail: 2 << 5 | 5 = 64 + 5 = 69 = 0x45.",
    },
    events: [
      pkt("server", "client", "green", "ACK 2.05", ["22.5", "MID 0x7d34"], {
        time: 0.012, info: "ACK, MID:32052, 2.05 Content, TKN:71 3a, /sensors/temp",
        packet: toClient(coap({ type: 2, code: 0x45, mid: 0x7d34, token: T1, options: [TEXT(), MAXAGE(60)], payload: "22.5" })),
      }),
    ],
  },
  {
    title: "Observe: subscribe",
    desc: "GET with Observe = 0",
    detail: "Polling wastes the sensor's battery. Instead the app sends the same GET with an Observe option set to 0, meaning \"register me\". It uses a new token, which will label every future notification. The sensor confirms with an ACK that carries the current value and an Observe sequence number, 12.",
    facts: [["Request option", "Observe = 0 (register)"], ["Token", "c4 09 5e 12"], ["First reply", "Observe = 12, 22.5"]] as [string, string][],
    events: [
      pkt("client", "server", "amber", "GET OBS", ["Observe 0", "/sensors/temp"], {
        time: 1.0, info: "CON, MID:32053, GET, TKN:c4 09 5e 12, /sensors/temp, Observe: 0",
        packet: toNode(coap({ type: 0, code: 0x01, mid: 0x7d35, token: T2, options: [OBS(0), ...path("sensors/temp")] })),
      }),
      pkt("server", "client", "green", "ACK 2.05", ["Observe 12", "22.5"], {
        time: 1.012, info: "ACK, MID:32053, 2.05 Content, TKN:c4 09 5e 12, Observe: 12",
        packet: toClient(coap({ type: 2, code: 0x45, mid: 0x7d35, token: T2, options: [OBS(12), TEXT(), MAXAGE(60)], payload: "22.5" })),
      }),
    ],
  },
  {
    title: "NON notification",
    desc: "A new value, no ACK needed",
    detail: "When the temperature changes to 22.7, the sensor pushes a notification. It's type NON (non-confirmable): fire and forget, cheap on battery and radio. It has a new Message ID chosen by the sensor, but the same token as the Observe request, and the Observe number goes up to 13 so the app can spot old or reordered messages.",
    facts: [["Type", "NON (no ACK)"], ["Token", "Same as the Observe request"], ["Observe", "13 (increases each time)"]] as [string, string][],
    quiz: {
      q: "The notification has a brand-new Message ID. How does the app know it belongs to its temperature subscription?",
      options: ["By the Message ID", "By the token", "By the UDP checksum", "It can't"],
      answer: 1,
      why: "Message IDs are per message (for ACKs and duplicates). The token ties every response to the original request.",
    },
    events: [
      pkt("server", "client", "violet", "NON 2.05", ["22.7", "Observe 13"], {
        time: 41.3, info: "NON, MID:5120, 2.05 Content, TKN:c4 09 5e 12, Observe: 13",
        packet: toClient(coap({ type: 1, code: 0x45, mid: 0x1400, token: T2, options: [OBS(13), TEXT(), MAXAGE(60)], payload: "22.7" })),
      }),
    ],
  },
  {
    title: "CON notification",
    desc: "Now and then: are you still there?",
    detail: "Every so often (at least once a day) the sensor sends a notification as CON instead. The app must answer with an empty ACK (code 0.00, same Message ID). If no ACK comes after the retries, the sensor removes the app from its observer list. That's how dead subscribers get cleaned up.",
    facts: [["Type", "CON 2.05, Observe 14"], ["Reply", "Empty ACK, code 0.00"], ["No ACK?", "Observer removed"]] as [string, string][],
    events: [
      pkt("server", "client", "violet", "CON 2.05", ["23.1", "Observe 14"], {
        time: 102.8, info: "CON, MID:5121, 2.05 Content, TKN:c4 09 5e 12, Observe: 14",
        packet: toClient(coap({ type: 0, code: 0x45, mid: 0x1401, token: T2, options: [OBS(14), TEXT(), MAXAGE(60)], payload: "23.1" })),
      }),
      pkt("client", "server", "green", "ACK", ["empty, MID 0x1401"], {
        time: 102.812, info: "ACK, MID:5121, Empty Message",
        packet: toNode(coap({ type: 2, code: 0x00, mid: 0x1401, token: [] })),
      }),
      note("client", "TEMP: 23.1 °C", "green"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 2: lost CON

const T3: Bytes = [0x2b, 0x80];
const lostSteps = [
  {
    title: "The CON is lost",
    desc: "Radio noise eats the request",
    detail: "The app sends GET /sensors/temp as CON with Message ID 0x7d40. A burst of interference drops it before it reaches the sensor. UDP doesn't notice anything; CoAP's own timer does. The first timeout is chosen at random between 2 and 3 seconds (ACK_TIMEOUT 2 s × a random factor up to 1.5); here 2.4 s.",
    facts: [["MID", "0x7d40"], ["First timeout", "2.4 s (random 2–3 s)"], ["Max retries", "4 (MAX_RETRANSMIT)"]] as [string, string][],
    events: [
      pkt("client", "server", "amber", "GET CON", ["MID 0x7d40", "lost"], {
        time: 0, lost: true, info: "CON, MID:32064, GET, TKN:2b 80, /sensors/temp",
        packet: toNode(coap({ type: 0, code: 0x01, mid: 0x7d40, token: T3, options: path("sensors/temp") })),
      }),
      note("ap", "INTERFERENCE: DROPPED", "red"),
    ],
  },
  {
    title: "Retry, wait twice as long",
    desc: "Exponential backoff: 2.4 s, then 4.8 s",
    detail: "No ACK after 2.4 s, so the app resends the exact same message, same Message ID. That one is lost too. The timeout doubles to 4.8 s; the third copy at 7.2 s gets through. The sensor ACKs with the same MID. Because the MID is unchanged, a sensor that received two copies would know it's a duplicate.",
    facts: [["Sent at", "0 s, 2.4 s, 7.2 s"], ["Timeout", "Doubles each try"], ["Gives up", "After 4 retries, 62–93 s from the start"]] as [string, string][],
    quiz: {
      q: "The first timeout was 2.4 s. When is the third copy sent if the second is lost?",
      options: ["4.8 s", "7.2 s", "9.6 s", "2.4 s after the second"],
      answer: 1,
      why: "Copy 2 at 2.4 s, then wait twice as long (4.8 s): 2.4 + 4.8 = 7.2 s.",
    },
    events: [
      pkt("client", "server", "amber", "RETRY 1", ["MID 0x7d40", "lost again"], {
        time: 2.4, lost: true, info: "CON, MID:32064, GET, TKN:2b 80, /sensors/temp [Retransmission]",
        packet: toNode(coap({ type: 0, code: 0x01, mid: 0x7d40, token: T3, options: path("sensors/temp") })),
      }),
      pkt("client", "server", "amber", "RETRY 2", ["MID 0x7d40", "same message"], {
        time: 7.2, info: "CON, MID:32064, GET, TKN:2b 80, /sensors/temp [Retransmission]",
        packet: toNode(coap({ type: 0, code: 0x01, mid: 0x7d40, token: T3, options: path("sensors/temp") })),
      }),
      pkt("server", "client", "green", "ACK 2.05", ["22.6", "MID 0x7d40"], {
        time: r(7.212), info: "ACK, MID:32064, 2.05 Content, TKN:2b 80",
        packet: toClient(coap({ type: 2, code: 0x45, mid: 0x7d40, token: T3, options: [TEXT(), MAXAGE(60)], payload: "22.6" })),
      }),
    ],
  },
];

// ---------------------------------------------------------------- scenario 3: 4.04

const T4: Bytes = [0x90, 0x11];
const notFoundSteps = [
  {
    title: "Ask for humidity",
    desc: "GET /sensors/humidity",
    detail: "The app assumes every sensor node also measures humidity and asks for /sensors/humidity. This node only has a temperature sensor.",
    facts: [["Path", "/sensors/humidity"], ["Type", "CON GET"], ["MID", "0x7d50"]] as [string, string][],
    events: [
      pkt("client", "server", "amber", "GET CON", ["/sensors/humidity"], {
        time: 0, info: "CON, MID:32080, GET, TKN:90 11, /sensors/humidity",
        packet: toNode(coap({ type: 0, code: 0x01, mid: 0x7d50, token: T4, options: path("sensors/humidity") })),
      }),
    ],
  },
  {
    title: "4.04 Not Found",
    desc: "Piggybacked error with a short reason",
    detail: "The sensor answers in the ACK with code 4.04 (byte 0x84), just like HTTP 404. It may add a short diagnostic text as payload. Apps can find out what a node really offers by asking GET /.well-known/core, which lists its resources.",
    facts: [["Code", "4.04 Not Found (0x84)"], ["Type", "ACK, MID 0x7d50"], ["Discover", "GET /.well-known/core"]] as [string, string][],
    quiz: {
      q: "How is 4.04 written in the one-byte Code field?",
      options: ["0x44", "0x84", "0x404", "0x4F"],
      answer: 1,
      why: "4 << 5 | 4 = 128 + 4 = 132 = 0x84.",
    },
    events: [
      pkt("server", "client", "red", "ACK 4.04", ["Not Found"], {
        time: 0.011, info: "ACK, MID:32080, 4.04 Not Found, TKN:90 11",
        packet: toClient(coap({ type: 2, code: 0x84, mid: 0x7d50, token: T4, payload: "no such resource" })),
      }),
      note("client", "4.04 NOT FOUND", "red"),
    ],
  },
];

export default defineLesson({
  id: "coap",
  name: "CoAP",
  full: "Constrained Application Protocol",
  group: "iot",
  layer: 7,
  difficulty: 2,
  tagline: "HTTP-style requests for tiny battery sensors, over UDP.",
  description:
    "CoAP gives small devices a web-like way to talk: GET, PUT, POST and DELETE on paths like /sensors/temp, with response codes like 2.05 and 4.04. It runs over UDP with a 4-byte header and adds its own lightweight reliability, and Observe lets a client get updates without polling.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "UDP 5683 (5684 with DTLS)"],
    ["Defined in", "RFC 7252, Observe RFC 7641"],
    ["Header", "4 bytes fixed"],
    ["Message types", "CON, NON, ACK, RST"],
    ["Reliability", "ACKs + exponential backoff"],
  ],
  ports: "UDP 5683 CoAP, 5684 CoAPS (DTLS)",
  rfc: "RFC 7252, RFC 7641, RFC 6690",
  keywords: ["iot", "coap", "udp", "observe", "confirmable", "con", "non", "ack", "piggyback", "uri-path", "2.05", "4.04", "6lowpan", "thread", "lwm2m"],
  related: ["mqtt", "udp", "http", "modbus"],
  devices,
  links,
  legend: [
    ["amber", "Requests from the app"],
    ["green", "ACKs and successful replies"],
    ["violet", "Observe notifications"],
    ["red", "Errors and losses"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Read and observe a temperature",
      summary: "A confirmable GET with a piggybacked reply, then Observe with NON and CON notifications.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "Updates without polling",
        text: "One CON GET got its answer inside the ACK. With Observe the sensor then pushed changes on its own, mostly as cheap NON messages, with an occasional CON to check the app was still listening.",
        facts: [["Smallest message", "4 bytes (empty ACK)"], ["Matching", "MID for ACKs, token for responses"], ["Observe numbers", "12, 13, 14"], ["Transport", "UDP 5683"]],
      },
    },
    {
      id: "lost-con",
      name: "Lost CON: retransmission with backoff",
      summary: "The request is lost twice; CoAP resends it with doubling timeouts until the ACK arrives.",
      kind: "failure",
      steps: lostSteps,
      outro: {
        title: "Reliable over UDP",
        text: "CoAP added just enough reliability on top of UDP: resend a CON with the same Message ID, doubling the wait each time, up to 4 retries. The third copy got through.",
        facts: [["ACK_TIMEOUT", "2 s × random 1–1.5"], ["Backoff", "Doubles each retry"], ["MAX_RETRANSMIT", "4"]],
      },
    },
    {
      id: "not-found",
      name: "4.04 Not Found",
      summary: "Asking for a resource the node doesn't have returns a piggybacked 4.04.",
      kind: "failure",
      steps: notFoundSteps,
      outro: {
        title: "Wrong path",
        text: "CoAP errors look like HTTP's but are packed into one byte as class.detail. 4.04 means the path doesn't exist; GET /.well-known/core shows what does.",
        facts: [["Code byte", "0x84"], ["HTTP equivalent", "404"], ["Discovery", "/.well-known/core (RFC 6690)"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Message types",
      items: [["CON (0)", "Confirmable: wants an ACK"], ["NON (1)", "Non-confirmable: fire and forget"], ["ACK (2)", "Confirms a CON, may carry the response"], ["RST (3)", "I can't process that message"]],
    },
    {
      title: "Codes",
      items: [["0.01–0.04", "GET, POST, PUT, DELETE"], ["2.01 / 2.04 / 2.05", "Created / Changed / Content"], ["4.00 / 4.04", "Bad Request / Not Found"], ["5.00", "Internal Server Error"], ["Byte", "class << 5 | detail"]],
    },
    {
      title: "Options",
      items: [["6 Observe", "Register / sequence number"], ["11 Uri-Path", "One per path segment"], ["12 Content-Format", "0 text/plain, 50 JSON, 60 CBOR"], ["14 Max-Age", "Seconds the value stays fresh"], ["Encoding", "Delta nibble | length nibble"]],
    },
  ],
});
