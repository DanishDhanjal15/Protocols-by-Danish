import { defineLesson, note, pkt, Device } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { tcp } from "@/lib/proto";
import { Bytes, rand, text, u32le } from "@/lib/bytes";
import { ADDR, down, homeToServer, up } from "./_common";

// OBS on the laptop pushes a live stream to a generic ingest server over RTMP (TCP 1935).

const S = ADDR.server2;
const PORT = 1935;
const CB = 0x3c1a0000; // laptop's initial sequence number base
const SB = 0x7e520000; // server's
const APP = "live";
const TC_URL = "rtmp://ingest.example.com/live";
const KEY = "sk-7f3a-91qd-2bxe-k4pz";
const BAD_KEY = "sk-7f3a-91qd-2bxe-k4pq";

const t = (n: number) => Number(n.toFixed(4));

// ------------------------------------------------------------ AMF0 encoding

const f64 = (n: number): Bytes => {
  const dv = new DataView(new ArrayBuffer(8));
  dv.setFloat64(0, n);
  return Array.from(new Uint8Array(dv.buffer));
};

const amfStr = (s: string, name?: string): FieldSpec => ({
  name: name ?? `String "${s}"`,
  value: `"${s}"`,
  fields: [
    { name: "AMF0 type", u8: 0x02, value: "0x02 (string)" },
    { name: "Length", u16: text(s).length },
    { name: "Text", text: s },
  ],
});

const amfNum = (n: number, name?: string): FieldSpec => ({
  name: name ?? `Number ${n}`,
  value: String(n),
  fields: [
    { name: "AMF0 type", u8: 0x00, value: "0x00 (number)" },
    { name: "Value", bytes: f64(n), value: `${n} (64-bit float)`, note: "AMF0 stores every number as an 8-byte IEEE double, big-endian." },
  ],
});

const amfNull = (name = "Null"): FieldSpec => ({ name, u8: 0x05, value: "null (0x05)", note: "A placeholder for the unused command object." });

const amfObj = (name: string, props: [string, FieldSpec][]): FieldSpec => ({
  name,
  value: `{ ${props.map(([k]) => k).join(", ")} }`,
  fields: [
    { name: "AMF0 type", u8: 0x03, value: "0x03 (object)" },
    ...props.map(([k, v]): FieldSpec => ({
      name: `Property "${k}"`,
      value: v.value,
      fields: [{ name: "Key length", u16: text(k).length }, { name: "Key", text: k }, { ...v, name: "Value" }],
    })),
    { name: "Object end", bytes: "000009", value: "00 00 09", note: "An empty key followed by the end marker 0x09." },
  ],
});

// ------------------------------------------------------------ RTMP chunk

const TYPE_NAMES: Record<number, string> = {
  1: "Set Chunk Size", 3: "Acknowledgement", 5: "Window Acknowledgement Size", 6: "Set Peer Bandwidth", 8: "Audio Data", 9: "Video Data", 20: "AMF0 Command",
};

/** One RTMP message in one chunk with a type-0 (full, 11-byte) message header. */
function msg(o: { csid: number; type: number; streamId?: number; ts?: number; body: FieldSpec[]; summary: string; bodyName?: string }): LayerSpec {
  const bodyLen = o.body.map(field).reduce((n, f) => n + f.bytes.length, 0);
  const sid = o.streamId ?? 0;
  return proto({
    id: "rtmp",
    name: "RTMP",
    summary: `Real Time Messaging Protocol (${o.summary})`,
    fields: [
      { name: "Chunk basic header", u8: o.csid & 0x3f, value: `fmt 0, chunk stream ${o.csid}`, note: "Top 2 bits: header format 0 (full header follows). Low 6 bits: the chunk stream ID." },
      {
        name: "Message header",
        value: "11 bytes (format 0)",
        fields: [
          { name: "Timestamp", u24: o.ts ?? 0, value: `${o.ts ?? 0} ms`, note: "Milliseconds on the stream’s own clock." },
          { name: "Message length", u24: bodyLen, value: `${bodyLen} bytes` },
          { name: "Message type", u8: o.type, value: `${o.type} (${TYPE_NAMES[o.type]})` },
          { name: "Message stream ID", bytes: u32le(sid), value: String(sid), note: "Little-endian, unlike every other number in RTMP. 0 = the connection itself." },
        ],
      },
      { name: o.bodyName ?? TYPE_NAMES[o.type], value: `${bodyLen} bytes`, fields: o.body },
    ],
  });
}

const setChunkSize = () => msg({ csid: 2, type: 1, body: [{ name: "Chunk size", u32: 4096, value: "4096 bytes", note: "From now on, messages up to 4096 bytes travel as one chunk (the default is 128)." }], summary: "Set Chunk Size 4096" });
const winAck = () => msg({ csid: 2, type: 5, body: [{ name: "Window size", u32: 2500000, note: "Send me an Acknowledgement after every 2.5 MB." }], summary: "Window Acknowledgement Size 2500000" });
const peerBw = () => msg({ csid: 2, type: 6, body: [{ name: "Window size", u32: 2500000 }, { name: "Limit type", u8: 2, value: "2 (dynamic)" }], summary: "Set Peer Bandwidth 2500000, Dynamic" });

const connect = () =>
  msg({
    csid: 3, type: 20, summary: `connect('${APP}')`, bodyName: "AMF0 command: connect",
    body: [
      amfStr("connect", "Command name"),
      amfNum(1, "Transaction ID"),
      amfObj("Command object", [
        ["app", amfStr(APP)],
        ["type", amfStr("nonprivate")],
        ["flashVer", amfStr("FMLE/3.0 (compatible; FMSc/1.0)")],
        ["tcUrl", amfStr(TC_URL)],
      ]),
    ],
  });

const connectResult = () =>
  msg({
    csid: 3, type: 20, summary: "_result('NetConnection.Connect.Success')", bodyName: "AMF0 command: _result",
    body: [
      amfStr("_result", "Command name"),
      amfNum(1, "Transaction ID"),
      amfObj("Properties", [["fmsVer", amfStr("FMS/3,0,1,123")], ["capabilities", amfNum(31)]]),
      amfObj("Information", [
        ["level", amfStr("status")],
        ["code", amfStr("NetConnection.Connect.Success")],
        ["description", amfStr("Connection succeeded.")],
      ]),
    ],
  });

const createStream = () =>
  msg({ csid: 3, type: 20, summary: "createStream()", bodyName: "AMF0 command: createStream", body: [amfStr("createStream", "Command name"), amfNum(2, "Transaction ID"), amfNull("Command object")] });

const createResult = () =>
  msg({ csid: 3, type: 20, summary: "_result()", bodyName: "AMF0 command: _result", body: [amfStr("_result", "Command name"), amfNum(2, "Transaction ID"), amfNull("Command object"), amfNum(1, "Stream ID")] });

const publish = (key: string) =>
  msg({
    csid: 4, type: 20, streamId: 1, summary: `publish('${key}')`, bodyName: "AMF0 command: publish",
    body: [amfStr("publish", "Command name"), amfNum(0, "Transaction ID"), amfNull("Command object"), amfStr(key, "Publishing name (stream key)"), amfStr("live", "Publishing type")],
  });

const onStatus = (level: string, code: string, desc: string) =>
  msg({
    csid: 4, type: 20, streamId: 1, summary: `onStatus('${code}')`, bodyName: "AMF0 command: onStatus",
    body: [
      amfStr("onStatus", "Command name"),
      amfNum(0, "Transaction ID"),
      amfNull("Command object"),
      amfObj("Information", [["level", amfStr(level)], ["code", amfStr(code)], ["description", amfStr(desc)]]),
    ],
  });

const audio = () =>
  msg({
    csid: 4, type: 8, streamId: 1, ts: 23, summary: "Audio Data", bodyName: "Audio tag",
    body: [
      { name: "Sound format, rate, size, type", u8: 0xaf, value: "0xaf (AAC, 44 kHz, 16-bit, stereo)", note: "Top 4 bits 10 = AAC. The rest is fixed for AAC." },
      { name: "AAC packet type", u8: 1, value: "1 (raw frame)", note: "0 would be the AAC sequence header sent once at the start." },
      { name: "AAC frame", random: 368, seed: 811, opaque: true, note: "About 23 ms of compressed sound." },
    ],
  });

const video = () =>
  msg({
    csid: 6, type: 9, streamId: 1, ts: 33, summary: "Video Data", bodyName: "Video tag",
    body: [
      { name: "Frame type, codec", u8: 0x17, value: "0x17 (keyframe, AVC/H.264)", note: "Top 4 bits 1 = keyframe; low 4 bits 7 = AVC (H.264)." },
      { name: "AVC packet type", u8: 1, value: "1 (NAL units)" },
      { name: "Composition time", u24: 0, value: "0 ms" },
      { name: "NAL unit length", u32: 1150, value: "1150 bytes" },
      { name: "NAL unit (slice of a frame)", random: 1150, seed: 812, opaque: true, note: "Compressed picture data. A real keyframe is tens of kilobytes split over many chunks; one slice is shown." },
    ],
  });

// ------------------------------------------------------------ handshake blocks (1536 bytes each)

const C1_RAND = rand(1528, 101);
const S1_RAND = rand(1528, 202);

const c0c1a = () =>
  proto({
    id: "rtmp", name: "RTMP handshake", summary: "RTMP Handshake C0+C1 (first 1460 bytes)",
    fields: [
      { name: "C0: version", u8: 3, value: "3 (plain RTMP)", note: "One byte. 3 means unencrypted RTMP." },
      { name: "C1: time", u32: 0, value: "0", note: "C1 is 1536 bytes: a 4-byte time, 4 zero bytes, 1528 random bytes." },
      { name: "C1: zero", zero: 4 },
      { name: "C1: random (part 1)", bytes: C1_RAND.slice(0, 1451), value: "1451 of 1528 bytes", opaque: true, note: "Random filler. The server must echo it back exactly in S2." },
    ],
  });
const c0c1b = () => proto({ id: "rtmp", name: "RTMP handshake", summary: "RTMP Handshake C1 (last 77 bytes)", fields: [{ name: "C1: random (part 2)", bytes: C1_RAND.slice(1451), value: "77 bytes", opaque: true }] });
const s012a = () =>
  proto({
    id: "rtmp", name: "RTMP handshake", summary: "RTMP Handshake S0+S1 (first 1460 bytes)",
    fields: [
      { name: "S0: version", u8: 3, value: "3 (plain RTMP)", note: "The server agrees on version 3." },
      { name: "S1: time", u32: 0 },
      { name: "S1: zero", zero: 4 },
      { name: "S1: random (part 1)", bytes: S1_RAND.slice(0, 1451), value: "1451 of 1528 bytes", opaque: true, note: "The server’s own random block. The laptop echoes it in C2." },
    ],
  });
const s012b = () =>
  proto({
    id: "rtmp", name: "RTMP handshake", summary: "RTMP Handshake S1 end + S2",
    fields: [
      { name: "S1: random (part 2)", bytes: S1_RAND.slice(1451), value: "77 bytes", opaque: true },
      { name: "S2: time", u32: 0, note: "Copy of the time from C1." },
      { name: "S2: time read", u32: 12, value: "12 ms", note: "When the server read C1." },
      { name: "S2: echo of C1 random (part 1)", bytes: C1_RAND.slice(0, 1375), value: "1375 of 1528 bytes", opaque: true, note: "Byte for byte the same as C1’s random block." },
    ],
  });
const s012c = () => proto({ id: "rtmp", name: "RTMP handshake", summary: "RTMP Handshake S2 (last 153 bytes)", fields: [{ name: "S2: echo of C1 random (part 2)", bytes: C1_RAND.slice(1375), value: "153 bytes", opaque: true }] });
const c2a = () =>
  proto({
    id: "rtmp", name: "RTMP handshake", summary: "RTMP Handshake C2 (first 1460 bytes)",
    fields: [
      { name: "C2: time", u32: 0, note: "Copy of the time from S1." },
      { name: "C2: time read", u32: 35, value: "35 ms", note: "When the laptop read S1." },
      { name: "C2: echo of S1 random (part 1)", bytes: S1_RAND.slice(0, 1452), value: "1452 of 1528 bytes", opaque: true },
    ],
  });
const c2b = () => proto({ id: "rtmp", name: "RTMP handshake", summary: "RTMP Handshake C2 (last 76 bytes)", fields: [{ name: "C2: echo of S1 random (part 2)", bytes: S1_RAND.slice(1452), value: "76 bytes", opaque: true }] });

// ------------------------------------------------------------ TCP conversation helper (keeps seq/ack right)

function session(sport: number) {
  let c = 1, s = 1;
  const FL: Record<string, string> = { A: "ACK", PA: "PSH, ACK", FA: "FIN, ACK" };
  return {
    up: (flags: string, ...layers: LayerSpec[]) => {
      const n = build(...layers).bytes.length;
      const packet = build(...up(S), tcp({ sport, dport: PORT, seq: c, ack: s, flags, win: 502, seqBase: CB, ackBase: SB }), ...layers);
      const info = `${sport} → ${PORT} [${FL[flags]}] Seq=${c} Ack=${s} Len=${n}`;
      c += n + (flags.includes("F") ? 1 : 0);
      return { packet, info };
    },
    down: (flags: string, ...layers: LayerSpec[]) => {
      const n = build(...layers).bytes.length;
      const packet = build(...down(S), tcp({ sport: PORT, dport: sport, seq: s, ack: c, flags, win: 509, seqBase: SB, ackBase: CB }), ...layers);
      const info = `${PORT} → ${sport} [${FL[flags]}] Seq=${s} Ack=${c} Len=${n}`;
      s += n + (flags.includes("F") ? 1 : 0);
      return { packet, info };
    },
  };
}

const base = homeToServer({ kind: "server", label: "Ingest server", sub: S });
const devices: Device[] = base.devices.map((d) => (d.id === "client" ? { ...d, label: "Laptop (OBS)" } : d));

// ------------------------------------------------------------ normal scenario packets
const A = session(50712);
const hs = {
  c1: A.up("A", c0c1a()), c2: A.up("PA", c0c1b()),
  s1: A.down("A", s012a()), s2: A.down("A", s012b()), s3: A.down("PA", s012c()),
  c3: A.up("A", c2a()), c4: A.up("PA", c2b()),
};
const conn = A.up("PA", setChunkSize(), connect());
const connRes = A.down("PA", winAck(), peerBw(), setChunkSize(), connectResult());
const cs = A.up("PA", createStream());
const csRes = A.down("PA", createResult());
const pub = A.up("PA", publish(KEY));
const pubRes = A.down("PA", onStatus("status", "NetStream.Publish.Start", `Publishing ${KEY}.`));
const aud = A.up("PA", audio());
const vid = A.up("PA", video());
const ack = A.down("A");

// ------------------------------------------------------------ wrong key scenario packets
const B = session(50744);
const b = {
  c1: B.up("A", c0c1a()), c2: B.up("PA", c0c1b()),
  s1: B.down("A", s012a()), s2: B.down("A", s012b()), s3: B.down("PA", s012c()),
  c3: B.up("A", c2a()), c4: B.up("PA", c2b()),
};
const bConn = B.up("PA", setChunkSize(), connect());
const bConnRes = B.down("PA", winAck(), peerBw(), setChunkSize(), connectResult());
const bCs = B.up("PA", createStream());
const bCsRes = B.down("PA", createResult());
const bPub = B.up("PA", publish(BAD_KEY));
const bPubRes = B.down("PA", onStatus("error", "NetStream.Publish.BadName", "Stream key is not valid."));
const bFin = B.down("FA");
const bFinAck = B.up("FA");

export default defineLesson({
  id: "rtmp",
  name: "RTMP",
  full: "Real-Time Messaging Protocol",
  group: "realtime",
  layer: 7,
  difficulty: 2,
  tagline: "How OBS pushes your live stream up to the platform.",
  description:
    "RTMP is the upload path behind most live streams. The streaming app opens one TCP connection to an ingest server, does a short handshake, logs in to an app with a secret stream key, and then sends audio and video as a steady flow of small chunks.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP, port 1935"],
    ["Encoding", "Chunks + AMF0 commands"],
    ["Handshake", "C0/C1, S0/S1/S2, C2 (1536-byte blocks)"],
    ["Media", "H.264 video, AAC audio (FLV tags)"],
    ["Defined in", "Adobe RTMP spec (2012)"],
  ],
  ports: "TCP 1935 (RTMP), 443 (RTMPS over TLS)",
  rfc: "Adobe RTMP 1.0 specification",
  keywords: ["obs", "live streaming", "stream key", "ingest", "amf0", "flv", "chunk", "publish", "rtmps"],
  related: ["tcp", "rtsp", "webrtc", "hls"],
  devices,
  links: base.links,
  legend: [
    ["green", "Handshake and success replies"],
    ["blue", "Commands (connect, createStream, publish)"],
    ["amber", "Audio and video from OBS"],
    ["red", "Errors"],
    ["slate", "Closing"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Go live from OBS",
      summary: "OBS connects to the ingest server, publishes with its stream key and starts sending audio and video.",
      kind: "normal",
      steps: [
        {
          title: "Send C0 and C1",
          desc: "A version byte and a 1536-byte block",
          detail:
            "The TCP connection to port 1935 is already open. OBS sends C0, a single version byte (3), followed straight away by C1: 1536 bytes made of a timestamp, four zeros and 1528 random bytes. That is 1537 bytes, too big for one TCP segment, so it leaves in two.",
          facts: [["C0", "1 byte, version 3"], ["C1", "1536 bytes"], ["Segments", "1460 + 77 bytes"]],
          quiz: {
            q: "C0 + C1 is 1537 bytes and the segment size is 1460. How many TCP segments carry it?",
            options: ["1", "2", "3", "It is split into 128-byte chunks"],
            answer: 1,
            why: "1537 is more than 1460, so TCP sends 1460 bytes and then the remaining 77. RTMP chunking only starts after the handshake.",
          },
          events: [
            note("client", "TCP TO :1935 ALREADY OPEN", "blue"),
            pkt("client", "server", "green", "C0+C1", ["version 3", "1536 random-ish bytes"], { time: 0, info: `Handshake C0+C1 (${hs.c1.info})`, packet: hs.c1.packet }),
            pkt("client", "server", "green", "C1 (end)", ["last 77 bytes"], { time: 0.0001, parallel: true, info: `Handshake C1 continued (${hs.c2.info})`, packet: hs.c2.packet }),
          ],
        },
        {
          title: "S0, S1, S2 then C2",
          desc: "Each side echoes the other’s random block",
          detail:
            "The server answers with S0 (version 3), its own random block S1, and S2, which is an exact copy of C1. OBS checks the echo and replies with C2, a copy of S1. The random content is meaningless; the echo just proves both sides are speaking RTMP and reading each other correctly.",
          facts: [["Server sends", "1 + 1536 + 1536 = 3073 bytes"], ["Laptop sends", "C2, 1536 bytes"], ["Rule", "S2 = C1, C2 = S1"]],
          quiz: {
            q: "What must the random part of S2 contain?",
            options: ["Fresh random bytes", "A copy of C1’s random bytes", "The stream key", "Zeros"],
            answer: 1,
            why: "S2 echoes C1 and C2 echoes S1. Each side proves it received the other’s block intact.",
          },
          events: [
            pkt("server", "client", "green", "S0+S1", ["version 3", "server random"], { time: 0.035, info: `Handshake S0+S1 (${hs.s1.info})`, packet: hs.s1.packet }),
            pkt("server", "client", "green", "S1+S2", ["S2 = copy of C1"], { time: 0.0351, parallel: true, info: `Handshake S1+S2 (${hs.s2.info})`, packet: hs.s2.packet }),
            pkt("server", "client", "green", "S2 (end)", ["last 153 bytes"], { time: 0.0352, parallel: true, info: `Handshake S2 continued (${hs.s3.info})`, packet: hs.s3.packet }),
            pkt("client", "server", "green", "C2", ["copy of S1"], { time: 0.036, info: `Handshake C2 (${hs.c3.info})`, packet: hs.c3.packet }),
            pkt("client", "server", "green", "C2 (end)", ["last 76 bytes"], { time: 0.0361, parallel: true, info: `Handshake C2 continued (${hs.c4.info})`, packet: hs.c4.packet }),
          ],
        },
        {
          title: "connect to the app",
          desc: "The first AMF0 command",
          detail:
            `Now RTMP switches to chunks. OBS first raises its chunk size from the default 128 bytes to 4096, then sends the connect command. Commands are encoded in AMF0: a type byte, then the value. Here the name is the string "connect", the transaction ID is the number 1, and an object lists the app name "${APP}" and the full URL.`,
          facts: [["Command", `connect('${APP}')`], ["URL", TC_URL], ["Chunk stream", "3 (commands)"]],
          quiz: {
            q: "How does AMF0 encode the transaction ID 1?",
            options: ["One byte: 0x01", "0x00 then an 8-byte double", "A 4-byte integer", "The text \"1\""],
            answer: 1,
            why: "AMF0 has only one number type: marker 0x00 followed by a 64-bit IEEE double (3F F0 00 00 00 00 00 00 for 1).",
          },
          events: [
            pkt("client", "server", "blue", "CONNECT", ["Set Chunk Size 4096", `connect('${APP}')`], { time: 0.037, info: `Set Chunk Size 4096|connect('${APP}')`, packet: conn.packet }),
            pkt("server", "client", "green", "_RESULT", ["window, bandwidth", "Connect.Success"], { time: 0.072, info: "Window Acknowledgement Size 2500000|Set Peer Bandwidth 2500000,Dynamic|Set Chunk Size 4096|_result('NetConnection.Connect.Success')", packet: connRes.packet }),
          ],
        },
        {
          title: "Create a stream",
          desc: "Ask for a message stream ID",
          detail:
            "One RTMP connection can carry several streams, so OBS asks for one with createStream (transaction 2). The server replies _result with the number 1. From now on, audio, video and stream commands carry message stream ID 1 in their chunk headers.",
          facts: [["Request", "createStream, transaction 2"], ["Answer", "Stream ID 1"], ["Used in", "Message stream ID field"]],
          events: [
            pkt("client", "server", "blue", "CREATE", ["createStream()"], { time: 0.073, info: "createStream()", packet: cs.packet }),
            pkt("server", "client", "green", "_RESULT", ["stream id = 1"], { time: 0.108, info: "_result()", packet: csRes.packet }),
          ],
        },
        {
          title: "Publish with the key",
          desc: "The stream key is the password",
          detail:
            "OBS sends publish on stream 1 with the secret stream key and the type \"live\". The server looks the key up, ties it to your channel and answers onStatus with NetStream.Publish.Start. Plain RTMP sends the key in clear text, which is why platforms now prefer RTMPS (RTMP inside TLS on port 443).",
          facts: [["Command", "publish(key, \"live\")"], ["Reply", "NetStream.Publish.Start"], ["Key sent", "In clear text on plain RTMP"]],
          quiz: {
            q: "Someone on the same Wi-Fi captures this plain RTMP session. What can they take?",
            options: ["Nothing, RTMP is encrypted", "The stream key, and so stream to your channel", "Only the video", "Only the server name"],
            answer: 1,
            why: "Plain RTMP has no encryption, so the publish command and its key are readable. RTMPS wraps everything in TLS.",
          },
          events: [
            pkt("client", "server", "blue", "PUBLISH", ["stream key", "type live"], { time: 0.109, info: `publish('${KEY}')`, packet: pub.packet }),
            pkt("server", "client", "green", "ONSTATUS", ["Publish.Start"], { time: 0.144, info: "onStatus('NetStream.Publish.Start')", packet: pubRes.packet }),
            note("server", "YOU ARE LIVE", "green"),
          ],
        },
        {
          title: "Audio and video flow",
          desc: "FLV tags inside RTMP chunks",
          detail:
            "Media now streams nonstop. Each audio message starts with 0xAF (AAC) and each video message with 0x17 (H.264 keyframe) or 0x27 (other frame), followed by the compressed data. Audio and video use different chunk streams so a big video frame never blocks the sound for long. TCP acknowledges the bytes as usual.",
          facts: [["Audio", "Type 8, AAC, about 23 ms per frame"], ["Video", "Type 9, H.264"], ["Chunk streams", "4 audio, 6 video"]],
          events: [
            pkt("client", "server", "amber", "AUDIO", ["AAC frame", "ts 23 ms"], { time: 0.15, info: "Audio Data", packet: aud.packet }),
            pkt("client", "server", "amber", "VIDEO", ["H.264 keyframe slice", "ts 33 ms"], { time: 0.151, info: "Video Data", packet: vid.packet }),
            pkt("server", "client", "green", "ACK", ["TCP ack"], { time: 0.186, info: ack.info, packet: ack.packet }),
          ],
        },
      ],
      outro: {
        title: "Streaming live",
        text: "OBS opened a TCP connection, proved both sides speak RTMP with the C/S handshake, connected to the app, got a stream ID, published with its secret key and started sending audio and video chunks. The platform then repackages the stream for viewers, usually as HLS or DASH.",
        facts: [["Handshake", "3 × 1536-byte blocks each way"], ["Commands", "connect, createStream, publish"], ["Media", "AAC + H.264 in chunks"], ["Time to live", "About 0.15 s"]],
      },
    },
    {
      id: "bad-key",
      name: "Wrong stream key",
      summary: "One character of the stream key is wrong, so the server refuses to publish.",
      kind: "failure",
      steps: [
        {
          title: "Handshake and connect",
          desc: "Everything looks normal so far",
          detail:
            "The handshake and the connect command do not involve the stream key, so they succeed exactly as before. The key is only checked when OBS tries to publish.",
          facts: [["Handshake", "OK"], ["connect", "NetConnection.Connect.Success"], ["Key checked", "Not yet"]],
          events: [
            pkt("client", "server", "green", "C0+C1", ["version 3"], { time: 0, info: `Handshake C0+C1 (${b.c1.info})`, packet: b.c1.packet }),
            pkt("client", "server", "green", "C1 (end)", ["last 77 bytes"], { time: 0.0001, parallel: true, info: `Handshake C1 continued (${b.c2.info})`, packet: b.c2.packet }),
            pkt("server", "client", "green", "S0+S1", ["version 3"], { time: 0.035, info: `Handshake S0+S1 (${b.s1.info})`, packet: b.s1.packet }),
            pkt("server", "client", "green", "S1+S2", ["S2 = copy of C1"], { time: 0.0351, parallel: true, info: `Handshake S1+S2 (${b.s2.info})`, packet: b.s2.packet }),
            pkt("server", "client", "green", "S2 (end)", ["last 153 bytes"], { time: 0.0352, parallel: true, info: `Handshake S2 continued (${b.s3.info})`, packet: b.s3.packet }),
            pkt("client", "server", "green", "C2", ["copy of S1"], { time: 0.036, info: `Handshake C2 (${b.c3.info})`, packet: b.c3.packet }),
            pkt("client", "server", "green", "C2 (end)", ["last 76 bytes"], { time: 0.0361, parallel: true, info: `Handshake C2 continued (${b.c4.info})`, packet: b.c4.packet }),
            pkt("client", "server", "blue", "CONNECT", [`connect('${APP}')`], { time: 0.037, info: `Set Chunk Size 4096|connect('${APP}')`, packet: bConn.packet }),
            pkt("server", "client", "green", "_RESULT", ["Connect.Success"], { time: 0.072, info: "Window Acknowledgement Size 2500000|Set Peer Bandwidth 2500000,Dynamic|Set Chunk Size 4096|_result('NetConnection.Connect.Success')", packet: bConnRes.packet }),
            pkt("client", "server", "blue", "CREATE", ["createStream()"], { time: 0.073, info: "createStream()", packet: bCs.packet }),
            pkt("server", "client", "green", "_RESULT", ["stream id = 1"], { time: 0.108, info: "_result()", packet: bCsRes.packet }),
          ],
        },
        {
          title: "Publish with a typo",
          desc: "The last character is wrong",
          detail: `The stream key pasted into OBS ends in "pq" instead of "pz". OBS cannot know that, so it sends publish exactly as before with the wrong name.`,
          facts: [["Key sent", BAD_KEY], ["Correct key", "…2bxe-k4pz"], ["Stream ID", "1"]],
          quiz: {
            q: "What will the server answer?",
            options: ["NetStream.Publish.Start", "onStatus with an error code", "A TCP reset with no message", "It silently ignores the video"],
            answer: 1,
            why: "RTMP reports problems with an onStatus message whose level is \"error\". The code says what went wrong.",
          },
          events: [pkt("client", "server", "blue", "PUBLISH", ["wrong key"], { time: 0.109, info: `publish('${BAD_KEY}')`, packet: bPub.packet })],
        },
        {
          title: "Publish.BadName",
          desc: "Rejected, then the connection closes",
          detail:
            "The server finds no channel for that key and replies onStatus with level \"error\" and code NetStream.Publish.BadName. It then closes the TCP connection. OBS shows a “failed to connect” style error and the usual fix is to copy the key again from the platform’s dashboard.",
          facts: [["Level", "error"], ["Code", "NetStream.Publish.BadName"], ["Then", "Server closes TCP (FIN)"]],
          events: [
            pkt("server", "client", "red", "ONSTATUS", ["Publish.BadName"], { time: 0.144, info: "onStatus('NetStream.Publish.BadName')", packet: bPubRes.packet }),
            pkt("server", "client", "slate", "FIN", ["closing"], { time: 0.145, info: bFin.info, packet: bFin.packet }),
            pkt("client", "server", "slate", "FIN", ["closing too"], { time: 0.18, info: bFinAck.info, packet: bFinAck.packet }),
            note("client", "STREAM KEY REJECTED", "red"),
          ],
        },
      ],
      outro: {
        title: "No stream, no harm",
        text: "The stream key is the only thing that ties an upload to your channel, so the server checks it at publish time and refuses anything it doesn’t know. Treat the key like a password: never show it on screen, and reset it if it leaks.",
        facts: [["Checked at", "publish"], ["Error code", "NetStream.Publish.BadName"], ["Fix", "Copy the key again or reset it"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Handshake",
      items: [["C0 / S0", "1 byte: version 3"], ["C1 / S1", "1536 bytes: time, zero, random"], ["C2 / S2", "Echo of S1 / C1"]],
    },
    {
      title: "Message types",
      items: [["1", "Set Chunk Size"], ["3", "Acknowledgement"], ["5 / 6", "Window Ack Size / Set Peer Bandwidth"], ["8 / 9", "Audio / Video"], ["18 / 20", "AMF0 data / AMF0 command"]],
    },
    {
      title: "AMF0 markers",
      items: [["0x00", "Number (8-byte double)"], ["0x01", "Boolean"], ["0x02", "String (2-byte length)"], ["0x03", "Object, ends 00 00 09"], ["0x05", "Null"]],
    },
    {
      title: "Status codes",
      items: [["NetConnection.Connect.Success", "connect OK"], ["NetStream.Publish.Start", "You are live"], ["NetStream.Publish.BadName", "Bad or busy stream key"]],
    },
  ],
});
