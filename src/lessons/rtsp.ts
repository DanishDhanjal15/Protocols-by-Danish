import { defineLesson, note, pkt, Device, PacketEvent } from "@/lib/lesson";
import { build, FieldSpec, proto, textLayer } from "@/lib/packet";
import { eth, ipv4, tcp, udp } from "@/lib/proto";
import { ADDR } from "./_common";

// ---------------------------------------------------------------- addresses

const CAM = "192.168.1.64";
const CAM_MAC = "bc:ad:28:5e:11:9f";
const STREAM_URL = `rtsp://${CAM}:554/stream1`;
const UA = "User-Agent: LibVLC/3.0.21 (LIVE555 Streaming Media v2016.11.28)";
const SESSION = "1F3A92C4";
const SSRC = 0x5a3c1e07;
const RR_SSRC = 0x9b1d44e2;
const RTP_C = 50000; // laptop RTP port (RTCP = 50001)
const RTP_S = 6970; // camera RTP port (RTCP = 6971)
const NONCE = "5f2b8c1e9a7d4036";
const auth = (uri: string, response: string) =>
  `Authorization: Digest username="viewer", realm="IPCam", nonce="${NONCE}", uri="${uri}", response="${response}"`;
const GOOD = "a3c9e1f07b2d48e6915c0d7f3e8a2b64";
const BAD = "0e71d4b98c2a5f3016e8b7c4d92a1f05";

const toCam = () => [eth({ src: ADDR.laptopMac, dst: CAM_MAC }), ipv4({ src: ADDR.laptop, dst: CAM, ttl: 64 })];
const fromCam = () => [eth({ src: CAM_MAC, dst: ADDR.laptopMac }), ipv4({ src: CAM, dst: ADDR.laptop, ttl: 64, id: 0x3a10 })];

const msgLen = (lines: string[], body?: string) => lines.reduce((n, l) => n + l.length + 2, 0) + 2 + (body?.length ?? 0);

/** One RTSP TCP connection; tracks sequence numbers so every segment is consistent. */
function rtspConn(sport: number, cBase: number, sBase: number) {
  let c = 1;
  let s = 1;
  const layer = (lines: string[], body?: string, notes?: Record<number, string>) =>
    textLayer({ id: "rtsp", name: "RTSP", lines, blankLine: true, notes, body: body !== undefined ? { text: body, what: "SDP (session description)", note: "Describes the stream: codec, clock rate, and how to ask for each track." } : undefined });
  return {
    syn: () => build(...toCam(), tcp({ sport, dport: 554, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", { ts: [811200, 0] }, "nop", { ws: 7 }], seqBase: cBase })),
    synAck: () => build(...fromCam(), tcp({ sport: 554, dport: sport, seq: 0, ack: 1, flags: "SA", win: 28960, opts: [{ mss: 1460 }, "sackOk", { ts: [40211, 811200] }, "nop", { ws: 6 }], seqBase: sBase, ackBase: cBase })),
    ack: () => build(...toCam(), tcp({ sport, dport: 554, seq: 1, ack: 1, flags: "A", win: 502, seqBase: cBase, ackBase: sBase })),
    req(lines: string[], notes?: Record<number, string>) {
      const packet = build(...toCam(), tcp({ sport, dport: 554, seq: c, ack: s, flags: "PA", win: 502, seqBase: cBase, ackBase: sBase }), layer(lines, undefined, notes));
      const info = `Request: ${lines[0]}`;
      c += msgLen(lines);
      return { packet, info };
    },
    resp(lines: string[], body?: string, notes?: Record<number, string>) {
      const packet = build(...fromCam(), tcp({ sport: 554, dport: sport, seq: s, ack: c, flags: "PA", win: 453, seqBase: sBase, ackBase: cBase }), layer(lines, body, notes));
      const info = `Reply: ${lines[0]}`;
      s += msgLen(lines, body);
      return { packet, info };
    },
  };
}

const ev = (from: string, to: string, color: PacketEvent["color"], label: string, lines: string[], time: number, m: { packet: PacketEvent["packet"]; info: string }, extra: Partial<PacketEvent> = {}) =>
  pkt(from, to, color, label, lines, { time, info: m.info, packet: m.packet, ...extra });

// ---------------------------------------------------------------- SDP

const SDP = [
  "v=0",
  `o=- 1763540000 1 IN IP4 ${CAM}`,
  "s=Live stream",
  "c=IN IP4 0.0.0.0",
  "t=0 0",
  "a=control:*",
  "a=range:npt=0-",
  "m=video 0 RTP/AVP 96",
  "a=rtpmap:96 H264/90000",
  "a=fmtp:96 packetization-mode=1;profile-level-id=4d401f;sprop-parameter-sets=Z01AH5WgFAFuQA==,aO48gA==",
  "a=framerate:25",
  "a=control:trackID=1",
].map((l) => l + "\r\n").join("");

const describeOk = (cseq: number) => [
  "RTSP/1.0 200 OK",
  `CSeq: ${cseq}`,
  `Content-Base: ${STREAM_URL}/`,
  "Content-Type: application/sdp",
  `Content-Length: ${SDP.length}`,
];

// ---------------------------------------------------------------- RTP with H.264 FU-A (RFC 6184)

const NAL_IDR = 0x65; // F=0, NRI=3, type 5 (IDR slice)
const FU_INDICATOR = (NAL_IDR & 0xe0) | 28; // keep F+NRI, type 28 = FU-A
const fuHeader = (start: boolean, end: boolean) => (start ? 0x80 : 0) | (end ? 0x40 : 0) | (NAL_IDR & 0x1f);

const rtpH264 = (o: { seq: number; ts: number; start: boolean; end: boolean; len: number; seed: number }) => {
  const fu = fuHeader(o.start, o.end);
  const fields: FieldSpec[] = [
    { name: "V, P, X, CC", u8: 0x80, value: "V=2, no padding, no extension, 0 CSRC", note: "RTP version 2." },
    { name: "Marker, payload type", u8: ((o.end ? 1 : 0) << 7) | 96, value: `M=${o.end ? 1 : 0}, PT=96 (H.264)`, note: o.end ? "Marker set: this is the last packet of the frame, so the player can decode it now." : "Marker clear: more pieces of this frame follow." },
    { name: "Sequence number", u16: o.seq, note: "Up by one per packet. A gap means a lost piece." },
    { name: "Timestamp", u32: o.ts, note: "90 kHz clock. Every piece of one frame has the same value; the next frame is 3600 ticks later (25 fps)." },
    { name: "SSRC", u32: SSRC, value: `0x${SSRC.toString(16)}`, note: "Names this stream; matches ssrc= in the SETUP reply." },
    {
      name: "FU indicator",
      u8: FU_INDICATOR,
      value: `0x${FU_INDICATOR.toString(16)} (F=0, NRI=3, type 28 FU-A)`,
      note: "Looks like a NAL header, but type 28 says: this is a fragment of a bigger NAL unit. F and NRI are copied from the original NAL header (0x65).",
    },
    {
      name: "FU header",
      u8: fu,
      value: `0x${fu.toString(16).padStart(2, "0")} (S=${o.start ? 1 : 0}, E=${o.end ? 1 : 0}, R=0, type 5 IDR)`,
      note: "S marks the first fragment, E the last. The low 5 bits hold the real NAL type: 5, a key frame (IDR) slice.",
    },
    { name: "H.264 slice data (fragment)", random: o.len, seed: o.seed, opaque: true, note: "Compressed picture data. Not encrypted, just not decoded here." },
  ];
  return proto({
    id: "rtp",
    name: "RTP",
    osi: 7,
    summary: `Real-Time Transport Protocol: PT=96 (H.264), SSRC=0x${SSRC.toString(16)}, Seq=${o.seq}, Time=${o.ts}${o.end ? ", Mark" : ""}`,
    fields,
  });
};

const rtpPkt = (o: Parameters<typeof rtpH264>[0]) => build(...fromCam(), udp({ sport: RTP_S, dport: RTP_C }), rtpH264(o));

// ---------------------------------------------------------------- RTCP

const NTP_SEC = Math.floor(Date.UTC(2026, 10, 19, 10, 0, 5) / 1000) + 2208988800;
const NTP_FRAC = 0x40000000; // .25 s
const LSR = (((NTP_SEC & 0xffff) << 16) | (NTP_FRAC >>> 16)) >>> 0;

const rtcpSR = proto({
  id: "rtcp",
  name: "RTCP",
  osi: 7,
  summary: `Real-time Transport Control Protocol (Sender Report), SSRC 0x${SSRC.toString(16)}`,
  fields: [
    { name: "V, P, RC", u8: 0x80, value: "V=2, no padding, 0 report blocks" },
    { name: "Packet type", u8: 200, value: "200 (Sender Report)" },
    { name: "Length", u16: 6, value: "6 (28 bytes)", note: "In 32-bit words, minus one." },
    { name: "Sender SSRC", u32: SSRC, value: `0x${SSRC.toString(16)}` },
    { name: "NTP timestamp", u64: (BigInt(NTP_SEC) << BigInt(32)) | BigInt(NTP_FRAC), value: "2026-11-19 10:00:05.25 UTC", note: "Wall-clock time when this report was made." },
    { name: "RTP timestamp", u32: 1402213760 + 125 * 3600, value: String(1402213760 + 125 * 3600), note: "The RTP clock at that same moment. Pairing the two lets a player sync video with audio." },
    { name: "Sender packet count", u32: 5480 },
    { name: "Sender octet count", u32: 7395110, value: "7 395 110 bytes" },
  ],
});

const rtcpRR = proto({
  id: "rtcp",
  name: "RTCP",
  osi: 7,
  summary: `Real-time Transport Control Protocol (Receiver Report), SSRC 0x${RR_SSRC.toString(16)}`,
  fields: [
    { name: "V, P, RC", u8: 0x81, value: "V=2, no padding, 1 report block" },
    { name: "Packet type", u8: 201, value: "201 (Receiver Report)" },
    { name: "Length", u16: 7, value: "7 (32 bytes)" },
    { name: "Reporter SSRC", u32: RR_SSRC, value: `0x${RR_SSRC.toString(16)}` },
    {
      name: "Report block",
      fields: [
        { name: "Source SSRC", u32: SSRC, value: `0x${SSRC.toString(16)}` },
        { name: "Fraction lost", u8: 0, value: "0%", note: "Share of packets lost since the last report." },
        { name: "Cumulative lost", u24: 0, value: "0 packets" },
        { name: "Highest sequence", u32: 27110 + 5480, note: "Highest sequence number received so far." },
        { name: "Jitter", u32: 12, value: "12 ticks", note: "How uneven the arrival times are, in 90 kHz ticks." },
        { name: "Last SR (LSR)", u32: LSR, value: `0x${LSR.toString(16)}`, note: "Middle 32 bits of the sender report’s NTP time." },
        { name: "Delay since last SR", u32: 3277, value: "0.05 s", note: "In 1/65536 s. With LSR the camera can work out the round-trip time." },
      ],
    },
  ],
});

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop (VLC)", sub: ADDR.laptop, x: 10, y: 64 },
  { id: "router", kind: "router", label: "Home router", sub: ADDR.router, x: 50, y: 34 },
  { id: "camera", kind: "camera", label: "IP camera", sub: CAM, x: 89, y: 64 },
];
const links: [string, string][] = [
  ["client", "router"],
  ["router", "camera"],
];

const n = rtspConn(51500, 0x1d4e7700, 0x8a33c100);
const f = rtspConn(51520, 0x47b21a00, 0x0e9cd800);
const TS0 = 1402213760;

export default defineLesson({
  id: "rtsp",
  name: "RTSP",
  full: "Real Time Streaming Protocol",
  group: "realtime",
  layer: 7,
  difficulty: 2,
  tagline: "The remote control for IP cameras and live video.",
  description:
    "RTSP is how a video player asks a camera for its stream. It looks like HTTP: text requests such as DESCRIBE, SETUP and PLAY over TCP port 554. The video itself travels separately in RTP packets, with RTCP reports on the side.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Control", "TCP 554, text like HTTP"],
    ["Media", "RTP over UDP (or interleaved in TCP)"],
    ["Description", "SDP"],
    ["Common codec", "H.264 / H.265, 90 kHz clock"],
    ["Defined in", "RFC 2326 (1.0), RFC 7826 (2.0)"],
  ],
  ports: "TCP 554 (RTSP); RTP/RTCP on an even/odd UDP port pair",
  rfc: "RFC 2326, RFC 3550 (RTP), RFC 6184 (H.264 over RTP)",
  keywords: ["ip camera", "cctv", "vlc", "rtp", "rtcp", "h264", "fu-a", "describe", "setup", "play", "teardown", "nvr", "stream"],
  related: ["webrtc", "sip", "rtmp", "udp", "tcp"],
  devices,
  links,
  legend: [
    ["blue", "RTSP requests"],
    ["green", "Handshake and 200 OK"],
    ["violet", "Video from the camera"],
    ["teal", "RTCP reports"],
    ["red", "Errors"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Watching a camera in VLC",
      summary: "VLC opens rtsp://192.168.1.64/stream1, sets up an RTP stream, plays it, then stops.",
      kind: "normal",
      steps: [
        {
          title: "Connect and ask OPTIONS",
          desc: "TCP to port 554, then: what can you do?",
          detail:
            "VLC opens a TCP connection to the camera on port 554. Its first RTSP request is OPTIONS, which asks which methods the camera supports. Every request carries a CSeq number, and the reply repeats it so answers can be matched to questions.",
          facts: [["Camera", `${CAM}, TCP 554`], ["Laptop port", "51500"], ["CSeq", "1"]],
          events: [
            pkt("client", "camera", "green", "SYN", ["to port 554"], { time: 0, info: "51500 → 554 [SYN] Seq=0 Win=64240 Len=0 MSS=1460", packet: n.syn() }),
            pkt("camera", "client", "green", "SYN-ACK", [], { time: 0.0004, info: "554 → 51500 [SYN, ACK] Seq=0 Ack=1 Win=28960 Len=0 MSS=1460", packet: n.synAck() }),
            pkt("client", "camera", "green", "ACK", [], { time: 0.0005, info: "51500 → 554 [ACK] Seq=1 Ack=1 Win=502 Len=0", packet: n.ack() }),
            ev("client", "camera", "blue", "OPTIONS", ["CSeq 1"], 0.001, n.req([`OPTIONS ${STREAM_URL} RTSP/1.0`, "CSeq: 1", UA])),
            ev("camera", "client", "green", "200 OK", ["Public: DESCRIBE,", "SETUP, PLAY…"], 0.004, n.resp(["RTSP/1.0 200 OK", "CSeq: 1", "Public: OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN, GET_PARAMETER, SET_PARAMETER"])),
          ],
        },
        {
          title: "DESCRIBE the stream",
          desc: "The camera answers with SDP",
          detail:
            "VLC asks for a description of the stream. This camera needs a login, so it first answered 401 and VLC repeated the request with a Digest answer (the what-if shows that part). The 200 OK carries an SDP body: one video track, payload type 96, H.264 with a 90 kHz clock, plus the codec settings VLC needs before the first frame.",
          facts: [["Body", `SDP, ${SDP.length} bytes`], ["Codec", "H.264, PT 96, 90 000 Hz"], ["Track STREAM_URL", "trackID=1"]],
          quiz: {
            q: "Which SDP line tells VLC the video clock runs at 90 000 ticks per second?",
            options: ["m=video 0 RTP/AVP 96", "a=rtpmap:96 H264/90000", "a=framerate:25", "c=IN IP4 0.0.0.0"],
            answer: 1,
            why: "a=rtpmap maps payload type 96 to a codec name and its clock rate. The RTP timestamps are counted in that clock.",
          },
          events: [
            ev("client", "camera", "blue", "DESCRIBE", ["CSeq 3", "Accept: SDP"], 0.006, n.req([`DESCRIBE ${STREAM_URL} RTSP/1.0`, "CSeq: 3", auth(STREAM_URL, GOOD), UA, "Accept: application/sdp"])),
            ev("camera", "client", "green", "200 OK", ["SDP: H.264", "PT 96, 90 kHz"], 0.011, n.resp(describeOk(3), SDP)),
          ],
        },
        {
          title: "SETUP the transport",
          desc: "Agree on UDP ports for RTP and RTCP",
          detail: `VLC says where it wants the video: RTP on UDP port ${RTP_C} and RTCP reports on ${RTP_C + 1}. The camera replies with its own port pair and a Session ID, which every later request must carry. Instead of UDP, a client can ask for RTP/AVP/TCP;interleaved=0-1 to get the video inside this same TCP connection, which helps through firewalls.`,
          facts: [["Client ports", `${RTP_C} (RTP), ${RTP_C + 1} (RTCP)`], ["Server ports", `${RTP_S}, ${RTP_S + 1}`], ["Session", SESSION]],
          quiz: {
            q: `RTP goes to port ${RTP_C}. Where will the camera send RTCP reports?`,
            options: [String(RTP_C - 1), String(RTP_C + 1), "554", "The same port"],
            answer: 1,
            why: "By convention RTP uses an even port and RTCP the next odd one. That is why the Transport header lists a range like 50000-50001.",
          },
          events: [
            ev("client", "camera", "blue", "SETUP", ["CSeq 4", `client_port=${RTP_C}-${RTP_C + 1}`], 0.013, n.req([`SETUP ${STREAM_URL}/trackID=1 RTSP/1.0`, "CSeq: 4", auth(`${STREAM_URL}/`, GOOD), UA, `Transport: RTP/AVP;unicast;client_port=${RTP_C}-${RTP_C + 1}`])),
            ev("camera", "client", "green", "200 OK", [`Session ${SESSION}`, `server_port=${RTP_S}-${RTP_S + 1}`], 0.016, n.resp(["RTSP/1.0 200 OK", "CSeq: 4", `Session: ${SESSION};timeout=60`, `Transport: RTP/AVP;unicast;client_port=${RTP_C}-${RTP_C + 1};server_port=${RTP_S}-${RTP_S + 1};ssrc=${SSRC.toString(16).toUpperCase()}`])),
          ],
        },
        {
          title: "PLAY",
          desc: "Start sending, please",
          detail:
            "VLC sends PLAY with the Session ID. The reply’s RTP-Info header gives the sequence number and RTP timestamp of the first packet, so VLC can line up the stream with the wall clock from the very start.",
          facts: [["Range", "npt=0.000- (live, from now)"], ["First seq", "27110"], ["First rtptime", String(TS0)]],
          events: [
            ev("client", "camera", "blue", "PLAY", ["CSeq 5", `Session ${SESSION}`], 0.018, n.req([`PLAY ${STREAM_URL}/ RTSP/1.0`, "CSeq: 5", auth(`${STREAM_URL}/`, GOOD), UA, `Session: ${SESSION}`, "Range: npt=0.000-"])),
            ev("camera", "client", "green", "200 OK", ["RTP-Info:", "seq=27110"], 0.021, n.resp(["RTSP/1.0 200 OK", "CSeq: 5", `Session: ${SESSION}`, "Range: npt=0.000-", `RTP-Info: url=${STREAM_URL}/trackID=1;seq=27110;rtptime=${TS0}`])),
          ],
        },
        {
          title: "Video in pieces (FU-A)",
          desc: "A key frame split across many RTP packets",
          detail:
            "A key frame (IDR) is about 60 KB, far bigger than one packet. H.264 over RTP cuts it into FU-A fragments. Each starts with an FU indicator (type 28) and an FU header whose S bit marks the first piece and E bit the last. All pieces share one timestamp, and the last also sets the RTP marker bit.",
          facts: [["FU indicator", `0x${FU_INDICATOR.toString(16)} (NRI 3, type 28)`], ["FU header", `start 0x${fuHeader(true, false).toString(16)}, middle 0x0${fuHeader(false, false).toString(16)}, end 0x${fuHeader(false, true).toString(16)}`], ["Pieces", "43 for this frame"]],
          quiz: {
            q: "The original NAL header is 0x65 (an IDR slice). What FU header byte does the LAST fragment carry?",
            options: ["0x85", "0x05", "0x45", "0x7C"],
            answer: 2,
            why: "E bit (0x40) set, S bit clear, plus the real NAL type 5: 0x40 | 0x05 = 0x45. The first fragment has 0x85, the middle ones 0x05.",
          },
          events: [
            pkt("camera", "client", "violet", "RTP FU-A", ["seq 27110", "S=1 first piece"], { time: 0.03, info: `PT=DynamicRTP-Type-96, SSRC=0x${SSRC.toString(16).toUpperCase()}, Seq=27110, Time=${TS0} FU-A Start:IDR-Slice`, packet: rtpPkt({ seq: 27110, ts: TS0, start: true, end: false, len: 1398, seed: 610 }) }),
            pkt("camera", "client", "violet", "RTP FU-A", ["seq 27111", "middle piece"], { time: 0.0301, info: `PT=DynamicRTP-Type-96, SSRC=0x${SSRC.toString(16).toUpperCase()}, Seq=27111, Time=${TS0} FU-A`, packet: rtpPkt({ seq: 27111, ts: TS0, start: false, end: false, len: 1398, seed: 611 }) }),
            pkt("camera", "client", "violet", "RTP FU-A", ["seq 27152", "E=1, marker"], { time: 0.0312, info: `PT=DynamicRTP-Type-96, SSRC=0x${SSRC.toString(16).toUpperCase()}, Seq=27152, Time=${TS0}, Mark FU-A End`, packet: rtpPkt({ seq: 27152, ts: TS0, start: false, end: true, len: 612, seed: 612 }) }),
            note("client", "FRAME 1 DECODED", "green"),
          ],
        },
        {
          title: "RTCP reports",
          desc: "Sender report out, receiver report back",
          detail:
            "Every few seconds the camera sends an RTCP Sender Report that pairs a wall-clock time with an RTP timestamp and counts what it has sent. VLC answers with a Receiver Report: packets lost, jitter, and timing that lets the camera measure the round trip. These travel on the odd ports next to RTP.",
          facts: [["SR", "Type 200, 28 bytes"], ["RR", "Type 201, 32 bytes"], ["Ports", `${RTP_S + 1} → ${RTP_C + 1} and back`]],
          quiz: {
            q: "Why does the Sender Report pair an NTP time with an RTP timestamp?",
            options: ["To encrypt the stream", "So players can sync tracks (like audio and video) to one real clock", "To pick a new codec", "To renew the session"],
            answer: 1,
            why: "Each track’s RTP clock starts at a random number. The SR ties it to real time, so separate audio and video tracks can be lined up.",
          },
          events: [
            pkt("camera", "client", "teal", "RTCP SR", ["Sender Report", "5480 packets sent"], { time: 5.0, info: `Sender Report   SSRC 0x${SSRC.toString(16)}`, packet: build(...fromCam(), udp({ sport: RTP_S + 1, dport: RTP_C + 1 }), rtcpSR) }),
            pkt("client", "camera", "teal", "RTCP RR", ["Receiver Report", "0% lost"], { time: 5.05, info: `Receiver Report   SSRC 0x${RR_SSRC.toString(16)}`, packet: build(...toCam(), udp({ sport: RTP_C + 1, dport: RTP_S + 1 }), rtcpRR) }),
          ],
        },
        {
          title: "TEARDOWN",
          desc: "Stop the stream and free the session",
          detail:
            "When you close VLC it sends TEARDOWN with the Session ID. The camera stops sending RTP and forgets the session. If a client simply vanished, the camera would end the session itself once the 60-second timeout passed without any request.",
          facts: [["CSeq", "6"], ["Session", `${SESSION} closed`], ["Timeout if silent", "60 s"]],
          events: [
            ev("client", "camera", "slate", "TEARDOWN", ["CSeq 6", `Session ${SESSION}`], 120.0, n.req([`TEARDOWN ${STREAM_URL}/ RTSP/1.0`, "CSeq: 6", auth(`${STREAM_URL}/`, GOOD), UA, `Session: ${SESSION}`])),
            ev("camera", "client", "green", "200 OK", ["stream stopped"], 120.003, n.resp(["RTSP/1.0 200 OK", "CSeq: 6", `Session: ${SESSION}`])),
          ],
        },
      ],
      outro: {
        title: "Stream watched and closed",
        text: "RTSP did the talking: OPTIONS, DESCRIBE for the SDP, SETUP for the ports, PLAY, and TEARDOWN. The video travelled beside it as RTP, with big H.264 frames cut into FU-A pieces, and RTCP reported on how well it arrived.",
        facts: [["Control", "TCP 554, CSeq-matched text"], ["Video", `RTP/UDP ${RTP_S} → ${RTP_C}`], ["Reports", "RTCP on the odd ports"], ["Session", "Session ID + timeout"]],
      },
    },
    {
      id: "unauthorized",
      name: "401 Unauthorized on DESCRIBE",
      summary: "The camera demands a login, the first password is wrong, and the danger of default passwords.",
      kind: "failure",
      steps: [
        {
          title: "DESCRIBE without a login",
          desc: "The camera answers 401 with a challenge",
          detail:
            "VLC asks for the stream without credentials. The camera answers 401 Unauthorized and a WWW-Authenticate header with a realm and a random nonce. Digest login means the password itself is never sent, only a hash mixed with this nonce.",
          facts: [["Status", "401 Unauthorized"], ["Scheme", "Digest (MD5)"], ["Nonce", NONCE]],
          quiz: {
            q: "With Digest login, what does VLC send in its next DESCRIBE?",
            options: ["The password in plain text", "A hash of username, password, nonce, method and STREAM_URL", "Nothing, it gives up", "A TLS certificate"],
            answer: 1,
            why: "Digest sends response = MD5 of (username:realm:password) combined with the nonce, method and URI. The camera computes the same and compares.",
          },
          events: [
            ev("client", "camera", "blue", "DESCRIBE", ["CSeq 2", "no login"], 0, f.req([`DESCRIBE ${STREAM_URL} RTSP/1.0`, "CSeq: 2", UA, "Accept: application/sdp"])),
            ev("camera", "client", "red", "401", ["Unauthorized", "Digest challenge"], 0.004, f.resp(["RTSP/1.0 401 Unauthorized", "CSeq: 2", `WWW-Authenticate: Digest realm="IPCam", nonce="${NONCE}"`, "Content-Length: 0"])),
          ],
        },
        {
          title: "Wrong password",
          desc: "The hash doesn’t match: 401 again",
          detail:
            "VLC asks for a password and retries with a Digest answer. The password typed was wrong, so the camera’s own hash comes out different and it answers 401 again. VLC shows a login box. Many cameras lock out or slow down after several wrong tries.",
          facts: [["CSeq", "3"], ["Result", "401 Unauthorized"], ["Password on the wire", "Never, only the hash"]],
          events: [
            ev("client", "camera", "blue", "DESCRIBE", ["CSeq 3", "Digest (wrong)"], 3.2, f.req([`DESCRIBE ${STREAM_URL} RTSP/1.0`, "CSeq: 3", auth(STREAM_URL, BAD), UA, "Accept: application/sdp"])),
            ev("camera", "client", "red", "401", ["hash mismatch"], 3.204, f.resp(["RTSP/1.0 401 Unauthorized", "CSeq: 3", `WWW-Authenticate: Digest realm="IPCam", nonce="${NONCE}"`, "Content-Length: 0"])),
            note("client", "WRONG PASSWORD", "red"),
          ],
        },
        {
          title: "Right password, and a warning",
          desc: "200 OK with the SDP",
          detail:
            "With the correct password the hashes match and the camera sends the SDP. A warning: many cameras ship with default logins like admin/admin or none at all, and bots scan the internet for port 554. Change the password, keep the camera off the public internet (no port forwarding of 554), and use a VPN to watch from outside.",
          facts: [["CSeq", "4"], ["Result", "200 OK + SDP"], ["Security", "Change default credentials; never expose 554"]],
          quiz: {
            q: "Your camera works with admin/admin and the router forwards port 554 to it. What is the risk?",
            options: ["None, RTSP is encrypted", "Anyone scanning the internet can log in and watch the camera", "Only slower video", "The camera will refuse VLC"],
            answer: 1,
            why: "Plain RTSP is unencrypted and bots try default passwords on every open 554 they find. Strong passwords and no public exposure are the fix.",
          },
          events: [
            ev("client", "camera", "blue", "DESCRIBE", ["CSeq 4", "Digest (correct)"], 9.8, f.req([`DESCRIBE ${STREAM_URL} RTSP/1.0`, "CSeq: 4", auth(STREAM_URL, GOOD), UA, "Accept: application/sdp"])),
            ev("camera", "client", "green", "200 OK", ["SDP: H.264"], 9.806, f.resp(describeOk(4), SDP)),
            note("camera", "CHANGE DEFAULT PASSWORDS", "amber"),
          ],
        },
      ],
      outro: {
        title: "Logged in, and a lesson",
        text: "The camera protected its stream with Digest login: a 401 challenge, a hash instead of the password, and 401 again for a wrong one. Login is only as strong as the password, and plain RTSP is not encrypted, so keep cameras on the local network.",
        facts: [["Challenge", "401 + WWW-Authenticate: Digest"], ["Answer", "Authorization: Digest … response=hash"], ["Biggest real risk", "Default passwords + port 554 open to the internet"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Methods",
      items: [["OPTIONS", "Which methods do you support?"], ["DESCRIBE", "Send me the SDP for this stream"], ["SETUP", "Agree on transport and ports, get a Session"], ["PLAY / PAUSE", "Start or pause sending"], ["TEARDOWN", "Stop and free the session"], ["GET_PARAMETER", "Often used as a keep-alive"]],
    },
    {
      title: "Transports",
      items: [["RTP/AVP;unicast;client_port=a-b", "RTP over UDP to ports a (RTP) and b (RTCP)"], ["RTP/AVP/TCP;interleaved=0-1", "RTP inside the RTSP TCP connection, prefixed with $, channel, length"], ["multicast", "One stream for many viewers on a LAN"]],
    },
    {
      title: "Numbers to know",
      items: [["RTSP port", "TCP 554 (322 for RTSPS)"], ["RTP header", "12 bytes, V=2"], ["H.264 clock", "90 000 Hz; 3600 ticks per frame at 25 fps"], ["FU-A", "Indicator type 28; header S=0x80, E=0x40"], ["RTCP types", "200 SR, 201 RR, 202 SDES, 203 BYE"]],
    },
  ],
});
