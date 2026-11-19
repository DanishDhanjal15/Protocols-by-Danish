import { defineLesson, note, pkt, Step } from "@/lib/lesson";
import { build, LayerSpec, proto, textLayer } from "@/lib/packet";
import { eth, ipv4, udp } from "@/lib/proto";
import { text } from "@/lib/bytes";
import { ADDR } from "./_common";

// ------------------------------------------------------------------ addresses and identities

const PH = ADDR.phone; // 192.168.1.23, the softphone
const PBX = "203.0.113.50"; // sip.example.com
const DOMAIN = "example.com";
const ME = "2001"; // Danish's extension
const RAVI = "2002"; // the person being called
const RTP_ME = 40000;
const RTP_PBX = 16384;
const TAG_ME = "a73kszlfl";
const TAG_RAVI = "8d1f0c2e";
const CALL_ID = "3848276298220188511@192.168.1.23";
const REG_ID = "843817637684230@192.168.1.23";
const NONCE = "5f1c2a7be4d0a9c3";
const t = (n: number) => Number(n.toFixed(4));

const up = (id: number) => [eth({ src: ADDR.phoneMac, dst: ADDR.routerMac }), ipv4({ src: PH, dst: PBX, ttl: 64, id })];
const down = (id: number) => [eth({ src: ADDR.routerMac, dst: ADDR.phoneMac }), ipv4({ src: PBX, dst: PH, ttl: 54, id })];
const sigUp = (id: number, ...l: LayerSpec[]) => build(...up(id), udp({ sport: 5060, dport: 5060 }), ...l);
const sigDown = (id: number, ...l: LayerSpec[]) => build(...down(id), udp({ sport: 5060, dport: 5060 }), ...l);

/** A SIP message: headers + Content-Length computed from the real body bytes. */
function sip(lines: string[], body?: string, notes?: Record<number, string>): LayerSpec {
  const len = body ? text(body).length : 0;
  return textLayer({
    id: "sip",
    name: "SIP",
    lines: [...lines, `Content-Length: ${len}`],
    blankLine: true,
    body: body ? { text: body, what: "SDP body", note: "Session Description Protocol: what media this side can send and where to send it." } : undefined,
    notes,
    summary: `Session Initiation Protocol: ${lines[0]}`,
  });
}

const sdp = (o: { origin: string; ip: string; port: number; sess: number }) =>
  [
    "v=0",
    `o=${o.origin} ${o.sess} ${o.sess} IN IP4 ${o.ip}`,
    "s=call",
    `c=IN IP4 ${o.ip}`,
    "t=0 0",
    `m=audio ${o.port} RTP/AVP 0 101`,
    "a=rtpmap:0 PCMU/8000",
    "a=rtpmap:101 telephone-event/8000",
    "a=ptime:20",
    "a=sendrecv",
    "",
  ].join("\r\n");
const OFFER = sdp({ origin: ME, ip: PH, port: RTP_ME, sess: 1789 });
const ANSWER = sdp({ origin: "pbx", ip: PBX, port: RTP_PBX, sess: 4021 });

// ------------------------------------------------------------------ messages

const regLines = (cseq: number, branch: string, auth?: boolean) => [
  `REGISTER sip:${DOMAIN} SIP/2.0`,
  `Via: SIP/2.0/UDP ${PH}:5060;branch=z9hG4bK${branch};rport`,
  "Max-Forwards: 70",
  `From: <sip:${ME}@${DOMAIN}>;tag=r${TAG_ME}`,
  `To: <sip:${ME}@${DOMAIN}>`,
  `Call-ID: ${REG_ID}`,
  `CSeq: ${cseq} REGISTER`,
  `Contact: <sip:${ME}@${PH}:5060>`,
  ...(auth
    ? [`Authorization: Digest username="${ME}", realm="${DOMAIN}", nonce="${NONCE}", uri="sip:${DOMAIN}", response="b9e3d8f40c2a71e6a5d0f3c8e17b2a94", algorithm=MD5`]
    : []),
  "Expires: 3600",
  "User-Agent: Softphone/5.2",
];

const viaInv = `Via: SIP/2.0/UDP ${PH}:5060;branch=z9hG4bK776asdhds;rport`;
const fromMe = `From: "Danish" <sip:${ME}@${DOMAIN}>;tag=${TAG_ME}`;
const toRavi = `To: <sip:${RAVI}@${DOMAIN}>`;
const toRaviTag = `${toRavi};tag=${TAG_RAVI}`;

const invite = (cseq: number) =>
  sip(
    [
      `INVITE sip:${RAVI}@${DOMAIN} SIP/2.0`,
      viaInv,
      "Max-Forwards: 70",
      fromMe,
      toRavi,
      `Call-ID: ${CALL_ID}`,
      `CSeq: ${cseq} INVITE`,
      `Contact: <sip:${ME}@${PH}:5060>`,
      "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS",
      "Content-Type: application/sdp",
    ],
    OFFER,
    { 0: "The method and who to call (Request-URI).", 6: "Call-ID: one value for the whole call, so every message can be matched to it." }
  );

const resp = (status: string, cseq: string, toTag: boolean, extra: string[] = [], body?: string) =>
  sip([`SIP/2.0 ${status}`, `${viaInv};received=${ADDR.routerWan}`, fromMe, toTag ? toRaviTag : toRavi, `Call-ID: ${CALL_ID}`, `CSeq: ${cseq}`, ...extra], body);

// ------------------------------------------------------------------ RTP

function rtp(o: { seq: number; ts: number; ssrc: number; marker?: boolean; seed: number }): LayerSpec {
  const b1 = (o.marker ? 0x80 : 0) | 0; // PT 0 = PCMU
  return proto({
    id: "rtp",
    name: "RTP",
    osi: 7,
    summary: `Real-Time Transport Protocol, PT=ITU-T G.711 PCMU, SSRC=0x${o.ssrc.toString(16).toUpperCase()}, Seq=${o.seq}, Time=${o.ts}${o.marker ? ", Mark" : ""}`,
    fields: [
      { name: "V, P, X, CC", u8: 0x80, value: "Version 2, no padding, no extension, 0 CSRC", note: "0x80: RTP version 2 and nothing optional." },
      { name: "Marker, payload type", u8: b1, value: `${o.marker ? "M=1, " : "M=0, "}PT 0 (PCMU)`, note: o.marker ? "Marker set on the first packet of a talk spurt." : "Payload type 0 means G.711 μ-law audio at 8000 samples per second." },
      { name: "Sequence number", u16: o.seq, note: "Goes up by 1 per packet, so loss and reordering can be spotted." },
      { name: "Timestamp", u32: o.ts, note: "Counts audio samples. Goes up by 160 per packet (20 ms at 8 kHz)." },
      { name: "SSRC", u32: o.ssrc, value: `0x${o.ssrc.toString(16).padStart(8, "0")}`, note: "Random ID of this audio source." },
      { name: "Payload (G.711 μ-law)", random: 160, seed: o.seed, value: "160 bytes = 20 ms of audio", opaque: true, note: "One byte per sample. Plain RTP is NOT encrypted: anyone on the path could replay this as sound." },
    ],
  });
}
const SSRC_ME = 0x5a3e91c4;
const SSRC_PBX = 0x1d07b2e8;
const rtpUp = (seq: number, ts: number, id: number, marker = false) =>
  build(...up(id), udp({ sport: RTP_ME, dport: RTP_PBX }), rtp({ seq, ts, ssrc: SSRC_ME, marker, seed: seq }));
const rtpDown = (seq: number, ts: number, id: number, marker = false) =>
  build(...down(id), udp({ sport: RTP_PBX, dport: RTP_ME }), rtp({ seq, ts, ssrc: SSRC_PBX, marker, seed: seq + 7 }));

// ------------------------------------------------------------------ shared events

const inviteAndTrying = (base: number): Step["events"] => [
  pkt("client", "pbx", "amber", "INVITE", [`call ${RAVI}`, "SDP: PCMU, port 40000"], {
    time: t(base), info: `Request: INVITE sip:${RAVI}@${DOMAIN} | SDP (PCMU)`,
    packet: sigUp(0x2a10, invite(1)),
  }),
  pkt("pbx", "client", "blue", "100", ["Trying"], {
    time: t(base + 0.031), info: "Status: 100 Trying",
    packet: sigDown(0x7101, resp("100 Trying", "1 INVITE", false)),
  }),
];

// ------------------------------------------------------------------ devices

const devices = [
  { id: "client", kind: "phone" as const, label: "Danish’s phone", sub: `${PH} · ext ${ME}`, x: 8, y: 64 },
  { id: "router", kind: "router" as const, label: "Home router", sub: ADDR.routerWan, x: 28, y: 64 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 50, y: 34 },
  { id: "pbx", kind: "phonepbx" as const, label: "SIP server", sub: `${PBX}`, x: 72, y: 64 },
  { id: "callee", kind: "phone" as const, label: "Ravi’s desk phone", sub: `ext ${RAVI}`, x: 92, y: 40 },
];
const links: [string, string][] = [
  ["client", "router"],
  ["router", "internet"],
  ["internet", "pbx"],
  ["pbx", "callee"],
];

export default defineLesson({
  id: "sip",
  name: "SIP",
  full: "Session Initiation Protocol",
  group: "realtime",
  layer: 7,
  difficulty: 2,
  tagline: "How internet phone calls ring, connect and hang up.",
  description:
    "SIP is the signalling protocol behind most VoIP phones and office phone systems. It registers your phone, rings the other side and agrees on audio settings with SDP. The voice itself travels separately in RTP packets, usually 50 per second in each direction.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "UDP or TCP 5060, TLS 5061"],
    ["Style", "Text, like HTTP"],
    ["Media", "RTP (separate UDP ports)"],
    ["Defined in", "RFC 3261"],
  ],
  ports: "5060 (UDP/TCP), 5061 (TLS); RTP on even UDP ports",
  rfc: "RFC 3261, RFC 4566 (SDP), RFC 3550 (RTP)",
  keywords: ["voip", "sip", "invite", "register", "rtp", "sdp", "g.711", "pcmu", "ringing", "bye", "pbx", "digest", "busy"],
  related: ["rtp", "webrtc", "udp", "stun", "rtsp"],
  devices,
  links,
  legend: [
    ["amber", "Requests from the phone"],
    ["violet", "Voice (RTP)"],
    ["blue", "Progress replies (1xx) and challenges"],
    ["green", "Success (2xx) and ACK"],
    ["slate", "Hanging up"],
    ["red", "Errors"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Register and make a call",
      summary: "The phone logs in to the SIP server, calls extension 2002, talks in G.711 audio and hangs up.",
      kind: "normal",
      steps: [
        {
          title: "Register, get challenged",
          desc: "REGISTER, then 401 Unauthorized",
          detail:
            "When the phone starts, it tells the SIP server where extension 2001 can be reached with a REGISTER. The server doesn’t take its word for it and answers 401 Unauthorized with a digest challenge: a realm and a random nonce the phone must use in its proof.",
          facts: [["Server", `${PBX}:5060 (UDP)`], ["Reply", "401 + WWW-Authenticate"], ["Nonce", NONCE]],
          quiz: {
            q: "The phone’s first REGISTER has no password proof. What does the server reply?",
            options: ["200 OK", "401 Unauthorized with a challenge", "404 Not Found", "Nothing"],
            answer: 1,
            why: "SIP digest auth works like HTTP: the first try is answered with 401 and a nonce, then the client retries with a hash.",
          },
          events: [
            pkt("client", "pbx", "amber", "REGISTER", [`ext ${ME}`, "no credentials"], {
              time: 0, info: `Request: REGISTER sip:${DOMAIN}`,
              packet: sigUp(0x2a01, sip(regLines(1, "a1b2c3"))),
            }),
            pkt("pbx", "client", "blue", "401", ["Unauthorized", "here’s a nonce"], {
              time: 0.031, info: "Status: 401 Unauthorized",
              packet: sigDown(0x70f1, sip([
                "SIP/2.0 401 Unauthorized",
                `Via: SIP/2.0/UDP ${PH}:5060;branch=z9hG4bKa1b2c3;rport=5060;received=${ADDR.routerWan}`,
                `From: <sip:${ME}@${DOMAIN}>;tag=r${TAG_ME}`,
                `To: <sip:${ME}@${DOMAIN}>;tag=as1f0d`,
                `Call-ID: ${REG_ID}`,
                "CSeq: 1 REGISTER",
                `WWW-Authenticate: Digest realm="${DOMAIN}", nonce="${NONCE}", algorithm=MD5, qop="auth"`,
              ])),
            }),
          ],
        },
        {
          title: "Register with proof",
          desc: "Digest response, then 200 OK",
          detail:
            "The phone sends REGISTER again with an Authorization header. Its response value is an MD5 hash of the username, realm, password, nonce and request, so the password never travels. The server checks the hash and replies 200 OK: calls for 2001 will now be sent to this phone for an hour.",
          facts: [["CSeq", "2 (new request)"], ["Proof", "MD5 digest"], ["Expires", "3600 s"]],
          events: [
            pkt("client", "pbx", "amber", "REGISTER", ["with digest", "CSeq 2"], {
              time: 0.033, info: `Request: REGISTER sip:${DOMAIN} (with Authorization)`,
              packet: sigUp(0x2a02, sip(regLines(2, "d4e5f6", true))),
            }),
            pkt("pbx", "client", "green", "200 OK", ["registered", "for 3600 s"], {
              time: 0.064, info: "Status: 200 OK (REGISTER)",
              packet: sigDown(0x70f2, sip([
                "SIP/2.0 200 OK",
                `Via: SIP/2.0/UDP ${PH}:5060;branch=z9hG4bKd4e5f6;rport=5060;received=${ADDR.routerWan}`,
                `From: <sip:${ME}@${DOMAIN}>;tag=r${TAG_ME}`,
                `To: <sip:${ME}@${DOMAIN}>;tag=as1f0d`,
                `Call-ID: ${REG_ID}`,
                "CSeq: 2 REGISTER",
                `Contact: <sip:${ME}@${PH}:5060>;expires=3600`,
              ])),
            }),
            note("client", "REGISTERED", "green"),
          ],
        },
        {
          title: "Place the call",
          desc: "INVITE with an SDP offer",
          detail:
            "Danish dials 2002. The phone sends an INVITE whose body is SDP: it offers G.711 μ-law (PCMU) audio and says “send my audio to 192.168.1.23 port 40000”. The server replies 100 Trying straight away, which only means “got it, stop resending”.",
          facts: [["Codec offered", "PCMU (PT 0), 8 kHz"], ["Audio port", String(RTP_ME)], ["Body", `${text(OFFER).length} bytes of SDP`]],
          quiz: {
            q: "What does 100 Trying tell the phone?",
            options: ["Ravi’s phone is ringing", "The call is answered", "The server got the INVITE, so stop retransmitting it", "The number is busy"],
            answer: 2,
            why: "Over UDP the phone would resend the INVITE after 500 ms. 100 Trying is a hop-by-hop receipt; ringing is 180.",
          },
          events: inviteAndTrying(5),
        },
        {
          title: "It rings",
          desc: "180 Ringing comes back",
          detail:
            "The server forwards the INVITE to Ravi’s desk phone, which starts ringing and answers 180 Ringing. The server passes it back. Danish’s phone now plays the ringback tone itself. The To header gains a tag, which marks the start of a dialog between the two phones.",
          facts: [["Status", "180 Ringing"], ["To tag", TAG_RAVI], ["Ringback", "Played locally"]],
          events: [
            note("callee", "RING RING", "blue"),
            pkt("pbx", "client", "blue", "180", ["Ringing"], {
              time: 5.12, info: "Status: 180 Ringing",
              packet: sigDown(0x7102, resp("180 Ringing", "1 INVITE", true, [`Contact: <sip:${RAVI}@${PBX}:5060>`])),
            }),
          ],
        },
        {
          title: "Answered",
          desc: "200 OK with the SDP answer, then ACK",
          detail:
            "Ravi picks up. The 200 OK carries the SDP answer: PCMU is fine, send audio to the server at port 16384. Danish’s phone confirms with ACK, completing a three-way handshake (INVITE, 200, ACK). From now on the dialog is established.",
          facts: [["Codec agreed", "PCMU"], ["Media to", `${PBX}:${RTP_PBX}`], ["Handshake", "INVITE → 200 OK → ACK"]],
          quiz: {
            q: "Why does SIP need an ACK after 200 OK?",
            options: ["To start ringing", "So the callee knows the caller got the answer and can stop resending 200 OK", "To send the password", "It doesn’t; ACK is optional"],
            answer: 1,
            why: "Over UDP the 200 OK might be lost. The callee keeps resending it until the ACK arrives.",
          },
          events: [
            note("callee", "PICKED UP", "green"),
            pkt("pbx", "client", "green", "200 OK", ["answered", `SDP: port ${RTP_PBX}`], {
              time: 9.4, info: "Status: 200 OK (INVITE) | SDP (PCMU)",
              packet: sigDown(0x7103, resp("200 OK", "1 INVITE", true, [`Contact: <sip:${RAVI}@${PBX}:5060>`, "Content-Type: application/sdp"], ANSWER)),
            }),
            pkt("client", "pbx", "green", "ACK", ["got it"], {
              time: 9.401, info: `Request: ACK sip:${RAVI}@${PBX}:5060`,
              packet: sigUp(0x2a11, sip([
                `ACK sip:${RAVI}@${PBX}:5060 SIP/2.0`,
                `Via: SIP/2.0/UDP ${PH}:5060;branch=z9hG4bK9ff21c;rport`,
                "Max-Forwards: 70",
                fromMe,
                toRaviTag,
                `Call-ID: ${CALL_ID}`,
                "CSeq: 1 ACK",
              ])),
            }),
          ],
        },
        {
          title: "Talk",
          desc: "RTP voice packets every 20 ms",
          detail:
            "Voice now flows in RTP over UDP, outside SIP. Each packet carries 20 ms of sound: 160 G.711 samples of one byte each, so the timestamp rises by 160 and the sequence number by 1. The phone sits behind NAT and wrote its private address in SDP; the server simply sends audio back to the address the packets come from (symmetric RTP).",
          facts: [["Packet rate", "50 per second each way"], ["Payload", "160 bytes (20 ms)"], ["Bit rate", "64 kbit/s audio, about 87 kbit/s with headers"]],
          quiz: {
            q: "The first RTP packet has timestamp 8000. What is the timestamp of the next one?",
            options: ["8001", "8020", "8160", "8320"],
            answer: 2,
            why: "The timestamp counts samples. 20 ms at 8000 samples per second is 160 samples.",
          },
          events: [
            pkt("client", "pbx", "violet", "RTP", ["seq 3101", "20 ms voice"], {
              time: 9.42, info: `PT=ITU-T G.711 PCMU, SSRC=0x${SSRC_ME.toString(16).toUpperCase()}, Seq=3101, Time=8000, Mark`,
              packet: rtpUp(3101, 8000, 0x2a20, true),
            }),
            pkt("pbx", "client", "violet", "RTP", ["seq 17", "20 ms voice"], {
              time: 9.43, info: `PT=ITU-T G.711 PCMU, SSRC=0x${SSRC_PBX.toString(16).toUpperCase()}, Seq=17, Time=160, Mark`,
              packet: rtpDown(17, 160, 0x7201, true),
            }),
            pkt("client", "pbx", "violet", "RTP", ["seq 3102", "+160 samples"], {
              time: 9.44, info: `PT=ITU-T G.711 PCMU, SSRC=0x${SSRC_ME.toString(16).toUpperCase()}, Seq=3102, Time=8160`,
              packet: rtpUp(3102, 8160, 0x2a21),
            }),
            pkt("pbx", "client", "violet", "RTP", ["seq 18", "+160 samples"], {
              time: 9.45, info: `PT=ITU-T G.711 PCMU, SSRC=0x${SSRC_PBX.toString(16).toUpperCase()}, Seq=18, Time=320`,
              packet: rtpDown(18, 320, 0x7202),
            }),
          ],
        },
        {
          title: "Hang up",
          desc: "BYE, then 200 OK",
          detail:
            "Danish ends the call. His phone sends BYE inside the same dialog (same Call-ID and tags) and the other side answers 200 OK. Both phones stop sending RTP. Note that BYE needs no ACK: only INVITE uses the three-way handshake.",
          facts: [["Request", "BYE (CSeq 2)"], ["Reply", "200 OK"], ["Call length", "About 3 minutes"]],
          events: [
            pkt("client", "pbx", "slate", "BYE", ["hanging up"], {
              time: 190, info: `Request: BYE sip:${RAVI}@${PBX}:5060`,
              packet: sigUp(0x2b40, sip([
                `BYE sip:${RAVI}@${PBX}:5060 SIP/2.0`,
                `Via: SIP/2.0/UDP ${PH}:5060;branch=z9hG4bK31a7e0;rport`,
                "Max-Forwards: 70",
                fromMe,
                toRaviTag,
                `Call-ID: ${CALL_ID}`,
                "CSeq: 2 BYE",
              ])),
            }),
            pkt("pbx", "client", "green", "200 OK", ["bye"], {
              time: 190.031, info: "Status: 200 OK (BYE)",
              packet: sigDown(0x7340, sip([
                "SIP/2.0 200 OK",
                `Via: SIP/2.0/UDP ${PH}:5060;branch=z9hG4bK31a7e0;rport=5060;received=${ADDR.routerWan}`,
                fromMe,
                toRaviTag,
                `Call-ID: ${CALL_ID}`,
                "CSeq: 2 BYE",
              ])),
            }),
            note("callee", "CALL ENDED", "blue"),
          ],
        },
      ],
      outro: {
        title: "Call complete",
        text: "SIP did the paperwork: it registered the phone, rang the other side, agreed a codec with SDP and closed the call. The voice itself went in RTP packets, 160 bytes every 20 ms, on separate UDP ports. Plain RTP is readable by anyone on the path, which is why many providers use SIP over TLS with SRTP.",
        facts: [["Signalling", "SIP over UDP 5060"], ["Media", "RTP, G.711 PCMU"], ["Audio per packet", "20 ms / 160 bytes"], ["Secure version", "SIPS (TLS 5061) + SRTP"]],
      },
    },
    {
      id: "busy",
      name: "The other phone is busy",
      summary: "Ravi is already on a call, so the INVITE is refused with 486 Busy Here.",
      kind: "failure",
      steps: [
        {
          title: "Place the call",
          desc: "INVITE and 100 Trying as usual",
          detail: "The phone is already registered, so it sends the same INVITE with an SDP offer, and the server confirms it with 100 Trying.",
          facts: [["Calling", `ext ${RAVI}`], ["Codec offered", "PCMU"], ["Reply so far", "100 Trying"]],
          events: inviteAndTrying(0),
        },
        {
          title: "Busy Here",
          desc: "486, then ACK",
          detail:
            "Ravi’s phone is already on another call and has no free line, so it answers 486 Busy Here. Danish’s phone plays a busy tone. Even a failure response to INVITE must be acknowledged with ACK, so the server stops resending the 486.",
          facts: [["Status", "486 Busy Here"], ["Class", "4xx: client-side failure"], ["Still needs", "ACK"]],
          quiz: {
            q: "After 486 Busy Here, what does the caller’s phone send?",
            options: ["BYE", "ACK", "CANCEL", "Nothing"],
            answer: 1,
            why: "Every final response to INVITE, success or failure, is acknowledged with ACK. BYE is only for calls that were answered.",
          },
          events: [
            note("callee", "ALREADY ON A CALL", "amber"),
            pkt("pbx", "client", "red", "486", ["Busy Here"], {
              time: 0.09, info: "Status: 486 Busy Here",
              packet: sigDown(0x7104, resp("486 Busy Here", "1 INVITE", true)),
            }),
            pkt("client", "pbx", "green", "ACK", ["ok, understood"], {
              time: 0.091, info: `Request: ACK sip:${RAVI}@${DOMAIN}`,
              packet: sigUp(0x2a12, sip([
                `ACK sip:${RAVI}@${DOMAIN} SIP/2.0`,
                viaInv,
                "Max-Forwards: 70",
                fromMe,
                toRaviTag,
                `Call-ID: ${CALL_ID}`,
                "CSeq: 1 ACK",
              ])),
            }),
            note("client", "BUSY TONE", "red"),
          ],
        },
      ],
      outro: {
        title: "Call refused, cleanly",
        text: "A busy callee answers 486 Busy Here and the caller acknowledges it with ACK, reusing the INVITE’s branch because the ACK for a failure belongs to the same transaction. No RTP is ever sent. A server might instead forward the call to voicemail.",
        facts: [["Packets", "4"], ["Final status", "486 Busy Here"], ["Media sent", "None"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Requests",
      items: [["REGISTER", "Tell the server where I am"], ["INVITE", "Start a call (with SDP offer)"], ["ACK", "Confirm a final reply to INVITE"], ["BYE", "End an answered call"], ["CANCEL", "Stop a call that hasn’t been answered"], ["OPTIONS", "Ask what the other side supports"]],
    },
    {
      title: "Responses",
      items: [["100 Trying", "Got it, working on it"], ["180 Ringing", "The phone is ringing"], ["200 OK", "Success"], ["401 / 407", "Prove who you are (digest)"], ["486 Busy Here", "Callee is busy"], ["404 / 408 / 603", "Not found / timeout / declined"]],
    },
    {
      title: "Numbers to know",
      items: [["SIP ports", "5060 UDP/TCP, 5061 TLS"], ["G.711", "8000 samples/s, 1 byte each, 64 kbit/s"], ["Per RTP packet", "20 ms, 160 bytes, timestamp +160"], ["RTP header", "12 bytes (V=2)"]],
    },
  ],
});
