import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { text } from "@/lib/bytes";
import { eth, ext, hsMsg, ipv4, tcp, TcpOpt, tls, udp, vec } from "@/lib/proto";

// ---------------------------------------------------------------- addresses

const FW = "192.168.50.1";
const LOG = "192.168.50.20";
const FW_MAC = "00:90:0b:5c:aa:01";
const LOG_MAC = "00:50:56:b2:00:20";

const fwToLog = (id: number) => [eth({ src: FW_MAC, dst: LOG_MAC }), ipv4({ src: FW, dst: LOG, ttl: 64, id, df: false })];
const logToFw = (id: number) => [eth({ src: LOG_MAC, dst: FW_MAC }), ipv4({ src: LOG, dst: FW, ttl: 64, id })];

// ---------------------------------------------------------------- RFC 5424 message builder

interface SyslogMsg {
  pri: number;
  ts: string;
  host: string;
  app: string;
  procid: string;
  msgid: string;
  sd: string;
  msg: string;
}

const line = (m: SyslogMsg) => `<${m.pri}>1 ${m.ts} ${m.host} ${m.app} ${m.procid} ${m.msgid} ${m.sd} ${m.msg}`;

function syslogFields(m: SyslogMsg): FieldSpec[] {
  const fac = m.pri >> 3, sev = m.pri & 7;
  return [
    { name: "PRI", text: `<${m.pri}>`, value: `<${m.pri}> = facility ${fac} (local${fac - 16}) × 8 + severity ${sev} (${SEV[sev]})`, note: "Priority: facility (which part of the system) times 8, plus severity (0 emergency … 7 debug)." },
    { name: "Version", text: "1 ", value: "1", note: "RFC 5424 format. The older BSD format (RFC 3164) has no version number." },
    { name: "Timestamp", text: `${m.ts} `, value: m.ts, note: "Full date, time with fractions, and time zone (Z = UTC). The old format had no year and no zone." },
    { name: "Hostname", text: `${m.host} `, value: m.host },
    { name: "App name", text: `${m.app} `, value: m.app, note: "Which program on the device wrote the message." },
    { name: "Process ID", text: `${m.procid} `, value: m.procid },
    { name: "Message ID", text: `${m.msgid} `, value: m.msgid, note: "A short type label that makes filtering easy." },
    { name: "Structured data", text: `${m.sd} `, value: m.sd, note: "Machine-readable key=value pairs in [ID@enterprise …] blocks. 32473 is the example enterprise number reserved for documentation." },
    { name: "Message", text: m.msg, value: m.msg, note: "Free text for humans." },
  ];
}

const SEV = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"];

const syslogUdp = (m: SyslogMsg) => proto({ id: "syslog", name: "Syslog", summary: `Syslog ${m.app}: ${m.msg}`, fields: syslogFields(m) });

const deny = (n: number, ip: string, port: number, ms: number): SyslogMsg => ({
  pri: 134,
  ts: `2026-11-19T10:15:02.${String(ms).padStart(3, "0")}Z`,
  host: "fw01.example.com",
  app: "filterlog",
  procid: "2417",
  msgid: "FW_DENY",
  sd: `[meta@32473 src="${ip}" dst="198.51.100.7" dport="${port}" proto="tcp"]`,
  msg: `Blocked inbound TCP to port ${port} (rule ${n})`,
});

const M1 = deny(12, "203.0.113.77", 23, 123);
const M2: SyslogMsg = {
  pri: 132,
  ts: "2026-11-19T10:15:07.481Z",
  host: "fw01.example.com",
  app: "sshd",
  procid: "3302",
  msgid: "AUTH_FAIL",
  sd: `[meta@32473 user="admin" src="203.0.113.77"]`,
  msg: "Failed password for admin",
};
const M3: SyslogMsg = {
  pri: 133,
  ts: "2026-11-19T10:15:09.002Z",
  host: "fw01.example.com",
  app: "configd",
  procid: "880",
  msgid: "CFG_CHANGE",
  sd: `[meta@32473 user="danish"]`,
  msg: "Rule 12 edited",
};
const octetFrame = (m: SyslogMsg) => `${text(line(m)).length} ${line(m)}`;

// ---------------------------------------------------------------- tiny TCP conversation helper

const FLAG_TXT: Record<string, string> = { S: "SYN", A: "ACK", P: "PSH", F: "FIN", R: "RST" };
function conv(o: { cHdr: (id: number) => LayerSpec[]; sHdr: (id: number) => LayerSpec[]; sport: number; dport: number; cBase: number; sBase: number }) {
  let cs = 0, ss = 0, idC = 0x3a10, idS = 0;
  const go = (fromClient: boolean, flags: string, payload?: LayerSpec, opts?: TcpOpt[]) => {
    const len = payload ? build(payload).bytes.length : 0;
    const seq = fromClient ? cs : ss;
    const ack = fromClient ? ss : cs;
    const hasA = flags.includes("A");
    const sport = fromClient ? o.sport : o.dport, dport = fromClient ? o.dport : o.sport;
    const packet = build(
      ...(fromClient ? o.cHdr(idC++) : o.sHdr(idS++)),
      tcp({ sport, dport, seq, ack: hasA ? ack : undefined, flags, win: flags.includes("S") ? 64240 : 502, opts, seqBase: fromClient ? o.cBase : o.sBase, ackBase: hasA ? (fromClient ? o.sBase : o.cBase) : undefined }),
      ...(payload ? [payload] : [])
    );
    const bump = len + (flags.includes("S") || flags.includes("F") ? 1 : 0);
    if (fromClient) cs += bump; else ss += bump;
    const names = ["F", "S", "R", "P", "A"].filter((f) => flags.includes(f)).map((f) => FLAG_TXT[f]).join(", ");
    const info = `${sport} → ${dport} [${names}] Seq=${seq}${hasA ? ` Ack=${ack}` : ""} Len=${len}`;
    return { packet, info, len };
  };
  return { c: (f: string, p?: LayerSpec, opts?: TcpOpt[]) => go(true, f, p, opts), s: (f: string, p?: LayerSpec, opts?: TcpOpt[]) => go(false, f, p, opts) };
}

// ---------------------------------------------------------------- TLS 1.3 handshake records

function clientHello(sni: string, seed: number): LayerSpec {
  const name = text(sni);
  return tls({
    records: [{
      type: "handshake",
      version: 0x0301,
      fields: [hsMsg("client_hello", "Client Hello", [
        { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "Frozen for compatibility; the real version is in supported_versions." },
        { name: "Random", random: 32, seed, opaque: true },
        vec("Session ID", 1, [{ name: "Legacy session ID", random: 32, seed: seed + 1 }]),
        vec("Cipher suites", 2, [
          { name: "TLS_AES_128_GCM_SHA256", u16: 0x1301, value: "0x1301" },
          { name: "TLS_AES_256_GCM_SHA384", u16: 0x1302, value: "0x1302" },
          { name: "TLS_CHACHA20_POLY1305_SHA256", u16: 0x1303, value: "0x1303" },
        ], "3 suites"),
        vec("Compression methods", 1, [{ name: "null", u8: 0 }], "null"),
        vec("Extensions", 2, [
          ext(0, "server_name", [vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name" }, vec("Host name", 2, [{ name: "Name", bytes: name, value: sni }], sni)], sni)], sni, "SNI: which site the client wants. Sent in clear text."),
          ext(10, "supported_groups", [vec("Groups", 2, [{ name: "x25519", u16: 0x001d, value: "x25519" }], "x25519")], "x25519"),
          ext(13, "signature_algorithms", [vec("Algorithms", 2, [{ name: "ecdsa_secp256r1_sha256", u16: 0x0403 }, { name: "rsa_pss_rsae_sha256", u16: 0x0804 }, { name: "rsa_pkcs1_sha256", u16: 0x0401 }], "3 algorithms")], "3 algorithms"),
          ext(43, "supported_versions", [vec("Versions", 1, [{ name: "TLS 1.3", u16: 0x0304, value: "0x0304" }], "TLS 1.3")], "TLS 1.3"),
          ext(51, "key_share", [vec("Client shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 2, opaque: true }], "32 bytes")], "x25519 key")], "x25519 key", "The client’s half of the key exchange."),
        ], "5 extensions"),
      ])],
    }],
  });
}

function serverFlight(seed: number, encLen: number): LayerSpec {
  return tls({
    records: [
      {
        type: "handshake",
        fields: [hsMsg("server_hello", "Server Hello", [
          { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
          { name: "Random", random: 32, seed, opaque: true },
          vec("Session ID", 1, [{ name: "Echoed session ID", random: 32, seed: seed - 99 }]),
          { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256" },
          { name: "Compression", u8: 0, value: "null" },
          vec("Extensions", 2, [
            ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3" }], "TLS 1.3"),
            ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 1, opaque: true }], "32 bytes")], "x25519 key"),
          ], "2 extensions"),
        ])],
      },
      { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1, note: "A dummy message kept for middleboxes; TLS 1.3 ignores it." }] },
      { type: "appdata", encrypted: encLen, what: "Encrypted handshake: EncryptedExtensions, Certificate, CertificateVerify, Finished" },
    ],
  });
}

const clientFinished = tls({
  records: [
    { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] },
    { type: "appdata", encrypted: 53, what: "Encrypted Finished (+ client certificate, if asked)" },
  ],
});

const appData = (n: number, what: string) => tls({ records: [{ type: "appdata", encrypted: n, what }] });
// TLS 1.3 record: plaintext + 1 byte inner content type + 16-byte AEAD tag
const encLenOf = (s: string) => text(s).length + 17;

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "internet", kind: "cloud", label: "Internet", sub: "scanners knocking", x: 10, y: 30 },
  { id: "fw", kind: "firewall", label: "Firewall fw01", sub: FW, x: 34, y: 62 },
  { id: "switch", kind: "switch", label: "Switch", x: 60, y: 62 },
  { id: "log", kind: "server", label: "Log server", sub: LOG, x: 88, y: 62 },
];
const links: [string, string][] = [["internet", "fw"], ["fw", "switch"], ["switch", "log"]];

const TLS_PORT = 6514;
const C = conv({ cHdr: fwToLog, sHdr: logToFw, sport: 40522, dport: TLS_PORT, cBase: 0x71c2a000, sBase: 0x0de4b000 });
const synOpts: TcpOpt[] = [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }];
const p = {
  syn: C.c("S", undefined, synOpts),
  synack: C.s("SA", undefined, synOpts),
  ack: C.c("A"),
  ch: C.c("PA", clientHello("logs.example.com", 501)),
  sf: C.s("PA", serverFlight(601, 1180)),
  cf: C.c("PA", clientFinished),
  d1: C.c("PA", appData(encLenOf(octetFrame(M1)), "Encrypted syslog frame (octet-counted)")),
  a1: C.s("A"),
  d2: C.c("PA", tls({ records: [
    { type: "appdata", encrypted: encLenOf(octetFrame(M2)), what: "Encrypted syslog frame 2" },
    { type: "appdata", encrypted: encLenOf(octetFrame(M3)), what: "Encrypted syslog frame 3" },
  ] })),
  a2: C.s("A"),
};

// ---------------------------------------------------------------- RELP (what-if)

const RELP_PORT = 2514;
const R = conv({ cHdr: fwToLog, sHdr: logToFw, sport: 40610, dport: RELP_PORT, cBase: 0x22b40000, sBase: 0x5d0e0000 });
function relpFrame(txnr: number, cmd: string, data: string, what: string): LayerSpec {
  const len = text(data).length;
  return proto({
    id: "relp",
    name: "RELP",
    summary: `RELP ${txnr} ${cmd} ${len}`,
    fields: [
      { name: "Transaction number", text: `${txnr} `, value: String(txnr), note: "Counts up per frame; the reply quotes it back." },
      { name: "Command", text: `${cmd} `, value: cmd },
      { name: "Data length", text: `${len}${len ? " " : ""}`, value: String(len) },
      ...(len ? [{ name: what, text: data, value: data.length > 60 ? `${data.slice(0, 57)}…` : data }] : []),
      { name: "Trailer", text: "\n", value: "\\n", note: "Every RELP frame ends with a line feed." },
    ],
  });
}
const rp = {
  syn: R.c("S", undefined, synOpts),
  synack: R.s("SA", undefined, synOpts),
  ack: R.c("A"),
  send: R.c("PA", relpFrame(7, "syslog", line(M2), "Syslog message")),
  rsp: R.s("PA", relpFrame(7, "rsp", "200 OK", "Response")),
};

const burst = [24, 25, 80, 110, 139, 443, 445, 3389].map((port, i) => deny(12, `203.0.113.${100 + i}`, port, 500 + i));

export default defineLesson({
  id: "syslog",
  name: "Syslog",
  full: "Syslog Protocol (RFC 5424)",
  group: "iot",
  layer: 7,
  difficulty: 1,
  tagline: "How firewalls, routers and servers ship their logs to one place.",
  description:
    "Syslog is the common format and transport for log messages. A device writes a line with a priority, a timestamp, its name and a message, and sends it to a central log server. The classic transport is UDP port 514; important logs travel over TLS on port 6514, framed so the receiver knows where each message ends.",
  facts: [
    ["Layer", "Application"],
    ["Transports", "UDP 514, TCP/TLS 6514"],
    ["Format", "RFC 5424 (old style RFC 3164)"],
    ["Priority", "facility × 8 + severity"],
    ["TLS framing", "Octet counting (RFC 5425)"],
    ["Reliable option", "RELP (acknowledged)"],
  ],
  ports: "UDP 514, TLS 6514",
  rfc: "RFC 5424, RFC 5425, RFC 5426",
  keywords: ["logs", "logging", "siem", "pri", "facility", "severity", "rfc 5424", "rfc 5425", "tls", "6514", "relp", "rsyslog", "udp 514"],
  related: ["snmp", "tls", "udp", "tcp"],
  devices,
  links,
  legend: [
    ["amber", "Log messages"],
    ["green", "TCP handshake and ACKs"],
    ["teal", "TLS (encrypted)"],
    ["red", "Lost logs or blocked traffic"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A firewall logs a blocked connection",
      summary: "The firewall sends a log line over UDP 514, then the same kind of logs over TLS 6514 with octet counting.",
      kind: "normal",
      steps: [
        {
          title: "Something worth logging",
          desc: "A scanner knocks on port 23",
          detail:
            "A machine on the internet tries to open a Telnet connection (port 23) to the office. The firewall’s rule 12 blocks it. The firewall keeps no long history itself, so it turns the event into a syslog line and sends it to the central log server.",
          facts: [["Blocked", "203.0.113.77 → port 23"], ["Rule", "12 (deny inbound)"], ["Next", "Write a log line"]],
          events: [note("internet", "SYN TO PORT 23", "red"), note("fw", "DENIED BY RULE 12", "amber")],
        },
        {
          title: "Syslog over UDP 514",
          desc: "One datagram, one message",
          detail:
            "The whole log line goes into a single UDP datagram to port 514. It starts with <134>: facility local0 (16) × 8 + severity informational (6). Then come the version, a precise UTC timestamp, the host name, the program (filterlog), its process ID, a message ID, structured data in square brackets and finally the text for humans.",
          facts: [["To", `${LOG} : 514`], ["PRI", "<134> = local0.info"], ["Size", `${text(line(M1)).length} bytes of text`]],
          quiz: {
            q: "A message starts with <132>. Its facility is local0 (16). What is the severity?",
            options: ["2 critical", "4 warning", "6 informational", "32"],
            answer: 1,
            why: "PRI = facility × 8 + severity. 16 × 8 = 128, and 132 − 128 = 4, which is warning.",
          },
          events: [
            pkt("fw", "log", "amber", "SYSLOG", ["<134> FW_DENY", "port 23 blocked"], {
              time: 0.001, info: `LOCAL0.INFO: ${line(M1).slice(0, 70)}…`,
              packet: build(...fwToLog(0x51a0), udp({ sport: 514, dport: 514 }), syslogUdp(M1)),
            }),
            note("log", "STORED", "green"),
          ],
        },
        {
          title: "Open a TLS connection",
          desc: "TCP to 6514, then a TLS 1.3 handshake",
          detail:
            "Security logs shouldn’t travel in clear text or go missing, so the firewall is also set up to send over TLS (RFC 5425). It opens TCP to port 6514 and runs a TLS 1.3 handshake. The log server proves its identity with a certificate; many setups also ask the firewall for a client certificate so fake devices can’t inject logs.",
          facts: [["Port", "TCP 6514"], ["TLS", "1.3, AES-128-GCM"], ["Auth", "Server cert (and often client cert)"]],
          events: [
            pkt("fw", "log", "green", "SYN", ["to 6514"], { time: 5, info: p.syn.info, packet: p.syn.packet }),
            pkt("log", "fw", "green", "SYN-ACK", [], { time: 5.0003, info: p.synack.info, packet: p.synack.packet }),
            pkt("fw", "log", "green", "ACK", [], { time: 5.0005, info: p.ack.info, packet: p.ack.packet }),
            pkt("fw", "log", "teal", "C.HELLO", ["TLS 1.3", "SNI logs.example.com"], { time: 5.0006, info: "Client Hello (SNI=logs.example.com)", packet: p.ch.packet }),
            pkt("log", "fw", "teal", "S.HELLO", ["+ certificate", "(encrypted)"], { time: 5.0012, info: "Server Hello, Change Cipher Spec, Application Data", packet: p.sf.packet }),
            pkt("fw", "log", "teal", "FINISHED", [], { time: 5.0016, info: "Change Cipher Spec, Application Data", packet: p.cf.packet }),
          ],
        },
        {
          title: "Octet-counted frames",
          desc: "Length, a space, then the message",
          detail: `TCP is a stream with no message boundaries, so RFC 5425 puts the length in front of each message: “${octetFrame(M1).slice(0, 26)}…”. The receiver reads digits up to the space, then exactly that many bytes. Inside TLS the whole frame is encrypted; on the wire you see only a ${encLenOf(octetFrame(M1))}-byte Application Data record.`,
          facts: [["Frame", `${text(line(M1)).length} SP <134>1 …`], ["Record", `${encLenOf(octetFrame(M1))} bytes encrypted`], ["Why a length", "TCP has no message edges"]],
          quiz: {
            q: "Why not just end each message with a newline, like a text file?",
            options: ["Newlines are not allowed in TLS", "A message can itself contain a newline, which would split it wrongly", "It wastes bytes", "UDP needs it"],
            answer: 1,
            why: "Stack traces and multi-line messages are common. A length prefix tells the receiver exactly where each message ends, whatever is inside.",
          },
          events: [
            pkt("fw", "log", "teal", "LOG (TLS)", [`${text(line(M1)).length} <134>1 …`, "encrypted"], { time: 5.002, info: p.d1.info, packet: p.d1.packet }),
            pkt("log", "fw", "green", "ACK", [], { time: 5.0022, info: p.a1.info, packet: p.a1.packet }),
          ],
        },
        {
          title: "More logs, same connection",
          desc: "Several frames can share one segment",
          detail:
            "The connection stays open. A failed SSH login (<132>, warning) and a config change (<133>, notice) follow seconds later; here both leave in one TCP segment as two TLS records. TCP’s acknowledgements tell the firewall the bytes arrived at the server, and TLS keeps them private and untampered on the way.",
          facts: [["Messages", "AUTH_FAIL, CFG_CHANGE"], ["Records", "2 in one segment"], ["Delivery", "Acknowledged by TCP"]],
          events: [
            pkt("fw", "log", "teal", "LOG ×2", ["<132> AUTH_FAIL", "<133> CFG_CHANGE"], { time: 7.003, info: p.d2.info, packet: p.d2.packet }),
            pkt("log", "fw", "green", "ACK", [], { time: 7.0032, info: p.a2.info, packet: p.a2.packet }),
            note("log", "3 EVENTS INDEXED", "green"),
          ],
        },
      ],
      outro: {
        title: "Logs collected",
        text: "Each event became one RFC 5424 line: priority, timestamp, host, app, IDs, structured data and text. Over UDP 514 it was quick and simple; over TLS 6514 it was encrypted, acknowledged by TCP, and framed with a length so messages never run together.",
        facts: [["UDP", "514, one message per datagram"], ["TLS", "6514, length-prefixed frames"], ["PRI", "facility × 8 + severity"], ["Standard", "RFC 5424 / 5425 / 5426"]],
      },
    },
    {
      id: "burst",
      name: "Logs lost in a burst (UDP)",
      summary: "During a port scan the firewall fires hundreds of UDP logs a second and some vanish; RELP over TCP fixes it.",
      kind: "failure",
      steps: [
        {
          title: "A scan starts",
          desc: "Hundreds of blocked connections a second",
          detail:
            "A scanner sweeps through many ports at once. Every blocked attempt becomes a syslog message, so the firewall suddenly sends hundreds of UDP datagrams per second to the log server.",
          facts: [["Rate", "Hundreds of logs a second"], ["Transport", "UDP 514"], ["Feedback", "None"]],
          events: [note("internet", "PORT SCAN", "red"), note("fw", "LOG STORM", "amber")],
        },
        {
          title: "Some datagrams vanish",
          desc: "No sequence numbers, no resends",
          detail:
            "The log server’s receive buffer fills faster than the program can read it, and the kernel drops new datagrams. Nobody notices: UDP has no ACKs and syslog messages have no sequence numbers, so the firewall never learns that some lines are missing. Those could be exactly the lines an investigator needs.",
          facts: [["Sent", "8 shown"], ["Lost", "3 (buffer full)"], ["Firewall told", "Nothing"]],
          quiz: {
            q: "How does the firewall find out that three messages were lost?",
            options: ["The server sends a NACK", "UDP retransmits them", "It doesn’t; UDP gives no feedback", "An ICMP error for each one"],
            answer: 2,
            why: "UDP is fire-and-forget. A full socket buffer on the receiver drops datagrams silently, and the sender has no way to know.",
          },
          events: burst.map((m, i) =>
            pkt("fw", "log", "amber", "SYSLOG", [`port ${m.sd.match(/dport="(\d+)"/)?.[1]}`], {
              time: 1 + i * 0.002, parallel: i > 0, lost: i === 2 || i === 4 || i === 5,
              info: `LOCAL0.INFO: ${line(m).slice(0, 60)}…`,
              packet: build(...fwToLog(0x6000 + i), udp({ sport: 514, dport: 514 }), syslogUdp(m)),
            })
          ),
        },
        {
          title: "Fix: an acknowledged transport",
          desc: "RELP: every message gets an answer",
          detail:
            "Plain TCP or TLS already stops network loss, but if the server crashes, data sitting in buffers can still disappear. RELP (Reliable Event Logging Protocol, used by rsyslog) adds an application-level reply: each frame carries a transaction number, and the server answers “rsp 200 OK” for that number only after it has the message. Unconfirmed messages are sent again after reconnecting.",
          facts: [["Port", `TCP ${RELP_PORT} (common choice)`], ["Frame", "TXNR SP CMD SP LEN SP DATA LF"], ["Reply", "rsp 200 OK per message"]],
          quiz: {
            q: "The TCP connection breaks after the firewall sent frame 7 but before any rsp arrived. What happens to message 7?",
            options: ["It is lost for good", "The firewall resends it after reconnecting", "TCP resends it on the new connection by itself", "The server asks for it by name"],
            answer: 1,
            why: "RELP keeps every unconfirmed message and replays it on the next session. TCP alone can’t do that because its buffers die with the connection.",
          },
          events: [
            pkt("fw", "log", "green", "SYN", [`to ${RELP_PORT}`], { time: 2, info: rp.syn.info, packet: rp.syn.packet }),
            pkt("log", "fw", "green", "SYN-ACK", [], { time: 2.0003, info: rp.synack.info, packet: rp.synack.packet }),
            pkt("fw", "log", "green", "ACK", [], { time: 2.0005, info: rp.ack.info, packet: rp.ack.packet }),
            pkt("fw", "log", "amber", "RELP 7", ["7 syslog …"], { time: 2.0006, info: `RELP 7 syslog ${text(line(M2)).length}`, packet: rp.send.packet }),
            pkt("log", "fw", "green", "RSP 200", ["7 rsp 6 200 OK"], { time: 2.0009, info: "RELP 7 rsp 6 200 OK", packet: rp.rsp.packet }),
            note("fw", "MESSAGE 7 CONFIRMED", "green"),
          ],
        },
      ],
      outro: {
        title: "Pick the transport for the job",
        text: "UDP syslog is fine for chatty, low-value logs, but it drops messages silently under load. For security and audit logs use TCP or TLS (6514), and RELP when every message must be confirmed by the receiver.",
        facts: [["UDP 514", "Fast, lossy, no feedback"], ["TLS 6514", "Encrypted, TCP reliable"], ["RELP", "Per-message acknowledgment"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Severity (PRI mod 8)",
      items: [["0 Emergency", "System unusable"], ["1 Alert", "Act now"], ["2 Critical", "Critical condition"], ["3 Error", "Error"], ["4 Warning", "Warning"], ["5 Notice", "Normal but significant"], ["6 Info", "Informational"], ["7 Debug", "Debug detail"]],
    },
    {
      title: "Facilities (PRI ÷ 8)",
      items: [["0", "kernel"], ["1", "user"], ["4", "auth"], ["10", "authpriv"], ["16–23", "local0–local7 (free for devices)"]],
    },
    {
      title: "Ports and framing",
      items: [["UDP 514", "One message per datagram (RFC 5426)"], ["TLS 6514", "LEN SP MSG (RFC 5425)"], ["RELP", "TXNR CMD LEN DATA LF, rsp 200 OK"], ["Format", "<PRI>1 TIME HOST APP PROCID MSGID [SD] MSG"]],
    },
  ],
});
