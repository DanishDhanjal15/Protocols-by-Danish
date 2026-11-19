import { Color, defineLesson, Device, note, pkt, PacketEvent } from "@/lib/lesson";
import { build, LayerSpec, textLayer } from "@/lib/packet";
import { eth, ext, hsMsg, ipv4, tcp, TcpOpt, tls, vec } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

const S = ADDR.server2; // 203.0.113.40
const HOST = "ftp.example.com";
const USER = "danish";
const PASS = "correct-horse-42";
const FILE = "report.pdf";
const MSS = 1460;
const FILE_SIZE = 2 * MSS;
// PASV port: 195 × 256 + 149 = 50069
const P1 = 195, P2 = 149;
const DATA_PORT = P1 * 256 + P2;
const PASV_REPLY = `227 Entering Passive Mode (${S.split(".").join(",")},${P1},${P2}).`;
const r = (n: number) => Number(n.toFixed(4));

// ---------------------------------------------------------------- TCP conversation helper

interface End { id: string; layers: () => LayerSpec[]; port: number; base: number; win: number }

function conversation(a: End, b: End) {
  const next = { a: 0, b: 0 };
  const send = (fromA: boolean, flags: string, app: LayerSpec[], opts?: TcpOpt[]) => {
    const me = fromA ? a : b, them = fromA ? b : a;
    const seq = fromA ? next.a : next.b;
    const ack = fromA ? next.b : next.a;
    const len = app.length ? build(...app).bytes.length : 0;
    const packet = build(
      ...me.layers(),
      tcp({ sport: me.port, dport: them.port, seq, ...(flags.includes("A") ? { ack } : {}), flags, win: me.win, opts, seqBase: me.base, ackBase: them.base }),
      ...app
    );
    const adv = len + (/[SF]/.test(flags) ? 1 : 0);
    if (fromA) next.a += adv; else next.b += adv;
    return packet;
  };
  const msg = (fromA: boolean) => (color: Color, label: string, lines: string[], time: number, info: string, app: LayerSpec[], extra: Partial<PacketEvent> = {}, flags = "PA"): PacketEvent =>
    pkt(fromA ? a.id : b.id, fromA ? b.id : a.id, color, label, lines, { time: r(time), info, packet: send(fromA, flags, app), ...extra });
  return {
    a: msg(true),
    b: msg(false),
    handshake: (t: number, rtt: number, color: Color = "green"): PacketEvent[] => [
      pkt(a.id, b.id, color, "SYN", [`to port ${b.port}`], {
        time: r(t), info: `${a.port} → ${b.port} [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
        packet: send(true, "S", [], [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }]),
      }),
      pkt(b.id, a.id, color, "SYN-ACK", ["port open"], {
        time: r(t + rtt), info: `${b.port} → ${a.port} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128`,
        packet: send(false, "SA", [], [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }]),
      }),
      pkt(a.id, b.id, color, "ACK", ["connected"], {
        time: r(t + rtt + 0.0005), info: `${a.port} → ${b.port} [ACK] Seq=1 Ack=1 Win=502 Len=0`,
        packet: send(true, "A", []),
      }),
    ],
  };
}

// ---------------------------------------------------------------- layers

const ftp = (lines: string[], notes?: Record<number, string>) => textLayer({ id: "ftp", name: "FTP", lines, notes });
const fileChunk = (from: number) =>
  textLayer({ id: "ftp-data", name: "FTP Data", lines: [], body: { opaque: MSS, what: `${FILE} bytes ${from}–${from + MSS - 1}`, note: "Raw file bytes. On plain FTP anyone on the path could save them." }, summary: `FTP Data: ${MSS} bytes of ${FILE}` });
const encLen = (lines: string[]) => lines.reduce((n, l) => n + l.length + 2, 0) + 17;
const enc = (lines: string[], what: string) => tls({ records: [{ type: "appdata", encrypted: encLen(lines), what }], summary: `TLS Application Data (inside: ${what})` });

const clientHello = (sni: string) =>
  tls({
    records: [{
      type: "handshake", version: 0x0301,
      fields: [hsMsg("client_hello", "Client Hello", [
        { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "A legacy field. The real version list is in supported_versions." },
        { name: "Random", random: 32 },
        vec("Session ID", 1, [{ name: "Session ID", random: 32 }]),
        vec("Cipher suites", 2, [
          { name: "TLS_AES_128_GCM_SHA256", u16: 0x1301, value: "0x1301" },
          { name: "TLS_AES_256_GCM_SHA384", u16: 0x1302, value: "0x1302" },
        ], "2 suites"),
        vec("Compression methods", 1, [{ name: "null", u8: 0 }]),
        vec("Extensions", 2, [
          ext(0, "server_name", [vec("Server name list", 2, [{ name: "Type", u8: 0, value: "host_name" }, vec("Host name", 2, [{ name: "Name", text: sni }], sni)])], sni),
          ext(10, "supported_groups", [vec("Groups", 2, [{ name: "x25519", u16: 0x001d, value: "x25519" }])]),
          ext(13, "signature_algorithms", [vec("Algorithms", 2, [{ name: "ecdsa_secp256r1_sha256", u16: 0x0403, value: "0x0403" }, { name: "rsa_pss_rsae_sha256", u16: 0x0804, value: "0x0804" }])]),
          ext(43, "supported_versions", [vec("Versions", 1, [{ name: "TLS 1.3", u16: 0x0304, value: "TLS 1.3" }])], "TLS 1.3"),
          ext(51, "key_share", [vec("Client key shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32 }])])], "x25519"),
        ]),
      ])],
    }],
  });

// ---------------------------------------------------------------- devices

const base = homeToServer({ kind: "server", label: "FTP server", sub: `${HOST} ${S}` });

const control = (sport: number, bases: [number, number]) =>
  conversation(
    { id: "client", layers: () => up(S), port: sport, base: bases[0], win: 502 },
    { id: "server", layers: () => down(S), port: 21, base: bases[1], win: 509 }
  );

// ---------------------------------------------------------------- scenario 1: passive download

const C = control(50110, [0x5d10a001, 0x13f0be22]);
const D = conversation(
  { id: "client", layers: () => up(S), port: 50112, base: 0x2a0c0f00, win: 502 },
  { id: "server", layers: () => down(S), port: DATA_PORT, base: 0x7b3e9100, win: 509 }
);

const normalSteps = [
  {
    title: "Control connection on 21",
    desc: "One TCP connection just for commands",
    detail: `FTP uses two kinds of connection. The control connection, to port 21, carries text commands and numbered replies for the whole session. Files travel on separate data connections. After the handshake the server greets with 220.`,
    facts: [["Server", `${S} port 21`], ["Greeting", "220 (vsFTPd 3.0.5)"], ["Connections", "1 control + 1 per transfer"]] as [string, string][],
    events: [
      ...C.handshake(0, 0.03),
      C.b("green", "220", ["ready"], 0.061, "Response: 220 (vsFTPd 3.0.5)", [ftp(["220 (vsFTPd 3.0.5)"])]),
    ],
  },
  {
    title: "USER and PASS",
    desc: "331 asks for the password, 230 logs in",
    detail: `The client sends USER ${USER}; the server answers 331, which means "OK so far, send the password". Then PASS ${PASS} travels in plain text and the server replies 230 Login successful. Classic FTP has no encryption at all, so this password is readable by anyone on the path.`,
    facts: [["331", "User OK, need password"], ["230", "Logged in"], ["Password", "Sent in clear text!"]] as [string, string][],
    quiz: {
      q: "After USER danish the server replies 331. What is the client expected to send next?",
      options: ["QUIT", "PASS with the password", "PASV", "Another USER"],
      answer: 1,
      why: "3xx replies mean \"more information needed\". 331 specifically asks for the password.",
    },
    events: [
      C.a("amber", "USER", [USER], 0.062, `Request: USER ${USER}`, [ftp([`USER ${USER}`])]),
      C.b("violet", "331", ["need password"], 0.092, "Response: 331 Please specify the password.", [ftp(["331 Please specify the password."])]),
      C.a("red", "PASS", [PASS, "in clear text"], 0.093, `Request: PASS ${PASS}`, [ftp([`PASS ${PASS}`], { 0: "The password, readable by anyone who captures this packet." })]),
      C.b("green", "230", ["logged in"], 0.135, "Response: 230 Login successful.", [ftp(["230 Login successful."])]),
    ],
  },
  {
    title: "PWD and TYPE I",
    desc: "Where am I, and switch to binary",
    detail: "PWD prints the working directory: the server answers 257 with the path in quotes. TYPE I switches to image (binary) mode so the file is sent byte for byte. In the old ASCII mode the server would rewrite line endings, which corrupts PDFs and images.",
    facts: [["257", "\"/home/danish\" is the current directory"], ["TYPE I", "Binary, no changes to bytes"], ["TYPE A", "ASCII, rewrites line endings"]] as [string, string][],
    events: [
      C.a("amber", "PWD", [], 0.136, "Request: PWD", [ftp(["PWD"])]),
      C.b("violet", "257", ["/home/danish"], 0.166, 'Response: 257 "/home/danish" is the current directory', [ftp(['257 "/home/danish" is the current directory'])]),
      C.a("amber", "TYPE I", ["binary mode"], 0.167, "Request: TYPE I", [ftp(["TYPE I"], { 0: "I = image: transfer bytes exactly as they are." })]),
      C.b("violet", "200", ["binary"], 0.197, "Response: 200 Switching to Binary mode.", [ftp(["200 Switching to Binary mode."])]),
    ],
  },
  {
    title: "PASV: where to connect",
    desc: "227 with six numbers",
    detail: `PASV asks the server to open a fresh port and wait for the client. The reply packs an address and port into six numbers: (h1,h2,h3,h4,p1,p2). Here that is ${S} and port ${P1} × 256 + ${P2} = ${DATA_PORT}. Because the client opens the connection outward, it works through home routers and NAT.`,
    facts: [["Reply", PASV_REPLY], ["Address", `${S}`], ["Port", `${P1} × 256 + ${P2} = ${DATA_PORT}`]] as [string, string][],
    quiz: {
      q: `The reply ends in (…,${P1},${P2}). Which port should the client connect to?`,
      options: [`${P1}${P2}`, String(P1 + P2), String(DATA_PORT), "20"],
      answer: 2,
      why: `The port is p1 × 256 + p2 = ${P1} × 256 + ${P2} = ${DATA_PORT}. p1 is the high byte, p2 the low byte.`,
    },
    events: [
      C.a("amber", "PASV", [], 0.198, "Request: PASV", [ftp(["PASV"])]),
      C.b("violet", "227", [`port ${DATA_PORT}`], 0.228, `Response: ${PASV_REPLY}`, [ftp([PASV_REPLY], { 0: `Four numbers for the IP, then the port as two bytes: ${P1}×256+${P2} = ${DATA_PORT}.` })]),
    ],
  },
  {
    title: "Open the data connection",
    desc: `A second TCP connection to port ${DATA_PORT}`,
    detail: `The client opens a brand-new TCP connection from port 50112 to ${S}:${DATA_PORT}. This is the data connection. Nothing has been sent on it yet: the client still has to say which file it wants, on the control connection.`,
    facts: [["From", `${ADDR.laptop}:50112`], ["To", `${S}:${DATA_PORT}`], ["Direction", "Client → server (passive mode)"]] as [string, string][],
    events: D.handshake(0.229, 0.03, "blue"),
  },
  {
    title: "RETR and the file",
    desc: "150 on control, bytes on data",
    detail: `On the control connection the client sends RETR ${FILE}. The server answers 150 and starts pushing the file down the data connection: here two full ${MSS}-byte segments. When it's done it closes the data connection with FIN. The end of the connection marks the end of the file.`,
    facts: [["Command", `RETR ${FILE}`], ["150", "Opening data connection"], ["Size", `${FILE_SIZE} bytes in 2 segments`]] as [string, string][],
    quiz: {
      q: "How does the client know the whole file has arrived?",
      options: ["A dot on its own line", "The server closes the data connection", "A checksum at the end", "It counts to 1000 bytes"],
      answer: 1,
      why: "In FTP's normal stream mode, the data connection's FIN marks the end of the file. The 226 reply on control confirms it.",
    },
    events: [
      C.a("amber", "RETR", [FILE], 0.260, `Request: RETR ${FILE}`, [ftp([`RETR ${FILE}`])]),
      C.b("violet", "150", ["opening data"], 0.290, `Response: 150 Opening BINARY mode data connection for ${FILE} (${FILE_SIZE} bytes).`, [ftp([`150 Opening BINARY mode data connection for ${FILE} (${FILE_SIZE} bytes).`])]),
      D.b("violet", "DATA", [`bytes 1–${MSS}`], 0.291, `FTP Data: ${MSS} bytes (PASV) (RETR ${FILE})`, [fileChunk(1)], {}, "A"),
      D.b("violet", "DATA", [`bytes ${MSS + 1}–${FILE_SIZE}`], 0.291, `FTP Data: ${MSS} bytes (PASV) (RETR ${FILE})`, [fileChunk(MSS + 1)], { parallel: true }),
      D.b("slate", "FIN", ["end of file"], 0.292, `${DATA_PORT} → 50112 [FIN, ACK]`, [], {}, "FA"),
      D.a("slate", "FIN", ["closed"], 0.322, `50112 → ${DATA_PORT} [FIN, ACK]`, [], {}, "FA"),
    ],
  },
  {
    title: "226 and goodbye",
    desc: "Transfer complete, then QUIT",
    detail: "On the control connection the server confirms with 226 Transfer complete. The client could now ask for more files, each with its own PASV and data connection. Instead it sends QUIT and gets 221 Goodbye.",
    facts: [["226", "Transfer complete"], ["221", "Goodbye"], ["Data connections used", "1"]] as [string, string][],
    events: [
      C.b("green", "226", ["transfer complete"], 0.323, "Response: 226 Transfer complete.", [ftp(["226 Transfer complete."])]),
      C.a("slate", "QUIT", [], 0.324, "Request: QUIT", [ftp(["QUIT"])]),
      C.b("slate", "221", ["goodbye"], 0.354, "Response: 221 Goodbye.", [ftp(["221 Goodbye."])]),
      note("client", `${FILE} SAVED`, "green"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 2: active mode blocked

const A = control(50130, [0x0c0ffee0, 0x44aa1100]);
const ACTIVE_PORT = 195 * 256 + 200; // 50120
const PORT_CMD = `PORT 192,168,1,10,195,200`;
const serverOut = () => [eth({ src: ADDR.serverMac, dst: "00:00:5e:00:01:01" }), ipv4({ src: S, dst: ADDR.laptop, ttl: 64 })];
const activeSyn = (t: number) =>
  pkt("server", "client", "red", "SYN", [`20 → ${ACTIVE_PORT}`, "can't get in"], {
    time: r(t), lost: true, info: `20 → ${ACTIVE_PORT} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`,
    packet: build(...serverOut(), tcp({ sport: 20, dport: ACTIVE_PORT, seq: 0, flags: "S", opts: [{ mss: 1460 }], seqBase: 0x6600aa00 })),
  });

const activeSteps = [
  {
    title: "Client asks for active mode",
    desc: `${PORT_CMD}`,
    detail: `An old FTP client uses active mode. Instead of PASV it sends PORT with its own address and a port, ${PORT_CMD}, meaning "connect to me at 192.168.1.10 port ${ACTIVE_PORT}". That is a private home address, which means nothing on the internet.`,
    facts: [["Command", PORT_CMD], ["Means", `192.168.1.10 port 195×256+200 = ${ACTIVE_PORT}`], ["Problem", "Private address behind NAT"]] as [string, string][],
    quiz: {
      q: "In active mode, who opens the data connection?",
      options: ["The client", "The server, connecting back to the client", "The home router", "Nobody, data uses the control connection"],
      answer: 1,
      why: "Active mode reverses the direction: the server connects from port 20 to the address in the PORT command.",
    },
    events: [
      ...A.handshake(0, 0.03),
      A.b("green", "220", [], 0.061, "Response: 220 (vsFTPd 3.0.5)", [ftp(["220 (vsFTPd 3.0.5)"])]),
      A.a("amber", "PORT", ["192.168.1.10", `port ${ACTIVE_PORT}`], 0.062, `Request: ${PORT_CMD}`, [ftp([PORT_CMD], { 0: "h1–h4 = the client's IP, p1,p2 = its port. A private IP!" })]),
      A.b("violet", "200", ["PORT ok"], 0.092, "Response: 200 PORT command successful. Consider using PASV.", [ftp(["200 PORT command successful. Consider using PASV."])]),
    ],
  },
  {
    title: "Server can't connect in",
    desc: "SYNs from port 20 never arrive",
    detail: "After RETR the server tries to connect from port 20 to 192.168.1.10. That address can't be routed on the internet, and even if it reached Danish's router, the router's firewall drops connection attempts nobody inside asked for. The server retries after 1 and 3 seconds.",
    facts: [["Server port", "20 (ftp-data)"], ["Blocked by", "NAT and the router's firewall"], ["Retries", "1 s, then 3 s"]] as [string, string][],
    events: [
      A.a("amber", "RETR", [FILE], 0.093, `Request: RETR ${FILE}`, [ftp([`RETR ${FILE}`])]),
      activeSyn(0.124),
      activeSyn(1.124),
      activeSyn(3.124),
      note("router", "UNSOLICITED SYN: DROPPED", "red"),
    ],
  },
  {
    title: "425: no data connection",
    desc: "The fix is passive mode",
    detail: "The server gives up and reports 425 on the control connection. The fix is PASV (or EPSV), where the client opens the data connection outward, which NAT and firewalls allow. Modern clients use passive mode by default.",
    facts: [["Reply", "425 Failed to establish connection."], ["Fix", "PASV / EPSV (client connects out)"], ["Firewall rule", "Inbound only what was asked for"]] as [string, string][],
    quiz: {
      q: "Why does PASV work behind a home router when PORT fails?",
      options: ["PASV is encrypted", "In PASV the client starts the data connection outward, which NAT allows", "PASV uses UDP", "PASV uses port 21 for data"],
      answer: 1,
      why: "Home routers let outgoing connections and their replies through, but block unexpected incoming ones.",
    },
    events: [
      A.b("red", "425", ["no connection"], 7.13, "Response: 425 Failed to establish connection.", [ftp(["425 Failed to establish connection."])]),
      note("client", "TRANSFER FAILED", "red"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 3: sniffed password, use FTPS/SFTP

const sniffDevices: Device[] = [
  ...base.devices,
  { id: "attacker", kind: "attacker", label: "Eavesdropper", sub: "on the path", x: 45, y: 16 },
];
const sniffLinks: [string, string][] = [...base.links, ["attacker", "internet"]];
const X = control(50150, [0x1badb002, 0x3d3d0000]);
const T = control(50160, [0x6789abcd, 0x0a0b0c0d]);

const sniffSteps = [
  {
    title: "Password on the wire",
    desc: "Plain FTP shows everything",
    detail: "Someone who can see Danish's traffic (a shared Wi-Fi, a compromised router) runs a capture filtered to port 21. The USER and PASS lines are plain text, and so is every file on the data connections. No cracking is needed.",
    facts: [["Seen", `USER ${USER}, PASS ${PASS}`], ["Also seen", "File names and contents"], ["Effort", "Just a packet capture"]] as [string, string][],
    events: [
      X.a("amber", "USER", [USER], 0, `Request: USER ${USER}`, [ftp([`USER ${USER}`])]),
      X.b("violet", "331", [], 0.03, "Response: 331 Please specify the password.", [ftp(["331 Please specify the password."])]),
      X.a("red", "PASS", [PASS], 0.031, `Request: PASS ${PASS}`, [ftp([`PASS ${PASS}`])]),
      note("attacker", `GOT ${USER} / ${PASS}`, "red"),
    ],
  },
  {
    title: "Defence: FTPS",
    desc: "AUTH TLS before logging in",
    detail: "FTPS adds TLS to FTP. The client sends AUTH TLS, the server replies 234, and a TLS handshake runs on the control connection. After that USER and PASS are encrypted, and PROT P protects the data connections too. SFTP is a different protocol that runs inside SSH on port 22 with one connection, and is usually the simpler choice.",
    facts: [["FTPS", "AUTH TLS → 234, then TLS"], ["Data", "PROT P encrypts data connections"], ["SFTP", "Over SSH, port 22, one connection"]] as [string, string][],
    quiz: {
      q: "Which is true about SFTP?",
      options: ["It is FTP with TLS", "It runs over SSH, usually on port 22, with no separate data connections", "It is still plain text", "It uses port 21"],
      answer: 1,
      why: "Despite the name, SFTP isn't FTP at all. It's a file protocol inside an SSH connection, so firewall setup is easy.",
    },
    events: [
      ...T.handshake(1, 0.03),
      T.b("green", "220", [], 1.061, "Response: 220 (vsFTPd 3.0.5)", [ftp(["220 (vsFTPd 3.0.5)"])]),
      T.a("teal", "AUTH TLS", [], 1.062, "Request: AUTH TLS", [ftp(["AUTH TLS"], { 0: "Asks to switch the control connection to TLS (RFC 4217)." })]),
      T.b("teal", "234", ["go ahead"], 1.092, "Response: 234 Proceed with negotiation.", [ftp(["234 Proceed with negotiation."])]),
      T.a("teal", "HELLO", ["Client Hello", HOST], 1.093, `Client Hello (SNI=${HOST})`, [clientHello(HOST)]),
    ],
  },
  {
    title: "Nothing left to steal",
    desc: "Encrypted USER and PASS",
    detail: "Once TLS is up, the login travels inside encrypted records. The eavesdropper still sees that Danish talks to an FTP server, but not the password or the files.",
    facts: [["Inside", "USER, PASS, PROT P"], ["Attacker sees", "IPs, ports, sizes"], ["Best practice", "Disable plain FTP entirely"]] as [string, string][],
    events: [
      T.b("teal", "TLS", ["Server Hello…", "(after handshake)"], 1.124, "Application Data", [tls({ records: [{ type: "appdata", encrypted: 1150, what: "Rest of the TLS handshake (certificate, Finished)" }] })]),
      T.a("teal", "USER/PASS", ["(encrypted)"], 1.126, "Application Data", [enc([`USER ${USER}`, `PASS ${PASS}`], "FTP: USER / PASS")]),
      T.b("teal", "230", ["(encrypted)"], 1.168, "Application Data", [enc(["331 Please specify the password.", "230 Login successful."], "FTP: 331 / 230")]),
      note("attacker", "ONLY CIPHERTEXT", "green"),
    ],
  },
];

export default defineLesson({
  id: "ftp",
  name: "FTP",
  full: "File Transfer Protocol",
  group: "mail-files",
  layer: 7,
  difficulty: 2,
  tagline: "Two connections: one for talking, one for the file.",
  description:
    "FTP is one of the oldest internet protocols for moving files. Commands and numbered replies travel on a control connection to port 21, and each file goes over its own separate data connection. Plain FTP sends everything, passwords included, in clear text.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP 21 control, separate data connections"],
    ["Defined in", "RFC 959 (1985)"],
    ["Modes", "Active (PORT) and passive (PASV/EPSV)"],
    ["Security", "None; use FTPS (RFC 4217) or SFTP"],
    ["Replies", "3-digit codes, like SMTP"],
  ],
  ports: "21 control, 20 active data, high ports for passive data, 990 implicit FTPS",
  rfc: "RFC 959, RFC 2428, RFC 4217",
  keywords: ["file transfer", "ftp", "pasv", "port", "active", "passive", "227", "data connection", "ftps", "sftp", "nat"],
  related: ["tcp", "smb", "tls", "ssh"],
  ...base,
  legend: [
    ["green", "Handshake and success replies"],
    ["amber", "Commands from the client"],
    ["violet", "Server replies and file data"],
    ["blue", "Data connection setup"],
    ["red", "Exposed secrets or blocked traffic"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Download a file in passive mode",
      summary: "Log in on port 21, switch to binary, PASV, and fetch report.pdf on a second connection.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "File downloaded",
        text: `The control connection carried the login and commands; a separate data connection to port ${DATA_PORT} carried the file and closed to mark its end. It worked, but the password crossed the internet in plain text.`,
        facts: [["Connections", "2 (control + data)"], ["PASV port", `${P1}×256+${P2} = ${DATA_PORT}`], ["File", `${FILE}, ${FILE_SIZE} bytes`], ["Total time", "0.354 s"]],
      },
    },
    {
      id: "active-nat",
      name: "Active mode blocked by NAT",
      summary: "PORT sends a private address; the server's SYNs from port 20 never arrive.",
      kind: "failure",
      steps: activeSteps,
      outro: {
        title: "Use passive mode",
        text: "Active mode needs the server to connect into the client, which home routers and firewalls block. Passive mode turns it around so the client always connects outward.",
        facts: [["Result", "425 Failed to establish connection"], ["Cause", "Private IP + firewall drops inbound SYN"], ["Fix", "PASV or EPSV"]],
      },
    },
    {
      id: "sniffed",
      name: "Sniffed password: why FTPS and SFTP",
      summary: "A passive listener reads the FTP login; TLS (FTPS) or SSH (SFTP) hides it.",
      kind: "attack",
      devices: sniffDevices,
      links: sniffLinks,
      steps: sniffSteps,
      outro: {
        title: "Encrypt file transfers",
        text: "Plain FTP hands the password and files to anyone who can watch the path. FTPS wraps FTP in TLS, and SFTP replaces it with a file protocol inside SSH. Either one keeps the login and data private.",
        facts: [["Attack", "Passive sniffing"], ["Defences", "FTPS (AUTH TLS), SFTP (SSH port 22)"], ["Plain FTP today", "Only for public, anonymous files"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Commands",
      items: [["USER / PASS", "Log in (clear text)"], ["PWD / CWD", "Show / change directory"], ["TYPE I / TYPE A", "Binary / ASCII"], ["PASV / EPSV", "Server opens a port for the client"], ["PORT", "Client gives its address (active)"], ["RETR / STOR", "Download / upload"], ["LIST", "Directory listing (on a data connection)"], ["AUTH TLS", "Upgrade to FTPS"]],
    },
    {
      title: "Replies",
      items: [["150", "Opening data connection"], ["220", "Ready"], ["226", "Transfer complete"], ["227", "Passive mode (h1,h2,h3,h4,p1,p2)"], ["230", "Logged in"], ["331", "Need password"], ["425", "Can't open data connection"], ["530", "Not logged in"]],
    },
    {
      title: "Numbers",
      items: [["Port from p1,p2", "p1 × 256 + p2"], ["21", "Control"], ["20", "Active-mode data (from server)"], ["22", "SFTP (SSH)"]],
    },
  ],
});
