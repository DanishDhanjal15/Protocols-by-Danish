import { Color, defineLesson, note, pkt, PacketEvent } from "@/lib/lesson";
import { build, LayerSpec, textLayer } from "@/lib/packet";
import { ext, hsMsg, tcp, TcpOpt, tls, vec } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

const S = ADDR.mail;
const HOST = "pop.mailhost.example";
const USER = "danish";
const PASS = "correct-horse-42";
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
    handshake: (t: number, rtt: number): PacketEvent[] => [
      pkt(a.id, b.id, "green", "SYN", [`to port ${b.port}`], {
        time: r(t), info: `${a.port} → ${b.port} [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
        packet: send(true, "S", [], [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }]),
      }),
      pkt(b.id, a.id, "green", "SYN-ACK", ["port open"], {
        time: r(t + rtt), info: `${b.port} → ${a.port} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128`,
        packet: send(false, "SA", [], [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }]),
      }),
      pkt(a.id, b.id, "green", "ACK", ["connected"], {
        time: r(t + rtt + 0.0005), info: `${a.port} → ${b.port} [ACK] Seq=1 Ack=1 Win=502 Len=0`,
        packet: send(true, "A", []),
      }),
    ],
  };
}

// ---------------------------------------------------------------- POP3 and TLS layers

const pop = (lines: string[], notes?: Record<number, string>) => textLayer({ id: "pop", name: "POP3", lines, notes });
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
          { name: "TLS_CHACHA20_POLY1305_SHA256", u16: 0x1303, value: "0x1303" },
        ], "3 suites"),
        vec("Compression methods", 1, [{ name: "null", u8: 0 }]),
        vec("Extensions", 2, [
          ext(0, "server_name", [vec("Server name list", 2, [{ name: "Type", u8: 0, value: "host_name" }, vec("Host name", 2, [{ name: "Name", text: sni }], sni)])], sni),
          ext(10, "supported_groups", [vec("Groups", 2, [{ name: "x25519", u16: 0x001d, value: "x25519" }, { name: "secp256r1", u16: 0x0017, value: "secp256r1" }])]),
          ext(13, "signature_algorithms", [vec("Algorithms", 2, [{ name: "ecdsa_secp256r1_sha256", u16: 0x0403, value: "0x0403" }, { name: "rsa_pss_rsae_sha256", u16: 0x0804, value: "0x0804" }])]),
          ext(43, "supported_versions", [vec("Versions", 1, [{ name: "TLS 1.3", u16: 0x0304, value: "TLS 1.3" }])], "TLS 1.3"),
          ext(51, "key_share", [vec("Client key shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32 }])])], "x25519"),
        ]),
      ])],
    }],
  });

const serverFlight = (encrypted: number) =>
  tls({
    records: [
      {
        type: "handshake",
        fields: [hsMsg("server_hello", "Server Hello", [
          { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
          { name: "Random", random: 32 },
          vec("Session ID", 1, [{ name: "Session ID", random: 32 }]),
          { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256" },
          { name: "Compression method", u8: 0, value: "null" },
          vec("Extensions", 2, [
            ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3" }], "TLS 1.3"),
            ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32 }])], "x25519"),
          ]),
        ])],
      },
      { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] },
      { type: "appdata", encrypted, what: "Encrypted Extensions, Certificate, Certificate Verify, Finished" },
    ],
  });

const clientFinished = () =>
  tls({ records: [{ type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] }, { type: "appdata", encrypted: 53, what: "Finished" }] });

// ---------------------------------------------------------------- the mailbox

const MSG1 = [
  "Return-Path: <priya@example.org>",
  "From: Priya <priya@example.org>",
  "To: Danish <danish@mailhost.example>",
  "Subject: Re: Notes for Friday",
  "Date: Thu, 19 Nov 2026 11:02:41 +0530",
  "Message-ID: <77e1@example.org>",
  "",
  "Thanks! See you on Friday.",
];
const SIZE1 = MSG1.reduce((n, l) => n + l.length + 2, 0);
const SIZE2 = 1361;
const GREETING = "+OK Dovecot ready.";

const base = homeToServer({ kind: "mail", label: "Mail server", sub: `${HOST} ${S}` });

const conv = (port: number, sport: number, bases: [number, number]) =>
  conversation(
    { id: "client", layers: () => up(S), port: sport, base: bases[0], win: 502 },
    { id: "server", layers: () => down(S), port, base: bases[1], win: 509 }
  );

// ---------------------------------------------------------------- scenario 1

const P = conv(110, 50620, [0x41d0aa10, 0x0f13c870]);

const normalSteps = [
  {
    title: "Connect to port 110",
    desc: "TCP handshake, then +OK greeting",
    detail: `Danish's mail app connects to ${HOST} on port 110, the plain POP3 port. As with SMTP, the server talks first. POP3 replies are simple: +OK means yes, -ERR means no. There are no number codes.`,
    facts: [["Server", `${S} port 110`], ["Greeting", GREETING], ["Replies", "+OK or -ERR"]] as [string, string][],
    events: [
      ...P.handshake(0, 0.03),
      P.b("green", "+OK", ["server ready"], 0.061, `S: ${GREETING}`, [pop([GREETING])]),
    ],
  },
  {
    title: "USER and PASS",
    desc: "Logging in, in plain text",
    detail: `The client sends USER ${USER} and then PASS ${PASS}. On port 110 there is no encryption, so the password sits in the packet as readable text. Click the PASS packet and look at the bytes: anyone on the same Wi-Fi, or any router on the path, can read it. That is why real apps use POP3S on port 995 or STLS.`,
    facts: [["Commands", `USER ${USER}, PASS ${PASS}`], ["Encryption", "None on port 110"], ["Safer", "Port 995 (POP3S) or STLS"]] as [string, string][],
    quiz: {
      q: "Who on the network path can read the PASS line on port 110?",
      options: ["Only the mail server", "Nobody, POP3 hashes passwords", "Anyone who can capture the packets", "Only the home router"],
      answer: 2,
      why: "Port 110 POP3 is plain text. Every device that sees the packets can read the password byte for byte.",
    },
    events: [
      P.a("amber", "USER", [USER], 0.062, `C: USER ${USER}`, [pop([`USER ${USER}`])]),
      P.b("violet", "+OK", [], 0.092, "S: +OK", [pop(["+OK"])]),
      P.a("red", "PASS", [PASS, "readable by anyone!"], 0.093, `C: PASS ${PASS}`, [pop([`PASS ${PASS}`], { 0: "The password in clear text. This is the problem with port 110." })]),
      P.b("green", "+OK", ["logged in"], 0.135, "S: +OK Logged in.", [pop(["+OK Logged in."])]),
      note("client", "PASSWORD SENT IN CLEAR", "red"),
    ],
  },
  {
    title: "STAT and LIST",
    desc: "How many messages, and how big?",
    detail: `STAT gives a quick summary: number of messages and total size in bytes (octets). LIST gives the size of each message, one per line, and ends with a line holding a single dot. Danish has 2 messages totalling ${SIZE1 + SIZE2} bytes.`,
    facts: [["STAT", `+OK 2 ${SIZE1 + SIZE2}`], ["LIST", `1 → ${SIZE1}, 2 → ${SIZE2} bytes`], ["Multi-line end", "A line with only a dot"]] as [string, string][],
    quiz: {
      q: `The server replies "+OK 2 ${SIZE1 + SIZE2}" to STAT. What does 2 mean?`,
      options: ["Protocol version 2", "Two messages in the mailbox", "Two new messages since yesterday", "Message number 2 is next"],
      answer: 1,
      why: "STAT answers with the message count and total size in octets. Here: 2 messages.",
    },
    events: [
      P.a("amber", "STAT", [], 0.136, "C: STAT", [pop(["STAT"])]),
      P.b("violet", "+OK 2", [`${SIZE1 + SIZE2} bytes`], 0.166, `S: +OK 2 ${SIZE1 + SIZE2}`, [pop([`+OK 2 ${SIZE1 + SIZE2}`], { 0: "Message count, then total size in octets." })]),
      P.a("amber", "LIST", [], 0.167, "C: LIST", [pop(["LIST"])]),
      P.b("violet", "+OK", [`1: ${SIZE1}`, `2: ${SIZE2}`], 0.197, "S: +OK 2 messages:", [pop(["+OK 2 messages:", `1 ${SIZE1}`, `2 ${SIZE2}`, "."], { 3: "A single dot ends a multi-line reply." })]),
    ],
  },
  {
    title: "RETR 1",
    desc: "Download message 1, headers and body",
    detail: `RETR 1 asks for the whole of message 1. The server says +OK ${SIZE1} octets, then sends the message exactly as it was stored: headers, a blank line, the body, and the closing dot. POP3 can't fetch just part of a message (TOP is a rarely used exception).`,
    facts: [["Command", "RETR 1"], ["Size", `${SIZE1} octets`], ["From", "Priya <priya@example.org>"]] as [string, string][],
    events: [
      P.a("amber", "RETR 1", [], 0.198, "C: RETR 1", [pop(["RETR 1"])]),
      P.b("violet", "MESSAGE", ["Re: Notes for Friday", `${SIZE1} bytes`], 0.229, `S: +OK ${SIZE1} octets`, [pop([`+OK ${SIZE1} octets`, ...MSG1, "."], { 1: "Added at delivery: where bounces would go.", 7: "A blank line separates headers from the body.", 9: "End of the message." })]),
    ],
  },
  {
    title: "DELE and QUIT",
    desc: "Mark for deletion, then commit",
    detail: "DELE 1 only marks the message. Nothing is removed until QUIT moves the session into the UPDATE state, where the server really deletes it. If the connection drops before QUIT, the message stays. This download-and-delete habit is why POP3 suits one device and IMAP suits many.",
    facts: [["DELE 1", "Marked, not yet deleted"], ["QUIT", "Commit deletions, close"], ["States", "AUTHORIZATION → TRANSACTION → UPDATE"]] as [string, string][],
    quiz: {
      q: "The Wi-Fi drops after DELE 1 but before QUIT. What happens to message 1?",
      options: ["It is deleted", "It stays on the server", "It is moved to Trash", "It is corrupted"],
      answer: 1,
      why: "Deletions only happen in the UPDATE state, which starts with QUIT. A broken session deletes nothing.",
    },
    events: [
      P.a("amber", "DELE 1", [], 0.230, "C: DELE 1", [pop(["DELE 1"])]),
      P.b("violet", "+OK", ["marked"], 0.260, "S: +OK Marked to be deleted.", [pop(["+OK Marked to be deleted."])]),
      P.a("slate", "QUIT", [], 0.261, "C: QUIT", [pop(["QUIT"])]),
      P.b("slate", "+OK", ["bye"], 0.291, "S: +OK Logging out, messages deleted.", [pop(["+OK Logging out, messages deleted."])]),
      P.b("slate", "FIN", ["server closes"], 0.292, "110 → 50620 [FIN, ACK]", [], {}, "FA"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 2: wrong password

const W = conv(110, 50644, [0x2210ff01, 0x6bd04120]);
const wrongSteps = [
  {
    title: "Wrong password",
    desc: "USER is fine, PASS is not",
    detail: "Danish changed his password on the web but his old laptop still has the old one saved. The server accepts USER (it doesn't reveal whether the user exists) and then rejects PASS with -ERR.",
    facts: [["Reply", "-ERR [AUTH] Authentication failed."], ["USER reply", "Always +OK, to hide which accounts exist"], ["Delay", "About 2 s before -ERR"]] as [string, string][],
    quiz: {
      q: "Why does the server answer +OK to USER even for names that don't exist?",
      options: ["It's a bug", "So attackers can't use it to test which accounts exist", "Because POP3 has no user list", "To save time"],
      answer: 1,
      why: "If USER said -ERR for unknown names, an attacker could check names one by one. Hiding it until PASS gives nothing away.",
    },
    events: [
      ...W.handshake(0, 0.03),
      W.b("green", "+OK", ["ready"], 0.061, `S: ${GREETING}`, [pop([GREETING])]),
      W.a("amber", "USER", [USER], 0.062, `C: USER ${USER}`, [pop([`USER ${USER}`])]),
      W.b("violet", "+OK", [], 0.092, "S: +OK", [pop(["+OK"])]),
      W.a("amber", "PASS", ["old password"], 0.093, "C: PASS old-password-1", [pop(["PASS old-password-1"])]),
      W.b("red", "-ERR", ["auth failed"], 2.095, "S: -ERR [AUTH] Authentication failed.", [pop(["-ERR [AUTH] Authentication failed."], { 0: "[AUTH] is a response code from RFC 3206: a login problem, not a server fault." })]),
      note("server", "WAITED 2 s BEFORE -ERR", "amber"),
    ],
  },
  {
    title: "Give up cleanly",
    desc: "The app quits and asks Danish",
    detail: "The mail app sends QUIT and shows a password prompt. The 2-second delay before each -ERR slows down anyone trying to guess passwords, and many servers lock or throttle an account after several failures.",
    facts: [["Client", "QUIT, then prompt the user"], ["Defence", "Delay + rate limit failed logins"], ["Mailbox", "Untouched"]] as [string, string][],
    events: [
      W.a("slate", "QUIT", [], 2.096, "C: QUIT", [pop(["QUIT"])]),
      W.b("slate", "+OK", ["bye"], 2.126, "S: +OK Logging out", [pop(["+OK Logging out"])]),
      note("client", "PLEASE ENTER PASSWORD", "red"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 3: sniffed on café Wi-Fi, fixed by POP3S

const cafeDevices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: "café Wi-Fi", x: 9, y: 62 },
  { id: "router", kind: "ap" as const, label: "Café Wi-Fi", sub: "open network", x: 32, y: 62 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 58, y: 40 },
  { id: "server", kind: "mail" as const, label: "Mail server", sub: `${HOST} ${S}`, x: 87, y: 62 },
  { id: "attacker", kind: "attacker" as const, label: "Eavesdropper", sub: "same Wi-Fi", x: 22, y: 22 },
];
const cafeLinks: [string, string][] = [["client", "router"], ["router", "internet"], ["internet", "server"], ["attacker", "router"]];

const X = conv(110, 50701, [0x7a001234, 0x19ab0001]);
const T = conv(995, 50702, [0x55aa0101, 0x3c3c0f0f]);

const sniffSteps = [
  {
    title: "Login on open Wi-Fi",
    desc: "Same USER/PASS, but someone is listening",
    detail: "Danish checks mail in a café. The Wi-Fi has no password, so every radio frame can be captured by anyone nearby. An eavesdropper runs a packet capture and filters for port 110.",
    facts: [["Network", "Open café Wi-Fi"], ["Port", "110, plain text"], ["Eavesdropper", "Passive, sends nothing"]] as [string, string][],
    events: [
      X.a("amber", "USER", [USER], 0, `C: USER ${USER}`, [pop([`USER ${USER}`])]),
      X.b("violet", "+OK", [], 0.03, "S: +OK", [pop(["+OK"])]),
      X.a("red", "PASS", [PASS], 0.031, `C: PASS ${PASS}`, [pop([`PASS ${PASS}`])]),
      note("attacker", `CAPTURED: ${USER} / ${PASS}`, "red"),
    ],
  },
  {
    title: "Defence: POP3S on 995",
    desc: "TLS first, then POP3",
    detail: "With POP3S the TLS handshake happens straight after TCP connects, before a single POP3 word. The client also checks the server's certificate for pop.mailhost.example, so a fake server can't step in. (STLS on port 110 does the same upgrade, like STARTTLS in SMTP.)",
    facts: [["Port", "995 (implicit TLS)"], ["Checks", `Certificate for ${HOST}`], ["Alternative", "STLS command on 110"]] as [string, string][],
    quiz: {
      q: "On port 995, what is the first thing the client sends after the TCP handshake?",
      options: ["USER danish", "STLS", "A TLS Client Hello", "CAPA"],
      answer: 2,
      why: "Port 995 is implicit TLS: TLS starts at once. POP3 only begins once the tunnel is up.",
    },
    events: [
      ...T.handshake(1, 0.03),
      T.a("teal", "HELLO", ["Client Hello", `SNI ${HOST}`], 1.031, `Client Hello (SNI=${HOST})`, [clientHello(HOST)]),
      T.b("teal", "HELLO", ["Server Hello", "+ certificate"], 1.062, "Server Hello, Change Cipher Spec, Application Data", [serverFlight(1150)]),
      T.a("teal", "FINISHED", ["keys agreed"], 1.063, "Change Cipher Spec, Application Data", [clientFinished()]),
    ],
  },
  {
    title: "The eavesdropper sees noise",
    desc: "USER and PASS, encrypted",
    detail: "The same POP3 commands now ride inside TLS records. The eavesdropper sees that Danish talked to a mail server and roughly how many bytes moved, but not the username, password or messages.",
    facts: [["Inside", `+OK greeting, USER, PASS`], ["Attacker sees", "IP, port 995, sizes"], ["Attacker can't see", "Password, mail"]] as [string, string][],
    events: [
      T.b("teal", "+OK", ["(encrypted)"], 1.094, "Application Data", [enc([GREETING], `POP3: ${GREETING}`)]),
      T.a("teal", "USER", ["(encrypted)"], 1.095, "Application Data", [enc([`USER ${USER}`], `POP3: USER ${USER}`)]),
      T.b("teal", "+OK", ["(encrypted)"], 1.125, "Application Data", [enc(["+OK"], "POP3: +OK")]),
      T.a("teal", "PASS", ["(encrypted)"], 1.126, "Application Data", [enc([`PASS ${PASS}`], "POP3: PASS <hidden>")]),
      T.b("teal", "+OK", ["logged in", "(encrypted)"], 1.168, "Application Data", [enc(["+OK Logged in."], "POP3: +OK Logged in.")]),
      note("attacker", "ONLY RANDOM-LOOKING BYTES", "green"),
    ],
  },
];

export default defineLesson({
  id: "pop3",
  name: "POP3",
  full: "Post Office Protocol version 3",
  group: "mail-files",
  layer: 7,
  difficulty: 1,
  tagline: "Download your mail, then (usually) delete it from the server.",
  description:
    "POP3 is the oldest simple way to read mail: log in, list the messages, download them and optionally delete them from the server. It's a short text conversation where every reply starts with +OK or -ERR. Today it should always run inside TLS on port 995.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP 110 (plain/STLS), 995 (POP3S)"],
    ["Defined in", "RFC 1939"],
    ["Replies", "+OK or -ERR"],
    ["Model", "Download and delete"],
    ["Secure version", "POP3S (RFC 8314)"],
  ],
  ports: "110 POP3, 995 POP3S",
  rfc: "RFC 1939, RFC 2595, RFC 8314",
  keywords: ["email", "mail", "pop", "retr", "dele", "stat", "list", "995", "plaintext password", "download"],
  related: ["imap", "smtp", "tls", "tcp"],
  ...base,
  legend: [
    ["green", "Handshake and success"],
    ["amber", "Commands from the mail app"],
    ["violet", "Replies and mail from the server"],
    ["teal", "TLS: encrypted"],
    ["red", "Exposed password or error"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Download and delete one message",
      summary: "Log in on port 110, check the mailbox, fetch message 1, delete it and quit.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "Mail downloaded",
        text: "POP3 logged in, counted and sized the messages, downloaded message 1, and deleted it on QUIT. It worked, but the password crossed the network in plain text, which is why port 110 without TLS should never be used today.",
        facts: [["Commands", "USER, PASS, STAT, LIST, RETR, DELE, QUIT"], ["Message size", `${SIZE1} octets`], ["Weak spot", "Plain-text password on 110"], ["Total time", "0.292 s"]],
      },
    },
    {
      id: "bad-password",
      name: "Wrong password: -ERR",
      summary: "An old saved password is rejected after a deliberate delay.",
      kind: "failure",
      steps: wrongSteps,
      outro: {
        title: "Login refused",
        text: "The server answered -ERR [AUTH] after a delay and the app asked Danish for his new password. The delay and rate limits make guessing passwords slow.",
        facts: [["Reply", "-ERR [AUTH] Authentication failed."], ["Delay", "≈2 s"], ["Mailbox", "Unchanged"]],
      },
    },
    {
      id: "sniffed",
      name: "Sniffed on café Wi-Fi, fixed by POP3S",
      summary: "A listener grabs the clear-text password; port 995 with TLS hides it.",
      kind: "attack",
      devices: cafeDevices,
      links: cafeLinks,
      steps: sniffSteps,
      outro: {
        title: "Encrypt or expose",
        text: "On port 110 the eavesdropper copied the password without sending a single packet. On port 995 the same commands were wrapped in TLS, so the capture showed only the server address and byte counts.",
        facts: [["Attack", "Passive sniffing"], ["Defence", "POP3S on 995 (or STLS), app passwords"], ["Rule", "Never send passwords on 110"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Commands",
      items: [["USER / PASS", "Log in (plain text!)"], ["STAT", "Count and total size"], ["LIST", "Size of each message"], ["RETR n", "Download message n"], ["DELE n", "Mark message n for deletion"], ["RSET", "Undo deletion marks"], ["QUIT", "Commit and close"], ["STLS", "Upgrade to TLS on port 110"]],
    },
    {
      title: "Replies and states",
      items: [["+OK", "Success"], ["-ERR", "Failure"], ["Multi-line", "Ends with a line holding only a dot"], ["States", "AUTHORIZATION, TRANSACTION, UPDATE"]],
    },
    {
      title: "Ports",
      items: [["110", "POP3 (plain or STLS)"], ["995", "POP3S: TLS from the first byte"]],
    },
  ],
});
