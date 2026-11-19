import { Color, defineLesson, note, pkt, PacketEvent } from "@/lib/lesson";
import { build, LayerSpec, textLayer } from "@/lib/packet";
import { ext, hsMsg, tcp, TcpOpt, tls, vec } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

const S = ADDR.mail;
const HOST = "imap.mailhost.example";
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

// ---------------------------------------------------------------- IMAP and TLS layers

const imap = (lines: string[], notes?: Record<number, string>) => textLayer({ id: "imap", name: "IMAP", lines, notes });
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

// ---------------------------------------------------------------- mailbox content

const GREETING = "* OK [CAPABILITY IMAP4rev1 SASL-IR LITERAL+ ID ENABLE IDLE STARTTLS LOGINDISABLED] Dovecot ready.";
const LOGIN = 'a1 LOGIN danish "correct-horse-42"';
const LOGIN_OK = "a1 OK [CAPABILITY IMAP4rev1 SASL-IR LITERAL+ ID ENABLE IDLE SORT THREAD=REFS MOVE CONDSTORE] Logged in";
const SELECT_REPLY = [
  "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)",
  "* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted.",
  "* 4 EXISTS",
  "* 0 RECENT",
  "* OK [UNSEEN 4] First unseen.",
  "* OK [UIDVALIDITY 1763529600] UIDs valid",
  "* OK [UIDNEXT 105] Predicted next UID",
  "a2 OK [READ-WRITE] Select completed (0.001 + 0.000 secs).",
];

const MAILS: [string, string, string, string][] = [
  ["\\Seen", "Bank of Example <alerts@bank.example>", "Your statement is ready", "Mon, 16 Nov 2026 09:00:12 +0530"],
  ["\\Seen", "Priya <priya@example.org>", "Re: Notes for Friday", "Thu, 19 Nov 2026 11:02:41 +0530"],
  ["\\Seen \\Flagged", "Ravi <ravi@example.net>", "Lab report draft", "Thu, 19 Nov 2026 12:40:05 +0530"],
  ["", "College Office <office@example.edu>", "Exam timetable", "Thu, 19 Nov 2026 14:18:30 +0530"],
];
const NEW_MAIL: [string, string, string, string] = ["", "Priya <priya@example.org>", "One more thing", "Thu, 19 Nov 2026 15:07:52 +0530"];
const FIELDS = "BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)]";

/** One FETCH response with a correctly sized {literal}. */
const fetchLines = (n: number, [flags, from, subj, date]: [string, string, string, string]) => {
  const hdr = [`From: ${from}`, `Subject: ${subj}`, `Date: ${date}`, ""];
  const len = hdr.reduce((k, l) => k + l.length + 2, 0);
  return [`* ${n} FETCH (UID ${100 + n} FLAGS (${flags}) BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {${len}}`, ...hdr, ")"];
};
const FETCH_REPLY = [...MAILS.flatMap((m, i) => fetchLines(i + 1, m)), "a3 OK Fetch completed (0.002 + 0.000 secs)."];
const NEW_FETCH_REPLY = [...fetchLines(5, NEW_MAIL), "a5 OK Fetch completed."];

// ---------------------------------------------------------------- devices and conversations

const base = homeToServer({ kind: "mail", label: "IMAP server", sub: `${HOST} ${S}` });
const conv = (sport: number, bases: [number, number]) =>
  conversation(
    { id: "client", layers: () => up(S), port: sport, base: bases[0], win: 502 },
    { id: "server", layers: () => down(S), port: 143, base: bases[1], win: 509 }
  );

const C = conv(50432, [0x61b0e3a2, 0x2c0a7710]);

/** connect + STARTTLS + TLS handshake, reused by both scenarios */
const connectAndUpgrade = (X: ReturnType<typeof conv>, t: number) => ({
  connect: [
    ...X.handshake(t, 0.03),
    X.b("green", "* OK", ["IDLE, STARTTLS", "LOGINDISABLED"], t + 0.062, `S: ${GREETING}`, [imap([GREETING], { 0: "Untagged (*) greeting. LOGINDISABLED: no password allowed until TLS is on." })]),
  ],
  upgrade: [
    X.a("teal", "STARTTLS", ["a0 STARTTLS"], t + 0.063, "C: a0 STARTTLS", [imap(["a0 STARTTLS"], { 0: "a0 is the tag: the client's label for this command." })]),
    X.b("teal", "a0 OK", ["begin TLS"], t + 0.093, "S: a0 OK Begin TLS negotiation now.", [imap(["a0 OK Begin TLS negotiation now."], { 0: "The reply carries the same tag, a0." })]),
    X.a("teal", "HELLO", ["Client Hello", `SNI ${HOST}`], t + 0.094, `Client Hello (SNI=${HOST})`, [clientHello(HOST)]),
    X.b("teal", "HELLO", ["Server Hello", "+ certificate"], t + 0.126, "Server Hello, Change Cipher Spec, Application Data", [serverFlight(1150)]),
    X.a("teal", "FINISHED", ["keys agreed"], t + 0.127, "Change Cipher Spec, Application Data", [clientFinished()]),
  ],
});

const U1 = connectAndUpgrade(C, 0);

const normalSteps = [
  {
    title: "Connect to port 143",
    desc: "The server greets with its capabilities",
    detail: "Danish's mail app connects to port 143. The server's greeting starts with *, which marks an untagged response: information the client didn't ask for directly. It lists capabilities, including IDLE and STARTTLS, and LOGINDISABLED, which means passwords are refused until TLS is running.",
    facts: [["Server", `${S} port 143`], ["*", "Untagged: server information"], ["LOGINDISABLED", "No login before STARTTLS"]] as [string, string][],
    events: U1.connect,
  },
  {
    title: "STARTTLS",
    desc: "Tagged command, tagged reply, then TLS",
    detail: "Every IMAP command starts with a tag the client invents, like a0. The server's final answer repeats the tag, so the client can match replies even when several commands are in flight. After a0 OK, the TLS 1.3 handshake runs on the same TCP connection. Everything after this is encrypted.",
    facts: [["Command", "a0 STARTTLS"], ["Reply", "a0 OK Begin TLS negotiation now."], ["After", "TLS 1.3 on the same connection"]] as [string, string][],
    quiz: {
      q: "Why does every IMAP command carry a tag like a0 or a1?",
      options: ["To encrypt the command", "So replies can be matched to commands, even when several run at once", "To count messages", "Because TCP needs it"],
      answer: 1,
      why: "The final reply repeats the tag. Untagged * lines can arrive any time, so tags keep things matched.",
    },
    events: [...U1.upgrade, note("client", "ENCRYPTED FROM HERE", "green")],
  },
  {
    title: "a1 LOGIN",
    desc: "Username and password, inside TLS",
    detail: `Decrypted, the client sends: ${LOGIN}. The server answers "a1 OK [CAPABILITY …] Logged in" and lists more capabilities now that Danish is known, such as MOVE and CONDSTORE. On the wire, an eavesdropper only sees two TLS records of about ${encLen([LOGIN])} and ${encLen([LOGIN_OK])} bytes.`,
    facts: [["Decrypted", LOGIN], ["Reply", "a1 OK … Logged in"], ["On the wire", "TLS Application Data only"]] as [string, string][],
    events: [
      C.a("teal", "a1 LOGIN", ["danish ****", "(encrypted)"], 0.128, "Application Data", [enc([LOGIN], "IMAP: a1 LOGIN danish <password>")]),
      C.b("teal", "a1 OK", ["logged in", "(encrypted)"], 0.170, "Application Data", [enc([LOGIN_OK], "IMAP: a1 OK [CAPABILITY …] Logged in")]),
    ],
  },
  {
    title: "a2 SELECT INBOX",
    desc: "Open a mailbox and get its state",
    detail: "SELECT opens a folder. Decrypted, the server sends several untagged lines first: the allowed flags, * 4 EXISTS (four messages), the first unseen message, and UIDVALIDITY and UIDNEXT, which let the app cache messages by their permanent UID. The tagged a2 OK [READ-WRITE] closes the reply.",
    facts: [["Decrypted", "a2 SELECT INBOX"], ["* 4 EXISTS", "4 messages in INBOX"], ["UIDNEXT", "105: the next message gets UID 105"]] as [string, string][],
    quiz: {
      q: "The server sends untagged lines and then \"a2 OK\". How does the app know the SELECT reply is complete?",
      options: ["The connection closes", "The tagged line a2 OK arrives", "After exactly 8 lines", "A line with a single dot"],
      answer: 1,
      why: "A tagged response with the command's tag always ends that command. Everything before it was untagged data.",
    },
    events: [
      C.a("teal", "a2 SELECT", ["INBOX", "(encrypted)"], 0.171, "Application Data", [enc(["a2 SELECT INBOX"], "IMAP: a2 SELECT INBOX")]),
      C.b("teal", "4 EXISTS", ["flags, UIDs", "a2 OK"], 0.202, "Application Data", [enc(SELECT_REPLY, "IMAP: * FLAGS … * 4 EXISTS … a2 OK [READ-WRITE]")]),
    ],
  },
  {
    title: "a3 FETCH headers",
    desc: "Just From, Subject and Date for the list",
    detail: `To draw the message list the app doesn't download whole mails. Decrypted: "a3 FETCH 1:4 (UID FLAGS ${FIELDS})". Each answer carries the header text as a literal: {n} announces exactly n bytes follow. PEEK means "don't mark as read". The bodies stay on the server until Danish opens a message.`,
    facts: [["Range", "1:4 (all four)"], ["Literal", "{n} = n bytes of header text follow"], ["BODY.PEEK", "Fetch without setting \\Seen"]] as [string, string][],
    quiz: {
      q: "Why use BODY.PEEK[…] instead of BODY[…] here?",
      options: ["PEEK is faster", "BODY[…] would mark the messages as read", "PEEK is encrypted", "BODY[…] only works on POP3"],
      answer: 1,
      why: "Fetching BODY[…] sets the \\Seen flag. Showing a list shouldn't mark mail as read, so PEEK is used.",
    },
    events: [
      C.a("teal", "a3 FETCH", ["1:4 headers", "(encrypted)"], 0.203, "Application Data", [enc([`a3 FETCH 1:4 (UID FLAGS ${FIELDS})`], `IMAP: a3 FETCH 1:4 (UID FLAGS ${FIELDS})`)]),
      C.b("teal", "4 × FETCH", ["From, Subject, Date", "a3 OK"], 0.236, "Application Data", [enc(FETCH_REPLY, "IMAP: * 1 FETCH … * 4 FETCH … a3 OK")]),
    ],
  },
  {
    title: "a4 IDLE",
    desc: "Keep the line open, wait for news",
    detail: "Instead of asking for new mail every few minutes, the app sends a4 IDLE. The server answers with a continuation line, \"+ idling\", and then the connection simply stays quiet. The app re-sends IDLE at least every 29 minutes so routers don't forget the connection.",
    facts: [["Command", "a4 IDLE"], ["Reply", "+ idling (continuation)"], ["Refresh", "Every < 29 minutes"]] as [string, string][],
    events: [
      C.a("teal", "a4 IDLE", ["(encrypted)"], 0.3, "Application Data", [enc(["a4 IDLE"], "IMAP: a4 IDLE")]),
      C.b("teal", "+ idling", ["(encrypted)"], 0.331, "Application Data", [enc(["+ idling"], "IMAP: + idling")]),
      note("client", "WAITING FOR PUSH", "blue"),
    ],
  },
  {
    title: "New mail is pushed",
    desc: "* 5 EXISTS, then DONE and a FETCH",
    detail: "Twelve seconds later Priya's new mail lands. The server immediately pushes the untagged line * 5 EXISTS. The app ends IDLE with DONE (no tag), the server closes it with a4 OK, and the app fetches just the headers of message 5. Danish sees a notification almost instantly.",
    facts: [["Push", "* 5 EXISTS"], ["End idle", "DONE → a4 OK Idle completed."], ["Then", "a5 FETCH 5 (headers)"]] as [string, string][],
    quiz: {
      q: "The app is idling with 4 messages. What does the untagged line \"* 5 EXISTS\" tell it?",
      options: ["Message 5 was deleted", "The mailbox now holds 5 messages: one new one arrived", "5 messages are unread", "The server wants a 5-second break"],
      answer: 1,
      why: "EXISTS gives the new message count. Going from 4 to 5 means one message was added.",
    },
    events: [
      C.b("teal", "* 5 EXISTS", ["new mail!", "(encrypted)"], 12.48, "Application Data", [enc(["* 5 EXISTS", "* 1 RECENT"], "IMAP: * 5 EXISTS / * 1 RECENT")]),
      C.a("teal", "DONE", ["(encrypted)"], 12.481, "Application Data", [enc(["DONE"], "IMAP: DONE")]),
      C.b("teal", "a4 OK", ["(encrypted)"], 12.512, "Application Data", [enc(["a4 OK Idle completed (12.18 secs)."], "IMAP: a4 OK Idle completed.")]),
      C.a("teal", "a5 FETCH", ["5 headers", "(encrypted)"], 12.513, "Application Data", [enc([`a5 FETCH 5 (UID FLAGS ${FIELDS})`], "IMAP: a5 FETCH 5 (UID FLAGS BODY.PEEK[HEADER.FIELDS …])")]),
      C.b("teal", "FETCH", ["One more thing", "(encrypted)"], 12.545, "Application Data", [enc(NEW_FETCH_REPLY, "IMAP: * 5 FETCH (UID 105 …) a5 OK")]),
      note("client", "NEW: ONE MORE THING", "green"),
    ],
  },
];

// ---------------------------------------------------------------- failure: wrong password

const W = conv(50470, [0x0abc1234, 0x7f00e001]);
const U2 = connectAndUpgrade(W, 0);
const BAD_LOGIN = 'a1 LOGIN danish "old-password-1"';
const BAD_REPLY = "a1 NO [AUTHENTICATIONFAILED] Authentication failed.";

const failSteps = [
  {
    title: "Connect and STARTTLS",
    desc: "Same start as always",
    detail: "Danish's phone still has his old password. It connects to port 143, upgrades with STARTTLS and is ready to log in. Nothing looks wrong yet.",
    facts: [["Port", "143 + STARTTLS"], ["TLS", "1.3"], ["Saved password", "Out of date"]] as [string, string][],
    events: [...U2.connect, ...U2.upgrade],
  },
  {
    title: "a1 NO [AUTHENTICATIONFAILED]",
    desc: "The tagged reply says NO",
    detail: `Decrypted, the app sends ${BAD_LOGIN} and gets "${BAD_REPLY}". IMAP has three result words: OK (worked), NO (refused, the command was fine) and BAD (the command itself was broken). The code in square brackets tells software exactly why, so the app can ask for a new password instead of showing a vague error.`,
    facts: [["Reply", BAD_REPLY], ["NO vs BAD", "Refused vs malformed command"], ["Delay", "Server waits ~2 s to slow guessing"]] as [string, string][],
    quiz: {
      q: "What would the server reply if the app sent \"a1 LOGN danish x\" (a typo in the command)?",
      options: ["a1 NO [AUTHENTICATIONFAILED]", "a1 BAD Error in IMAP command", "* BYE", "a1 OK"],
      answer: 1,
      why: "BAD is for commands the server can't understand. NO means it understood but refused.",
    },
    events: [
      W.a("teal", "a1 LOGIN", ["old password", "(encrypted)"], 0.128, "Application Data", [enc([BAD_LOGIN], "IMAP: a1 LOGIN danish <old password>")]),
      W.b("red", "a1 NO", ["AUTHENTICATIONFAILED", "(encrypted)"], 2.131, "Application Data", [enc([BAD_REPLY], `IMAP: ${BAD_REPLY}`)]),
      note("client", "AUTHENTICATION FAILED", "red"),
    ],
  },
  {
    title: "Log out politely",
    desc: "a2 LOGOUT, * BYE, a2 OK",
    detail: "The app logs out and asks Danish for his password. LOGOUT gets an untagged * BYE (the server is about to close) and then the tagged a2 OK. Many servers lock an account for a while after repeated NO replies.",
    facts: [["Command", "a2 LOGOUT"], ["Replies", "* BYE, then a2 OK"], ["Next", "Prompt for new password"]] as [string, string][],
    events: [
      W.a("slate", "a2 LOGOUT", ["(encrypted)"], 2.132, "Application Data", [enc(["a2 LOGOUT"], "IMAP: a2 LOGOUT")]),
      W.b("slate", "* BYE", ["a2 OK", "(encrypted)"], 2.163, "Application Data", [enc(["* BYE Logging out", "a2 OK Logout completed."], "IMAP: * BYE Logging out / a2 OK Logout completed.")]),
    ],
  },
];

export default defineLesson({
  id: "imap",
  name: "IMAP",
  full: "Internet Message Access Protocol",
  group: "mail-files",
  layer: 7,
  difficulty: 2,
  tagline: "Mail that stays on the server and syncs to every device.",
  description:
    "IMAP lets mail apps work with mailboxes that live on the server, so your phone and laptop see the same folders, flags and messages. Commands are tagged so replies can be matched, and IDLE lets the server push new mail the moment it arrives.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP 143 (STARTTLS), 993 (IMAPS)"],
    ["Defined in", "RFC 9051 (IMAP4rev2), RFC 3501"],
    ["Style", "Tagged commands, untagged data"],
    ["Push", "IDLE (RFC 2177)"],
    ["Model", "Mail stays on the server"],
  ],
  ports: "143 IMAP + STARTTLS, 993 IMAPS",
  rfc: "RFC 9051, RFC 3501, RFC 2177",
  keywords: ["email", "mail", "imap", "idle", "push", "fetch", "select", "starttls", "993", "tag", "exists"],
  related: ["pop3", "smtp", "tls", "tcp"],
  ...base,
  legend: [
    ["green", "Handshake and success"],
    ["teal", "TLS and encrypted IMAP"],
    ["violet", "Server replies (in clear)"],
    ["red", "Login refused"],
    ["slate", "Logging out"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Sync the inbox and get a push",
      summary: "STARTTLS, LOGIN, SELECT, FETCH headers, then IDLE until new mail is pushed.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "Inbox in sync",
        text: "The app upgraded to TLS, logged in, opened INBOX, fetched only the headers it needed, then waited with IDLE. When mail arrived, the server pushed * 5 EXISTS and the app fetched the new headers within milliseconds.",
        facts: [["Tags used", "a0 to a5"], ["Messages", "4, then 5"], ["Push delay", "Instant (IDLE)"], ["Bodies downloaded", "None yet"]],
      },
    },
    {
      id: "auth-failed",
      name: "Old password: NO [AUTHENTICATIONFAILED]",
      summary: "The phone's saved password is out of date and the server refuses the login.",
      kind: "failure",
      steps: failSteps,
      outro: {
        title: "Login refused",
        text: "The LOGIN command was understood but refused, so the server said NO with the AUTHENTICATIONFAILED code. The app logged out cleanly and asked Danish for his new password.",
        facts: [["Reply", "a1 NO [AUTHENTICATIONFAILED]"], ["Result words", "OK, NO, BAD"], ["Fix", "Update the saved password"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Commands",
      items: [["LOGIN / AUTHENTICATE", "Log in"], ["SELECT / EXAMINE", "Open a folder (read-write / read-only)"], ["FETCH", "Get flags, headers, bodies"], ["STORE", "Change flags (\\Seen, \\Flagged…)"], ["SEARCH", "Find messages on the server"], ["IDLE / DONE", "Wait for push / stop waiting"], ["LOGOUT", "Close the session"]],
    },
    {
      title: "Responses",
      items: [["a1 OK / NO / BAD", "Tagged: success / refused / malformed"], ["*", "Untagged data (EXISTS, FETCH, FLAGS…)"], ["+", "Continuation: go on"], ["{n}", "A literal of exactly n bytes follows"]],
    },
    {
      title: "Ports",
      items: [["143", "IMAP, upgrade with STARTTLS"], ["993", "IMAPS: TLS from the first byte"]],
    },
  ],
});
