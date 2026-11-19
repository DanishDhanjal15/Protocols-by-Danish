import { Color, defineLesson, note, pkt, PacketEvent } from "@/lib/lesson";
import { build, LayerSpec, textLayer } from "@/lib/packet";
import { dns, eth, ext, hsMsg, ipv4, tcp, TcpOpt, tls, udp, vec } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

// ---------------------------------------------------------------- addresses and names

const SUBMIT = ADDR.mail; // 203.0.113.25, Danish's mail provider
const MX = "198.51.100.25"; // the recipient's mail exchanger
const GW_MAC = "00:00:5e:00:01:01"; // the data-centre gateway next to the submission server
const MX_MAC = "00:16:3e:9c:44:10";
const SUBMIT_HOST = "smtp.mailhost.example";
const MX_HOST = "mx1.example.org";
const FROM = "danish@mailhost.example";
const TO = "priya@example.org";
const PASSWORD = "correct-horse-42";
const AUTH_B64 = btoa(`\0${FROM}\0${PASSWORD}`);

const r = (n: number) => Number(n.toFixed(4));

// ---------------------------------------------------------------- a small TCP conversation helper

interface End { id: string; layers: () => LayerSpec[]; port: number; base: number; win: number }

/** Tracks relative sequence numbers in both directions so every segment lines up. */
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
  const msg = (fromA: boolean) => (color: Color, label: string, lines: string[], time: number, info: string, app: LayerSpec[], extra: Partial<PacketEvent> = {}): PacketEvent =>
    pkt(fromA ? a.id : b.id, fromA ? b.id : a.id, color, label, lines, { time: r(time), info, packet: send(fromA, "PA", app), ...extra });
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

// ---------------------------------------------------------------- SMTP and TLS layers

const smtp = (lines: string[], notes?: Record<number, string>, name = "SMTP") => textLayer({ id: "smtp", name, lines, notes });
/** size of a TLS 1.3 record carrying these text lines: text + 1 content-type byte + 16-byte tag */
const encLen = (lines: string[]) => lines.reduce((n, l) => n + l.length + 2, 0) + 17;
const enc = (lines: string[], what: string) => tls({ records: [{ type: "appdata", encrypted: encLen(lines), what }], summary: `TLS Application Data (inside: ${what})` });

const clientHello = (sni: string) =>
  tls({
    records: [{
      type: "handshake", version: 0x0301,
      fields: [hsMsg("client_hello", "Client Hello", [
        { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "A legacy field. The real version list is in supported_versions." },
        { name: "Random", random: 32, note: "32 fresh random bytes from the client." },
        vec("Session ID", 1, [{ name: "Session ID", random: 32 }]),
        vec("Cipher suites", 2, [
          { name: "TLS_AES_128_GCM_SHA256", u16: 0x1301, value: "0x1301" },
          { name: "TLS_AES_256_GCM_SHA384", u16: 0x1302, value: "0x1302" },
          { name: "TLS_CHACHA20_POLY1305_SHA256", u16: 0x1303, value: "0x1303" },
        ], "3 suites"),
        vec("Compression methods", 1, [{ name: "null", u8: 0 }]),
        vec("Extensions", 2, [
          ext(0, "server_name", [vec("Server name list", 2, [{ name: "Type", u8: 0, value: "host_name" }, vec("Host name", 2, [{ name: "Name", text: sni }], sni)])], sni, "Which server name the client expects on the certificate."),
          ext(10, "supported_groups", [vec("Groups", 2, [{ name: "x25519", u16: 0x001d, value: "x25519" }, { name: "secp256r1", u16: 0x0017, value: "secp256r1" }])]),
          ext(13, "signature_algorithms", [vec("Algorithms", 2, [{ name: "ecdsa_secp256r1_sha256", u16: 0x0403, value: "0x0403" }, { name: "rsa_pss_rsae_sha256", u16: 0x0804, value: "0x0804" }, { name: "rsa_pkcs1_sha256", u16: 0x0401, value: "0x0401" }])]),
          ext(43, "supported_versions", [vec("Versions", 1, [{ name: "TLS 1.3", u16: 0x0304, value: "TLS 1.3" }])], "TLS 1.3"),
          ext(51, "key_share", [vec("Client key shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32 }])])], "x25519", "The client's half of the key agreement."),
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
          vec("Session ID", 1, [{ name: "Session ID", random: 32 }], undefined, "Echoes the client's session ID."),
          { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256" },
          { name: "Compression method", u8: 0, value: "null" },
          vec("Extensions", 2, [
            ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3" }], "TLS 1.3"),
            ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32 }])], "x25519"),
          ]),
        ])],
      },
      { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1, note: "A dummy record kept only so old middleboxes don't get confused." }] },
      { type: "appdata", encrypted, what: "Encrypted Extensions, Certificate, Certificate Verify, Finished" },
    ],
  });

const clientFinished = () =>
  tls({ records: [{ type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] }, { type: "appdata", encrypted: 53, what: "Finished" }] });

// ---------------------------------------------------------------- the two TCP conversations

const fromSubmit = () => [eth({ src: ADDR.serverMac, dst: GW_MAC }), ipv4({ src: SUBMIT, dst: MX, ttl: 64 })];
const fromMx = () => [eth({ src: GW_MAC, dst: ADDR.serverMac }), ipv4({ src: MX, dst: SUBMIT, ttl: 52 })];

const submission = () =>
  conversation(
    { id: "client", layers: () => up(SUBMIT), port: 52114, base: 0x3b1c9a20, win: 502 },
    { id: "submit", layers: () => down(SUBMIT), port: 587, base: 0x7e02d411, win: 509 }
  );
const relay = (port = 41822) =>
  conversation(
    { id: "submit", layers: fromSubmit, port, base: 0x11aa3c00, win: 502 },
    { id: "mx", layers: fromMx, port: 25, base: 0x5c7f0e90, win: 509 }
  );

// ---------------------------------------------------------------- message content

const EHLO_REPLY_1 = [`250-${SUBMIT_HOST}`, "250-PIPELINING", "250-SIZE 52428800", "250-STARTTLS", "250-8BITMIME", "250 SMTPUTF8"];
const EHLO_REPLY_2 = [`250-${SUBMIT_HOST}`, "250-PIPELINING", "250-SIZE 52428800", "250-AUTH PLAIN LOGIN", "250-8BITMIME", "250 SMTPUTF8"];
const ENVELOPE = [`MAIL FROM:<${FROM}> SIZE=412`, `RCPT TO:<${TO}>`, "DATA"];
const ENVELOPE_REPLY = ["250 2.1.0 Ok", "250 2.1.5 Ok", "354 End data with <CR><LF>.<CR><LF>"];

const HEADERS = [
  `From: Danish <${FROM}>`,
  `To: Priya <${TO}>`,
  "Subject: Notes for Friday",
  "Date: Thu, 19 Nov 2026 10:15:00 +0530",
  "Message-ID: <a1b2c3d4@laptop.home>",
  "MIME-Version: 1.0",
  "Content-Type: text/plain; charset=utf-8",
];
const BODY = ["", "Hi Priya,", "The notes are ready. See you on Friday.", "Danish", "."];
const RECEIVED = [
  "Received: from laptop.home ([198.51.100.7])",
  `\tby ${SUBMIT_HOST} (Postfix) with ESMTPSA id 4XyZ81`,
  `\tfor <${TO}>; Thu, 19 Nov 2026 10:15:02 +0530`,
];
const RELAYED = [...RECEIVED, ...HEADERS, ...BODY];

// ---------------------------------------------------------------- devices

const devices = [
  { id: "client", kind: "laptop" as const, label: "Danish's laptop", sub: ADDR.laptop, x: 8, y: 64 },
  { id: "router", kind: "router" as const, label: "Home router", sub: ADDR.routerWan, x: 26, y: 64 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 48, y: 36 },
  { id: "submit", kind: "mail" as const, label: "Submission server", sub: `${SUBMIT_HOST}`, x: 62, y: 74 },
  { id: "dns", kind: "dns" as const, label: "DNS resolver", sub: ADDR.dns, x: 72, y: 18 },
  { id: "mx", kind: "mail" as const, label: "Recipient MX", sub: `${MX_HOST}`, x: 91, y: 52 },
];
const links: [string, string][] = [
  ["client", "router"],
  ["router", "internet"],
  ["internet", "submit"],
  ["internet", "dns"],
  ["internet", "mx"],
];

// ---------------------------------------------------------------- scenario 1: send a mail

const S1 = submission();
const R1 = relay();

const mxQuery = (t: number, id: number) => [
  pkt("submit", "dns", "blue", "DNS MX?", ["example.org MX"], {
    time: r(t), info: `Standard query 0x${id.toString(16)} MX example.org`,
    packet: build(eth({ src: ADDR.serverMac, dst: GW_MAC }), ipv4({ src: SUBMIT, dst: ADDR.dns, ttl: 64 }), udp({ sport: 48213, dport: 53 }), dns({ id, qd: [{ name: "example.org", type: "MX" }] })),
  }),
  pkt("dns", "submit", "blue", "MX 10", [MX_HOST, MX], {
    time: r(t + 0.004), info: `Standard query response 0x${id.toString(16)} MX example.org MX 10 ${MX_HOST} A ${MX}`,
    packet: build(eth({ src: GW_MAC, dst: ADDR.serverMac }), ipv4({ src: ADDR.dns, dst: SUBMIT, ttl: 60 }), udp({ sport: 53, dport: 48213 }), dns({
      id, response: true, ra: true,
      qd: [{ name: "example.org", type: "MX" }],
      an: [{ name: "example.org", type: "MX", ttl: 3600, data: `10 ${MX_HOST}`, note: "Preference 10: lower numbers are tried first." }],
      ar: [{ name: MX_HOST, type: "A", ttl: 3600, data: MX, note: "The resolver adds the address too, saving a second lookup." }],
    })),
  }),
];

const normalSteps = [
  {
    title: "Connect to port 587",
    desc: "The mail app opens a TCP connection to its submission server",
    detail: `Danish presses Send. His mail app does not deliver the message itself. It hands it to his provider's submission server, ${SUBMIT_HOST}, on port 587. After the TCP handshake the server speaks first with a 220 greeting.`,
    facts: [["Server", `${SUBMIT} port 587`], ["Port 587", "Submission (users sending mail)"], ["First words", "Server speaks first: 220"]] as [string, string][],
    quiz: {
      q: "Once the TCP connection is open, who sends the first SMTP line?",
      options: ["The client, with EHLO", "The server, with a 220 greeting", "The client, with MAIL FROM", "Nobody until TLS starts"],
      answer: 1,
      why: "SMTP servers greet first with a 220 line. The client waits for it before saying EHLO.",
    },
    events: [
      ...S1.handshake(0, 0.031),
      S1.b("green", "220", ["service ready"], 0.063, `S: 220 ${SUBMIT_HOST} ESMTP Postfix`, [smtp([`220 ${SUBMIT_HOST} ESMTP Postfix`], { 0: "220 = service ready. The text after the code is for humans." })]),
    ],
  },
  {
    title: "EHLO and capabilities",
    desc: "The client introduces itself; the server lists its extensions",
    detail: "EHLO (extended hello) tells the server the client's name and asks what it supports. The reply is a multi-line 250: a dash after the code means more lines follow, a space marks the last. Notice STARTTLS in the list, and no AUTH yet: this server refuses to take a password over a plain connection.",
    facts: [["Command", "EHLO laptop.home"], ["Multi-line", "250- … then 250 (space) on the last"], ["Offered", "STARTTLS, PIPELINING, SIZE"]] as [string, string][],
    quiz: {
      q: "Why doesn't the first EHLO reply list AUTH?",
      options: ["The server has no accounts", "The server only allows login after the connection is encrypted", "AUTH is only used on port 25", "AUTH is always hidden"],
      answer: 1,
      why: "Most providers only advertise AUTH after STARTTLS so a password can never cross the network in clear.",
    },
    events: [
      S1.a("amber", "EHLO", ["laptop.home"], 0.064, "C: EHLO laptop.home", [smtp(["EHLO laptop.home"], { 0: "The client's name for itself. Servers log it but don't trust it." })]),
      S1.b("violet", "250", ["STARTTLS, SIZE…"], 0.096, `S: 250-${SUBMIT_HOST} | 250-PIPELINING | 250-SIZE 52428800 | 250-STARTTLS | 250-8BITMIME | 250 SMTPUTF8`, [smtp(EHLO_REPLY_1, { 3: "The server can switch this connection to TLS.", 5: "A space after 250 means this is the last line." })]),
    ],
  },
  {
    title: "STARTTLS: switch to TLS",
    desc: "Same TCP connection, now encrypted",
    detail: "The client sends STARTTLS and the server answers 220 Ready. Then, on the very same TCP connection, a normal TLS 1.3 handshake runs. From here on every byte is encrypted, and the SMTP conversation starts over with a fresh EHLO.",
    facts: [["Command", "STARTTLS"], ["Reply", "220 2.0.0 Ready to start TLS"], ["TLS", "1.3, X25519, AES-128-GCM"]] as [string, string][],
    events: [
      S1.a("teal", "STARTTLS", ["please encrypt"], 0.097, "C: STARTTLS", [smtp(["STARTTLS"])]),
      S1.b("teal", "220", ["go ahead"], 0.129, "S: 220 2.0.0 Ready to start TLS", [smtp(["220 2.0.0 Ready to start TLS"], { 0: "2.0.0 is an enhanced status code: class.subject.detail." })]),
      S1.a("teal", "HELLO", ["Client Hello", `SNI ${SUBMIT_HOST}`], 0.130, "Client Hello (SNI=smtp.mailhost.example)", [clientHello(SUBMIT_HOST)]),
      S1.b("teal", "HELLO", ["Server Hello", "+ certificate"], 0.163, "Server Hello, Change Cipher Spec, Application Data", [serverFlight(1180)]),
      S1.a("teal", "FINISHED", ["keys agreed"], 0.165, "Change Cipher Spec, Application Data", [clientFinished()]),
      note("client", "ENCRYPTED FROM HERE", "green"),
    ],
  },
  {
    title: "Log in with AUTH",
    desc: "EHLO again, then AUTH PLAIN inside TLS",
    detail: `Inside the tunnel the client says EHLO again, and now the list includes AUTH PLAIN LOGIN. The client sends "AUTH PLAIN ${AUTH_B64}". That is only Base64 of the username and password, not encryption. Anyone could decode it, which is why it must travel inside TLS. The server replies 235: logged in.`,
    facts: [["Decrypted", "AUTH PLAIN <base64>"], ["Base64 of", `\\0${FROM}\\0${PASSWORD}`], ["Reply", "235 2.7.0 Authentication successful"]] as [string, string][],
    quiz: {
      q: "If this AUTH PLAIN line were sent without TLS, what could a listener learn?",
      options: ["Nothing, Base64 is encryption", "Only the username", "The username and the password", "Only that a login happened"],
      answer: 2,
      why: "Base64 is just a way to write bytes as text. Decoding it gives back the username and password directly.",
    },
    events: [
      S1.a("teal", "EHLO", ["(encrypted)"], 0.166, "Application Data", [enc(["EHLO laptop.home"], "SMTP: EHLO laptop.home")]),
      S1.b("teal", "250", ["AUTH PLAIN LOGIN", "(encrypted)"], 0.198, "Application Data", [enc(EHLO_REPLY_2, "SMTP: 250-… 250-AUTH PLAIN LOGIN …")]),
      S1.a("teal", "AUTH", ["PLAIN <base64>", "(encrypted)"], 0.199, "Application Data", [enc([`AUTH PLAIN ${AUTH_B64}`], "SMTP: AUTH PLAIN <username and password in Base64>")]),
      S1.b("teal", "235", ["logged in", "(encrypted)"], 0.262, "Application Data", [enc(["235 2.7.0 Authentication successful"], "SMTP: 235 2.7.0 Authentication successful")]),
    ],
  },
  {
    title: "Envelope and message",
    desc: "MAIL FROM, RCPT TO, DATA (pipelined), then the message",
    detail: "Because the server offered PIPELINING, the client sends MAIL FROM, RCPT TO and DATA in one go and the server answers all three together: 250, 250, 354. The envelope (MAIL FROM and RCPT TO) is what servers use to route the mail. The headers inside DATA are what Priya will see. A line with a single dot ends the message, and the server answers 250 with a queue id.",
    facts: [["Envelope", `${FROM} → ${TO}`], ["354", "Go ahead, end with <CRLF>.<CRLF>"], ["Queued as", "4XyZ81"]] as [string, string][],
    quiz: {
      q: "How does the server know where the message text ends?",
      options: ["A Content-Length header", "The client closes the connection", "A line holding only a dot", "A blank line after the headers"],
      answer: 2,
      why: "SMTP ends DATA with CRLF . CRLF. A body line that really starts with a dot gets an extra dot added (dot-stuffing).",
    },
    events: [
      S1.a("amber", "ENVELOPE", ["MAIL FROM, RCPT TO", "DATA (encrypted)"], 0.263, "Application Data", [enc(ENVELOPE, `SMTP: MAIL FROM:<${FROM}> / RCPT TO:<${TO}> / DATA`)]),
      S1.b("teal", "250 250 354", ["send the message"], 0.296, "Application Data", [enc(ENVELOPE_REPLY, "SMTP: 250 2.1.0 Ok / 250 2.1.5 Ok / 354 End data with <CR><LF>.<CR><LF>")]),
      S1.a("amber", "MESSAGE", ["headers + body", "(encrypted)"], 0.297, "Application Data", [enc([...HEADERS, ...BODY], "SMTP DATA: headers, blank line, body, final dot")]),
      S1.b("green", "250", ["queued as 4XyZ81"], 0.341, "Application Data", [enc(["250 2.0.0 Ok: queued as 4XyZ81"], "SMTP: 250 2.0.0 Ok: queued as 4XyZ81")]),
      S1.a("slate", "QUIT", ["(encrypted)"], 0.342, "Application Data", [enc(["QUIT"], "SMTP: QUIT")]),
      S1.b("slate", "221", ["bye"], 0.374, "Application Data", [enc(["221 2.0.0 Bye"], "SMTP: 221 2.0.0 Bye")]),
      note("submit", "QUEUED 4XyZ81", "green"),
    ],
  },
  {
    title: "Find the recipient's MX",
    desc: "A DNS lookup for example.org MX",
    detail: "Now the submission server is the client. It looks at the part after @ in the recipient, example.org, and asks DNS for its MX (mail exchanger) records. The answer says mail for example.org goes to mx1.example.org with preference 10, and gives its address.",
    facts: [["Query", "example.org MX"], ["Answer", `10 ${MX_HOST}`], ["Address", MX]] as [string, string][],
    quiz: {
      q: "A domain has MX 10 mx1 and MX 20 mx2. Which server is tried first?",
      options: ["mx2, the higher number", "mx1, the lower number", "Both at the same time", "Whichever answers DNS first"],
      answer: 1,
      why: "Lower preference numbers win. mx2 is only a backup if mx1 does not answer.",
    },
    events: mxQuery(0.4, 0x6c21),
  },
  {
    title: "Relay on port 25",
    desc: "Server to server, plain SMTP",
    detail: `The submission server connects to ${MX_HOST} on port 25, the port mail servers use to talk to each other. No password is needed here: the receiving server accepts mail for its own users from anyone. Most servers would now upgrade with STARTTLS too, but this capture shows the plain dialogue so you can read every line.`,
    facts: [["From", `${SUBMIT} (port 41822)`], ["To", `${MX} port 25`], ["Login", "None: MX accepts mail for its own domain"]] as [string, string][],
    quiz: {
      q: "Why doesn't the relay step send AUTH?",
      options: ["Port 25 is always encrypted", "The receiving MX accepts mail addressed to its own users from any server", "The password was already sent on port 587", "DNS proved who the sender is"],
      answer: 1,
      why: "An MX must accept mail from the whole internet for its own users. It checks the sender other ways: SPF, DKIM, DMARC, reputation.",
    },
    events: [
      ...R1.handshake(0.41, 0.022),
      R1.b("green", "220", [MX_HOST], 0.454, `S: 220 ${MX_HOST} ESMTP`, [smtp([`220 ${MX_HOST} ESMTP`])]),
      R1.a("amber", "EHLO", [SUBMIT_HOST], 0.455, `C: EHLO ${SUBMIT_HOST}`, [smtp([`EHLO ${SUBMIT_HOST}`])]),
      R1.b("violet", "250", ["capabilities"], 0.477, `S: 250-${MX_HOST} | 250-PIPELINING | 250-SIZE 36700160 | 250-STARTTLS | 250 8BITMIME`, [smtp([`250-${MX_HOST}`, "250-PIPELINING", "250-SIZE 36700160", "250-STARTTLS", "250 8BITMIME"])]),
      R1.a("amber", "MAIL FROM", [FROM], 0.478, `C: MAIL FROM:<${FROM}> SIZE=520`, [smtp([`MAIL FROM:<${FROM}> SIZE=520`], { 0: "The envelope sender. Bounces will go back to this address." })]),
      R1.b("green", "250", ["sender ok"], 0.500, "S: 250 2.1.0 Ok", [smtp(["250 2.1.0 Ok"])]),
      R1.a("amber", "RCPT TO", [TO], 0.501, `C: RCPT TO:<${TO}>`, [smtp([`RCPT TO:<${TO}>`], { 0: "The envelope recipient. One RCPT line per person." })]),
      R1.b("green", "250", ["recipient ok"], 0.523, "S: 250 2.1.5 Ok", [smtp(["250 2.1.5 Ok"])]),
    ],
  },
  {
    title: "DATA and goodbye",
    desc: "354, the message with real headers, 250, 221",
    detail: "After DATA and the 354 go-ahead, the message travels as plain text: a Received header added by the submission server (a trace of each hop), then Danish's headers, a blank line, the body and the final dot. The MX answers 250, takes responsibility for the mail, and the connection closes with QUIT and 221.",
    facts: [["New header", "Received: … with ESMTPSA"], ["250", "The MX now owns the message"], ["Goodbye", "QUIT → 221"]] as [string, string][],
    quiz: {
      q: "After the MX replies 250 to the final dot, what is the submission server's job?",
      options: ["Keep retrying every hour", "Nothing: responsibility has passed to the MX", "Wait for Priya to read the mail", "Send a copy to the DNS resolver"],
      answer: 1,
      why: "A 250 after DATA is a promise. The receiving server now delivers it or sends a bounce itself.",
    },
    events: [
      R1.a("amber", "DATA", ["ready to send"], 0.524, "C: DATA", [smtp(["DATA"])]),
      R1.b("violet", "354", ["go ahead"], 0.546, "S: 354 End data with <CR><LF>.<CR><LF>", [smtp(["354 End data with <CR><LF>.<CR><LF>"], { 0: "354 = intermediate reply: send the message now." })]),
      R1.a("amber", "MESSAGE", ["Received, From, To…", "body, final dot"], 0.547, "C: DATA fragment, from: Danish, subject: Notes for Friday", [smtp(RELAYED, { 0: "Added by the submission server. Every hop adds one on top.", 3: "The From header is what Priya's app shows. It can differ from MAIL FROM.", 14: "A line holding only a dot ends the message." }, "SMTP / IMF")]),
      R1.b("green", "250", ["queued on MX"], 0.590, "S: 250 2.0.0 Ok: queued as 9QwE27", [smtp(["250 2.0.0 Ok: queued as 9QwE27"])]),
      R1.a("slate", "QUIT", [], 0.591, "C: QUIT", [smtp(["QUIT"])]),
      R1.b("slate", "221", ["bye"], 0.613, "S: 221 2.0.0 Bye", [smtp(["221 2.0.0 Bye"])]),
      note("mx", "DELIVERED TO PRIYA'S MAILBOX", "green"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 2: 550, then a bounce

const R2 = relay(41870);
const BAD = "priyaa@example.org";
const DSN = [
  "From: Mail Delivery System <MAILER-DAEMON@mailhost.example>",
  `To: ${FROM}`,
  "Subject: Undelivered Mail Returned to Sender",
  "Content-Type: multipart/report; report-type=delivery-status; boundary=\"b1\"",
];

const bounceSteps = [
  {
    title: "Typo in the address",
    desc: "Relay starts as usual",
    detail: `Danish typed ${BAD} by mistake. His provider accepted it on port 587 (it can't know every remote mailbox), looked up the MX and connected on port 25. Greeting, EHLO and MAIL FROM all go fine.`,
    facts: [["Recipient", BAD], ["MX", `${MX_HOST} (${MX})`], ["Sender", FROM]] as [string, string][],
    events: [
      ...R2.handshake(0, 0.022),
      R2.b("green", "220", [MX_HOST], 0.044, `S: 220 ${MX_HOST} ESMTP`, [smtp([`220 ${MX_HOST} ESMTP`])]),
      R2.a("amber", "EHLO", [SUBMIT_HOST], 0.045, `C: EHLO ${SUBMIT_HOST}`, [smtp([`EHLO ${SUBMIT_HOST}`])]),
      R2.b("violet", "250", ["capabilities"], 0.067, `S: 250-${MX_HOST} | 250-PIPELINING | 250 8BITMIME`, [smtp([`250-${MX_HOST}`, "250-PIPELINING", "250 8BITMIME"])]),
      R2.a("amber", "MAIL FROM", [FROM], 0.068, `C: MAIL FROM:<${FROM}>`, [smtp([`MAIL FROM:<${FROM}>`])]),
      R2.b("green", "250", ["sender ok"], 0.090, "S: 250 2.1.0 Ok", [smtp(["250 2.1.0 Ok"])]),
    ],
  },
  {
    title: "550: no such mailbox",
    desc: "The MX rejects the recipient",
    detail: "The MX checks its user list and finds no priyaa. It answers 550 with the enhanced code 5.1.1 (bad destination mailbox). A reply starting with 5 is permanent: trying again won't help. A 4xx reply would mean try again later. The submission server quits.",
    facts: [["Reply", "550 5.1.1 User unknown"], ["5xx", "Permanent failure, don't retry"], ["4xx", "Temporary, retry later"]] as [string, string][],
    quiz: {
      q: "What would change if the MX had answered 450 instead of 550?",
      options: ["Nothing", "The submission server would keep the mail and retry later", "The mail would be delivered to postmaster", "Danish would need to log in again"],
      answer: 1,
      why: "4xx codes are temporary (mailbox busy, greylisting). The sender queues the message and retries, often for days.",
    },
    events: [
      R2.a("amber", "RCPT TO", [BAD], 0.091, `C: RCPT TO:<${BAD}>`, [smtp([`RCPT TO:<${BAD}>`])]),
      R2.b("red", "550", ["User unknown"], 0.113, `S: 550 5.1.1 <${BAD}>: Recipient address rejected: User unknown`, [smtp([`550 5.1.1 <${BAD}>: Recipient address rejected: User unknown`], { 0: "5 = permanent, 5.1.1 = the mailbox does not exist." })]),
      R2.a("slate", "QUIT", [], 0.114, "C: QUIT", [smtp(["QUIT"])]),
      R2.b("slate", "221", ["bye"], 0.136, "S: 221 2.0.0 Bye", [smtp(["221 2.0.0 Bye"])]),
      note("mx", "550 USER UNKNOWN", "red"),
    ],
  },
  {
    title: "The bounce comes home",
    desc: "A delivery status notification for Danish",
    detail: "The submission server now writes a bounce (a delivery status notification) and puts it straight into Danish's mailbox on the same server. Bounces are sent with an empty envelope sender, MAIL FROM:<>, so a bounce can never bounce again in a loop. Danish's mail app is keeping an IMAP connection open, so it hears about the new message at once.",
    facts: [["Bounce sender", "MAIL FROM:<> (empty)"], ["Subject", "Undelivered Mail Returned to Sender"], ["Contains", "The 550 reason + original headers"]] as [string, string][],
    quiz: {
      q: "Why are bounces sent with an empty MAIL FROM:<>?",
      options: ["To hide the server's name", "So that a failed bounce is never bounced again", "Because the sender is unknown", "To skip spam filters"],
      answer: 1,
      why: "If a bounce itself fails, there's nobody to tell. The empty reverse path stops mail loops between servers.",
    },
    events: [
      note("submit", "BOUNCE WRITTEN (MAIL FROM:<>)", "amber"),
      pkt("submit", "client", "red", "NEW MAIL", ["bounce in inbox", "(IMAP, encrypted)"], {
        time: 0.2, info: "Application Data",
        packet: build(...down(SUBMIT), tcp({ sport: 993, dport: 50432, seq: 4120, ack: 911, flags: "PA", win: 509, seqBase: 0x2c0a7710, ackBase: 0x61b0e3a2 }), tls({ records: [{ type: "appdata", encrypted: encLen(["* 3 EXISTS"]), what: "IMAP: * 3 EXISTS" }] })),
      }),
      note("client", "UNDELIVERABLE: USER UNKNOWN", "red"),
    ],
  },
];

export default defineLesson({
  id: "smtp",
  name: "SMTP",
  full: "Simple Mail Transfer Protocol",
  group: "mail-files",
  layer: 7,
  difficulty: 2,
  tagline: "How an email leaves your laptop and hops between servers.",
  description:
    "SMTP moves email. Your mail app submits a message to your provider on port 587 after logging in over TLS, and your provider then relays it to the recipient's mail server on port 25, found with a DNS MX lookup. It is a plain-text conversation of commands and three-digit reply codes.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP 587 (submission), 25 (relay), 465 (implicit TLS)"],
    ["Defined in", "RFC 5321 (SMTP), RFC 5322 (message format)"],
    ["Style", "Text commands, 3-digit replies"],
    ["Encryption", "STARTTLS or implicit TLS"],
    ["Finding servers", "DNS MX records"],
  ],
  ports: "587 submission, 25 relay, 465 submissions (implicit TLS)",
  rfc: "RFC 5321, RFC 5322, RFC 6409, RFC 3207",
  keywords: ["email", "mail", "ehlo", "starttls", "mx", "relay", "bounce", "550", "auth plain", "mail from", "rcpt to", "submission"],
  related: ["imap", "pop3", "emailauth", "dns", "tls", "tcp"],
  devices,
  links,
  legend: [
    ["green", "Handshake and success replies"],
    ["amber", "Commands and mail from the sender"],
    ["violet", "Server replies"],
    ["teal", "TLS: encrypted traffic"],
    ["blue", "DNS lookup"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Send an email to Priya",
      summary: "Submit on 587 with STARTTLS and AUTH, then the provider relays on port 25 after an MX lookup.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "Mail delivered",
        text: "The message made two SMTP journeys: laptop to provider on port 587, encrypted and logged in, then provider to the recipient's MX on port 25, found through DNS. Each hop ended with a 250 that handed over responsibility for the message.",
        facts: [["SMTP hops", "2 (submission, relay)"], ["Port 587", "Login required, STARTTLS"], ["Port 25", "Server to server, found via MX"], ["Total time", "0.613 s"]],
      },
    },
    {
      id: "bounce",
      name: "Wrong address: 550 and a bounce",
      summary: "A typo in the address gets a permanent 550, and Danish gets a bounce message.",
      kind: "failure",
      steps: bounceSteps,
      outro: {
        title: "Bounced back",
        text: "The MX rejected the recipient with 550 5.1.1. Because the error was permanent, the sending server stopped at once and wrote a bounce for Danish, sent with an empty envelope sender so it can never loop.",
        facts: [["Code", "550 5.1.1 User unknown"], ["Retry?", "No, 5xx is permanent"], ["Bounce from", "MAILER-DAEMON, MAIL FROM:<>"], ["Bounce headers", DSN[2]]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Commands",
      items: [["EHLO", "Hello + list your extensions"], ["STARTTLS", "Upgrade this connection to TLS"], ["AUTH", "Log in (PLAIN, LOGIN, XOAUTH2)"], ["MAIL FROM", "Envelope sender (bounce address)"], ["RCPT TO", "Envelope recipient, once per person"], ["DATA", "Message follows, end with <CRLF>.<CRLF>"], ["QUIT", "Goodbye"]],
    },
    {
      title: "Reply codes",
      items: [["220", "Service ready / ready for TLS"], ["235", "Logged in"], ["250", "OK"], ["354", "Send the message now"], ["221", "Closing"], ["4xx", "Temporary failure, retry later"], ["550", "Mailbox unavailable (permanent)"]],
    },
    {
      title: "Ports",
      items: [["25", "Server-to-server relay"], ["587", "Submission with STARTTLS + login"], ["465", "Submission over implicit TLS"]],
    },
  ],
});

