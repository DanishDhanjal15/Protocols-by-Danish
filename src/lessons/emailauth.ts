import { Color, defineLesson, Device, note, pkt, PacketEvent } from "@/lib/lesson";
import { Bytes, text } from "@/lib/bytes";
import { build, LayerSpec, textLayer } from "@/lib/packet";
import { dns, eth, ipv4, tcp, TcpOpt, udp } from "@/lib/proto";
import { ADDR } from "./_common";

// ---------------------------------------------------------------- addresses

const MX = ADDR.mail; // 203.0.113.25, mx.mailhost.example (Danish's provider)
const MX_HOST = "mx.mailhost.example";
const BANK = "198.51.100.80"; // mail.bank.example, the bank's real outgoing server
const BANK_HOST = "mail.bank.example";
const EVIL = "192.0.2.66"; // attacker's rented server
const MX_MAC = "00:16:3e:5a:01:22";
const GW_MAC = "00:00:5e:00:01:01";
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

// ---------------------------------------------------------------- DNS records

/** deterministic Base64-looking text so the signature and key look real */
const b64 = (n: number, seed: number) => {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let s = "", x = seed;
  for (let i = 0; i < n; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; s += A[(x >> 16) & 63]; }
  return s;
};

/** TXT rdata: strings longer than 255 bytes are split into several length-prefixed strings */
const txtRdata = (s: string): Bytes => {
  const b = text(s), out: Bytes = [];
  for (let i = 0; i < b.length; i += 255) { const c = b.slice(i, i + 255); out.push(c.length, ...c); }
  return out;
};

const SPF = `v=spf1 ip4:${BANK}/31 include:_spf.mailer.example -all`;
const SELECTOR = "mail2026";
const DKIM_KEY_NAME = `${SELECTOR}._domainkey.bank.example`;
const PUBKEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + b64(342, 77) + "IDAQAB";
const DKIM_TXT = `v=DKIM1; k=rsa; p=${PUBKEY}`;
const DMARC = "v=DMARC1; p=reject; rua=mailto:dmarc-reports@bank.example; adkim=s; aspf=r";

const mxSide = () => [eth({ src: MX_MAC, dst: GW_MAC }), ipv4({ src: MX, dst: ADDR.dns, ttl: 64 })];
const dnsSide = () => [eth({ src: GW_MAC, dst: MX_MAC }), ipv4({ src: ADDR.dns, dst: MX, ttl: 63 })];

const txtLookup = (t: number, id: number, name: string, answer: string | null, sport: number, label: string, lines: string[]): PacketEvent[] => [
  pkt("mx", "dns", "blue", "TXT?", [name.length > 22 ? name.slice(0, 22) + "…" : name], {
    time: r(t), info: `Standard query 0x${id.toString(16)} TXT ${name}`,
    packet: build(...mxSide(), udp({ sport, dport: 53 }), dns({ id, qd: [{ name, type: "TXT" }], ar: [{ name: ".", type: "OPT" }] })),
  }),
  pkt("dns", "mx", "blue", label, lines, {
    time: r(t + 0.003), info: `Standard query response 0x${id.toString(16)} TXT ${name}${answer ? ` TXT` : ""}`,
    packet: build(...dnsSide(), udp({ sport: 53, dport: sport }), dns({
      id, response: true, ra: true,
      qd: [{ name, type: "TXT" }],
      an: answer ? [{ name, type: "TXT", ttl: 3600, rdata: txtRdata(answer), value: answer.length > 70 ? answer.slice(0, 70) + "…" : answer, note: answer.length > 255 ? "Longer than 255 bytes, so it is stored as several strings that are joined back together." : undefined }] : [],
      ar: [{ name: ".", type: "OPT" }],
    })),
  }),
];

// ---------------------------------------------------------------- SMTP pieces

const smtp = (lines: string[], notes?: Record<number, string>, name = "SMTP") => textLayer({ id: "smtp", name, lines, notes });

const SIG_B = b64(344, 1234);
const DKIM_HDR = [
  `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bank.example;`,
  `\ts=${SELECTOR}; t=1763537400; h=from:to:subject:date:message-id;`,
  `\tbh=${b64(43, 99)}=;`,
  `\tb=${SIG_B.slice(0, 70)}`,
  ...[70, 140, 210, 280].map((i) => `\t ${SIG_B.slice(i, i + 70)}`),
];
const BANK_MAIL = [
  ...DKIM_HDR,
  "From: Bank of Example <alerts@bank.example>",
  "To: danish@mailhost.example",
  "Subject: Your November statement is ready",
  "Date: Thu, 19 Nov 2026 13:00:00 +0530",
  "Message-ID: <st-20261119-8812@bank.example>",
  "MIME-Version: 1.0",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Dear customer, your statement is ready in the bank app.",
  "We will never ask for your password by email.",
  ".",
];
const PHISH_MAIL = [
  "From: Bank of Example <security@bank.example>",
  "To: danish@mailhost.example",
  "Subject: URGENT: your account will be locked today",
  "Date: Thu, 19 Nov 2026 13:20:00 +0530",
  "Message-ID: <x93k1@bank.example>",
  "Content-Type: text/plain; charset=utf-8",
  "",
  "Unusual activity found. Confirm your login within 2 hours:",
  "http://bank-example.secure-check.example.net/login",
  ".",
];
const AUTH_RESULTS = `Authentication-Results: ${MX_HOST}; spf=pass smtp.mailfrom=bank.example; dkim=pass header.d=bank.example header.s=${SELECTOR}; dmarc=pass (p=REJECT) header.from=bank.example`;

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "bank", kind: "bank", label: "Bank mail server", sub: `${BANK_HOST} ${BANK}`, x: 9, y: 62 },
  { id: "internet", kind: "cloud", label: "Internet", x: 40, y: 40 },
  { id: "mx", kind: "mail", label: "Receiving MX", sub: `${MX_HOST} ${MX}`, x: 70, y: 66 },
  { id: "dns", kind: "dns", label: "DNS resolver", sub: ADDR.dns, x: 72, y: 18 },
  { id: "client", kind: "laptop", label: "Danish's inbox", sub: "danish@mailhost.example", x: 92, y: 40 },
];
const links: [string, string][] = [["bank", "internet"], ["internet", "mx"], ["mx", "dns"], ["mx", "client"]];

const attackDevices: Device[] = [
  ...devices,
  { id: "attacker", kind: "attacker", label: "Phisher", sub: EVIL, x: 12, y: 22 },
];
const attackLinks: [string, string][] = [...links, ["attacker", "internet"]];

// ---------------------------------------------------------------- scenario 1: real mail passes

const B = conversation(
  { id: "bank", layers: () => [eth({ src: GW_MAC, dst: MX_MAC }), ipv4({ src: BANK, dst: MX, ttl: 52 })], port: 39114, base: 0x20b1c002, win: 502 },
  { id: "mx", layers: () => [eth({ src: MX_MAC, dst: GW_MAC }), ipv4({ src: MX, dst: BANK, ttl: 64 })], port: 25, base: 0x6e4a0b10, win: 509 }
);

const normalSteps = [
  {
    title: "The bank connects",
    desc: "An SMTP connection on port 25",
    detail: `The bank's server ${BANK_HOST} (${BANK}) connects to Danish's provider to deliver a statement alert. The receiving MX notes the connecting IP address straight away: it is the one thing a sender can't fake on a TCP connection, and SPF will check it.`,
    facts: [["Connecting IP", BANK], ["Port", "25 (server to server)"], ["Checked later", "SPF uses this IP"]] as [string, string][],
    events: [
      ...B.handshake(0, 0.025),
      B.b("green", "220", [MX_HOST], 0.051, `S: 220 ${MX_HOST} ESMTP`, [smtp([`220 ${MX_HOST} ESMTP`])]),
      B.a("amber", "EHLO", [BANK_HOST], 0.052, `C: EHLO ${BANK_HOST}`, [smtp([`EHLO ${BANK_HOST}`])]),
      B.b("violet", "250", ["PIPELINING…"], 0.077, `S: 250-${MX_HOST} | 250-PIPELINING | 250 8BITMIME`, [smtp([`250-${MX_HOST}`, "250-PIPELINING", "250 8BITMIME"])]),
    ],
  },
  {
    title: "SPF: is this IP allowed?",
    desc: "Look up bank.example TXT",
    detail: `The envelope says MAIL FROM:<bounces@bank.example>. Before answering, the MX fetches the TXT record of bank.example and finds the SPF policy "${SPF}". The connecting IP ${BANK} is inside ${BANK}/31, so SPF passes. The -all at the end means every other IP should fail.`,
    facts: [["Domain checked", "bank.example (from MAIL FROM)"], ["Policy", "ip4:198.51.100.80/31 … -all"], ["Result", "spf=pass"]] as [string, string][],
    quiz: {
      q: "The SPF record ends in -all. What happens to mail from an IP not listed?",
      options: ["It passes", "SPF says fail (hard fail)", "SPF says neutral", "The DNS lookup fails"],
      answer: 1,
      why: "-all means \"everything else fails\". ~all would be a soft fail, ?all neutral.",
    },
    events: [
      B.a("amber", "ENVELOPE", ["MAIL FROM bounces@", "RCPT TO, DATA"], 0.078, "C: MAIL FROM:<bounces@bank.example> | RCPT TO:<danish@mailhost.example> | DATA", [smtp(["MAIL FROM:<bounces@bank.example>", "RCPT TO:<danish@mailhost.example>", "DATA"], { 0: "The envelope sender. SPF checks the domain after the @." })]),
      ...txtLookup(0.0785, 0x51f0, "bank.example", SPF, 40211, "SPF", ["v=spf1 ip4:…/31", "-all"]),
      note("mx", "SPF PASS", "green"),
      B.b("violet", "250 354", ["send it"], 0.104, "S: 250 2.1.0 Ok | 250 2.1.5 Ok | 354 End data with <CR><LF>.<CR><LF>", [smtp(["250 2.1.0 Ok", "250 2.1.5 Ok", "354 End data with <CR><LF>.<CR><LF>"])]),
    ],
  },
  {
    title: "The signed message",
    desc: "A DKIM-Signature header travels with the mail",
    detail: `The bank's server signed the message before sending. The DKIM-Signature header says who signed (d=bank.example), which key to use (s=${SELECTOR}), which headers are covered (h=from:to:subject:…), a hash of the body (bh=) and the RSA signature itself (b=). Change one covered byte and the check fails.`,
    facts: [["d=", "bank.example (signing domain)"], ["s=", `${SELECTOR} (selector, picks the key)`], ["Covers", "From, To, Subject, Date, Message-ID + body"]] as [string, string][],
    quiz: {
      q: `Where will the MX find the public key for d=bank.example, s=${SELECTOR}?`,
      options: ["In the email attachment", `TXT record ${DKIM_KEY_NAME}`, "TXT record _dmarc.bank.example", "From the bank's website over HTTPS"],
      answer: 1,
      why: "DKIM keys live in DNS at <selector>._domainkey.<domain>. Selectors let a domain rotate keys or use several senders.",
    },
    events: [
      B.a("amber", "DATA", ["DKIM-Signature", "From: alerts@bank…"], 0.105, "C: DATA fragment, from: alerts@bank.example, subject: Your November statement is ready", [smtp(BANK_MAIL, { 0: "d= is the domain that takes responsibility for this message.", 1: "s= is the selector; h= lists the signed headers.", 2: "bh= is a hash of the body.", 3: "b= is the RSA signature over the headers.", 8: "The From header people see. DMARC protects this one." }, "SMTP / IMF")]),
    ],
  },
  {
    title: "DKIM: fetch the key",
    desc: `TXT ${SELECTOR}._domainkey`,
    detail: "The MX looks up the public key and gets a 2048-bit RSA key in Base64. It hashes the body and compares with bh=, then checks the signature b= over the listed headers. Both match, so DKIM passes for bank.example. The key record is longer than 255 bytes, so DNS stores it as two strings that are joined.",
    facts: [["Query", DKIM_KEY_NAME], ["Key", "RSA 2048-bit (k=rsa)"], ["Result", "dkim=pass header.d=bank.example"]] as [string, string][],
    events: [
      ...txtLookup(0.15, 0x51f1, DKIM_KEY_NAME, DKIM_TXT, 40212, "DKIM KEY", ["v=DKIM1; k=rsa", "p=MIIBIjAN…"]),
      note("mx", "DKIM PASS", "green"),
    ],
  },
  {
    title: "DMARC: tie it to From",
    desc: "TXT _dmarc.bank.example",
    detail: "SPF and DKIM prove things about the envelope and the signer, but a reader only sees the From header. DMARC asks: did SPF or DKIM pass for the same domain as From? Here From is bank.example, DKIM d= is bank.example and SPF is bank.example, so both align. The policy p=reject tells receivers what to do when this check fails.",
    facts: [["Policy", "p=reject"], ["Alignment", "From = DKIM d= = SPF domain"], ["Reports", "rua=mailto:dmarc-reports@…"]] as [string, string][],
    quiz: {
      q: "DMARC passes if at least one of SPF or DKIM passes and…",
      options: ["the message has no links", "its domain matches the From header domain", "the IP is in India", "the message is under 1 MB"],
      answer: 1,
      why: "That's alignment. A pass for some unrelated domain doesn't count; it must match what the reader sees in From.",
    },
    events: [
      ...txtLookup(0.154, 0x51f2, "_dmarc.bank.example", DMARC, 40213, "DMARC", ["p=reject", "adkim=s aspf=r"]),
      note("mx", "DMARC PASS (ALIGNED)", "green"),
    ],
  },
  {
    title: "Accept and label",
    desc: "250 OK and an Authentication-Results header",
    detail: `All three checks passed, so the MX accepts the message with 250 and adds a header recording what it found: ${AUTH_RESULTS}. Danish's mail app may show a verified badge. The bank also gets daily aggregate reports at its rua address, showing who sends mail using its name.`,
    facts: [["Reply", "250 2.0.0 Ok: queued"], ["Added header", "Authentication-Results"], ["Verdict", "spf=pass dkim=pass dmarc=pass"]] as [string, string][],
    events: [
      B.b("green", "250", ["accepted"], 0.157, "S: 250 2.0.0 Ok: queued as 7HqA30", [smtp(["250 2.0.0 Ok: queued as 7HqA30"])]),
      note("mx", "SPF, DKIM, DMARC: PASS", "green"),
      note("client", "DELIVERED TO INBOX", "green"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 2: spoofed phishing mail is rejected

const E = conversation(
  { id: "attacker", layers: () => [eth({ src: GW_MAC, dst: MX_MAC }), ipv4({ src: EVIL, dst: MX, ttl: 49 })], port: 51337, base: 0x13371337, win: 502 },
  { id: "mx", layers: () => [eth({ src: MX_MAC, dst: GW_MAC }), ipv4({ src: MX, dst: EVIL, ttl: 64 })], port: 25, base: 0x0f0e0d0c, win: 509 }
);

const attackSteps = [
  {
    title: "A fake bank email",
    desc: "The phisher claims to be bank.example",
    detail: `A phisher rents a server at ${EVIL} and connects to Danish's MX. SMTP lets anyone write any address in MAIL FROM and in the From header, so it claims security@bank.example in both. Without checks, this would look exactly like the real bank.`,
    facts: [["Connecting IP", `${EVIL} (not the bank)`], ["Claims", "security@bank.example"], ["SMTP itself", "Has no sender check"]] as [string, string][],
    events: [
      ...E.handshake(0, 0.03),
      E.b("green", "220", [MX_HOST], 0.061, `S: 220 ${MX_HOST} ESMTP`, [smtp([`220 ${MX_HOST} ESMTP`])]),
      E.a("red", "EHLO", ["mail.bank.example?"], 0.062, "C: EHLO mail.bank.example", [smtp(["EHLO mail.bank.example"], { 0: "A lie. EHLO names are not trusted." })]),
      E.b("violet", "250", [], 0.092, `S: 250-${MX_HOST} | 250-PIPELINING | 250 8BITMIME`, [smtp([`250-${MX_HOST}`, "250-PIPELINING", "250 8BITMIME"])]),
      E.a("red", "ENVELOPE", ["MAIL FROM security@", "bank.example"], 0.093, "C: MAIL FROM:<security@bank.example> | RCPT TO:<danish@mailhost.example> | DATA", [smtp(["MAIL FROM:<security@bank.example>", "RCPT TO:<danish@mailhost.example>", "DATA"])]),
    ],
  },
  {
    title: "SPF fails",
    desc: `${EVIL} isn't in the bank's list`,
    detail: `The MX fetches bank.example's SPF record again. ${EVIL} is not in ip4:${BANK}/31, nor in the included mailer list, so the -all rule applies: spf=fail. The MX doesn't reject yet; it lets DMARC decide, and accepts the message text so it can check DKIM too.`,
    facts: [["IP", EVIL], ["Matches", "Nothing, so -all"], ["Result", "spf=fail"]] as [string, string][],
    quiz: {
      q: `Would SPF pass if the phisher used MAIL FROM:<x@phish.example.net> (a domain it owns) instead?`,
      options: ["No, never", "Yes, SPF only checks the envelope domain, which it controls", "Only on Mondays", "Only if DKIM passes"],
      answer: 1,
      why: "That's exactly the gap DMARC closes: SPF would pass for phish.example.net, but that domain doesn't match the From header, so DMARC still fails.",
    },
    events: [
      ...txtLookup(0.0935, 0x72a0, "bank.example", SPF, 40377, "SPF", ["192.0.2.66 not listed"]),
      note("mx", "SPF FAIL", "red"),
      E.b("violet", "250 354", [], 0.123, "S: 250 2.1.0 Ok | 250 2.1.5 Ok | 354 End data with <CR><LF>.<CR><LF>", [smtp(["250 2.1.0 Ok", "250 2.1.5 Ok", "354 End data with <CR><LF>.<CR><LF>"])]),
      E.a("red", "PHISH", ["URGENT: account", "will be locked"], 0.124, "C: DATA fragment, from: security@bank.example, subject: URGENT: your account will be locked today", [smtp(PHISH_MAIL, { 0: "Forged From header: the part DMARC protects.", 8: "The link goes to the phisher's site, not the bank." }, "SMTP / IMF")]),
    ],
  },
  {
    title: "No DKIM, DMARC says reject",
    desc: "Nothing aligned with bank.example",
    detail: "The message has no DKIM-Signature at all (the phisher doesn't have the bank's private key, so any fake signature would fail anyway). With SPF failed and DKIM missing, nothing passes for bank.example. The MX looks up _dmarc.bank.example and finds p=reject.",
    facts: [["DKIM", "none (no signature)"], ["SPF", "fail"], ["DMARC policy", "p=reject"]] as [string, string][],
    quiz: {
      q: "SPF failed and there's no DKIM signature. The policy is p=reject. What should the MX do?",
      options: ["Deliver it to the inbox", "Put it in spam", "Refuse it during the SMTP session", "Forward it to the bank"],
      answer: 2,
      why: "p=reject asks receivers to refuse failing mail outright. p=quarantine would mean spam folder; p=none only reports.",
    },
    events: [
      ...txtLookup(0.169, 0x72a1, "_dmarc.bank.example", DMARC, 40378, "DMARC", ["p=reject"]),
      note("mx", "DMARC FAIL → REJECT", "red"),
    ],
  },
  {
    title: "550 rejected",
    desc: "The phish never reaches Danish",
    detail: "The MX answers the end of DATA with a 550 5.7.1 rejection. Because it refused the message during the session, nothing is stored and no bounce is sent to the forged address. The failed attempt shows up in the bank's next DMARC aggregate report, so the bank learns someone is spoofing it.",
    facts: [["Reply", "550 5.7.1 rejected per DMARC policy"], ["Danish sees", "Nothing"], ["Bank learns", "Via rua aggregate report"]] as [string, string][],
    events: [
      E.b("red", "550", ["DMARC reject"], 0.172, "S: 550 5.7.1 Email rejected per DMARC policy for bank.example", [smtp(["550 5.7.1 Email rejected per DMARC policy for bank.example"], { 0: "5.7.1 = delivery not authorised. Permanent." })]),
      E.a("slate", "QUIT", [], 0.173, "C: QUIT", [smtp(["QUIT"])]),
      E.b("slate", "221", [], 0.203, "S: 221 2.0.0 Bye", [smtp(["221 2.0.0 Bye"])]),
      note("client", "PHISH NEVER ARRIVED", "green"),
    ],
  },
];

export default defineLesson({
  id: "emailauth",
  name: "SPF, DKIM, DMARC",
  full: "Sender Policy Framework, DomainKeys Identified Mail, Domain-based Message Authentication",
  group: "mail-files",
  layer: 7,
  difficulty: 3,
  tagline: "How mail servers tell the real bank from a fake one.",
  description:
    "SMTP lets anyone claim any sender address. SPF lists which servers may send for a domain, DKIM adds a signature checked with a key published in DNS, and DMARC ties both to the From address people actually see and tells receivers what to do when checks fail.",
  facts: [
    ["Layer", "Application (Layer 7), policies in DNS"],
    ["SPF", "TXT on the domain, RFC 7208"],
    ["DKIM", "TXT at selector._domainkey, RFC 6376"],
    ["DMARC", "TXT at _dmarc, RFC 7489"],
    ["Checked by", "The receiving mail server"],
    ["Policies", "none, quarantine, reject"],
  ],
  ports: "Uses SMTP (25) and DNS (53)",
  rfc: "RFC 7208, RFC 6376, RFC 7489",
  keywords: ["spf", "dkim", "dmarc", "email security", "spoofing", "phishing", "domainkey", "alignment", "txt record", "p=reject", "authentication-results"],
  related: ["smtp", "dns", "imap"],
  devices,
  links,
  legend: [
    ["green", "Handshake, pass, accepted"],
    ["amber", "Mail from the real sender"],
    ["violet", "MX replies"],
    ["blue", "DNS TXT lookups"],
    ["red", "Spoofed mail, failures, rejection"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A real bank email passes all checks",
      summary: "The MX checks SPF, DKIM and DMARC for a statement alert from bank.example and accepts it.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "Verified and delivered",
        text: "The connecting IP was on the bank's SPF list, the DKIM signature matched the key in DNS, and both lined up with the From domain, so DMARC passed. The MX recorded all of this in an Authentication-Results header.",
        facts: [["SPF", "pass (IP listed)"], ["DKIM", "pass (d=bank.example)"], ["DMARC", "pass (aligned)"], ["DNS lookups", "3 TXT"]],
      },
    },
    {
      id: "spoof",
      name: "Phishing email pretending to be the bank",
      summary: "A forged bank email fails SPF, has no DKIM, and the bank's DMARC p=reject blocks it.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: attackSteps,
      outro: {
        title: "Spoof blocked",
        text: "The phisher could write bank.example anywhere in the message, but couldn't send from the bank's IPs or sign with the bank's private key. DMARC saw no aligned pass and the bank's p=reject policy turned that into a 550.",
        facts: [["SPF", "fail"], ["DKIM", "none"], ["DMARC", "fail → p=reject → 550"], ["Defence for domains", "Publish SPF, sign with DKIM, move DMARC to p=reject"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Where the records live",
      items: [["SPF", "bank.example TXT \"v=spf1 … -all\""], ["DKIM key", "<selector>._domainkey.bank.example TXT \"v=DKIM1; p=…\""], ["DMARC", "_dmarc.bank.example TXT \"v=DMARC1; p=reject\""]],
    },
    {
      title: "What each one checks",
      items: [["SPF", "Connecting IP vs envelope MAIL FROM domain"], ["DKIM", "Signature over headers + body, domain d="], ["DMARC", "SPF or DKIM pass, aligned with From"]],
    },
    {
      title: "Results and policies",
      items: [["-all / ~all / ?all", "SPF fail / soft fail / neutral"], ["p=none", "Only report"], ["p=quarantine", "Send to spam"], ["p=reject", "Refuse the mail"], ["rua=", "Where to send daily aggregate reports"]],
    },
  ],
});
