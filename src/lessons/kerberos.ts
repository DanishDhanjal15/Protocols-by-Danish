import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { Bytes, u16le, u32le } from "@/lib/bytes";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, tcp } from "@/lib/proto";

// ------------------------------------------------------------ ASN.1 DER helpers
// Every Kerberos message is ASN.1 encoded with DER: tag, length, content.
// Lengths are computed from the real content bytes so nesting stays correct.

const sizeOf = (fs: FieldSpec[]) => fs.map(field).reduce((n, f) => n + f.bytes.length, 0);
const derLen = (n: number): Bytes => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, (n >> 8) & 0xff, n & 0xff]);
const h2 = (n: number) => `0x${n.toString(16).padStart(2, "0")}`;

function tlv(tag: number, name: string, content: FieldSpec[], value?: string, note?: string): FieldSpec {
  const n = sizeOf(content);
  return {
    name,
    value: value ?? `${n} bytes`,
    note,
    fields: [
      { name: "Tag", u8: tag, value: h2(tag) },
      { name: "Length", bytes: derLen(n), value: n >= 0x80 ? `${n} (long form)` : String(n) },
      ...content,
    ],
  };
}

const intBytes = (n: number): Bytes => {
  const b: number[] = [];
  let v = n;
  do { b.unshift(v % 256); v = Math.floor(v / 256); } while (v > 0);
  if (b[0] & 0x80) b.unshift(0);
  return b;
};

const int = (name: string, n: number, value?: string, note?: string) =>
  tlv(0x02, name, [{ name: "Value", bytes: intBytes(n), value: value ?? String(n) }], value ?? String(n), note);
const enumv = (name: string, n: number, value: string, note?: string) =>
  tlv(0x0a, name, [{ name: "Value", bytes: intBytes(n), value }], value, note);
const seq = (name: string, items: FieldSpec[], value?: string, note?: string) => tlv(0x30, name, items, value, note);
const ctx = (n: number, name: string, inner: FieldSpec, note?: string) => tlv(0xa0 + n, `[${n}] ${name}`, [inner], inner.value, note);
const kstr = (name: string, s: string, note?: string) => tlv(0x1b, name, [{ name: "Value", text: s, value: s }], s, note);
const ktime = (name: string, s: string, note?: string) => tlv(0x18, name, [{ name: "Value", text: s, value: s }], s, note);
const bits = (name: string, v: number, value: string, note?: string) =>
  tlv(0x03, name, [{ name: "Unused bits", u8: 0 }, { name: "Flag bits", u32: v, value: `0x${v.toString(16).padStart(8, "0")}` }], value, note);
const oid = (name: string, hexContent: string, value: string) => tlv(0x06, name, [{ name: "Value", bytes: hexContent, value }], value);
const octets = (name: string, content: FieldSpec[], value?: string, note?: string) => tlv(0x04, name, content, value, note);

// ------------------------------------------------------------ Kerberos structures (RFC 4120)

const REALM = "CORP.EXAMPLE.COM";
const ETN: Record<number, string> = { 17: "aes128-cts-hmac-sha1-96", 18: "aes256-cts-hmac-sha1-96", 23: "rc4-hmac" };
const etypeInt = (e: number) => int("etype", e, `${e} (${ETN[e]})`);

const principal = (type: number, parts: string[], note?: string) =>
  seq("PrincipalName", [
    ctx(0, "name-type", int("name-type", type, type === 1 ? "1 (NT-PRINCIPAL, a user)" : "2 (NT-SRV-INST, a service)")),
    ctx(1, "name-string", seq("name-string", parts.map((p) => kstr("KerberosString", p)), parts.join("/"))),
  ], parts.join("/"), note);

const encData = (etype: number, kvno: number | null, len: number, what: string, note: string) =>
  seq("EncryptedData", [
    ctx(0, "etype", etypeInt(etype)),
    ...(kvno !== null ? [ctx(1, "kvno", int("kvno", kvno, String(kvno), "Key version number: which version of the password-derived key was used."))] : []),
    ctx(2, "cipher", octets("cipher", [{ name: what, random: len, opaque: true, note }], `${len} bytes, encrypted`)),
  ], `${ETN[etype]}, ${len} bytes`);

const ticket = (sname: string[], etype: number, kvno: number, len: number, note: string) =>
  tlv(0x61, "Ticket [APPLICATION 1]", [
    seq("Ticket", [
      ctx(0, "tkt-vno", int("tkt-vno", 5)),
      ctx(1, "realm", kstr("realm", REALM)),
      ctx(2, "sname", principal(2, sname)),
      ctx(3, "enc-part", encData(etype, kvno, len, "EncTicketPart (session key, client name, times, PAC)", note)),
    ]),
  ], sname.join("/"), "The ticket. Its inside is locked with the target service’s own key, so the client can carry it but can’t read or change it.");

const paData = (type: number, name: string, value: FieldSpec[]) =>
  seq(`PA-DATA: ${name}`, [
    ctx(1, "padata-type", int("padata-type", type, `${type} (${name})`)),
    ctx(2, "padata-value", octets("padata-value", value)),
  ], `${type} (${name})`);

const paPacRequest = paData(128, "PA-PAC-REQUEST", [seq("KERB-PA-PAC-REQUEST", [ctx(0, "include-pac", tlv(0x01, "BOOLEAN", [{ name: "Value", u8: 0xff, value: "TRUE" }], "TRUE"))], "include PAC")]);
const paEncTs = (note: string) => paData(2, "PA-ENC-TIMESTAMP", [encData(18, null, 54, "PA-ENC-TS-ENC (current time)", note)]);
const etypeInfo2 = (entries: [number, string | null][]) =>
  paData(19, "PA-ETYPE-INFO2", [
    seq("ETYPE-INFO2", entries.map(([e, salt]) =>
      seq("ETYPE-INFO2-ENTRY", [ctx(0, "etype", etypeInt(e)), ...(salt ? [ctx(1, "salt", kstr("salt", salt, "Mixed with the password to make the AES key."))] : [])], ETN[e]))),
  ]);

const ASOPTS = 0x40810010; // forwardable, renewable, canonicalize, renewable-ok
const TGSOPTS = 0x40810000; // forwardable, renewable, canonicalize

const reqBody = (o: { opts: number; cname?: string; sname: string[]; nonce: number; etypes: number[]; rtime?: boolean }) =>
  seq("KDC-REQ-BODY", [
    ctx(0, "kdc-options", bits("KDCOptions", o.opts, o.opts === ASOPTS ? "forwardable, renewable, canonicalize, renewable-ok" : "forwardable, renewable, canonicalize")),
    ...(o.cname ? [ctx(1, "cname", principal(1, [o.cname], "Who is asking."))] : []),
    ctx(2, "realm", kstr("realm", REALM, "The Kerberos realm: the Windows domain name in capitals.")),
    ctx(3, "sname", principal(2, o.sname, "Which service the ticket is for.")),
    ctx(5, "till", ktime("till", "20370913024805Z", "Windows always asks for this far-future end time; the KDC cuts it to the policy (10 hours).")),
    ...(o.rtime ? [ctx(6, "rtime", ktime("rtime", "20370913024805Z"))] : []),
    ctx(7, "nonce", int("nonce", o.nonce, undefined, "A random number the reply must echo (inside the encrypted part), so old replies can’t be replayed.")),
    ctx(8, "etype", seq("etype list", o.etypes.map(etypeInt), o.etypes.join(", "), "Encryption types the client supports, best first.")),
  ]);

const asReq = (padata: FieldSpec[], nonce: number) =>
  tlv(0x6a, "AS-REQ [APPLICATION 10]", [
    seq("KDC-REQ", [
      ctx(1, "pvno", int("pvno", 5, "5 (Kerberos V5)")),
      ctx(2, "msg-type", int("msg-type", 10, "10 (AS-REQ)")),
      ...(padata.length ? [ctx(3, "padata", seq("padata", padata))] : []),
      ctx(4, "req-body", reqBody({ opts: ASOPTS, cname: "danish", sname: ["krbtgt", REALM], nonce, etypes: [18, 17, 23], rtime: true })),
    ]),
  ], "AS-REQ");

const apReq = (o: { tktSname: string[]; tktEtype: number; tktKvno: number; tktLen: number; tktNote: string; options: number; authLen: number }) =>
  tlv(0x6e, "AP-REQ [APPLICATION 14]", [
    seq("AP-REQ", [
      ctx(0, "pvno", int("pvno", 5)),
      ctx(1, "msg-type", int("msg-type", 14, "14 (AP-REQ)")),
      ctx(2, "ap-options", bits("APOptions", o.options, o.options ? "mutual-required" : "none")),
      ctx(3, "ticket", ticket(o.tktSname, o.tktEtype, o.tktKvno, o.tktLen, o.tktNote)),
      ctx(4, "authenticator", encData(18, null, o.authLen, "Authenticator (client name, current time)", "Encrypted with the session key from the ticket. Proves the sender knows that key right now.")),
    ]),
  ], "AP-REQ");

const TGT_NOTE = "Encrypted with the krbtgt account’s key. Only domain controllers can open it.";

const tgsReq = (sname: string[], etypes: number[], nonce: number) =>
  tlv(0x6c, "TGS-REQ [APPLICATION 12]", [
    seq("KDC-REQ", [
      ctx(1, "pvno", int("pvno", 5)),
      ctx(2, "msg-type", int("msg-type", 12, "12 (TGS-REQ)")),
      ctx(3, "padata", seq("padata", [
        paData(1, "PA-TGS-REQ", [apReq({ tktSname: ["krbtgt", REALM], tktEtype: 18, tktKvno: 2, tktLen: 880, tktNote: TGT_NOTE, options: 0, authLen: 160 })]),
      ])),
      ctx(4, "req-body", reqBody({ opts: TGSOPTS, sname, nonce, etypes })),
    ]),
  ], "TGS-REQ");

const kdcRep = (o: {
  app: number; msgType: number; label: string; padata?: FieldSpec[]; cname: string; tktSname: string[]; tktEtype: number; tktKvno: number; tktLen: number; tktNote: string;
  encEtype: number; encKvno: number | null; encLen: number; encWhat: string; encNote: string;
}) =>
  tlv(o.app, `${o.label} [APPLICATION ${o.app - 0x60}]`, [
    seq("KDC-REP", [
      ctx(0, "pvno", int("pvno", 5)),
      ctx(1, "msg-type", int("msg-type", o.msgType, `${o.msgType} (${o.label})`)),
      ...(o.padata ? [ctx(2, "padata", seq("padata", o.padata))] : []),
      ctx(3, "crealm", kstr("crealm", REALM)),
      ctx(4, "cname", principal(1, [o.cname])),
      ctx(5, "ticket", ticket(o.tktSname, o.tktEtype, o.tktKvno, o.tktLen, o.tktNote)),
      ctx(6, "enc-part", encData(o.encEtype, o.encKvno, o.encLen, o.encWhat, o.encNote)),
    ]),
  ], o.label);

const ERR: Record<number, string> = {
  14: "KDC_ERR_ETYPE_NOSUPP", 24: "KDC_ERR_PREAUTH_FAILED", 25: "KDC_ERR_PREAUTH_REQUIRED",
};

const krbError = (code: number, sname: string[], edata?: FieldSpec) =>
  tlv(0x7e, "KRB-ERROR [APPLICATION 30]", [
    seq("KRB-ERROR", [
      ctx(0, "pvno", int("pvno", 5)),
      ctx(1, "msg-type", int("msg-type", 30, "30 (KRB-ERROR)")),
      ctx(4, "stime", ktime("stime", "20261119083012Z", "The KDC’s clock. Kerberos refuses clocks more than 5 minutes apart.")),
      ctx(5, "susec", int("susec", 412733, undefined, "Microseconds part of the server time.")),
      ctx(6, "error-code", int("error-code", code, `${code} (${ERR[code]})`)),
      ctx(9, "realm", kstr("realm", REALM)),
      ctx(10, "sname", principal(2, sname)),
      ...(edata ? [ctx(12, "e-data", edata)] : []),
    ]),
  ], `${code} ${ERR[code]}`);

const kerb = (msg: FieldSpec, summary: string): LayerSpec =>
  proto({
    id: "kerberos", name: "Kerberos", osi: 7, summary: `Kerberos ${summary}`,
    fields: [
      { name: "Record mark", u32: sizeOf([msg]), value: `${sizeOf([msg])} bytes`, note: "Over TCP, every Kerberos message starts with a 4-byte length so the receiver knows where it ends." },
      msg,
    ],
  });

// ------------------------------------------------------------ SMB2 + SPNEGO carrying the AP-REQ

const le64 = (n: number): Bytes => [...u32le(n % 2 ** 32), ...u32le(Math.floor(n / 2 ** 32))];
const SPNEGO_OID = oid("SPNEGO", "2b0601050502", "1.3.6.1.5.5.2");
const MSKRB_OID = oid("MS KRB5", "2a864882f712010202", "1.2.840.48018.1.2.2");
const KRB5_OID = oid("KRB5", "2a864886f712010202", "1.2.840.113554.1.2.2");
const SESSION = 0x0000100000000039;

const smb2Hdr = (o: { resp?: boolean; msgId: number; session: number; signed?: boolean; credits: number }): FieldSpec[] => {
  const flags = (o.resp ? 1 : 0) | (o.signed ? 8 : 0);
  return [
    { name: "Protocol ID", bytes: "fe534d42", value: "\\xFESMB", note: "Marks an SMB version 2 or 3 message." },
    { name: "Header length", bytes: u16le(64), value: "64" },
    { name: "Credit charge", bytes: u16le(1), value: "1" },
    { name: "Status", bytes: u32le(0), value: "STATUS_SUCCESS (0)" },
    { name: "Command", bytes: u16le(1), value: "1 (SESSION_SETUP)", note: "Log in to the file server." },
    { name: o.resp ? "Credits granted" : "Credits requested", bytes: u16le(o.credits), value: String(o.credits) },
    { name: "Flags", bytes: u32le(flags), value: o.resp ? (o.signed ? "response, signed" : "response") : "request" },
    { name: "Next command", bytes: u32le(0), value: "0 (no chained command)" },
    { name: "Message ID", bytes: le64(o.msgId), value: String(o.msgId) },
    { name: "Process ID", bytes: u32le(0xfeff), value: "0xfeff" },
    { name: "Tree ID", bytes: u32le(0), value: "0 (no share opened yet)" },
    { name: "Session ID", bytes: le64(o.session), value: `0x${o.session.toString(16).padStart(16, "0")}` },
    o.signed
      ? { name: "Signature", random: 16, opaque: true, note: "Signed with a key derived from the Kerberos session key: proof the reply really came from fs01." }
      : { name: "Signature", zero: 16, value: "none" },
  ];
};

const nbss = (inner: FieldSpec[]): LayerSpec =>
  proto({
    id: "nbss", name: "NetBIOS Session Service", osi: 5,
    fields: [
      { name: "Message type", u8: 0, value: "0 (session message)" },
      { name: "Length", u24: sizeOf(inner), value: `${sizeOf(inner)} bytes`, note: "SMB over TCP 445 keeps this old 4-byte framing header." },
    ],
  });

const smbLayer = (fields: FieldSpec[], summary: string): LayerSpec => proto({ id: "smb2", name: "SMB2", osi: 7, summary, fields });

const spnegoInit = tlv(0x60, "GSS-API InitialContextToken [APPLICATION 0]", [
  SPNEGO_OID,
  tlv(0xa0, "negTokenInit [0]", [
    seq("NegTokenInit", [
      ctx(0, "mechTypes", seq("mechTypes", [MSKRB_OID, KRB5_OID], "MS KRB5, KRB5")),
      ctx(2, "mechToken", octets("mechToken", [
        tlv(0x60, "Kerberos GSS-API token", [
          KRB5_OID,
          { name: "TOK_ID", bytes: "0100", value: "0x0100 (KRB_AP_REQ)" },
          apReq({ tktSname: ["cifs", "fs01.corp.example.com"], tktEtype: 18, tktKvno: 5, tktLen: 880, tktNote: "Encrypted with fs01’s own computer-account key. The file server opens it without asking the DC.", options: 0x20000000, authLen: 180 }),
        ], "AP-REQ"),
      ])),
    ]),
  ], "Kerberos"),
], "SPNEGO: Kerberos AP-REQ");

const spnegoResp = tlv(0xa1, "negTokenResp [1]", [
  seq("NegTokenResp", [
    ctx(0, "negState", enumv("negState", 0, "0 (accept-completed)")),
    ctx(1, "supportedMech", MSKRB_OID),
    ctx(2, "responseToken", octets("responseToken", [
      tlv(0x60, "Kerberos GSS-API token", [
        KRB5_OID,
        { name: "TOK_ID", bytes: "0200", value: "0x0200 (KRB_AP_REP)" },
        tlv(0x6f, "AP-REP [APPLICATION 15]", [
          seq("AP-REP", [
            ctx(0, "pvno", int("pvno", 5)),
            ctx(1, "msg-type", int("msg-type", 15, "15 (AP-REP)")),
            ctx(2, "enc-part", encData(18, null, 92, "EncAPRepPart (client’s time echoed back)", "Encrypted with the session key. Only the real fs01 could make this, so the client knows the server is genuine (mutual authentication).")),
          ]),
        ], "AP-REP"),
      ], "AP-REP"),
    ])),
  ]),
], "accept-completed");

const setupReqFields = (): FieldSpec[] => {
  const blob = sizeOf([spnegoInit]);
  return [
    ...smb2Hdr({ msgId: 2, session: 0, credits: 33 }),
    { name: "Structure size", bytes: u16le(25), value: "25" },
    { name: "Flags", u8: 0 },
    { name: "Security mode", u8: 1, value: "signing enabled" },
    { name: "Capabilities", bytes: u32le(1), value: "DFS" },
    { name: "Channel", bytes: u32le(0), value: "0" },
    { name: "Security buffer offset", bytes: u16le(88), value: "88" },
    { name: "Security buffer length", bytes: u16le(blob), value: String(blob) },
    { name: "Previous session ID", zero: 8 },
    { ...spnegoInit, name: "Security blob: " + spnegoInit.name },
  ];
};
const setupRespFields = (): FieldSpec[] => {
  const blob = sizeOf([spnegoResp]);
  return [
    ...smb2Hdr({ resp: true, msgId: 2, session: SESSION, signed: true, credits: 1 }),
    { name: "Structure size", bytes: u16le(9), value: "9" },
    { name: "Session flags", bytes: u16le(0), value: "0 (a real user, not guest)" },
    { name: "Security buffer offset", bytes: u16le(72), value: "72" },
    { name: "Security buffer length", bytes: u16le(blob), value: String(blob) },
    { ...spnegoResp, name: "Security blob: " + spnegoResp.name },
  ];
};

// ------------------------------------------------------------ network

interface Host { ip: string; mac: string }
const WS: Host = { ip: "192.0.2.50", mac: "00:15:5d:0a:32:11" };
const DC: Host = { ip: "192.0.2.10", mac: "00:15:5d:0a:0a:01" };
const FS: Host = { ip: "192.0.2.20", mac: "00:15:5d:0a:14:02" };
const AT: Host = { ip: "192.0.2.66", mac: "00:15:5d:0a:42:66" };

let ipId = 0x2a10;
const lan = (a: Host, b: Host) => [eth({ src: a.mac, dst: b.mac }), ipv4({ src: a.ip, dst: b.ip, ttl: 128, id: ipId++ })];

/** One request/reply on a fresh TCP connection (handshake not shown): returns both packets. */
function exchange(c: Host, s: Host, sport: number, dport: number, isn: number, req: LayerSpec[], rep: LayerSpec[]) {
  const reqLen = build(...req).bytes.length;
  const sIsn = (isn + 0x3c3c1234) >>> 0;
  return {
    req: build(...lan(c, s), tcp({ sport, dport, seq: 1, ack: 1, flags: "PA", win: 1026, seqBase: isn, ackBase: sIsn }), ...req),
    rep: build(...lan(s, c), tcp({ sport: dport, dport: sport, seq: 1, ack: 1 + reqLen, flags: "PA", win: 2053, seqBase: sIsn, ackBase: isn }), ...rep),
  };
}

const methodData = octets("e-data", [
  seq("METHOD-DATA", [
    etypeInfo2([[18, "CORP.EXAMPLE.COMdanish"], [23, null]]),
    paData(2, "PA-ENC-TIMESTAMP", []),
    paData(16, "PA-PK-AS-REQ", []),
    paData(15, "PA-PK-AS-REP-19", []),
  ], "ways to pre-authenticate"),
], undefined, "Tells the client which pre-authentication methods work and which salt to use for its key.");

// Normal flow
const x1 = exchange(WS, DC, 49702, 88, 0x7a31c004,
  [kerb(asReq([paPacRequest], 0x5e3a91c4), "AS-REQ")],
  [kerb(krbError(25, ["krbtgt", REALM], methodData), "KRB-ERROR")]);
const x2 = exchange(WS, DC, 49703, 88, 0x1d00b2e8,
  [kerb(asReq([paEncTs("Encrypted with a key made from danish’s password. If the KDC can decrypt it, the password was right."), paPacRequest], 0x2f6b0d17), "AS-REQ")],
  [kerb(kdcRep({
    app: 0x6b, msgType: 11, label: "AS-REP", padata: [etypeInfo2([[18, "CORP.EXAMPLE.COMdanish"]])], cname: "danish",
    tktSname: ["krbtgt", REALM], tktEtype: 18, tktKvno: 2, tktLen: 880, tktNote: TGT_NOTE,
    encEtype: 18, encKvno: 3, encLen: 300, encWhat: "EncASRepPart (TGT session key, nonce, times)", encNote: "Encrypted with danish’s password key. Only the real danish can open it and get the session key.",
  }), "AS-REP")]);
const x3 = exchange(WS, DC, 49704, 88, 0x44e1c9a0,
  [kerb(tgsReq(["cifs", "fs01.corp.example.com"], [18, 17, 23], 0x31c27aa5), "TGS-REQ")],
  [kerb(kdcRep({
    app: 0x6d, msgType: 13, label: "TGS-REP", cname: "danish",
    tktSname: ["cifs", "fs01.corp.example.com"], tktEtype: 18, tktKvno: 5, tktLen: 880, tktNote: "Encrypted with fs01’s computer-account key. Only the file server can open it.",
    encEtype: 18, encKvno: null, encLen: 290, encWhat: "EncTGSRepPart (service session key, nonce, times)", encNote: "Encrypted with the TGT session key from the AS-REP, not the password.",
  }), "TGS-REP")]);
const smbReq = setupReqFields();
const smbResp = setupRespFields();
const x4 = exchange(WS, FS, 49705, 445, 0x0c81f0aa,
  [nbss(smbReq), smbLayer(smbReq, "SMB2 Session Setup Request (Kerberos AP-REQ)")],
  [nbss(smbResp), smbLayer(smbResp, "SMB2 Session Setup Response (AP-REP)")]);

// Wrong password
const f1 = exchange(WS, DC, 49820, 88, 0x6a0b3311,
  [kerb(asReq([paEncTs("Encrypted with a key made from the mistyped password. The KDC will fail to decrypt it."), paPacRequest], 0x4471a0c3), "AS-REQ")],
  [kerb(krbError(24, ["krbtgt", REALM]), "KRB-ERROR")]);

// Kerberoasting
const SQL = ["MSSQLSvc", "sql01.corp.example.com:1433"];
const k1 = exchange(AT, DC, 51544, 88, 0x2b8d0e61,
  [kerb(tgsReq(SQL, [23], 0x0aa1f2c9), "TGS-REQ")],
  [kerb(kdcRep({
    app: 0x6d, msgType: 13, label: "TGS-REP", cname: "intern",
    tktSname: SQL, tktEtype: 23, tktKvno: 3, tktLen: 880, tktNote: "RC4-encrypted with the key of svc_sql, which is just the MD4 hash of its password. This is what the attacker cracks offline.",
    encEtype: 23, encKvno: null, encLen: 280, encWhat: "EncTGSRepPart", encNote: "Encrypted with the attacker’s own TGT session key.",
  }), "TGS-REP")]);
const k2 = exchange(AT, DC, 51560, 88, 0x5f17cc02,
  [kerb(tgsReq(SQL, [23], 0x7b30e914), "TGS-REQ")],
  [kerb(krbError(14, SQL), "KRB-ERROR")]);

const devices: Device[] = [
  { id: "ws", kind: "desktop", label: "Workstation", sub: WS.ip, x: 10, y: 60 },
  { id: "switch", kind: "switch", label: "Office switch", x: 42, y: 60 },
  { id: "dc", kind: "auth", label: "DC01 (KDC)", sub: DC.ip, x: 84, y: 26 },
  { id: "fs", kind: "nas", label: "fs01 file server", sub: FS.ip, x: 84, y: 76 },
];
const links: [string, string][] = [["ws", "switch"], ["switch", "dc"], ["switch", "fs"]];

export default defineLesson({
  id: "kerberos",
  name: "Kerberos",
  full: "Kerberos Network Authentication Protocol (v5)",
  group: "security",
  layer: 7,
  difficulty: 3,
  tagline: "Log in once, get tickets, never send your password.",
  description:
    "Kerberos is how a Windows domain proves who you are. You prove your password once to the domain controller and get a ticket-granting ticket; after that you trade it for service tickets that file servers, mail and databases accept, without your password ever crossing the network.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP/UDP 88"],
    ["Encoding", "ASN.1 DER"],
    ["Encryption", "AES256-CTS-HMAC-SHA1 (RC4 is legacy)"],
    ["Ticket lifetime", "10 hours (Windows default)"],
    ["Defined in", "RFC 4120"],
  ],
  ports: "88 (TCP and UDP), 464 for password changes",
  rfc: "RFC 4120, RFC 3962, RFC 4178 (SPNEGO)",
  keywords: ["kdc", "tgt", "ticket", "active directory", "domain controller", "spn", "kerberoasting", "as-req", "tgs-req", "ap-req", "pac", "gmsa", "single sign-on"],
  related: ["ldap", "smb", "tls", "radius"],
  devices,
  links,
  legend: [
    ["amber", "Requests from the workstation"],
    ["teal", "Tickets and keys from the KDC"],
    ["green", "Access granted"],
    ["blue", "Pre-authentication hints"],
    ["red", "Errors and attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Log in and open \\\\fs01\\share",
      summary: "danish signs in to Windows, gets a TGT, trades it for a file-server ticket and opens a share.",
      kind: "normal",
      steps: [
        {
          title: "Ask for a TGT",
          desc: "AS-REQ without proof, KDC asks for pre-auth",
          detail:
            "After danish types his password, Windows sends an AS-REQ to the domain controller asking for a ticket for krbtgt, the ticket-granting service. The first try carries no proof of the password, so the KDC answers KRB-ERROR 25 (pre-authentication required) and lists the methods and salt the client should use. This extra round trip is normal and harmless.",
          facts: [["Server", `DC01 ${DC.ip}, TCP 88`], ["Asking for", `krbtgt/${REALM}`], ["Reply", "KDC_ERR_PREAUTH_REQUIRED (25)"]],
          quiz: {
            q: "Why does the KDC insist on pre-authentication instead of just sending the reply?",
            options: [
              "So anyone can’t ask for replies locked with your password key and crack them offline",
              "Because the reply is too big for one packet",
              "To check the client’s IP address",
              "Because the clocks are out of sync",
            ],
            answer: 0,
            why: "Without pre-auth, anyone could request an AS-REP for any user and try to guess the password offline (this attack is called AS-REP roasting).",
          },
          events: [
            pkt("ws", "dc", "amber", "AS-REQ", ["for krbtgt", "no proof yet"], { time: 0, info: "AS-REQ danish@CORP.EXAMPLE.COM → krbtgt/CORP.EXAMPLE.COM", packet: x1.req }),
            pkt("dc", "ws", "blue", "KRB-ERROR", ["25: pre-auth required", "use AES, salt …danish"], { time: 0.0006, info: "KRB Error: KRB5KDC_ERR_PREAUTH_REQUIRED", packet: x1.rep }),
          ],
        },
        {
          title: "Prove the password",
          desc: "Encrypted timestamp in, TGT out",
          detail:
            "Windows turns the password plus the salt into an AES key and encrypts the current time with it (PA-ENC-TIMESTAMP). The KDC makes the same key from the stored password hash; if the time decrypts and is within 5 minutes, the password is right. It replies with an AS-REP holding the TGT (locked with the krbtgt key) and a session key (locked with danish’s key).",
          facts: [["Proof", "AES-encrypted timestamp"], ["Got", "TGT, valid 10 hours"], ["Password on the wire", "Never"]],
          quiz: {
            q: "The TGT inside the AS-REP is encrypted with which key?",
            options: ["danish’s password key", "The krbtgt account’s key", "The file server’s key", "It isn’t encrypted"],
            answer: 1,
            why: "Only domain controllers know the krbtgt key, so the client can carry the TGT but can’t read or forge it.",
          },
          events: [
            pkt("ws", "dc", "amber", "AS-REQ", ["+ encrypted timestamp"], { time: 0.0031, info: "AS-REQ danish@CORP.EXAMPLE.COM (PA-ENC-TIMESTAMP)", packet: x2.req }),
            pkt("dc", "ws", "teal", "AS-REP", ["TGT + session key"], { time: 0.0049, info: "AS-REP danish@CORP.EXAMPLE.COM", packet: x2.rep }),
            note("ws", "TGT CACHED (10 H)", "green"),
          ],
        },
        {
          title: "Ask for a service ticket",
          desc: "TGS-REQ for cifs/fs01",
          detail:
            "danish opens \\\\fs01\\share. Windows needs a ticket for the service name cifs/fs01.corp.example.com, so it sends a TGS-REQ that includes the TGT and a fresh authenticator encrypted with the TGT session key. The KDC checks both and returns a TGS-REP with a service ticket locked with fs01’s own key.",
          facts: [["Service name (SPN)", "cifs/fs01.corp.example.com"], ["Proof", "TGT + authenticator"], ["Password needed", "No, the TGT is enough"]],
          quiz: {
            q: "Does the workstation need danish’s password again to get this ticket?",
            options: ["Yes, every ticket needs the password", "No, the TGT and its session key are the proof", "Only if the file server is in another building", "Yes, but only the hash"],
            answer: 1,
            why: "That is the point of a TGT: one password check, then tickets for many services until it expires.",
          },
          events: [
            pkt("ws", "dc", "amber", "TGS-REQ", ["TGT + authenticator", "for cifs/fs01"], { time: 0.0071, info: "TGS-REQ cifs/fs01.corp.example.com", packet: x3.req }),
            pkt("dc", "ws", "teal", "TGS-REP", ["ticket for fs01"], { time: 0.0085, info: "TGS-REP danish@CORP.EXAMPLE.COM", packet: x3.rep }),
          ],
        },
        {
          title: "Show the ticket to fs01",
          desc: "AP-REQ inside SMB2 Session Setup",
          detail:
            "The workstation hands the service ticket to the file server as an AP-REQ, wrapped in SPNEGO inside an SMB2 Session Setup. fs01 decrypts the ticket with its own key, checks the authenticator’s time, and reads danish’s groups from the PAC in the ticket. It answers with an AP-REP so the client knows the server is genuine too, and the share opens. The DC was not contacted at all.",
          facts: [["Carried in", "SMB2 over TCP 445"], ["Wrapped as", "SPNEGO → GSS-API → AP-REQ"], ["Mutual auth", "AP-REP proves the server"]],
          quiz: {
            q: "How does fs01 check the ticket without asking the domain controller?",
            options: ["It phones the DC over LDAP", "It decrypts the ticket with its own computer-account key", "It trusts any ticket it receives", "It compares the user’s password"],
            answer: 1,
            why: "Only the KDC and fs01 know fs01’s key. If the ticket decrypts and the authenticator matches, it must have come from the KDC.",
          },
          events: [
            pkt("ws", "fs", "amber", "AP-REQ", ["SMB2 session setup", "ticket + authenticator"], { time: 0.012, info: "Session Setup Request (Kerberos AP-REQ)", packet: x4.req }),
            pkt("fs", "ws", "green", "AP-REP", ["session ready", "signed"], { time: 0.0131, info: "Session Setup Response (AP-REP, accept-completed)", packet: x4.rep }),
            note("fs", "SHARE OPENED", "green"),
          ],
        },
      ],
      outro: {
        title: "Signed in once, tickets for everything",
        text: "danish proved his password to the KDC one time with an encrypted timestamp. The TGT then bought a service ticket for the file server, which fs01 checked on its own. The password never travelled, and every ticket expires on its own.",
        facts: [["Messages", "AS-REQ/REP, TGS-REQ/REP, AP-REQ/REP"], ["Round trips to DC", "3 (one was the pre-auth hint)"], ["Password sent", "Never"], ["Total time", "13 ms"]],
      },
    },
    {
      id: "wrong-password",
      name: "Wrong password",
      summary: "A typo in the password makes the encrypted timestamp unreadable to the KDC.",
      kind: "failure",
      steps: [
        {
          title: "Timestamp with the wrong key",
          desc: "AS-REQ built from a mistyped password",
          detail:
            "danish types his password with one letter wrong. Windows has no way to know, so it builds the AES key from the wrong password and encrypts the timestamp with it, exactly as before.",
          facts: [["Key made from", "The mistyped password"], ["Sent", "AS-REQ with PA-ENC-TIMESTAMP"], ["Server", `DC01 ${DC.ip}`]],
          quiz: {
            q: "What will the KDC find when it tries to decrypt the timestamp?",
            options: ["A timestamp 5 minutes off", "Garbage: the integrity check fails", "The plain password", "Nothing, it doesn’t check"],
            answer: 1,
            why: "AES with HMAC detects a wrong key: the checksum fails, so the KDC knows the password was wrong.",
          },
          events: [
            pkt("ws", "dc", "amber", "AS-REQ", ["+ encrypted timestamp", "(wrong key)"], { time: 0, info: "AS-REQ danish@CORP.EXAMPLE.COM (PA-ENC-TIMESTAMP)", packet: f1.req }),
          ],
        },
        {
          title: "Pre-auth failed",
          desc: "KRB-ERROR 24",
          detail:
            "The KDC answers KDC_ERR_PREAUTH_FAILED and adds one to danish’s bad-password count. Windows shows “The user name or password is incorrect.” After too many failures in a row the account policy locks the account, which slows down online guessing.",
          facts: [["Error", "24 KDC_ERR_PREAUTH_FAILED"], ["Event on DC", "4771 (pre-auth failed)"], ["Side effect", "badPwdCount + 1"]],
          events: [
            pkt("dc", "ws", "red", "KRB-ERROR", ["24: pre-auth failed"], { time: 0.0007, info: "KRB Error: KRB5KDC_ERR_PREAUTH_FAILED", packet: f1.rep }),
            note("dc", "BAD PASSWORD COUNT +1", "amber"),
            note("ws", "PASSWORD INCORRECT", "red"),
          ],
        },
      ],
      outro: {
        title: "Rejected without the password ever moving",
        text: "The KDC only ever saw an encrypted timestamp. Because it could not decrypt it, it knew the key, and so the password, was wrong. Clock skew gives a different error (37), so keep domain clocks in sync.",
        facts: [["Error", "24 PREAUTH_FAILED"], ["Clock too far off", "37 KRB_AP_ERR_SKEW"], ["Lockout", "Set by domain policy"]],
      },
    },
    {
      id: "kerberoasting",
      name: "Kerberoasting and how to stop it",
      summary: "A low-privilege user asks for a service ticket and cracks the service account’s password offline.",
      kind: "attack",
      devices: [...devices, { id: "attacker", kind: "attacker", label: "Phished laptop", sub: `${AT.ip} (user: intern)`, x: 12, y: 22 }],
      links: [...links, ["attacker", "switch"]],
      steps: [
        {
          title: "Pick a target",
          desc: "Ask for an RC4 ticket for a service account",
          detail:
            "An attacker controls a normal user account, intern. Any domain user may request a ticket for any service name, so the attacker asks for MSSQLSvc/sql01, which runs as a human-made account, svc_sql. The request lists only RC4 (etype 23) because RC4 keys are a plain hash of the password and are fast to guess.",
          facts: [["Requester", "intern (any domain user)"], ["Target SPN", "MSSQLSvc/sql01.corp.example.com:1433"], ["Asked etype", "23 (rc4-hmac) only"]],
          quiz: {
            q: "Which key is the service ticket’s encrypted part locked with?",
            options: ["intern’s password key", "The krbtgt key", "svc_sql’s password key", "A random key the attacker can’t use"],
            answer: 2,
            why: "Service tickets are locked with the service account’s key, which comes from its password. That is the weak point.",
          },
          events: [
            pkt("attacker", "dc", "red", "TGS-REQ", ["MSSQLSvc/sql01", "etype 23 only"], { time: 0, info: "TGS-REQ MSSQLSvc/sql01.corp.example.com:1433", packet: k1.req }),
          ],
        },
        {
          title: "The KDC obliges",
          desc: "A legitimate TGS-REP, RC4 encrypted",
          detail:
            "The KDC does its job: it returns a service ticket encrypted with svc_sql’s RC4 key. Nothing about this request looks unusual on its own, which is why the attack is popular. The attacker never even has to contact sql01.",
          facts: [["Ticket etype", "23 (rc4-hmac)"], ["Locked with", "MD4 hash of svc_sql’s password"], ["Logged as", "Event 4769, type 0x17"]],
          events: [
            pkt("dc", "attacker", "teal", "TGS-REP", ["ticket for sql01", "RC4!"], { time: 0.0008, info: "TGS-REP intern@CORP.EXAMPLE.COM", packet: k1.rep }),
          ],
        },
        {
          title: "Crack it offline",
          desc: "Billions of guesses, no lockout",
          detail:
            "The attacker copies the ticket to a fast GPU machine and guesses passwords. For each guess it makes the RC4 key and tries to decrypt the ticket; a correct guess gives a valid checksum. There is no lockout because the DC is not involved. A short, human-chosen service password like Summer2019! falls in minutes.",
          facts: [["Speed", "Billions of guesses per second (RC4)"], ["Lockout", "None, it’s offline"], ["Prize", "svc_sql’s password, often an admin"]],
          quiz: {
            q: "Which change makes the stolen ticket useless to crack?",
            options: ["Shorter ticket lifetime", "A 120-character random password for the service account", "Blocking port 88 at the switch", "Turning on SMB signing"],
            answer: 1,
            why: "Offline cracking only works if the password is guessable. A long random password (as gMSA accounts use) can’t be guessed in any realistic time.",
          },
          events: [note("attacker", "CRACKING OFFLINE", "red"), note("attacker", "svc_sql = Summer2019!", "red")],
        },
        {
          title: "The defence",
          desc: "AES only, gMSA, and monitoring",
          detail:
            "The admins switch svc_sql to a group managed service account (gMSA) with a 120-character random password that rotates every 30 days, and set it to AES only. Now an RC4-only request fails with KDC_ERR_ETYPE_NOSUPP, and even an AES ticket is impossible to crack. Alerts on bursts of 4769 events with RC4 catch anyone still trying.",
          facts: [["Error", "14 KDC_ERR_ETYPE_NOSUPP"], ["Account", "gMSA, 120 random chars, auto-rotated"], ["Also", "Disable RC4 domain-wide, alert on 4769"]],
          events: [
            pkt("attacker", "dc", "red", "TGS-REQ", ["MSSQLSvc/sql01", "etype 23 only"], { time: 5.2, info: "TGS-REQ MSSQLSvc/sql01.corp.example.com:1433", packet: k2.req }),
            pkt("dc", "attacker", "red", "KRB-ERROR", ["14: etype not supported"], { time: 5.2006, info: "KRB Error: KRB5KDC_ERR_ETYPE_NOSUPP", packet: k2.rep }),
            note("dc", "AES ONLY · ALERT RAISED", "green"),
          ],
        },
      ],
      outro: {
        title: "Tickets are only as strong as passwords",
        text: "Kerberoasting needs no special rights: any user can request a service ticket and attack it offline. The fix is to make service keys unguessable with gMSA or long random passwords, refuse RC4, and watch for unusual ticket requests.",
        facts: [["Attack", "Kerberoasting (offline cracking)"], ["Needs", "Any domain account"], ["Defence", "gMSA, AES only, monitoring"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Messages",
      items: [
        ["AS-REQ / AS-REP (10/11)", "Log in, get a TGT"],
        ["TGS-REQ / TGS-REP (12/13)", "Trade the TGT for a service ticket"],
        ["AP-REQ / AP-REP (14/15)", "Show a ticket to a service"],
        ["KRB-ERROR (30)", "Something went wrong; error-code says what"],
      ],
    },
    {
      title: "Error codes",
      items: [
        ["6 C_PRINCIPAL_UNKNOWN", "No such user"],
        ["14 ETYPE_NOSUPP", "No shared encryption type"],
        ["18 CLIENT_REVOKED", "Account disabled or locked"],
        ["24 PREAUTH_FAILED", "Wrong password"],
        ["25 PREAUTH_REQUIRED", "Send an encrypted timestamp first"],
        ["37 KRB_AP_ERR_SKEW", "Clocks more than 5 minutes apart"],
      ],
    },
    {
      title: "Numbers to know",
      items: [
        ["Port", "88 TCP/UDP"],
        ["Encryption types", "18 AES256, 17 AES128, 23 RC4 (avoid)"],
        ["TGT lifetime", "10 h, renewable for 7 days"],
        ["Max clock skew", "5 minutes"],
      ],
    },
  ],
});
