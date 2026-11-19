import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { Bytes } from "@/lib/bytes";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ext, hsMsg, ipv4, tcp, tls, vec } from "@/lib/proto";

// ------------------------------------------------------------ ASN.1 BER helpers
// LDAP messages are ASN.1 encoded with BER (definite lengths): tag, length, content.

const sizeOf = (fs: FieldSpec[]) => fs.map(field).reduce((n, f) => n + f.bytes.length, 0);
const berLen = (n: number): Bytes => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, (n >> 8) & 0xff, n & 0xff]);
const h2 = (n: number) => `0x${n.toString(16).padStart(2, "0")}`;

function tlv(tag: number, name: string, content: FieldSpec[], value?: string, note?: string): FieldSpec {
  const n = sizeOf(content);
  return {
    name,
    value: value ?? `${n} bytes`,
    note,
    fields: [
      { name: "Tag", u8: tag, value: h2(tag) },
      { name: "Length", bytes: berLen(n), value: n >= 0x80 ? `${n} (long form)` : String(n) },
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
const ostr = (name: string, s: string, note?: string) =>
  tlv(0x04, name, s ? [{ name: "Value", text: s, value: s }] : [], s ? s : "(empty)", note);
const seq = (name: string, items: FieldSpec[], value?: string, note?: string) => tlv(0x30, name, items, value, note);

// ------------------------------------------------------------ LDAP messages (RFC 4511)

const msg = (id: number, op: FieldSpec, label: string) =>
  seq(`LDAPMessage: ${label}`, [int("messageID", id, String(id), "Matches each response to its request."), op], `id ${id}, ${label}`);

const bindReq = (dn: string, pw: string) =>
  tlv(0x60, "bindRequest [APPLICATION 0]", [
    int("version", 3, "3 (LDAPv3)"),
    ostr("name", dn, "The DN (distinguished name) to log in as."),
    tlv(0x80, "authentication: simple [0]", [{ name: "Password", text: pw, value: pw, note: "Simple bind sends the password as plain bytes. Without TLS, anyone on the path can read it." }], `"${pw}" (clear text!)`),
  ], `simple bind as ${dn}`);

const RC: Record<number, string> = { 0: "success", 49: "invalidCredentials" };
const result = (tag: number, name: string, code: number, extra: FieldSpec[] = []) =>
  tlv(tag, name, [
    enumv("resultCode", code, `${code} (${RC[code]})`, code ? "Non-zero means the operation failed." : "0 means it worked."),
    ostr("matchedDN", ""),
    ostr("diagnosticMessage", ""),
    ...extra,
  ], `${code} (${RC[code]})`);

const BASE = "ou=people,dc=example,dc=com";
const eq = (attr: string, val: string, shown?: string) =>
  tlv(0xa3, "filter: equalityMatch [3]", [ostr("attributeDesc", attr), ostr("assertionValue", val)], `(${attr}=${shown ?? val})`);
const and = (items: FieldSpec[], shown: string) => tlv(0xa0, "filter: and [0]", items, shown);

const searchReq = (filter: FieldSpec, attrs: string[]) =>
  tlv(0x63, "searchRequest [APPLICATION 3]", [
    ostr("baseObject", BASE, "Where in the tree to start looking."),
    enumv("scope", 2, "2 (wholeSubtree)", "Search the base and everything under it."),
    enumv("derefAliases", 0, "0 (neverDerefAliases)"),
    int("sizeLimit", 2, "2", "Stop after 2 entries: a login should match exactly one."),
    int("timeLimit", 10, "10 seconds"),
    tlv(0x01, "typesOnly", [{ name: "Value", u8: 0, value: "FALSE" }], "FALSE", "FALSE: send attribute values, not just names."),
    filter,
    seq("attributes", attrs.map((a) => ostr("attribute", a)), attrs.join(", "), "Only these attributes come back."),
  ], `search ${filter.value}`);

const entry = (dn: string, attrs: [string, string[]][]) =>
  tlv(0x64, "searchResEntry [APPLICATION 4]", [
    ostr("objectName", dn, "The DN of the entry that matched."),
    seq("attributes", attrs.map(([t, vs]) => seq(`PartialAttribute: ${t}`, [ostr("type", t), tlv(0x31, "vals (SET)", vs.map((v) => ostr("value", v)), vs.join(", "))], vs.join(", "))), `${attrs.length} attributes`),
  ], dn);

const unbind = tlv(0x42, "unbindRequest [APPLICATION 2]", [], "(no content)", "Polite goodbye. The server closes the connection; there is no reply.");

const ldap = (msgs: FieldSpec[], summary: string): LayerSpec => proto({ id: "ldap", name: "LDAP", osi: 7, summary: `Lightweight Directory Access Protocol: ${summary}`, fields: msgs });

// ------------------------------------------------------------ network and TCP bookkeeping

interface Host { ip: string; mac: string }
const PC: Host = { ip: "192.0.2.50", mac: "3c:22:fb:7a:91:0e" };
const APP: Host = { ip: "192.0.2.30", mac: "00:16:3e:41:07:30" };
const DIR: Host = { ip: "192.0.2.20", mac: "00:16:3e:41:07:20" };
const ATT: Host = { ip: "203.0.113.66", mac: "00:1b:21:aa:00:66" };
const GW_MAC = "00:16:3e:41:07:01";

let ipId = 0x3b00;
const l2l3 = (a: Host, b: Host, ttl = 64) => [eth({ src: a.mac, dst: b.mac }), ipv4({ src: a.ip, dst: b.ip, ttl, id: ipId++ })];

/** A TCP connection whose sequence numbers advance as data is sent. */
function conn(c: Host, s: Host, cport: number, sport: number, cIsn: number, sIsn: number) {
  let cs = 1, ss = 1;
  const send = (fromC: boolean, app: LayerSpec | null, flags: string) => {
    const len = app ? build(app).bytes.length : 0;
    const seq = fromC ? cs : ss, ack = fromC ? ss : cs;
    const packet = build(
      ...(fromC ? l2l3(c, s) : l2l3(s, c)),
      tcp({ sport: fromC ? cport : sport, dport: fromC ? sport : cport, seq, ack, flags, win: fromC ? 502 : 509, seqBase: fromC ? cIsn : sIsn, ackBase: fromC ? sIsn : cIsn }),
      ...(app ? [app] : []),
    );
    const adv = len + (flags.includes("F") ? 1 : 0);
    if (fromC) cs += adv; else ss += adv;
    const fl = flags.split("").map((f) => ({ S: "SYN", A: "ACK", P: "PSH", F: "FIN" } as Record<string, string>)[f]).join(", ");
    return { packet, tcpInfo: `${fromC ? cport : sport} → ${fromC ? sport : cport} [${fl}] Seq=${seq} Ack=${ack} Len=${len}` };
  };
  return {
    syn: () => build(...l2l3(c, s), tcp({ sport: cport, dport: sport, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", { ts: [1200333, 0] }, "nop", { ws: 7 }], seqBase: cIsn })),
    synack: () => build(...l2l3(s, c), tcp({ sport, dport: cport, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1460 }, "sackOk", { ts: [7710022, 1200333] }, "nop", { ws: 7 }], seqBase: sIsn, ackBase: cIsn })),
    ack: () => build(...l2l3(c, s), tcp({ sport: cport, dport: sport, seq: 1, ack: 1, flags: "A", win: 502, seqBase: cIsn, ackBase: sIsn })),
    c: (app: LayerSpec | null, flags = "PA") => send(true, app, flags),
    s: (app: LayerSpec | null, flags = "PA") => send(false, app, flags),
  };
}

/** HTTPS request/response between a browser and the web app, shown as encrypted records. */
function https(from: Host, port: number, isn: number, reqLen: number, repLen: number, reqWhat: string, repWhat: string, viaGw = false) {
  const k = conn(from, APP, port, 443, isn, (isn + 0x2468ace) >>> 0);
  const fix = (p: ReturnType<typeof k.c>) => p;
  void viaGw;
  return {
    req: fix(k.c(tls({ records: [{ type: "appdata", encrypted: reqLen, what: reqWhat }] }))),
    rep: fix(k.s(tls({ records: [{ type: "appdata", encrypted: repLen, what: repWhat }] }))),
  };
}

// ------------------------------------------------------------ normal flow
const SVC_DN = "cn=webapp,ou=services,dc=example,dc=com";
const USER_DN = "uid=danish,ou=people,dc=example,dc=com";
const ATTRS = ["cn", "mail", "memberOf"];
const DANISH: [string, string[]][] = [["cn", ["Danish"]], ["mail", ["danish@example.com"]], ["memberOf", ["cn=staff,ou=groups,dc=example,dc=com", "cn=wiki-editors,ou=groups,dc=example,dc=com"]]];

const web1 = https(PC, 52110, 0x11aa2200, 640, 420, "HTTP POST /login (username=danish, password=…)", "HTTP 302 Found → /home, Set-Cookie: session=…");
const n = conn(APP, DIR, 50412, 389, 0x5c01d900, 0x90e3aa10);
const nSyn = n.syn(), nSynAck = n.synack(), nAck = n.ack();
const nBind = n.c(ldap([msg(1, bindReq(SVC_DN, "s3rv1ce-Pa55"), "bindRequest")], "bindRequest(1) cn=webapp simple"));
const nBindOk = n.s(ldap([msg(1, result(0x61, "bindResponse [APPLICATION 1]", 0), "bindResponse")], "bindResponse(1) success"));
const nSearch = n.c(ldap([msg(2, searchReq(eq("uid", "danish"), ATTRS), "searchRequest")], `searchRequest(2) "${BASE}" wholeSubtree (uid=danish)`));
const nFound = n.s(ldap([
  msg(2, entry(USER_DN, DANISH), "searchResEntry"),
  msg(2, result(0x65, "searchResDone [APPLICATION 5]", 0), "searchResDone"),
], `searchResEntry(2) "${USER_DN}" | searchResDone(2) success [1 result]`));
const nUserBind = n.c(ldap([msg(3, bindReq(USER_DN, "correct-horse-42"), "bindRequest")], "bindRequest(3) uid=danish simple"));
const nUserOk = n.s(ldap([msg(3, result(0x61, "bindResponse [APPLICATION 1]", 0), "bindResponse")], "bindResponse(3) success"));
const nUnbind = n.c(ldap([msg(4, unbind, "unbindRequest")], "unbindRequest(4)"));
const nFin = n.c(null, "FA");
const nFin2 = n.s(null, "FA");

// ------------------------------------------------------------ StartTLS
const st = conn(APP, DIR, 50430, 389, 0x22b10c00, 0x7e01f300);
const START_TLS = "1.3.6.1.4.1.1466.20037";
const stReq = st.c(ldap([msg(1, tlv(0x77, "extendedRequest [APPLICATION 23]", [tlv(0x80, "requestName [0]", [{ name: "OID", text: START_TLS, value: START_TLS }], `${START_TLS} (StartTLS)`)], "StartTLS"), "extendedRequest")], "extendedReq(1) LDAP_START_TLS_OID"));
const stResp = st.s(ldap([msg(1, result(0x78, "extendedResponse [APPLICATION 24]", 0, [tlv(0x8a, "responseName [10]", [{ name: "OID", text: START_TLS, value: START_TLS }], START_TLS)]), "extendedResponse")], "extendedResp(1) success"));
const SNI = "ldap.example.com";
const clientHello = tls({
  records: [{
    type: "handshake", version: 0x0301,
    fields: [hsMsg("client_hello", "Client Hello", [
      { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303, real version is in supported_versions)" },
      { name: "Random", random: 32 },
      vec("Session ID", 1, [{ name: "Session ID", random: 32 }]),
      vec("Cipher suites", 2, [
        { name: "Cipher suite", u16: 0x1302, value: "TLS_AES_256_GCM_SHA384" },
        { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256" },
        { name: "Cipher suite", u16: 0x1303, value: "TLS_CHACHA20_POLY1305_SHA256" },
      ], "3 suites"),
      vec("Compression methods", 1, [{ name: "Method", u8: 0, value: "null" }]),
      vec("Extensions", 2, [
        ext(0, "server_name", [vec("Server name list", 2, [{ name: "Type", u8: 0, value: "host_name" }, vec("Host name", 2, [{ name: "Name", text: SNI }], SNI)])], SNI),
        ext(10, "supported_groups", [vec("Groups", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, { name: "Group", u16: 0x0017, value: "secp256r1" }])], "x25519, secp256r1"),
        ext(13, "signature_algorithms", [vec("Algorithms", 2, [{ name: "Algorithm", u16: 0x0804, value: "rsa_pss_rsae_sha256" }, { name: "Algorithm", u16: 0x0403, value: "ecdsa_secp256r1_sha256" }])]),
        ext(43, "supported_versions", [vec("Versions", 1, [{ name: "Version", u16: 0x0304, value: "TLS 1.3" }, { name: "Version", u16: 0x0303, value: "TLS 1.2" }])], "TLS 1.3, 1.2"),
        ext(51, "key_share", [vec("Client shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32 }])])], "x25519"),
      ]),
    ])],
  }],
});
const serverHello = tls({
  records: [
    {
      type: "handshake",
      fields: [hsMsg("server_hello", "Server Hello", [
        { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
        { name: "Random", random: 32 },
        vec("Session ID", 1, [{ name: "Session ID (echo)", random: 32 }]),
        { name: "Cipher suite", u16: 0x1302, value: "TLS_AES_256_GCM_SHA384" },
        { name: "Compression method", u8: 0, value: "null" },
        vec("Extensions", 2, [
          ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3" }], "TLS 1.3"),
          ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32 }])], "x25519"),
        ]),
      ])],
    },
    { type: "appdata", encrypted: 1120, what: "EncryptedExtensions, Certificate (ldap.example.com), CertificateVerify, Finished" },
  ],
});
const stCH = st.c(clientHello);
const stSH = st.s(serverHello);
const stFin = st.c(tls({ records: [{ type: "appdata", encrypted: 53, what: "Client Finished" }] }));
const stBind = st.c(tls({ records: [{ type: "appdata", encrypted: 86, what: "LDAP bindRequest(2) cn=webapp (password now hidden)" }] }));
const stBindOk = st.s(tls({ records: [{ type: "appdata", encrypted: 31, what: "LDAP bindResponse(2) success" }] }));

// ------------------------------------------------------------ wrong password
const web2 = https(PC, 52190, 0x31bb0400, 640, 3100 > 1400 ? 980 : 980, "HTTP POST /login (username=danish, password=…)", "HTTP 200 OK, login page with “Invalid username or password”");
const w = conn(APP, DIR, 50441, 389, 0x6d00e100, 0x0aa7b200);
const wBind = w.c(ldap([msg(3, bindReq(USER_DN, "correct-horse-24"), "bindRequest")], "bindRequest(3) uid=danish simple"));
const wFail = w.s(ldap([msg(3, result(0x61, "bindResponse [APPLICATION 1]", 49), "bindResponse")], "bindResponse(3) invalidCredentials"));

// ------------------------------------------------------------ LDAP injection
const ADMIN: [string, string[]][] = [["cn", ["Directory Admin"]], ["mail", ["admin@example.com"]], ["memberOf", ["cn=admins,ou=groups,dc=example,dc=com"]]];
const attackWeb = https(ATT, 61002, 0x7c11d000, 650, 980, "HTTP POST /login (username=admin)(&), password=x)", "HTTP 302 Found → /admin, Set-Cookie: session=…");
const a = conn(APP, DIR, 50466, 389, 0x41f02a00, 0x13b7c900);
const aSearch = a.c(ldap([msg(2, searchReq(and([eq("uid", "admin"), and([], "(&) always true")], "(&(uid=admin)(&))"), ATTRS), "searchRequest")], `searchRequest(2) "${BASE}" wholeSubtree (&(uid=admin)(&))`));
const aFound = a.s(ldap([
  msg(2, entry("uid=admin,ou=people,dc=example,dc=com", ADMIN), "searchResEntry"),
  msg(2, result(0x65, "searchResDone [APPLICATION 5]", 0), "searchResDone"),
], `searchResEntry(2) "uid=admin,${BASE}" | searchResDone(2) success [1 result]`));
const fixedSearch = a.c(ldap([msg(3, searchReq(and([eq("uid", "admin)(&)", "admin\\29\\28&\\29"), eq("userPassword", "x")], "(&(uid=admin\\29\\28&\\29)(userPassword=x))"), ATTRS), "searchRequest")], `searchRequest(3) "${BASE}" wholeSubtree (&(uid=admin\\29\\28&\\29)(userPassword=x))`));
const fixedNone = a.s(ldap([msg(3, result(0x65, "searchResDone [APPLICATION 5]", 0), "searchResDone")], "searchResDone(3) success [0 results]"));

// ------------------------------------------------------------ lesson

const devices: Device[] = [
  { id: "pc", kind: "laptop", label: "Danish’s laptop", sub: PC.ip, x: 9, y: 62 },
  { id: "fw", kind: "firewall", label: "Firewall", x: 30, y: 62 },
  { id: "app", kind: "web", label: "Wiki web app", sub: APP.ip, x: 56, y: 40 },
  { id: "dir", kind: "auth", label: "LDAP directory", sub: DIR.ip, x: 88, y: 62 },
];
const links: [string, string][] = [["pc", "fw"], ["fw", "app"], ["app", "dir"]];
void GW_MAC;

export default defineLesson({
  id: "ldap",
  name: "LDAP",
  full: "Lightweight Directory Access Protocol",
  group: "security",
  layer: 7,
  difficulty: 2,
  tagline: "The company phone book that also checks your password.",
  description:
    "LDAP is how apps talk to a directory: the central list of users, groups and computers in an organisation (OpenLDAP, Active Directory). An app can log in (bind), look people up (search) and check a user’s password by binding as them. Messages are small ASN.1 structures encoded in BER.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP 389, LDAPS on 636"],
    ["Encoding", "ASN.1 BER"],
    ["Main operations", "Bind, Search, Modify, Unbind"],
    ["Secure it with", "StartTLS or LDAPS"],
    ["Defined in", "RFC 4511"],
  ],
  ports: "389 (LDAP, StartTLS), 636 (LDAPS), 3268/3269 (AD Global Catalog)",
  rfc: "RFC 4511, RFC 4515 (filters), RFC 4513 (StartTLS)",
  keywords: ["directory", "active directory", "openldap", "bind", "search filter", "dn", "starttls", "ldaps", "ldap injection", "invalidCredentials", "ber"],
  related: ["kerberos", "tls", "tcp", "radius"],
  devices,
  links,
  legend: [
    ["green", "Handshake and success"],
    ["amber", "Requests from the web app"],
    ["violet", "Directory answers"],
    ["teal", "TLS encryption"],
    ["red", "Errors and attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "A web app logs Danish in",
      summary: "The wiki looks Danish up in the directory, then checks his password by binding as him.",
      kind: "normal",
      steps: [
        {
          title: "Login form submitted",
          desc: "HTTPS POST, then a TCP connection to port 389",
          detail:
            "Danish types his username and password into the company wiki. The browser sends them over HTTPS, so that hop is encrypted. The wiki does not store passwords itself; it opens a TCP connection to the LDAP directory on port 389 to ask.",
          facts: [["Directory", `${DIR.ip}, TCP 389`], ["Web app port", "50412 (temporary)"], ["Browser hop", "HTTPS (encrypted)"]],
          events: [
            pkt("pc", "app", "amber", "HTTPS", ["POST /login"], { time: 0, info: "Application Data (POST /login)", packet: web1.req.packet }),
            pkt("app", "dir", "green", "SYN", ["port 389"], { time: 0.0021, info: "50412 → 389 [SYN] Seq=0 Win=64240 Len=0 MSS=1460", packet: nSyn }),
            pkt("dir", "app", "green", "SYN-ACK", [], { time: 0.0023, info: "389 → 50412 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0", packet: nSynAck }),
            pkt("app", "dir", "green", "ACK", [], { time: 0.0024, info: "50412 → 389 [ACK] Seq=1 Ack=1 Win=502 Len=0", packet: nAck }),
          ],
        },
        {
          title: "App logs in to LDAP",
          desc: "bindRequest as the service account",
          detail:
            "Before it may search, the wiki authenticates as its own service account, cn=webapp. A simple bind carries the DN and the password. Open the packet: the password is right there in plain bytes, because this connection has no TLS. The directory answers resultCode 0, success.",
          facts: [["Bind DN", SVC_DN], ["Method", "simple (password)"], ["Result", "0 success"]],
          quiz: {
            q: "Someone captures this packet on the network. What can they learn?",
            options: ["Nothing, LDAP is encrypted", "Only the username", "The service account’s password, in plain text", "A hash they must crack"],
            answer: 2,
            why: "Simple bind over plain port 389 sends the password as-is. That’s why LDAP should run inside TLS (StartTLS or LDAPS).",
          },
          events: [
            pkt("app", "dir", "amber", "BIND", ["cn=webapp", "password in clear!"], { time: 0.0026, info: "bindRequest(1) \"cn=webapp,ou=services,dc=example,dc=com\" simple", packet: nBind.packet }),
            note("app", "PASSWORD IN CLEAR TEXT", "red"),
            pkt("dir", "app", "violet", "BIND OK", ["resultCode 0"], { time: 0.0031, info: "bindResponse(1) success", packet: nBindOk.packet }),
          ],
        },
        {
          title: "Find the user",
          desc: "searchRequest with filter (uid=danish)",
          detail:
            "The wiki searches under ou=people for entries matching the filter (uid=danish) and asks only for cn, mail and memberOf. The filter is not sent as text: it is encoded as an equalityMatch structure with the attribute and the value. The directory sends one searchResEntry, then searchResDone to say the search is finished.",
          facts: [["Base", BASE], ["Filter", "(uid=danish)"], ["Found", USER_DN]],
          quiz: {
            q: "How does the wiki know there are no more results coming?",
            options: ["The TCP connection closes", "A searchResDone message with the same messageID", "A timeout", "The entry has a 'last' flag"],
            answer: 1,
            why: "Each search ends with searchResDone, which carries the result code. Entries before it share the same messageID.",
          },
          events: [
            pkt("app", "dir", "amber", "SEARCH", ["(uid=danish)"], { time: 0.0034, info: `searchRequest(2) "${BASE}" wholeSubtree`, packet: nSearch.packet }),
            pkt("dir", "app", "violet", "ENTRY", ["uid=danish,…", "+ searchResDone"], { time: 0.0041, info: `searchResEntry(2) "${USER_DN}" | searchResDone(2) success [1 result]`, packet: nFound.packet }),
          ],
        },
        {
          title: "Check the password",
          desc: "Bind again, this time as Danish",
          detail:
            "To check the password, the wiki simply tries to bind with Danish’s DN and the password he typed. The directory compares it with the stored hash and answers success. The wiki never sees the stored hash, and Danish’s groups (staff, wiki-editors) decide what he may do.",
          facts: [["Bind DN", USER_DN], ["Result", "0 success"], ["Groups", "staff, wiki-editors"]],
          quiz: {
            q: "If the password were wrong, what would come back?",
            options: ["An empty search result", "bindResponse with resultCode 49 (invalidCredentials)", "A TCP reset", "searchResDone with code 32"],
            answer: 1,
            why: "A failed bind returns resultCode 49, invalidCredentials. The connection stays open.",
          },
          events: [
            pkt("app", "dir", "amber", "BIND", ["uid=danish", "his password"], { time: 0.0045, info: "bindRequest(3) \"uid=danish,ou=people,dc=example,dc=com\" simple", packet: nUserBind.packet }),
            pkt("dir", "app", "violet", "BIND OK", ["resultCode 0"], { time: 0.0052, info: "bindResponse(3) success", packet: nUserOk.packet }),
            note("app", "PASSWORD CORRECT", "green"),
          ],
        },
        {
          title: "Say goodbye",
          desc: "unbindRequest, close, log the user in",
          detail:
            "The wiki sends unbindRequest, which has no reply, and closes the TCP connection. It then answers the browser with a redirect to the home page and a session cookie. Busy apps usually keep a pool of open LDAP connections instead of closing each time.",
          facts: [["unbind", "No response expected"], ["Then", "TCP FIN both ways"], ["Browser gets", "302 → /home + cookie"]],
          events: [
            pkt("app", "dir", "slate", "UNBIND", ["messageID 4"], { time: 0.0055, info: "unbindRequest(4)", packet: nUnbind.packet }),
            pkt("app", "dir", "slate", "FIN", [], { time: 0.0056, info: nFin.tcpInfo, packet: nFin.packet }),
            pkt("dir", "app", "slate", "FIN", [], { time: 0.0058, info: nFin2.tcpInfo, packet: nFin2.packet }),
            pkt("app", "pc", "green", "HTTPS", ["302 → /home"], { time: 0.0061, info: "Application Data (302 Found)", packet: web1.rep.packet }),
          ],
        },
      ],
      outro: {
        title: "Logged in through the directory",
        text: "The wiki bound as its service account, searched for uid=danish, and checked the password by binding as Danish. It works, but both passwords crossed the network in plain text. Next scenario: the same thing wrapped in TLS.",
        facts: [["LDAP messages", "7"], ["Operations", "bind, search, bind, unbind"], ["Weak spot", "Clear-text simple bind"], ["Total time", "6 ms"]],
      },
    },
    {
      id: "starttls",
      name: "Do it safely: StartTLS",
      summary: "The app upgrades port 389 to TLS before binding, so passwords are encrypted.",
      kind: "normal",
      steps: [
        {
          title: "Ask to upgrade",
          desc: "extendedRequest StartTLS",
          detail:
            "Right after connecting (handshake not shown), the app sends an extendedRequest with the StartTLS OID 1.3.6.1.4.1.1466.20037. The directory agrees with success. From the next byte on, both sides speak TLS on the same connection. The alternative is LDAPS: TLS from the first byte on port 636.",
          facts: [["Request OID", START_TLS], ["Port", "389, same connection"], ["Alternative", "LDAPS on 636"]],
          quiz: {
            q: "What must the app do if the server does NOT answer success to StartTLS?",
            options: ["Bind anyway in clear text", "Refuse to send the password and stop", "Switch to UDP", "Send the password twice"],
            answer: 1,
            why: "Falling back to clear text would let an attacker strip StartTLS and read passwords. A safe client fails closed.",
          },
          events: [
            pkt("app", "dir", "blue", "STARTTLS", ["extendedRequest"], { time: 0, info: "extendedReq(1) LDAP_START_TLS_OID", packet: stReq.packet }),
            pkt("dir", "app", "violet", "OK", ["go ahead"], { time: 0.0004, info: "extendedResp(1) success", packet: stResp.packet }),
          ],
        },
        {
          title: "TLS handshake",
          desc: "Client Hello, Server Hello, encrypted certificate",
          detail:
            "A normal TLS 1.3 handshake follows. The app checks that the directory’s certificate is valid for ldap.example.com and signed by a CA it trusts. That check stops someone in the middle from pretending to be the directory.",
          facts: [["Version", "TLS 1.3"], ["Key exchange", "x25519"], ["Certificate", "ldap.example.com"]],
          events: [
            pkt("app", "dir", "teal", "C.HELLO", ["TLS 1.3, x25519"], { time: 0.0007, info: "Client Hello (SNI=ldap.example.com)", packet: stCH.packet }),
            pkt("dir", "app", "teal", "S.HELLO", ["+ encrypted cert"], { time: 0.0019, info: "Server Hello, Application Data", packet: stSH.packet }),
            pkt("app", "dir", "teal", "FINISHED", [], { time: 0.0024, info: "Application Data (Finished)", packet: stFin.packet }),
          ],
        },
        {
          title: "Bind, now hidden",
          desc: "The same bindRequest inside TLS",
          detail:
            "The app now sends exactly the same bindRequest as before, but inside an encrypted TLS record. A capture shows only Application Data. The password is safe on the wire.",
          facts: [["Visible on the wire", "Only TLS records"], ["Inside", "bindRequest(2) cn=webapp"], ["Result", "success"]],
          quiz: {
            q: "Which part of the bind can an eavesdropper still see now?",
            options: ["The password", "The bind DN", "Only the record sizes and timing", "Everything, TLS only signs data"],
            answer: 2,
            why: "TLS encrypts the whole LDAP message. Only sizes and timing leak.",
          },
          events: [
            pkt("app", "dir", "teal", "BIND", ["encrypted"], { time: 0.0026, info: "Application Data (bindRequest)", packet: stBind.packet }),
            pkt("dir", "app", "teal", "BIND OK", ["encrypted"], { time: 0.0031, info: "Application Data (bindResponse)", packet: stBindOk.packet }),
            note("dir", "PASSWORD ENCRYPTED", "green"),
          ],
        },
      ],
      outro: {
        title: "Same LDAP, wrapped in TLS",
        text: "StartTLS upgrades a plain LDAP connection to TLS before any password is sent. Many directories (including Active Directory with LDAP signing and channel binding) can be set to refuse clear-text binds altogether.",
        facts: [["StartTLS", "Port 389, upgrade in place"], ["LDAPS", "Port 636, TLS from the start"], ["Best practice", "Refuse simple bind without TLS"]],
      },
    },
    {
      id: "wrong-password",
      name: "Wrong password (invalidCredentials)",
      summary: "Danish mistypes his password; the bind fails with resultCode 49.",
      kind: "failure",
      steps: [
        {
          title: "Bind with a typo",
          desc: "bindRequest as uid=danish",
          detail:
            "The app has already found Danish’s DN (as in the first scenario) and now binds with the password he typed, which has two digits swapped.",
          facts: [["Bind DN", USER_DN], ["Password", "correct-horse-24 (wrong)"], ["messageID", "3"]],
          events: [
            pkt("pc", "app", "amber", "HTTPS", ["POST /login"], { time: 0, info: "Application Data (POST /login)", packet: web2.req.packet }),
            pkt("app", "dir", "amber", "BIND", ["uid=danish", "wrong password"], { time: 0.0031, info: "bindRequest(3) \"uid=danish,ou=people,dc=example,dc=com\" simple", packet: wBind.packet }),
          ],
        },
        {
          title: "invalidCredentials",
          desc: "bindResponse resultCode 49",
          detail:
            "The directory answers resultCode 49, invalidCredentials. It deliberately gives the same answer for a wrong password and for a user that doesn’t exist, so attackers can’t use it to discover usernames. The wiki shows a vague “Invalid username or password” for the same reason.",
          facts: [["resultCode", "49 invalidCredentials"], ["Active Directory adds", "data 52e (bad password), 775 (locked)"], ["Policy", "Lockout after repeated failures"]],
          quiz: {
            q: "Why should the login page NOT say “wrong password” specifically?",
            options: ["It’s too long to display", "It would confirm that the username exists", "LDAP doesn’t tell the app", "Browsers block that text"],
            answer: 1,
            why: "Different messages for “no such user” and “wrong password” let attackers build a list of valid usernames.",
          },
          events: [
            pkt("dir", "app", "red", "BIND FAIL", ["resultCode 49"], { time: 0.0037, info: "bindResponse(3) invalidCredentials", packet: wFail.packet }),
            pkt("app", "pc", "red", "HTTPS", ["login failed"], { time: 0.0041, info: "Application Data (200 OK, login error)", packet: web2.rep.packet }),
            note("pc", "INVALID USERNAME OR PASSWORD", "red"),
          ],
        },
      ],
      outro: {
        title: "A clean, quiet failure",
        text: "A failed bind returns resultCode 49 and leaves the connection usable. Good apps show a generic error, count failures, and rely on the directory’s lockout policy to slow down guessing.",
        facts: [["Code", "49 invalidCredentials"], ["Connection", "Stays open"], ["Message to user", "Generic"]],
      },
    },
    {
      id: "injection",
      name: "LDAP injection and parameterised filters",
      summary: "An attacker types filter syntax into the username box and logs in as admin without a password.",
      kind: "attack",
      devices: [
        { id: "attacker", kind: "attacker", label: "Attacker", sub: ATT.ip, x: 9, y: 22 },
        ...devices,
      ],
      links: [...links, ["attacker", "fw"]],
      steps: [
        {
          title: "A strange username",
          desc: "username = admin)(&)",
          detail:
            "This older login page builds its filter by pasting text together: (&(uid=USER)(userPassword=PASS)). If the search finds an entry, the user is logged in. The attacker types admin)(&) as the username and x as the password.",
          facts: [["Typed username", "admin)(&)"], ["Typed password", "x"], ["App’s template", "(&(uid=…)(userPassword=…))"]],
          quiz: {
            q: "After pasting, the filter text is (&(uid=admin)(&))(userPassword=x)). What does the LDAP library actually send?",
            options: ["An error, nothing is sent", "(&(uid=admin)(&)), dropping the password part", "(uid=admin)(userPassword=x)", "The whole text as one string"],
            answer: 1,
            why: "Many libraries parse the first complete filter and ignore the rest. (&) is the always-true filter, so the password test vanishes.",
          },
          events: [
            pkt("attacker", "app", "red", "HTTPS", ["user=admin)(&)"], { time: 0, info: "Application Data (POST /login)", packet: attackWeb.req.packet }),
          ],
        },
        {
          title: "Filter hijacked",
          desc: "Search (&(uid=admin)(&)) matches admin",
          detail:
            "Look at the filter in the packet: an AND of (uid=admin) and an empty AND, which is always true. The password check is gone. The directory dutifully returns the admin entry, and the app logs the attacker in as admin.",
          facts: [["Sent filter", "(&(uid=admin)(&))"], ["Password checked", "No"], ["Result", "Logged in as admin"]],
          events: [
            pkt("app", "dir", "red", "SEARCH", ["(&(uid=admin)(&))"], { time: 0.003, info: `searchRequest(2) "${BASE}" wholeSubtree`, packet: aSearch.packet }),
            pkt("dir", "app", "violet", "ENTRY", ["uid=admin", "+ searchResDone"], { time: 0.0037, info: "searchResEntry(2) \"uid=admin,ou=people,dc=example,dc=com\" | searchResDone(2) success [1 result]", packet: aFound.packet }),
            pkt("app", "attacker", "red", "HTTPS", ["302 → /admin"], { time: 0.0041, info: "Application Data (302 Found)", packet: attackWeb.rep.packet }),
            note("app", "ATTACKER IS ADMIN", "red"),
          ],
        },
        {
          title: "The fix: escape input",
          desc: "Special characters become \\29 \\28",
          detail:
            "The fixed app escapes user input as RFC 4515 requires: ( becomes \\28, ) becomes \\29, * becomes \\2a, \\ becomes \\5c. Better still, it uses a filter builder that takes values as parameters. Now the whole typed text is just a value to compare, nobody has that uid, and the search returns zero entries. The real fix is also to stop comparing passwords in filters and bind as the user instead.",
          facts: [["Escaped value", "admin\\29\\28&\\29"], ["Result", "0 entries, login refused"], ["Best practice", "Parameterised filters + bind to check passwords"]],
          quiz: {
            q: "Which characters must be escaped in an LDAP filter value?",
            options: ["Only quotes", "( ) * \\ and NUL", "Only spaces", "Letters outside A–Z"],
            answer: 1,
            why: "RFC 4515 requires escaping (, ), *, \\ and NUL in assertion values, since they have meaning in filter syntax.",
          },
          events: [
            pkt("app", "dir", "amber", "SEARCH", ["uid = \"admin)(&)\"", "as a plain value"], { time: 30.1, info: `searchRequest(3) "${BASE}" wholeSubtree`, packet: fixedSearch.packet }),
            pkt("dir", "app", "violet", "DONE", ["0 entries"], { time: 30.1006, info: "searchResDone(3) success [0 results]", packet: fixedNone.packet }),
            note("app", "LOGIN REFUSED", "green"),
          ],
        },
      ],
      outro: {
        title: "Data must never become code",
        text: "LDAP injection is the directory cousin of SQL injection: text typed by a user changes the meaning of the query. Escaping values or using a filter builder keeps them as data, and checking passwords with a bind removes the most tempting target.",
        facts: [["Attack", "LDAP filter injection"], ["Defence", "RFC 4515 escaping / parameterised filters"], ["Also", "Bind to verify passwords, least-privilege service account"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Operations (BER tag)",
      items: [
        ["bindRequest 0x60 / bindResponse 0x61", "Log in"],
        ["searchRequest 0x63", "Find entries with a filter"],
        ["searchResEntry 0x64 / searchResDone 0x65", "Results, then the end marker"],
        ["unbindRequest 0x42", "Goodbye, no reply"],
        ["extendedRequest 0x77", "StartTLS, password modify, whoami"],
      ],
    },
    {
      title: "Result codes",
      items: [["0 success", "It worked"], ["32 noSuchObject", "Base DN doesn’t exist"], ["49 invalidCredentials", "Wrong DN or password"], ["50 insufficientAccessRights", "Not allowed"], ["4 sizeLimitExceeded", "More entries than sizeLimit"]],
    },
    {
      title: "Filters and ports",
      items: [["(uid=danish)", "Equality"], ["(&(a)(b)) (|(a)(b)) (!(a))", "AND, OR, NOT"], ["(cn=Dan*)", "Substring"], ["Escape", "( \\28  ) \\29  * \\2a  \\ \\5c"], ["Ports", "389 LDAP/StartTLS, 636 LDAPS"]],
    },
  ],
});
