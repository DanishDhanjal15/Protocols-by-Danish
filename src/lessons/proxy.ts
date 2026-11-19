import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, textLayer } from "@/lib/packet";
import { eth, ext, hsMsg, ipv4, tcp, TcpOpt, tls, vec } from "@/lib/proto";
import { ADDR } from "./_common";

// ---------------------------------------------------------------- TCP connection helper

type Seg = { flags?: string; data?: LayerSpec[]; info?: string; lost?: boolean; parallel?: boolean; via?: string[]; seq?: number; ack?: number; win?: number };
const SYN_OPTS: TcpOpt[] = [{ mss: 1460 }, "nop", { ws: 7 }, "nop", "nop", "sackOk"];
const FLAG_ORDER: [string, string][] = [["F", "FIN"], ["S", "SYN"], ["R", "RST"], ["P", "PSH"], ["A", "ACK"]];

/** One TCP connection: keeps the relative seq/ack numbers right for every segment. */
function conn(o: { a: string; b: string; cport: number; sport: number; cBase: number; sBase: number; cl: LayerSpec[]; sv: LayerSpec[] }) {
  const next = { a: 0, b: 0 };
  const seg = (fromA: boolean, time: number, color: Color, label: string, lines: string[], x: Seg = {}): PacketEvent => {
    const data = x.data ?? [];
    const len = data.length ? build(...data).bytes.length : 0;
    const flags = x.flags ?? (len ? "PA" : "A");
    const me = fromA ? "a" : "b", peer = fromA ? "b" : "a";
    const seq = x.seq ?? next[me];
    const ack = x.ack ?? next[peer];
    const hasAck = flags.includes("A"), syn = flags.includes("S");
    const win = x.win ?? (syn ? (fromA ? 64240 : 65160) : fromA ? 502 : 509);
    const sport = fromA ? o.cport : o.sport, dport = fromA ? o.sport : o.cport;
    const packet = build(...(fromA ? o.cl : o.sv), tcp({ sport, dport, seq, ack: hasAck ? ack : 0, flags, win, opts: syn ? SYN_OPTS : undefined, seqBase: fromA ? o.cBase : o.sBase, ackBase: hasAck ? (fromA ? o.sBase : o.cBase) : 0 }), ...data);
    if (x.seq === undefined) next[me] += len + (syn || flags.includes("F") ? 1 : 0);
    const names = FLAG_ORDER.filter(([c]) => flags.includes(c)).map(([, n]) => n).join(", ");
    const info = x.info ?? `${sport} → ${dport} [${names}] Seq=${seq}${hasAck ? ` Ack=${ack}` : ""} Win=${win} Len=${len}${syn ? " MSS=1460 WS=128 SACK_PERM" : ""}`;
    return pkt(fromA ? o.a : o.b, fromA ? o.b : o.a, color, label, lines, { time: Number(time.toFixed(4)), info, packet, lost: x.lost, parallel: x.parallel, via: x.via });
  };
  const c = (time: number, color: Color, label: string, lines: string[], x?: Seg) => seg(true, time, color, label, lines, x);
  const s = (time: number, color: Color, label: string, lines: string[], x?: Seg) => seg(false, time, color, label, lines, x);
  const open = (t: number, rtt: number): PacketEvent[] => [
    c(t, "green", "SYN", ["seq=0", `to port ${o.sport}`], { flags: "S" }),
    s(t + rtt, "green", "SYN-ACK", ["seq=0 ack=1"], { flags: "SA" }),
    c(t + rtt + 0.0001, "green", "ACK", ["ack=1", "connected"]),
  ];
  return { c, s, open, next };
}

// ---------------------------------------------------------------- TLS 1.3 hellos (passed through the tunnel)

function clientHello(host: string, seed: number): LayerSpec {
  const hello = hsMsg("client_hello", "Client Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
    { name: "Random", random: 32, seed },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: seed + 1 }], "32 bytes"),
    vec("Cipher suites", 2, [
      { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256 (0x1301)" },
      { name: "Cipher suite", u16: 0x1302, value: "TLS_AES_256_GCM_SHA384 (0x1302)" },
      { name: "Cipher suite", u16: 0x1303, value: "TLS_CHACHA20_POLY1305_SHA256 (0x1303)" },
    ], "3 suites"),
    vec("Compression methods", 1, [{ name: "Method", u8: 0, value: "null (0)" }], "null only"),
    vec("Extensions", 2, [
      ext(0, "server_name", [vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name (0)" }, vec("Host name", 2, [{ name: "Name", text: host }], host)])], host, "The proxy can read this name, but nothing after the handshake."),
      ext(10, "supported_groups", [vec("Groups", 2, [{ name: "Group", u16: 0x001d, value: "x25519 (0x001d)" }])], "x25519"),
      ext(13, "signature_algorithms", [vec("Algorithms", 2, [{ name: "Algorithm", u16: 0x0403, value: "ecdsa_secp256r1_sha256 (0x0403)" }, { name: "Algorithm", u16: 0x0804, value: "rsa_pss_rsae_sha256 (0x0804)" }])], "2 algorithms"),
      ext(43, "supported_versions", [vec("Versions", 1, [{ name: "Version", u16: 0x0304, value: "TLS 1.3 (0x0304)" }])], "TLS 1.3"),
      ext(51, "key_share", [vec("Client key shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 2 }], "32 bytes")])], "x25519 public key"),
    ]),
  ]);
  return tls({ records: [{ type: "handshake", version: 0x0301, fields: [hello] }], summary: `TLS 1.3 Client Hello (SNI=${host})` });
}
const serverHello = (seed: number): FieldSpec =>
  hsMsg("server_hello", "Server Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
    { name: "Random", random: 32, seed: seed + 50 },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: seed + 1 }], "32 bytes (echo)"),
    { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256 (0x1301)" },
    { name: "Compression method", u8: 0, value: "null (0)" },
    vec("Extensions", 2, [
      ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3 (0x0304)" }], "TLS 1.3"),
      ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 51 }], "32 bytes")], "x25519 public key"),
    ]),
  ]);
const serverFlight = (seed: number) => tls({ records: [
  { type: "handshake", fields: [serverHello(seed)] },
  { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] },
  { type: "appdata", encrypted: 1240, what: "EncryptedExtensions, Certificate, CertificateVerify, Finished (encrypted)" },
] });

// ---------------------------------------------------------------- network

const S = ADDR.web;
const PX = "192.168.1.5";
const PX_PORT = 3128;
const PX_MAC = "00:50:56:9c:31:28";
const toProxy = [eth({ src: ADDR.laptopMac, dst: PX_MAC }), ipv4({ src: ADDR.laptop, dst: PX })];
const fromProxy = [eth({ src: PX_MAC, dst: ADDR.laptopMac }), ipv4({ src: PX, dst: ADDR.laptop })];
const pxOut = [eth({ src: PX_MAC, dst: ADDR.routerMac }), ipv4({ src: PX, dst: S })];
const pxIn = [eth({ src: ADDR.routerMac, dst: PX_MAC }), ipv4({ src: S, dst: PX, ttl: 54 })];
const RTT = 0.034;

const devices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: ADDR.laptop, x: 9, y: 62 },
  { id: "proxy", kind: "proxy" as const, label: "Office proxy", sub: `${PX}:${PX_PORT}`, x: 34, y: 62 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 60, y: 38 },
  { id: "server", kind: "web" as const, label: "example.com", sub: S, x: 87, y: 62 },
];
const links: [string, string][] = [["client", "proxy"], ["proxy", "internet"], ["internet", "server"]];

const HTML = "<!doctype html><html><head><title>Example</title></head><body><h1>Hello via the proxy</h1></body></html>\n";
const blen = (s: string) => new TextEncoder().encode(s).length;
const UA = "User-Agent: curl/8.9.1";
const AUTH = "Proxy-Authorization: Basic ZGFuaXNoOnMzY3JldA==";

const absGet = (auth: boolean) => textLayer({
  id: "http", name: "HTTP", blankLine: true,
  lines: ["GET http://example.com/ HTTP/1.1", "Host: example.com", UA, "Accept: */*", ...(auth ? [AUTH] : []), "Proxy-Connection: Keep-Alive"],
  notes: auth
    ? { 0: "Absolute form: the full URL, scheme and host included. This is how the proxy knows where to go.", 4: "base64 of \"danish:s3cret\". Basic auth is encoding, not encryption: anyone on the LAN can decode it." }
    : { 0: "Absolute form: the full URL, scheme and host included. This is how the proxy knows where to go." },
});
const resp200 = (via: boolean) => textLayer({
  id: "http", name: "HTTP", blankLine: true,
  lines: ["HTTP/1.1 200 OK", "Date: Thu, 19 Nov 2026 09:30:12 GMT", "Content-Type: text/html; charset=utf-8", `Content-Length: ${blen(HTML)}`, ...(via ? ["Via: 1.1 office-proxy (squid/6.10)", "X-Cache: MISS from office-proxy"] : [])],
  body: { text: HTML, what: "HTML body" },
  notes: via ? { 4: "The proxy adds itself to Via.", 5: "MISS: the proxy had no cached copy. A second visit could be served from its cache." } : undefined,
});

export default defineLesson({
  id: "proxy",
  name: "HTTP proxy",
  full: "Forward HTTP proxy and CONNECT tunnels",
  group: "web",
  layer: 7,
  difficulty: 2,
  tagline: "A middleman that fetches pages for you, or tunnels them blind.",
  description:
    "A forward proxy sits between your browser and the internet, often in an office or school. For plain HTTP it reads your request, fetches the page itself and hands it back. For HTTPS it can only open a tunnel with CONNECT and pass encrypted bytes both ways.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Common ports", "3128, 8080"],
    ["Plain HTTP", "GET with an absolute URL"],
    ["HTTPS", "CONNECT host:443 tunnel"],
    ["Login", "407 + Proxy-Authorization"],
    ["Defined in", "RFC 9110, RFC 9112"],
  ],
  ports: "3128 (Squid), 8080",
  rfc: "RFC 9110 §9.3.6 (CONNECT), RFC 9112",
  keywords: ["forward proxy", "connect", "tunnel", "squid", "407", "proxy-authorization", "via", "absolute uri", "cache"],
  related: ["http", "https", "socks", "reverse"],
  devices,
  links,
  legend: [
    ["green", "TCP handshakes and ACKs"],
    ["amber", "Requests"],
    ["violet", "Responses"],
    ["teal", "TLS bytes through the tunnel"],
    ["red", "Proxy refusals"],
  ],
  scenarios: [
    (() => {
      const a = conn({ a: "client", b: "proxy", cport: 52610, sport: PX_PORT, cBase: 0x10a00000, sBase: 0x20b00000, cl: toProxy, sv: fromProxy });
      const b = conn({ a: "proxy", b: "server", cport: 40210, sport: 80, cBase: 0x30c00000, sBase: 0x40d00000, cl: pxOut, sv: pxIn });
      const c = conn({ a: "client", b: "proxy", cport: 52612, sport: PX_PORT, cBase: 0x50e00000, sBase: 0x60f00000, cl: toProxy, sv: fromProxy });
      const d = conn({ a: "proxy", b: "server", cport: 40212, sport: 443, cBase: 0x71000000, sBase: 0x82000000, cl: pxOut, sv: pxIn });
      const fwd = textLayer({
        id: "http", name: "HTTP", blankLine: true,
        lines: ["GET / HTTP/1.1", "Host: example.com", UA, "Accept: */*", "Via: 1.1 office-proxy (squid/6.10)", `X-Forwarded-For: ${ADDR.laptop}`, "Cache-Control: max-age=259200"],
        notes: { 0: "Back to the normal origin form: just the path.", 4: "Proxies add Via so loops and chains can be spotted.", 5: "Tells the server who the real client was." },
      });
      const connect = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["CONNECT example.com:443 HTTP/1.1", "Host: example.com:443", UA, "Proxy-Connection: Keep-Alive"], notes: { 0: "CONNECT: please open a raw TCP connection to this host and port and relay bytes." } });
      const est = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["HTTP/1.1 200 Connection established"], notes: { 0: "From here on this connection is a blind pipe. The next bytes are TLS." } });
      return {
        id: "normal",
        name: "Through the office proxy",
        summary: "curl fetches a plain HTTP page through the proxy, then opens an HTTPS tunnel with CONNECT.",
        kind: "normal" as const,
        steps: [
          {
            title: "Connect to the proxy",
            desc: "Not to the website",
            detail: "The laptop is set to use the proxy at 192.168.1.5 port 3128. So the TCP connection goes to the proxy, never directly to example.com. The laptop does not even need to look up example.com in DNS; the proxy will.",
            facts: [["Proxy", `${PX}:${PX_PORT}`], ["DNS lookup by", "The proxy"], ["Round trip", "< 1 ms (LAN)"]],
            events: a.open(0, 0.0004),
          },
          {
            title: "GET with the full URL",
            desc: "Absolute form tells the proxy where to go",
            detail: "Normally a request line has only the path, like GET /. Through a proxy it carries the whole URL: GET http://example.com/ HTTP/1.1. That is how the proxy learns which server to fetch from.",
            facts: [["Request line", "GET http://example.com/"], ["Sent to", "The proxy"], ["Encrypted", "No"]],
            quiz: {
              q: "Why does the request line include http://example.com and not just / ?",
              options: ["It is required by HTTP/1.1 everywhere", "The TCP connection goes to the proxy, so the URL must say which server is wanted", "To make it longer", "For DNS"],
              answer: 1,
              why: "The proxy's own address is in the IP header, so the target has to travel inside the request.",
            },
            events: [a.c(0.0006, "amber", "GET", ["http://example.com/", "absolute URL"], { data: [absGet(false)], info: "GET http://example.com/ HTTP/1.1" })],
          },
          {
            title: "The proxy fetches it",
            desc: "A new request from the proxy to the server",
            detail: "The proxy opens its own TCP connection to example.com and sends the request again in normal form, adding Via and X-Forwarded-For. The server sees the proxy's address as the client.",
            facts: [["Server sees", `${PX} (the proxy, after NAT)`], ["Added", "Via, X-Forwarded-For"], ["Two connections", "Laptop↔proxy, proxy↔server"]],
            events: [...b.open(0.002, RTT), b.c(0.0362, "amber", "GET /", ["from the proxy"], { data: [fwd], info: "GET / HTTP/1.1" })],
          },
          {
            title: "The page comes back",
            desc: "Server → proxy → laptop",
            detail: "The server answers the proxy, and the proxy passes the response to the laptop with its own Via and X-Cache headers. Because this is plain HTTP, the proxy can read, filter, log and cache every byte.",
            facts: [["Status", "200 OK"], ["Cache", "MISS (now stored)"], ["Proxy can see", "Everything"]],
            events: [
              b.s(0.0705, "violet", "200 OK", ["to the proxy"], { data: [resp200(false)], info: "HTTP/1.1 200 OK (text/html)" }),
              a.s(0.0712, "violet", "200 OK", ["via proxy", "X-Cache: MISS"], { data: [resp200(true)], info: "HTTP/1.1 200 OK (text/html)" }),
              a.c(0.0713, "green", "ACK", []),
            ],
          },
          {
            title: "CONNECT for HTTPS",
            desc: "Ask for a tunnel to port 443",
            detail: "For https://example.com the proxy must not read the traffic, and could not anyway. curl sends CONNECT example.com:443. The proxy opens a TCP connection to that host and port, then answers 200 Connection established.",
            facts: [["Request", "CONNECT example.com:443"], ["Reply", "200 Connection established"], ["After that", "Raw bytes both ways"]],
            quiz: {
              q: "After 200 Connection established, what will the laptop send next?",
              options: ["GET / HTTP/1.1 in plain text", "A TLS Client Hello", "Another CONNECT", "A DNS query"],
              answer: 1,
              why: "The tunnel is open, so the laptop starts TLS with the real server, right through the proxy.",
            },
            events: [
              ...c.open(1.0, 0.0004),
              c.c(1.0006, "amber", "CONNECT", ["example.com:443"], { data: [connect], info: "CONNECT example.com:443 HTTP/1.1" }),
              ...d.open(1.001, RTT),
              c.s(1.0353, "green", "200", ["Connection", "established"], { data: [est], info: "HTTP/1.1 200 Connection established" }),
            ],
          },
          {
            title: "TLS through the tunnel",
            desc: "The proxy relays bytes it cannot read",
            detail: "The laptop's Client Hello goes to the proxy, which copies the same bytes onto its connection to the server. The answer comes back the same way. The proxy sees the name example.com in the SNI, and the sizes, but nothing of the pages, cookies or passwords inside.",
            facts: [["Proxy sees", "SNI, sizes, timing"], ["Proxy can't see", "URLs, headers, bodies"], ["Certificate", "From the real server"]],
            events: [
              c.c(1.0355, "teal", "HELLO", ["into the tunnel"], { data: [clientHello("example.com", 7300)], info: "Client Hello (SNI=example.com)" }),
              d.c(1.0357, "teal", "HELLO", ["same bytes"], { data: [clientHello("example.com", 7300)], info: "Client Hello (SNI=example.com)" }),
              d.s(1.0698, "teal", "S.HELLO", ["+ encrypted cert"], { data: [serverFlight(7300)], info: "Server Hello, Change Cipher Spec, Application Data" }),
              c.s(1.07, "teal", "S.HELLO", ["relayed"], { data: [serverFlight(7300)], info: "Server Hello, Change Cipher Spec, Application Data" }),
              note("proxy", "BLIND RELAY", "blue"),
            ],
          },
        ],
        outro: {
          title: "Two ways through a proxy",
          text: "For plain HTTP the proxy acts as the client: it reads, rewrites, caches and forwards. For HTTPS it only opens a TCP tunnel with CONNECT and copies encrypted bytes, so end-to-end security between the laptop and the server stays intact.",
          facts: [["HTTP", "Proxy reads everything"], ["HTTPS", "CONNECT tunnel, proxy sees SNI only"], ["Connections", "Always two: client side and server side"]],
        },
      };
    })(),
    (() => {
      const a = conn({ a: "client", b: "proxy", cport: 52640, sport: PX_PORT, cBase: 0x13a00000, sBase: 0x23b00000, cl: toProxy, sv: fromProxy });
      const r407 = textLayer({
        id: "http", name: "HTTP", blankLine: true,
        lines: ["HTTP/1.1 407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"Office proxy\"", "Content-Length: 0", "Connection: keep-alive"],
        notes: { 0: "407 is like 401, but for the proxy: it wants to know who you are before fetching anything.", 1: "Which login methods the proxy accepts. realm is the name shown in the login box." },
      });
      return {
        id: "auth",
        name: "407 Proxy Authentication Required",
        summary: "The proxy wants a username and password before it will fetch anything.",
        kind: "failure" as const,
        steps: [
          {
            title: "Request without login",
            desc: "The proxy has never seen this user",
            detail: "curl sends the same absolute-URL GET as before. This proxy, however, only serves logged-in staff.",
            facts: [["Request", "GET http://example.com/"], ["Credentials", "None"], ["Proxy policy", "Login required"]],
            events: [...a.open(0, 0.0004), a.c(0.0006, "amber", "GET", ["no login"], { data: [absGet(false)], info: "GET http://example.com/ HTTP/1.1" })],
          },
          {
            title: "407 from the proxy",
            desc: "Proxy-Authenticate: Basic",
            detail: "The proxy itself answers, without contacting example.com. Status 407 means the proxy, not the website, wants credentials. The Proxy-Authenticate header says it accepts Basic login for the realm \"Office proxy\".",
            facts: [["Status", "407"], ["Challenge", "Basic realm=\"Office proxy\""], ["Website contacted?", "No"]],
            quiz: {
              q: "What is the difference between 401 and 407?",
              options: ["None", "401 is the website asking for login, 407 is the proxy asking", "407 means the password was wrong", "401 is only for HTTPS"],
              answer: 1,
              why: "401 uses WWW-Authenticate/Authorization for the origin server. 407 uses Proxy-Authenticate/Proxy-Authorization for the proxy in between.",
            },
            events: [a.s(0.0009, "red", "407", ["login required"], { data: [r407], info: "HTTP/1.1 407 Proxy Authentication Required" }), note("client", "PROXY LOGIN NEEDED", "red")],
          },
          {
            title: "Retry with credentials",
            desc: "Proxy-Authorization: Basic …",
            detail: "curl retries on the same connection, adding Proxy-Authorization with base64 of danish:s3cret. The proxy accepts it and fetches the page. Basic credentials are only encoded, so anyone sniffing the LAN can decode them; Kerberos/Negotiate or a TLS connection to the proxy is safer.",
            facts: [["Header", "Proxy-Authorization: Basic"], ["Value", "base64(\"danish:s3cret\")"], ["Safer options", "Negotiate (Kerberos), HTTPS to the proxy"]],
            quiz: {
              q: "Someone captures ZGFuaXNoOnMzY3JldA== on the office Wi-Fi. What can they do?",
              options: ["Nothing, it is a hash", "Decode it to danish:s3cret in one step", "Only replay it once", "Nothing without the server's key"],
              answer: 1,
              why: "base64 is a reversible encoding, not encryption. Basic auth over plain HTTP exposes the password.",
            },
            events: [
              a.c(4.2, "amber", "GET", ["+ Proxy-Authorization"], { data: [absGet(true)], info: "GET http://example.com/ HTTP/1.1 (with Proxy-Authorization)" }),
              a.s(4.272, "violet", "200 OK", ["via proxy"], { data: [resp200(true)], info: "HTTP/1.1 200 OK (text/html)" }),
              a.c(4.2722, "green", "ACK", []),
              note("client", "LOGGED IN", "green"),
            ],
          },
        ],
        outro: {
          title: "The proxy is a gatekeeper",
          text: "A proxy can demand a login before forwarding anything, using 407 and Proxy-Authorization. Browsers show a login box and then add the header to every request. With Basic, the password crosses the LAN in an easily decoded form.",
          facts: [["Challenge", "407 + Proxy-Authenticate"], ["Answer", "Proxy-Authorization"], ["Basic is", "base64, not encryption"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "Request forms",
      items: [["Origin form", "GET /path (to the server)"], ["Absolute form", "GET http://host/path (to a proxy)"], ["Authority form", "CONNECT host:443 (tunnel)"]],
    },
    {
      title: "Status codes",
      items: [["200 Connection established", "Tunnel open"], ["407", "Proxy wants credentials"], ["403", "Blocked by policy"], ["502 / 504", "Proxy couldn't reach the server / timed out"]],
    },
    {
      title: "Headers",
      items: [["Via", "Proxies the message passed through"], ["X-Forwarded-For", "The original client's address"], ["Proxy-Authenticate", "The proxy's login challenge"], ["Proxy-Authorization", "Credentials for the proxy"]],
    },
  ],
});
