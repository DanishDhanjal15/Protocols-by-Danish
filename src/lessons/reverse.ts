import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, textLayer } from "@/lib/packet";
import { eth, ext, hsMsg, ipv4, tcp, TcpOpt, tls, vec } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

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
    c(t + rtt + 0.0002, "green", "ACK", ["ack=1", "connected"]),
  ];
  return { c, s, open, next };
}

// ---------------------------------------------------------------- TLS 1.3 hellos

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
      ext(0, "server_name", [vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name (0)" }, vec("Host name", 2, [{ name: "Name", text: host }], host)])], host, "The reverse proxy uses this to pick which certificate to present."),
      ext(10, "supported_groups", [vec("Groups", 2, [{ name: "Group", u16: 0x001d, value: "x25519 (0x001d)" }, { name: "Group", u16: 0x0017, value: "secp256r1 (0x0017)" }])], "x25519, secp256r1"),
      ext(13, "signature_algorithms", [vec("Algorithms", 2, [{ name: "Algorithm", u16: 0x0403, value: "ecdsa_secp256r1_sha256 (0x0403)" }, { name: "Algorithm", u16: 0x0804, value: "rsa_pss_rsae_sha256 (0x0804)" }])], "2 algorithms"),
      ext(16, "application_layer_protocol_negotiation", [vec("Protocols", 2, [vec("Protocol", 1, [{ name: "Name", text: "http/1.1" }], "http/1.1")])], "http/1.1"),
      ext(43, "supported_versions", [vec("Versions", 1, [{ name: "Version", u16: 0x0304, value: "TLS 1.3 (0x0304)" }, { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)" }])], "TLS 1.3, TLS 1.2"),
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
const enc = (n: number, what: string) => tls({ records: [{ type: "appdata", encrypted: n, what }] });

// ---------------------------------------------------------------- network

const VIP = ADDR.web; // public address of the reverse proxy
const LB = "10.0.0.2", B1 = "10.0.0.11", B2 = "10.0.0.12";
const LB_MAC = "00:16:3e:10:00:02", B1_MAC = "00:16:3e:10:00:11", B2_MAC = "00:16:3e:10:00:12";
const lbTo = (ip: string, m: string) => [eth({ src: LB_MAC, dst: m }), ipv4({ src: LB, dst: ip })];
const lbFrom = (ip: string, m: string) => [eth({ src: m, dst: LB_MAC }), ipv4({ src: ip, dst: LB })];
const RTT = 0.034;

const devices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: `${ADDR.laptop} (NAT ${ADDR.routerWan})`, x: 9, y: 55 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 32, y: 35 },
  { id: "lb", kind: "proxy" as const, label: "Reverse proxy", sub: `${VIP} / ${LB}`, x: 56, y: 50 },
  { id: "b1", kind: "server" as const, label: "App server 1", sub: `${B1}:8080`, x: 88, y: 22 },
  { id: "b2", kind: "server" as const, label: "App server 2", sub: `${B2}:8080`, x: 88, y: 78 },
];
const links: [string, string][] = [["client", "internet"], ["internet", "lb"], ["lb", "b1"], ["lb", "b2"]];

const health = (ip: string) => textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["GET /healthz HTTP/1.1", `Host: ${ip}:8080`, "User-Agent: haproxy-healthcheck"], notes: { 0: "A cheap page the app answers only when it is really working." } });
const healthOk = () => textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["HTTP/1.1 200 OK", "Content-Type: text/plain", "Content-Length: 2"], body: { text: "ok" } });
const fwd = (path: string, reqId: string) => textLayer({
  id: "http", name: "HTTP", blankLine: true,
  lines: [`GET ${path} HTTP/1.1`, "Host: example.com", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0", "Accept: */*", `X-Forwarded-For: ${ADDR.routerWan}`, "X-Forwarded-Proto: https", `X-Request-ID: ${reqId}`],
  notes: {
    0: "Plain HTTP inside the private network: TLS ended at the proxy.",
    4: "The real client address. The app server only sees the proxy's address in the IP header.",
    5: "Tells the app the user came in over HTTPS, so it builds https:// links.",
    6: "One ID per request, logged by every hop, to trace problems.",
  },
});
const BODY = "<!doctype html><html><body><h1>Shop</h1><p>served by app-1</p></body></html>\n";
const BODY2 = '{"items":2,"total":"1499.00","server":"app-2"}\n';
const appOk = (type: string, body: string) => textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["HTTP/1.1 200 OK", `Content-Type: ${type}`, `Content-Length: ${new TextEncoder().encode(body).length}`], body: { text: body } });

const tlsSetup = (k: ReturnType<typeof conn>, t: number, seed: number): PacketEvent[] => [
  ...k.open(t, RTT),
  k.c(t + 0.0345, "teal", "HELLO", ["SNI example.com"], { data: [clientHello("example.com", seed)], info: "Client Hello (SNI=example.com)" }),
  k.s(t + 0.0692, "teal", "S.HELLO", ["proxy's certificate"], {
    info: "Server Hello, Change Cipher Spec, Application Data",
    data: [tls({ records: [
      { type: "handshake", fields: [serverHello(seed)] },
      { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] },
      { type: "appdata", encrypted: 1180, what: "EncryptedExtensions, Certificate, CertificateVerify, Finished (encrypted)", note: "Encrypted: the certificate for example.com, held by the reverse proxy, not the app servers." },
    ] })],
  }),
  k.c(t + 0.0711, "teal", "FINISHED", [], { info: "Change Cipher Spec, Application Data", data: [tls({ records: [{ type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] }, { type: "appdata", encrypted: 53, what: "Finished (encrypted)" }] })] }),
];

export default defineLesson({
  id: "reverse",
  name: "Reverse proxy",
  full: "Reverse proxy and load balancer with TLS offloading",
  group: "web",
  layer: 7,
  difficulty: 2,
  tagline: "One public front door, many servers behind it.",
  description:
    "A reverse proxy stands in front of a website's servers. It ends the TLS connection, picks a healthy backend, forwards the request over the private network with the client's address in X-Forwarded-For, and sends the answer back. Users only ever see one address.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Front side", "HTTPS on port 443"],
    ["Back side", "Plain HTTP on a private network"],
    ["Picks servers by", "Round robin, least connections…"],
    ["Health", "Regular checks like GET /healthz"],
    ["Examples", "nginx, HAProxy, Envoy, cloud LBs"],
  ],
  ports: "443 in front, 8080 (or any) behind",
  rfc: "RFC 9110 (intermediaries), RFC 7239 (Forwarded)",
  keywords: ["load balancer", "reverse proxy", "tls termination", "offloading", "x-forwarded-for", "health check", "502", "bad gateway", "round robin", "nginx", "haproxy"],
  related: ["https", "http", "proxy", "tcp"],
  devices,
  links,
  legend: [
    ["green", "TCP and health checks"],
    ["teal", "TLS with the client"],
    ["amber", "Requests"],
    ["violet", "Responses"],
    ["red", "Failures"],
  ],
  scenarios: [
    (() => {
      const h1 = conn({ a: "lb", b: "b1", cport: 33010, sport: 8080, cBase: 0x6b000000, sBase: 0x7c000000, cl: lbTo(B1, B1_MAC), sv: lbFrom(B1, B1_MAC) });
      const h2 = conn({ a: "lb", b: "b2", cport: 33012, sport: 8080, cBase: 0x6b100000, sBase: 0x7c100000, cl: lbTo(B2, B2_MAC), sv: lbFrom(B2, B2_MAC) });
      [h1, h2].forEach((h) => { h.next.a = 1; h.next.b = 1; }); // pooled keep-alive connections
      const k = conn({ a: "client", b: "lb", cport: 52810, sport: 443, cBase: 0x21c00000, sBase: 0x32d00000, cl: up(VIP), sv: down(VIP) });
      return {
        id: "normal",
        name: "Two requests, two backends",
        summary: "The proxy checks both app servers, ends TLS for the browser, and spreads two requests across the servers.",
        kind: "normal" as const,
        steps: [
          {
            title: "Health checks",
            desc: "Every 2 seconds: are you OK?",
            detail: "Long before any user arrives, the proxy asks each app server for /healthz every couple of seconds, over plain HTTP on the private network. Both answer 200 ok, so both are in the pool.",
            facts: [["Check", "GET /healthz"], ["Interval", "2 s"], ["Pool", "app-1 up, app-2 up"]],
            events: [
              h1.c(0, "green", "CHECK", ["GET /healthz"], { data: [health(B1)], info: "GET /healthz HTTP/1.1" }),
              h2.c(0.0001, "green", "CHECK", ["GET /healthz"], { parallel: true, data: [health(B2)], info: "GET /healthz HTTP/1.1" }),
              h1.s(0.0012, "green", "200", ["ok"], { data: [healthOk()], info: "HTTP/1.1 200 OK (text/plain)" }),
              h2.s(0.0013, "green", "200", ["ok"], { parallel: true, data: [healthOk()], info: "HTTP/1.1 200 OK (text/plain)" }),
              note("lb", "POOL: 2 UP", "green"),
            ],
          },
          {
            title: "TLS ends at the proxy",
            desc: "The browser talks only to the proxy",
            detail: "The browser connects to 203.0.113.10, which belongs to the reverse proxy. The proxy holds the certificate and private key for example.com and completes the TLS handshake. This is TLS offloading: the app servers never spend CPU on encryption.",
            facts: [["Public address", VIP], ["Certificate held by", "The proxy"], ["App servers", "Never see TLS"]],
            quiz: {
              q: "Which machine needs the private key for example.com's certificate?",
              options: ["Each app server", "Only the reverse proxy", "The browser", "The DNS server"],
              answer: 1,
              why: "TLS ends at the proxy, so only it proves the identity. Fewer machines with the key means less risk.",
            },
            events: tlsSetup(k, 1.0, 8800),
          },
          {
            title: "Decrypt and forward",
            desc: "Plain HTTP to app-1, with X-Forwarded-For",
            detail: "The proxy decrypts GET /, picks app-1 (round robin), and sends the request over plain HTTP. Because the app server sees the proxy's address as the source, the proxy adds X-Forwarded-For with the browser's public address and X-Forwarded-Proto: https.",
            facts: [["Chosen", "app-1 (round robin)"], ["X-Forwarded-For", ADDR.routerWan], ["Inside network", "Plain HTTP"]],
            quiz: {
              q: "The app logs the IP address of each visitor. Without X-Forwarded-For, which address would it log?",
              options: [ADDR.routerWan, LB, ADDR.laptop, VIP],
              answer: 1,
              why: "The app server's TCP connection comes from the proxy's private address. Only the header carries the real client.",
            },
            events: [
              k.c(1.0713, "amber", "GET /", ["encrypted"], { data: [enc(380, "HTTP request: GET / (encrypted)")], info: "Application Data" }),
              h1.c(1.0716, "amber", "GET /", ["plain", "X-Forwarded-For"], { data: [fwd("/", "8f1c2a7e")], info: "GET / HTTP/1.1" }),
            ],
          },
          {
            title: "Response goes back",
            desc: "Encrypted again by the proxy",
            detail: "app-1 answers in plain HTTP. The proxy encrypts the response with the browser's TLS keys and sends it out. To the browser, everything came from example.com.",
            facts: [["Backend time", "4 ms"], ["Re-encrypted", "Yes, by the proxy"], ["Browser sees", "One server"]],
            events: [
              h1.s(1.0758, "violet", "200", ["from app-1"], { data: [appOk("text/html", BODY)], info: "HTTP/1.1 200 OK (text/html)" }),
              k.s(1.1101, "violet", "200 OK", ["encrypted"], { data: [enc(260, "HTTP response (encrypted)")], info: "Application Data" }),
              k.c(1.1103, "green", "ACK", []),
            ],
          },
          {
            title: "Next request, other server",
            desc: "Round robin picks app-2",
            detail: "The page calls /api/cart on the same TLS connection. The proxy sends this one to app-2. Each request can go to a different backend, which is why apps behind a load balancer keep session data in a shared store, not in memory.",
            facts: [["Chosen", "app-2"], ["Same TLS connection?", "Yes"], ["Session data", "Shared store (e.g. Redis)"]],
            events: [
              k.c(1.2, "amber", "GET", ["/api/cart", "encrypted"], { data: [enc(390, "HTTP request: GET /api/cart (encrypted)")], info: "Application Data" }),
              h2.c(1.2003, "amber", "GET", ["/api/cart", "to app-2"], { data: [fwd("/api/cart", "8f1c2a7f")], info: "GET /api/cart HTTP/1.1" }),
              h2.s(1.2041, "violet", "200", ["from app-2"], { data: [appOk("application/json", BODY2)], info: "HTTP/1.1 200 OK (application/json)" }),
              k.s(1.2384, "violet", "200 OK", ["encrypted"], { data: [enc(230, "HTTP response (encrypted)")], info: "Application Data" }),
            ],
          },
        ],
        outro: {
          title: "One door, many rooms",
          text: "The reverse proxy did four jobs: checked backend health, ended TLS, chose a backend for each request, and told the backend who the real client was. Adding capacity is just adding servers to the pool.",
          facts: [["TLS", "Ended at the proxy"], ["Balancing", "Round robin"], ["Client IP", "X-Forwarded-For"], ["Health checks", "Every 2 s"]],
        },
      };
    })(),
    (() => {
      const h1 = conn({ a: "lb", b: "b1", cport: 33010, sport: 8080, cBase: 0x6b000000, sBase: 0x7c000000, cl: lbTo(B1, B1_MAC), sv: lbFrom(B1, B1_MAC) });
      h1.next.a = 1; h1.next.b = 1;
      const d2 = conn({ a: "lb", b: "b2", cport: 33020, sport: 8080, cBase: 0x6b200000, sBase: 0, cl: lbTo(B2, B2_MAC), sv: lbFrom(B2, B2_MAC) });
      const k = conn({ a: "client", b: "lb", cport: 52830, sport: 443, cBase: 0x23c00000, sBase: 0x34d00000, cl: up(VIP), sv: down(VIP) });
      return {
        id: "failover",
        name: "One backend down",
        summary: "app-2 crashes. Health checks notice, and the proxy quietly sends everyone to app-1.",
        kind: "failure" as const,
        steps: [
          {
            title: "app-2 refuses",
            desc: "Health check gets RST",
            detail: "The app on app-2 has crashed, so nothing listens on port 8080. The proxy's health-check connection is answered with RST: connection refused. After a few failed checks in a row (here 3), the proxy marks app-2 as down.",
            facts: [["Check result", "RST (refused)"], ["Rule", "3 failures = down"], ["Pool", "app-1 up, app-2 DOWN"]],
            events: [
              d2.c(0, "green", "SYN", ["to app-2:8080"], { flags: "S" }),
              d2.s(0.0003, "red", "RST", ["refused"], { flags: "RA", win: 0 }),
              note("lb", "APP-2 MARKED DOWN", "red"),
            ],
          },
          {
            title: "Users don't notice",
            desc: "Every request goes to app-1",
            detail: "A user loads the page. The proxy only picks from healthy servers, so the request goes to app-1 even though it is app-2's turn. The user sees a normal page.",
            facts: [["Chosen", "app-1 (only one up)"], ["User sees", "Normal page"], ["Capacity", "Halved"]],
            quiz: {
              q: "What would happen without health checks?",
              options: ["Nothing different", "About half the requests would be sent to app-2 and fail or wait", "All requests would fail", "The proxy would restart app-2"],
              answer: 1,
              why: "Without checks the proxy keeps sending app-2 its share until it notices errors on real requests.",
            },
            events: [
              ...tlsSetup(k, 5.0, 8900),
              k.c(5.0713, "amber", "GET /", ["encrypted"], { data: [enc(380, "HTTP request: GET / (encrypted)")], info: "Application Data" }),
              h1.c(5.0716, "amber", "GET /", ["to app-1"], { data: [fwd("/", "9a01b2c3")], info: "GET / HTTP/1.1" }),
              h1.s(5.0758, "violet", "200", ["from app-1"], { data: [appOk("text/html", BODY)], info: "HTTP/1.1 200 OK (text/html)" }),
              k.s(5.1101, "violet", "200 OK", ["encrypted"], { data: [enc(260, "HTTP response (encrypted)")], info: "Application Data" }),
            ],
          },
        ],
        outro: {
          title: "Failover without anyone noticing",
          text: "Health checks let the proxy take a broken server out of rotation before users hit it. When app-2 recovers and passes a few checks, it is added back automatically.",
          facts: [["Detected by", "Failed health checks"], ["Action", "Remove from pool"], ["Recovery", "Back in after passing checks"]],
        },
      };
    })(),
    (() => {
      const d1 = conn({ a: "lb", b: "b1", cport: 33040, sport: 8080, cBase: 0x6b400000, sBase: 0, cl: lbTo(B1, B1_MAC), sv: lbFrom(B1, B1_MAC) });
      const d2 = conn({ a: "lb", b: "b2", cport: 33042, sport: 8080, cBase: 0x6b500000, sBase: 0, cl: lbTo(B2, B2_MAC), sv: lbFrom(B2, B2_MAC) });
      const k = conn({ a: "client", b: "lb", cport: 52850, sport: 443, cBase: 0x25c00000, sBase: 0x36d00000, cl: up(VIP), sv: down(VIP) });
      return {
        id: "bad-gateway",
        name: "All backends down: 502",
        summary: "A bad deploy takes down both app servers. The proxy is fine, but has nobody to forward to.",
        kind: "failure" as const,
        steps: [
          {
            title: "A request arrives",
            desc: "TLS still works",
            detail: "A broken release has crashed the app on both servers. The reverse proxy itself is healthy, so the browser's TLS handshake succeeds and its request arrives as usual.",
            facts: [["Proxy", "Healthy"], ["app-1, app-2", "Crashed"], ["TLS", "Works normally"]],
            events: [...tlsSetup(k, 0, 9000), k.c(0.0713, "amber", "GET /", ["encrypted"], { data: [enc(380, "HTTP request: GET / (encrypted)")], info: "Application Data" })],
          },
          {
            title: "Both refuse",
            desc: "RST from app-1, then app-2",
            detail: "The proxy tries app-1 and gets RST, retries on app-2 and gets RST again. There is no healthy server left to try.",
            facts: [["app-1", "RST"], ["app-2", "RST"], ["Retries", "1 (to the other server)"]],
            quiz: {
              q: "What status will the proxy send to the browser?",
              options: ["404 Not Found", "500 Internal Server Error", "502 Bad Gateway", "200 OK with an empty page"],
              answer: 2,
              why: "502 means the proxy (acting as a gateway) got no valid answer from the server behind it. 503 is also common when the pool is empty.",
            },
            events: [
              d1.c(0.0716, "green", "SYN", ["to app-1"], { flags: "S" }),
              d1.s(0.0719, "red", "RST", ["refused"], { flags: "RA", win: 0 }),
              d2.c(0.072, "green", "SYN", ["to app-2"], { flags: "S" }),
              d2.s(0.0723, "red", "RST", ["refused"], { flags: "RA", win: 0 }),
              note("lb", "NO HEALTHY BACKEND", "red"),
            ],
          },
          {
            title: "502 Bad Gateway",
            desc: "Made by the proxy, encrypted",
            detail: "The proxy builds its own error page with status 502 Bad Gateway and sends it inside the TLS connection. The 5xx tells the user and any monitoring that the problem is on the server side, not with the request.",
            facts: [["Status", "502 Bad Gateway"], ["Made by", "The reverse proxy"], ["Similar", "503 (no servers), 504 (backend too slow)"]],
            events: [
              k.s(0.1067, "red", "502", ["Bad Gateway", "encrypted"], { data: [enc(310, "HTTP response: 502 Bad Gateway (encrypted)")], info: "Application Data" }),
              k.c(0.1069, "green", "ACK", []),
              note("client", "502 BAD GATEWAY", "red"),
            ],
          },
        ],
        outro: {
          title: "The front door works, the rooms are closed",
          text: "A 502 means the proxy is fine but nothing behind it answered properly. It is the classic sign of crashed or misconfigured backends. Rolling deploys, which update one server at a time, avoid taking them all down at once.",
          facts: [["502", "Bad answer or no answer from backend"], ["503", "No server available"], ["504", "Backend too slow"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "Headers added",
      items: [["X-Forwarded-For", "Original client IP"], ["X-Forwarded-Proto", "http or https"], ["X-Request-ID", "Trace one request through logs"], ["Forwarded", "Standard version of the above (RFC 7239)"]],
    },
    {
      title: "Balancing methods",
      items: [["Round robin", "Take turns"], ["Least connections", "The least busy server"], ["IP hash", "Same client, same server"], ["Weighted", "Bigger servers get more"]],
    },
    {
      title: "Gateway errors",
      items: [["502 Bad Gateway", "Backend refused or sent garbage"], ["503 Service Unavailable", "No healthy backend"], ["504 Gateway Timeout", "Backend too slow"]],
    },
  ],
});
