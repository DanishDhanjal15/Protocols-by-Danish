import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, LayerSpec } from "@/lib/packet";
import { dns, ext, hsMsg, tcp, tls, udp, vec } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

const DOH = "192.0.2.1"; // public DoH resolver (documentation address)
const HOST = "dns.example";
const ISP_DNS = ADDR.dns; // 192.0.2.53
const SP = 52814;
const CB = 0x3e5a1000; // client ISN
const SB = 0x8c22d400; // server ISN
const t = (n: number) => Number(n.toFixed(4));
const len = (spec: LayerSpec) => build(spec).bytes.length;

// ------------------------------------------------------------------ TLS 1.3 handshake messages

const clientHello = tls({
  summary: `TLS 1.3 Client Hello, SNI=${HOST}, ALPN=h2`,
  records: [{
    type: "handshake",
    version: 0x0301,
    fields: [hsMsg("client_hello", "Client Hello", [
      { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "Real version is in supported_versions." },
      { name: "Random", random: 32, seed: 101, note: "32 fresh random bytes." },
      vec("Session ID", 1, [{ name: "Session ID", random: 32, seed: 102 }], "32 bytes", "Kept for compatibility with old middleboxes."),
      vec("Cipher suites", 2, [
        { name: "Suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256" },
        { name: "Suite", u16: 0x1302, value: "TLS_AES_256_GCM_SHA384" },
        { name: "Suite", u16: 0x1303, value: "TLS_CHACHA20_POLY1305_SHA256" },
      ], "3 suites"),
      vec("Compression methods", 1, [{ name: "Method", u8: 0, value: "null" }], "null"),
      vec("Extensions", 2, [
        ext(0, "server_name", [{ name: "Server name list", fields: [
          { name: "List length", u16: HOST.length + 3 },
          { name: "Name type", u8: 0, value: "0 (host name)" },
          { name: "Name length", u16: HOST.length },
          { name: "Host name", text: HOST, value: HOST },
        ] }], HOST, "SNI: the resolver’s name in clear text. The ISP can see which DoH service you use, but not what you look up."),
        ext(10, "supported_groups", [{ name: "Length", u16: 2 }, { name: "Group", u16: 0x001d, value: "x25519" }], "x25519"),
        ext(13, "signature_algorithms", [{ name: "Length", u16: 6 }, { name: "Alg", u16: 0x0403, value: "ecdsa_secp256r1_sha256" }, { name: "Alg", u16: 0x0804, value: "rsa_pss_rsae_sha256" }, { name: "Alg", u16: 0x0401, value: "rsa_pkcs1_sha256" }], "3 algorithms"),
        ext(16, "application_layer_protocol_negotiation", [{ name: "List length", u16: 3 }, { name: "Length", u8: 2 }, { name: "Protocol", text: "h2", value: "h2" }], "h2", "ALPN: the browser wants HTTP/2 inside TLS."),
        ext(43, "supported_versions", [{ name: "Length", u8: 2 }, { name: "Version", u16: 0x0304, value: "TLS 1.3" }], "TLS 1.3"),
        ext(51, "key_share", [{ name: "Client shares length", u16: 36 }, { name: "Group", u16: 0x001d, value: "x25519" }, { name: "Key length", u16: 32 }, { name: "Public key", random: 32, seed: 103 }], "x25519 key", "The laptop’s half of the key exchange."),
      ], "6 extensions"),
    ])],
  }],
});

const serverFlight1 = tls({
  summary: "TLS 1.3 Server Hello, Change Cipher Spec, Application Data",
  records: [
    {
      type: "handshake",
      fields: [hsMsg("server_hello", "Server Hello", [
        { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
        { name: "Random", random: 32, seed: 201 },
        vec("Session ID", 1, [{ name: "Session ID", random: 32, seed: 102 }], "32 bytes (echoed)"),
        { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256" },
        { name: "Compression method", u8: 0, value: "null" },
        vec("Extensions", 2, [
          ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3" }], "TLS 1.3"),
          ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, { name: "Key length", u16: 32 }, { name: "Public key", random: 32, seed: 202 }], "x25519 key", "The server’s half. From here on everything is encrypted."),
        ], "2 extensions"),
      ])],
    },
    { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1, note: "A dummy record for old middleboxes; TLS 1.3 ignores it." }] },
    { type: "appdata", encrypted: 1290, what: "Encrypted handshake: EncryptedExtensions (ALPN h2) + Certificate", note: "The resolver’s ECDSA certificate chain for dns.example, now hidden from the network." },
  ],
});

const serverFlight2 = tls({
  summary: "TLS 1.3 Application Data (CertificateVerify, Finished)",
  records: [{ type: "appdata", encrypted: 133, what: "Encrypted handshake: CertificateVerify + Finished", note: "Proof the server owns the certificate’s key, and a hash of the whole handshake." }],
});

const clientFinished = tls({
  summary: "TLS 1.3 Change Cipher Spec, Application Data (Finished)",
  records: [
    { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] },
    { type: "appdata", encrypted: 53, what: "Encrypted handshake: Finished", note: "The laptop’s Finished: 36 bytes of handshake data, 1 byte of real type, 16-byte tag." },
  ],
});

const h2Request = tls({
  summary: "TLS Application Data (HTTP/2 POST /dns-query)",
  records: [{ type: "appdata", encrypted: 287, what: "HTTP/2: preface, SETTINGS, WINDOW_UPDATE, HEADERS (POST /dns-query), DATA (128-byte DNS query)", note: "Inside: the HTTP/2 request carrying a DNS query for example.com. Nobody on the path can read it." }],
});

const h2Response = tls({
  summary: "TLS Application Data (HTTP/2 200, application/dns-message)",
  records: [{ type: "appdata", encrypted: 563, what: "HTTP/2: SETTINGS, SETTINGS ACK, HEADERS (:status 200), DATA (468-byte DNS answer)", note: "Inside: an HTTP 200 whose body is the DNS answer example.com A 203.0.113.10." }],
});

const CH = len(clientHello), F1 = len(serverFlight1), F2 = len(serverFlight2), CF = len(clientFinished), RQ = len(h2Request), RS = len(h2Response);

const cUp = (o: { seq: number; ack: number; flags: string }, ...rest: LayerSpec[]) =>
  build(...up(DOH), tcp({ sport: SP, dport: 443, seq: o.seq, ack: o.ack, flags: o.flags, win: 502, seqBase: CB, ackBase: SB }), ...rest);
const sDown = (o: { seq: number; ack: number; flags: string }, ...rest: LayerSpec[]) =>
  build(...down(DOH, { ttl: 58 }), tcp({ sport: 443, dport: SP, seq: o.seq, ack: o.ack, flags: o.flags, win: 1024, seqBase: SB, ackBase: CB }), ...rest);

// plain DNS packets
const plainQ = (id: number, name: string, sport: number) =>
  build(...up(ISP_DNS), udp({ sport, dport: 53 }), dns({ id, qd: [{ name, type: "A" }], ar: [{ name: "", type: "OPT", ttl: 0 }] }));
const plainA = (id: number, name: string, sport: number) =>
  build(...down(ISP_DNS, { ttl: 63 }), udp({ sport: 53, dport: sport }), dns({ id, response: true, ra: true, qd: [{ name, type: "A" }], an: [{ name, type: "A", ttl: 300, data: ADDR.web }], ar: [{ name: "", type: "OPT", ttl: 0 }] }));
const nxA = (id: number, name: string, sport: number) =>
  build(...down(ISP_DNS, { ttl: 63 }), udp({ sport: 53, dport: sport }), dns({ id, response: true, ra: true, rcode: 3, qd: [{ name, type: "A" }], ar: [{ name: "", type: "OPT", ttl: 0 }] }));

const synOpts = [{ mss: 1460 }, "sackOk" as const, { ts: [881231, 0] as [number, number] }, "nop" as const, { ws: 7 }];

const devices = (ispKind: "isp" | "firewall", ispLabel: string, dnsLabel: string): Device[] => [
  { id: "client", kind: "laptop", label: "Laptop (browser)", sub: ADDR.laptop, x: 8, y: 62 },
  { id: "router", kind: "router", label: "Wi-Fi router", sub: ADDR.router, x: 28, y: 62 },
  { id: "isp", kind: ispKind, label: ispLabel, sub: "can watch traffic", x: 52, y: 45 },
  { id: "doh", kind: "dns", label: "DoH resolver", sub: `${DOH} · ${HOST}`, x: 86, y: 24 },
  { id: "plain", kind: "dns", label: dnsLabel, sub: ISP_DNS, x: 86, y: 76 },
];
const links: [string, string][] = [["client", "router"], ["router", "isp"], ["isp", "doh"], ["isp", "plain"]];

export default defineLesson({
  id: "doh",
  name: "DoH",
  full: "DNS over HTTPS",
  group: "naming",
  layer: 7,
  difficulty: 2,
  tagline: "DNS questions hidden inside ordinary HTTPS traffic.",
  description:
    "Normal DNS travels in plain text, so anyone on the path can read every name you look up. DNS over HTTPS puts the very same DNS message inside an encrypted HTTPS request, so the network sees only a TLS connection to a resolver on port 443.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "HTTPS: TCP 443 (or QUIC)"],
    ["Media type", "application/dns-message"],
    ["Path", "/dns-query (by convention)"],
    ["Message", "Ordinary DNS wire format"],
    ["Defined in", "RFC 8484"],
  ],
  ports: "TCP 443 (HTTP/2 over TLS), UDP 443 for HTTP/3",
  rfc: "RFC 8484",
  keywords: ["dns over https", "doh", "privacy", "encrypted dns", "dns-query", "application/dns-message", "dot", "canary", "1.1.1.1"],
  related: ["dns", "dnssec", "tls", "http2", "tcp"],
  devices: devices("isp", "ISP network", "ISP DNS"),
  links,
  legend: [
    ["green", "TCP handshake and ACKs"],
    ["teal", "TLS handshake and encrypted DNS"],
    ["blue", "Plain DNS (readable by anyone)"],
    ["red", "Blocked or refused"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Looking up example.com over HTTPS",
      summary: "The browser asks its DoH resolver for example.com inside an HTTP/2 request over TLS.",
      kind: "normal",
      steps: [
        {
          title: "Connect to port 443",
          desc: "A normal TCP handshake",
          detail: `The browser is set to use https://${HOST}/dns-query, which lives at ${DOH}. It opens a TCP connection to port 443, exactly like visiting any secure website. To the network this looks like the start of normal web browsing.`,
          facts: [["Resolver", `${DOH}:443`], ["Laptop port", String(SP)], ["Takes", "1 round trip (12 ms)"]],
          quiz: {
            q: "Which destination port does DoH use?",
            options: ["53, like normal DNS", "853, like DNS over TLS", "443, like any HTTPS site", "A random port"],
            answer: 2,
            why: "DoH is just HTTPS, so it uses 443. That makes it hard to tell apart from web browsing.",
          },
          events: [
            pkt("client", "doh", "green", "SYN", ["to :443"], {
              time: 0, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(...up(DOH), tcp({ sport: SP, dport: 443, seq: 0, flags: "S", opts: synOpts, seqBase: CB })),
            }),
            pkt("doh", "client", "green", "SYN-ACK", [], {
              time: 0.012, info: `443 → ${SP} [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460`,
              packet: build(...down(DOH, { ttl: 58 }), tcp({ sport: 443, dport: SP, seq: 0, ack: 1, flags: "SA", win: 65535, opts: [{ mss: 1460 }, "sackOk", { ts: [5512001, 881231] }, "nop", { ws: 9 }], seqBase: SB, ackBase: CB })),
            }),
            pkt("client", "doh", "green", "ACK", [], {
              time: 0.0121, info: `${SP} → 443 [ACK] Seq=1 Ack=1 Win=502 Len=0`,
              packet: cUp({ seq: 1, ack: 1, flags: "A" }),
            }),
          ],
        },
        {
          title: "TLS handshake",
          desc: "Agree keys and check the certificate",
          detail: `The Client Hello offers TLS 1.3, a key share and ALPN “h2” for HTTP/2. The resolver replies with its key share, then everything else, including its certificate for ${HOST}, is encrypted. The browser checks that certificate, so a fake resolver on the path can’t pretend to be the real one.`,
          facts: [["Version", "TLS 1.3"], ["Visible in clear", `SNI ${HOST}, ALPN h2`], ["Certificate", `${HOST}, checked by the browser`]],
          quiz: {
            q: "Which part of this connection can the ISP still read?",
            options: ["The names you look up", "The resolver’s name in the SNI and its IP address", "The DNS answers", "Nothing at all"],
            answer: 1,
            why: "The Client Hello and IP header are in clear text. The ISP learns you use a DoH service, but not what you ask it.",
          },
          events: [
            pkt("client", "doh", "teal", "C.HELLO", ["TLS 1.3", `SNI ${HOST}`], {
              time: 0.0122, info: "Client Hello (SNI=dns.example)",
              packet: cUp({ seq: 1, ack: 1, flags: "PA" }, clientHello),
            }),
            pkt("doh", "client", "teal", "S.HELLO", ["key share", "+ encrypted cert"], {
              time: 0.0245, info: "Server Hello, Change Cipher Spec, Application Data",
              packet: sDown({ seq: 1, ack: 1 + CH, flags: "A" }, serverFlight1),
            }),
            pkt("doh", "client", "teal", "FINISHED", ["encrypted"], {
              time: 0.0245, parallel: true, info: "Application Data",
              packet: sDown({ seq: 1 + F1, ack: 1 + CH, flags: "PA" }, serverFlight2),
            }),
            pkt("client", "doh", "teal", "FINISHED", ["handshake done"], {
              time: 0.0262, info: "Change Cipher Spec, Application Data",
              packet: cUp({ seq: 1 + CH, ack: 1 + F1 + F2, flags: "PA" }, clientFinished),
            }),
            note("client", "TLS 1.3 READY", "green"),
          ],
        },
        {
          title: "POST /dns-query",
          desc: "A DNS message as an HTTP body",
          detail: "Inside the encrypted record is an HTTP/2 request: :method POST, :path /dns-query, content-type and accept both application/dns-message. The body is a normal DNS query for example.com type A, in the same binary format as plain DNS. Its ID is 0, which helps caching, and it is padded to 128 bytes so its length doesn’t give the name away.",
          facts: [["HTTP", "POST /dns-query (HTTP/2)"], ["Body", "128-byte DNS query, ID 0"], ["On the wire", `one ${RQ - 5}-byte encrypted record`]],
          quiz: {
            q: "Why is the DNS query padded to 128 bytes before encryption?",
            options: ["DNS requires it", "So the length of the encrypted record doesn’t hint at which name was asked", "To make HTTP/2 faster", "To fit in one UDP packet"],
            answer: 1,
            why: "Encryption hides content but not size. Padding every query to the same block size (RFC 8467) stops length-based guessing.",
          },
          events: [
            pkt("client", "doh", "teal", "POST", ["/dns-query", "example.com A (hidden)"], {
              time: 0.0263, info: "Application Data (HTTP/2 POST /dns-query)",
              packet: cUp({ seq: 1 + CH + CF, ack: 1 + F1 + F2, flags: "PA" }, h2Request),
            }),
          ],
        },
        {
          title: "The answer arrives",
          desc: "HTTP 200 with a DNS message inside",
          detail: "The resolver looks up example.com the normal way (from its cache, or with plain DNS to the authoritative servers) and replies with :status 200, content-type application/dns-message and cache-control max-age=300, matching the record’s TTL. The body is a DNS response: example.com A 203.0.113.10, TTL 300.",
          facts: [["HTTP status", "200"], ["DNS answer", `example.com A ${ADDR.web}`], ["Cache-Control", "max-age=300 (= TTL)"]],
          quiz: {
            q: "The DNS answer says TTL 300. What max-age should the HTTP response carry?",
            options: ["0, DoH is never cached", "300 or less", "86400", "It doesn’t matter"],
            answer: 1,
            why: "RFC 8484 says the HTTP freshness must not outlive the smallest TTL in the answer, so caches never serve stale records.",
          },
          events: [
            pkt("doh", "client", "teal", "200 OK", ["application/dns-message", "A 203.0.113.10"], {
              time: 0.0391, info: "Application Data (HTTP/2 200)",
              packet: sDown({ seq: 1 + F1 + F2, ack: 1 + CH + CF + RQ, flags: "PA" }, h2Response),
            }),
            pkt("client", "doh", "green", "ACK", [], {
              time: 0.0392, info: `${SP} → 443 [ACK] Seq=${1 + CH + CF + RQ} Ack=${1 + F1 + F2 + RS} Win=502 Len=0`,
              packet: cUp({ seq: 1 + CH + CF + RQ, ack: 1 + F1 + F2 + RS, flags: "A" }),
            }),
            note("client", "EXAMPLE.COM = 203.0.113.10", "green"),
          ],
        },
        {
          title: "Compare: plain DNS",
          desc: "What the ISP sees without DoH",
          detail: "For contrast, an older app on the same laptop uses the ISP’s resolver over UDP port 53. Its question and the answer are plain text, so the ISP (or anyone on the Wi-Fi) can read, log or even change them. With DoH the ISP saw only a TLS connection to dns.example.",
          facts: [["Plain DNS", "UDP 53, readable"], ["ISP sees", "example.com → 203.0.113.10"], ["With DoH", "Only “talked to dns.example”"]],
          quiz: {
            q: "After switching to DoH, who can still see which sites you look up?",
            options: ["Nobody at all", "The DoH resolver operator", "Your ISP", "Every router on the path"],
            answer: 1,
            why: "DoH moves trust, it doesn’t remove it. The resolver decrypts your queries, so you need to trust whoever runs it.",
          },
          events: [
            pkt("client", "plain", "blue", "DNS Q", ["example.com A", "plain text"], {
              time: 0.5, info: "Standard query 0x8f3a A example.com OPT",
              packet: plainQ(0x8f3a, "example.com", 50312),
            }),
            note("isp", "SEES: EXAMPLE.COM", "red"),
            pkt("plain", "client", "blue", "DNS A", ["203.0.113.10", "plain text"], {
              time: 0.518, info: `Standard query response 0x8f3a A example.com A ${ADDR.web} OPT`,
              packet: plainA(0x8f3a, "example.com", 50312),
            }),
          ],
        },
      ],
      outro: {
        title: "Same DNS, new envelope",
        text: "DoH did not change DNS itself: the query and answer are ordinary DNS messages. It only wrapped them in HTTP/2 over TLS, so the network sees a secure web connection to the resolver instead of the names you look up.",
        facts: [["Packets", "10 for DoH (incl. setup)"], ["Later lookups", "Reuse the open connection: 1 round trip"], ["Hidden", "Names, answers, query sizes"], ["Still visible", "Resolver IP and SNI"]],
      },
    },
    {
      id: "blocked",
      name: "The network blocks DoH",
      summary: "An office firewall drops connections to known DoH resolvers, so the browser falls back to plain DNS.",
      kind: "failure",
      devices: devices("firewall", "Office firewall", "Office DNS"),
      links,
      steps: [
        {
          title: "Connection dropped",
          desc: "SYNs to the resolver vanish",
          detail: `The office firewall keeps a list of public DoH resolvers and silently drops traffic to them, so it can filter and log DNS itself. The browser’s SYN to ${DOH}:443 gets no answer; after 1 second it tries again, with the same result.`,
          facts: [["Target", `${DOH}:443`], ["Firewall action", "Drop (no reply)"], ["Retry", "After 1 s"]],
          quiz: {
            q: "Why can a firewall block DoH to 192.0.2.1 even though the traffic is encrypted?",
            options: ["It decrypts TLS", "It blocks by the resolver’s IP address and SNI, which are visible", "DoH uses port 53", "It can’t"],
            answer: 1,
            why: "Encryption hides the content, not where the packets go. Well-known resolver IPs and names are easy to block.",
          },
          events: [
            pkt("client", "doh", "red", "SYN", ["to :443"], {
              time: 0, lost: true, info: `${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(...up(DOH), tcp({ sport: SP, dport: 443, seq: 0, flags: "S", opts: synOpts, seqBase: CB })),
            }),
            note("isp", "DROP: KNOWN DOH", "red"),
            pkt("client", "doh", "red", "SYN", ["retry"], {
              time: 1.0, lost: true, info: `[TCP Retransmission] ${SP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`,
              packet: build(...up(DOH), tcp({ sport: SP, dport: 443, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", { ts: [882231, 0] }, "nop", { ws: 7 }], seqBase: CB })),
            }),
          ],
        },
        {
          title: "Fall back to plain DNS",
          desc: "The page still loads, privately no more",
          detail: "In its default mode the browser treats DoH as best effort. When the resolver can’t be reached it falls back to the DNS server the network handed out, over UDP 53. The lookup works, but the firewall can now read every name.",
          facts: [["Server", `Office DNS ${ISP_DNS}`], ["Transport", "UDP 53, plain text"], ["Privacy", "Lost on this network"]],
          quiz: {
            q: "A user picked “maximum protection” (strict DoH, no fallback). What happens here?",
            options: ["Same as now, plain DNS", "Names fail to resolve, so pages don’t load", "The browser switches to port 53 DoH", "The firewall is bypassed"],
            answer: 1,
            why: "Strict mode refuses to leak names, so with DoH blocked the lookup simply fails. Privacy wins over working.",
          },
          events: [
            pkt("client", "plain", "blue", "DNS Q", ["example.com A", "plain text"], {
              time: 3.0, info: "Standard query 0x2b17 A example.com OPT",
              packet: plainQ(0x2b17, "example.com", 50411),
            }),
            note("isp", "SEES: EXAMPLE.COM", "amber"),
            pkt("plain", "client", "blue", "DNS A", ["203.0.113.10"], {
              time: 3.004, info: `Standard query response 0x2b17 A example.com A ${ADDR.web} OPT`,
              packet: plainA(0x2b17, "example.com", 50411),
            }),
          ],
        },
        {
          title: "The canary domain",
          desc: "A polite way to say “no DoH here”",
          detail: "Firefox also asks the network’s resolver for a special name, use-application-dns.net. A network that wants to filter DNS answers NXDOMAIN for it, and the browser then leaves DoH off by default on that network, without waiting for timeouts.",
          facts: [["Canary", "use-application-dns.net"], ["NXDOMAIN means", "Don’t turn DoH on by default"], ["Checked", "At start and on network change"]],
          events: [
            pkt("client", "plain", "blue", "DNS Q", ["canary?"], {
              time: 3.01, info: "Standard query 0x6d40 A use-application-dns.net OPT",
              packet: plainQ(0x6d40, "use-application-dns.net", 50412),
            }),
            pkt("plain", "client", "red", "NXDOMAIN", ["no DoH here"], {
              time: 3.014, info: "Standard query response 0x6d40 No such name A use-application-dns.net OPT",
              packet: nxA(0x6d40, "use-application-dns.net", 50412),
            }),
            note("client", "DOH OFF ON THIS NETWORK", "amber"),
          ],
        },
      ],
      outro: {
        title: "Blocked, then fallen back",
        text: "DoH hides what you ask, not who you ask. A network can block well-known resolvers or signal with the canary domain, and the browser then falls back to plain DNS unless the user chose strict mode.",
        facts: [["Blocked by", "Resolver IP / SNI"], ["Fallback", "Plain DNS, UDP 53"], ["Canary", "use-application-dns.net"], ["Strict mode", "Fails instead of leaking"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "The HTTP request",
      items: [[":method", "POST (or GET with ?dns=base64url)"], [":path", "/dns-query"], ["content-type", "application/dns-message"], ["accept", "application/dns-message"]],
    },
    {
      title: "Encrypted DNS family",
      items: [["DoH", "DNS over HTTPS, TCP/UDP 443 (RFC 8484)"], ["DoT", "DNS over TLS, TCP 853 (RFC 7858)"], ["DoQ", "DNS over QUIC, UDP 853 (RFC 9250)"], ["Plain DNS", "UDP/TCP 53, no encryption"]],
    },
    {
      title: "Numbers to know",
      items: [["DNS ID in DoH", "0 (helps HTTP caching)"], ["Query padding", "Multiple of 128 bytes"], ["Response padding", "Multiple of 468 bytes"], ["Canary domain", "use-application-dns.net"]],
    },
  ],
});

