import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec } from "@/lib/packet";
import { eth, ext, hsMsg, ipv4, tcp, TcpOpt, tls, vec } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

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

// ---------------------------------------------------------------- TLS 1.3 builders

function clientHello(host: string, alpn: string[], seed: number): LayerSpec {
  const hello = hsMsg("client_hello", "Client Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "Frozen at 1.2 so old middleboxes don't choke. The real versions are in supported_versions." },
    { name: "Random", random: 32, seed, note: "32 fresh random bytes from the browser." },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: seed + 1 }], "32 bytes", "Not used by TLS 1.3, but filled in so the hello looks like a TLS 1.2 resumption to old devices."),
    vec("Cipher suites", 2, [
      { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256 (0x1301)" },
      { name: "Cipher suite", u16: 0x1302, value: "TLS_AES_256_GCM_SHA384 (0x1302)" },
      { name: "Cipher suite", u16: 0x1303, value: "TLS_CHACHA20_POLY1305_SHA256 (0x1303)" },
    ], "3 suites", "The encryption methods the browser can use, best first."),
    vec("Compression methods", 1, [{ name: "Method", u8: 0, value: "null (0)" }], "null only", "Compression inside TLS was abandoned after the CRIME attack."),
    vec("Extensions", 2, [
      ext(0, "server_name", [vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name (0)" }, vec("Host name", 2, [{ name: "Name", text: host }], host)])], host,
        "SNI: which website the browser wants. Sent in clear, so the network can see the site name (but not the page)."),
      ext(10, "supported_groups", [vec("Groups", 2, [{ name: "Group", u16: 0x001d, value: "x25519 (0x001d)" }, { name: "Group", u16: 0x0017, value: "secp256r1 (0x0017)" }])], "x25519, secp256r1", "Key-exchange curves the browser supports."),
      ext(13, "signature_algorithms", [vec("Algorithms", 2, [
        { name: "Algorithm", u16: 0x0403, value: "ecdsa_secp256r1_sha256 (0x0403)" },
        { name: "Algorithm", u16: 0x0804, value: "rsa_pss_rsae_sha256 (0x0804)" },
        { name: "Algorithm", u16: 0x0401, value: "rsa_pkcs1_sha256 (0x0401)" },
      ])], "3 algorithms", "Which signatures the browser can check on the server's certificate."),
      ext(16, "application_layer_protocol_negotiation", [vec("Protocols", 2, alpn.map((p) => vec("Protocol", 1, [{ name: "Name", text: p }], p)))], alpn.join(", "), "ALPN: which application protocol to speak inside TLS."),
      ext(43, "supported_versions", [vec("Versions", 1, [{ name: "Version", u16: 0x0304, value: "TLS 1.3 (0x0304)" }, { name: "Version", u16: 0x0303, value: "TLS 1.2 (0x0303)" }])], "TLS 1.3, TLS 1.2", "The real list of versions. Its presence is what signals TLS 1.3."),
      ext(45, "psk_key_exchange_modes", [vec("Modes", 1, [{ name: "Mode", u8: 1, value: "psk_dhe_ke (1)" }])], "psk_dhe_ke", "If a session is resumed later, still do a fresh key exchange."),
      ext(51, "key_share", [vec("Client key shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 2 }], "32 bytes")])], "x25519 public key",
        "The browser's half of the key exchange, sent up front so the handshake takes only one round trip."),
    ], undefined, "Everything modern TLS needs is in extensions."),
  ], "The browser's opening message: what it supports, which site it wants, and its key share.");
  return tls({ records: [{ type: "handshake", version: 0x0301, fields: [hello] }], summary: `TLS 1.3 Client Hello (SNI=${host})` });
}

const serverHello = (seed: number): FieldSpec =>
  hsMsg("server_hello", "Server Hello", [
    { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
    { name: "Random", random: 32, seed: seed + 50, note: "The server's own 32 random bytes." },
    vec("Legacy session ID", 1, [{ name: "Session ID", random: 32, seed: seed + 1 }], "32 bytes (echo)", "Copied back from the Client Hello."),
    { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256 (0x1301)", note: "The server's pick from the browser's list." },
    { name: "Compression method", u8: 0, value: "null (0)" },
    vec("Extensions", 2, [
      ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3 (0x0304)" }], "TLS 1.3", "The server agrees to TLS 1.3."),
      ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 51 }], "32 bytes")], "x25519 public key",
        "The server's half. Both sides can now compute the same shared secret; nobody watching can."),
    ]),
  ], "The server's choices and its key share. Everything after this is encrypted.");

const ccs = { type: "ccs" as const, fields: [{ name: "Change cipher spec", u8: 1, value: "1", note: "A dummy message kept only so old middleboxes stay calm. TLS 1.3 ignores it." }] };

// ---------------------------------------------------------------- lesson data

const S = ADDR.web;
const RTT = 0.034;
const SEED = 4100;
const devs = homeToServer({ label: "example.com", sub: S });

const ATK_MAC = "02:a7:7a:c6:00:66";
const atkDevices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: ADDR.laptop, x: 9, y: 62 },
  { id: "ap", kind: "ap" as const, label: "Café Wi-Fi", sub: ADDR.router, x: 30, y: 62 },
  { id: "attacker", kind: "attacker" as const, label: "Attacker", sub: "same Wi-Fi", x: 30, y: 22 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 60, y: 40 },
  { id: "server", kind: "web" as const, label: "example.com", sub: S, x: 87, y: 62 },
];
const atkLinks: [string, string][] = [["client", "ap"], ["ap", "attacker"], ["ap", "internet"], ["internet", "server"]];

export default defineLesson({
  id: "https",
  name: "HTTPS",
  full: "HTTP over TLS 1.3",
  group: "security",
  layer: 7,
  difficulty: 2,
  tagline: "The same HTTP, sealed in TLS so nobody on the path can read it.",
  description:
    "HTTPS is ordinary HTTP carried inside a TLS connection. TLS 1.3 agrees on fresh keys in one round trip, proves the server's identity with a certificate, and then encrypts every request and response. The padlock means all three worked.",
  facts: [
    ["Layer", "Application over TLS (5–7)"],
    ["Transport", "TCP, port 443"],
    ["Handshake", "1 round trip (TLS 1.3)"],
    ["Key exchange", "Ephemeral x25519"],
    ["Identity", "X.509 certificate"],
    ["Defined in", "RFC 9110, RFC 8446"],
  ],
  ports: "443",
  rfc: "RFC 8446 (TLS 1.3), RFC 9110, RFC 6797 (HSTS)",
  keywords: ["tls", "ssl", "certificate", "padlock", "sni", "hsts", "client hello", "server hello", "mitm", "encryption"],
  related: ["http", "tcp", "http2", "proxy", "reverse"],
  ...devs,
  legend: [
    ["green", "TCP handshake and ACKs"],
    ["teal", "TLS handshake (keys)"],
    ["amber", "Encrypted request"],
    ["violet", "Encrypted response"],
    ["red", "Attack or alert"],
  ],
  scenarios: [
    (() => {
      const k = conn({ a: "client", b: "server", cport: 52310, sport: 443, cBase: 0x1f2e3d00, sBase: 0x6c5b4a00, cl: up(S), sv: down(S) });
      return {
        id: "normal",
        name: "Opening https://example.com",
        summary: "TCP, a one-round-trip TLS 1.3 handshake, then an encrypted request and response.",
        kind: "normal" as const,
        steps: [
          {
            title: "TCP to port 443",
            desc: "Same handshake, different port",
            detail: "HTTPS still runs over TCP. The browser connects to port 443, the standard HTTPS port. Nothing is encrypted yet; that comes next.",
            facts: [["Server", `${S}:443`], ["Browser port", "52310"], ["Cost", "1 round trip"]],
            events: k.open(0, RTT),
          },
          {
            title: "Client Hello",
            desc: "Ciphers, site name and a key share",
            detail: "The browser sends everything at once: the cipher suites it supports, the site it wants (SNI), the versions it speaks, and its half of a fresh x25519 key exchange. Sending the key share up front is why TLS 1.3 needs only one round trip.",
            facts: [["SNI", "example.com (visible)"], ["Versions", "TLS 1.3, 1.2"], ["ALPN", "h2, http/1.1"]],
            quiz: {
              q: "Someone sniffing the café Wi-Fi sees this packet. What can they learn?",
              options: ["Nothing at all", "The site name example.com, but not the page or data", "The full URL and cookies", "The password"],
              answer: 1,
              why: "The SNI in the Client Hello is sent in clear. Paths, headers and bodies come later and are encrypted.",
            },
            events: [
              k.c(0.0345, "teal", "HELLO", ["SNI example.com", "key share"], { data: [clientHello("example.com", ["h2", "http/1.1"], SEED)], info: "Client Hello (SNI=example.com)" }),
            ],
          },
          {
            title: "Server Hello + certificate",
            desc: "Keys agreed; the rest is already encrypted",
            detail: "The server picks a cipher and sends its own key share in the Server Hello. Both sides now compute the same secret. Everything after that is encrypted: the server's certificate, its signature proving it owns the certificate, and its Finished message. It is too big for one segment, so it comes in two.",
            facts: [["Cipher", "TLS_AES_128_GCM_SHA256"], ["In clear", "Server Hello only"], ["Encrypted", "Certificate, CertificateVerify, Finished"]],
            quiz: {
              q: "In TLS 1.3, can an eavesdropper read the server's certificate?",
              options: ["Yes, it is always sent in clear", "No, it is encrypted with the handshake keys", "Only the expiry date", "Only if the server uses RSA"],
              answer: 1,
              why: "TLS 1.3 encrypts everything after the Server Hello, including the certificate. In TLS 1.2 it was visible.",
            },
            events: [
              k.s(0.0692, "teal", "S.HELLO", ["key share", "+ encrypted cert"], {
                info: "Server Hello, Change Cipher Spec, Application Data, Application Data",
                data: [tls({ records: [
                  { type: "handshake", fields: [serverHello(SEED)] },
                  ccs,
                  { type: "appdata", encrypted: 42, what: "EncryptedExtensions (encrypted)", note: "Encrypted: the rest of the server's settings, including ALPN = h2." },
                  { type: "appdata", encrypted: 1120, what: "Certificate (encrypted)", note: "Encrypted: the server's certificate chain for example.com." },
                ], summary: "TLS 1.3 Server Hello + encrypted handshake" })],
              }),
              k.s(0.0693, "teal", "CERT", ["signature", "Finished"], {
                parallel: true, info: "Application Data, Application Data",
                data: [tls({ records: [
                  { type: "appdata", encrypted: 281, what: "CertificateVerify (encrypted)", note: "Encrypted: a signature over the whole handshake with the certificate's private key." },
                  { type: "appdata", encrypted: 53, what: "Finished (encrypted)", note: "Encrypted: a MAC of the handshake so far, proving nothing was changed." },
                ] })],
              }),
              k.c(0.0695, "green", "ACK", []),
            ],
          },
          {
            title: "Check the certificate",
            desc: "Is this really example.com?",
            detail: "The browser decrypts the certificate and checks three things: the name matches example.com, it has not expired, and a chain of signatures leads to a root authority the browser trusts. It also checks the server's signature, which proves the server holds the private key. Then it sends its own Finished.",
            facts: [["Name", "Must match example.com"], ["Chain", "Must end at a trusted root"], ["Signature", "Proves the private key"]],
            quiz: {
              q: "What would happen if the certificate were for a different name?",
              options: ["The browser ignores it", "The browser stops with a certificate error", "The server sends another one", "TLS falls back to 1.2"],
              answer: 1,
              why: "A name mismatch means the browser cannot be sure who it is talking to, so it refuses to continue.",
            },
            events: [
              note("client", "CERTIFICATE OK", "green"),
              k.c(0.0712, "teal", "FINISHED", ["handshake done"], {
                info: "Change Cipher Spec, Application Data",
                data: [tls({ records: [ccs, { type: "appdata", encrypted: 53, what: "Finished (encrypted)" }] })],
              }),
            ],
          },
          {
            title: "Encrypted request",
            desc: "GET / travels as Application Data",
            detail: "Now the browser sends its request. On the wire it is just an Application Data record of random-looking bytes. Inside is GET / with all its headers and cookies, which nobody on the path can read or change without the tag check failing.",
            facts: [["Record type", "23 (Application Data)"], ["Inside", "GET / with headers"], ["Tamper check", "16-byte GCM tag"]],
            events: [
              k.c(0.0714, "amber", "GET", ["encrypted", "Application Data"], { data: [tls({ records: [{ type: "appdata", encrypted: 412, what: "HTTP request (encrypted)" }] })], info: "Application Data" }),
            ],
          },
          {
            title: "Encrypted response",
            desc: "200 OK, plus session tickets",
            detail: "The server first sends two session tickets the browser can use to reconnect faster later, then the 200 OK response with the page. All of it is encrypted. Among the response headers is Strict-Transport-Security, which you cannot see on the wire but the browser now remembers.",
            facts: [["Tickets", "2 NewSessionTicket"], ["Status", "200 OK (inside)"], ["HSTS", "max-age=31536000"]],
            events: [
              k.s(0.1058, "violet", "200 OK", ["tickets + page", "encrypted"], {
                info: "Application Data, Application Data, Application Data",
                data: [tls({ records: [
                  { type: "appdata", encrypted: 250, what: "NewSessionTicket (encrypted)" },
                  { type: "appdata", encrypted: 250, what: "NewSessionTicket (encrypted)" },
                  { type: "appdata", encrypted: 860, what: "HTTP response (encrypted)", note: "Encrypted: 200 OK, headers including Strict-Transport-Security, and the HTML." },
                ] })],
              }),
              k.c(0.106, "green", "ACK", []),
            ],
          },
          {
            title: "Padlock and HSTS",
            desc: "Secure, and remembered",
            detail: "The page shows with a padlock. Because of the header Strict-Transport-Security: max-age=31536000; includeSubDomains, for the next year the browser will turn any http://example.com link into https:// before sending anything, and it will not let you click past certificate errors.",
            facts: [["Padlock", "Encrypted + verified"], ["HSTS lasts", "1 year"], ["Effect", "No plain HTTP, no bypass"]],
            quiz: {
              q: "Next week you type http://example.com. What does the browser send first?",
              options: ["A plain GET to port 80", "A connection to port 443 straight away", "A DNS query for http.example.com", "Nothing until you confirm"],
              answer: 1,
              why: "HSTS makes the browser rewrite the URL to https:// internally, so no plain request ever leaves the laptop.",
            },
            events: [note("client", "🔒 SECURE", "green"), note("client", "HSTS SAVED: 1 YEAR", "blue")],
          },
        ],
        outro: {
          title: "Private and proven",
          text: "TCP connected, TLS 1.3 agreed on keys in one round trip, the certificate proved the server is example.com, and every HTTP byte after that was encrypted. HSTS makes sure future visits skip plain HTTP entirely.",
          facts: [["Round trips before data", "2 (TCP + TLS)"], ["Visible to the network", "IP, port, SNI, sizes, timing"], ["Hidden", "URL path, headers, cookies, body"], ["Total", "~106 ms"]],
        },
      };
    })(),
    (() => {
      // captured on the laptop: the attacker has poisoned the laptop's ARP cache, so frames go to its MAC
      const toAtk = [eth({ src: ADDR.laptopMac, dst: ATK_MAC }), ipv4({ src: ADDR.laptop, dst: S })];
      const fromAtk = [eth({ src: ATK_MAC, dst: ADDR.laptopMac }), ipv4({ src: S, dst: ADDR.laptop, ttl: 64 })];
      const k = conn({ a: "client", b: "attacker", cport: 52330, sport: 443, cBase: 0x2a3b4c00, sBase: 0x0dd0beef, cl: toAtk, sv: fromAtk });
      return {
        id: "mitm",
        name: "Man in the middle on café Wi-Fi",
        summary: "An attacker on the same Wi-Fi intercepts the connection and shows a fake certificate. The browser refuses.",
        kind: "attack" as const,
        devices: atkDevices,
        links: atkLinks,
        steps: [
          {
            title: "Traffic is hijacked",
            desc: "ARP spoofing sends packets to the attacker",
            detail: "The attacker on the café Wi-Fi tells the laptop \"I am the router\" with fake ARP replies. Now the laptop's frames go to the attacker's MAC address, even though the IP address inside still says 203.0.113.10. The attacker answers the TCP handshake pretending to be the server.",
            facts: [["Frame goes to", ATK_MAC], ["IP still says", S], ["Trick", "ARP spoofing"]],
            quiz: {
              q: "Can the laptop tell from the TCP handshake that something is wrong?",
              options: ["Yes, the IP address is different", "No, TCP has no way to prove who answered", "Yes, the SYN-ACK is missing", "Yes, the port changes"],
              answer: 1,
              why: "TCP and IP carry no proof of identity. Anyone in the path can answer. That proof is TLS's job.",
            },
            events: [note("attacker", "ARP SPOOF: I AM THE ROUTER", "red"), ...k.open(0, 0.004)],
          },
          {
            title: "Client Hello to the attacker",
            desc: "The browser asks for example.com",
            detail: "Unaware, the browser sends its normal Client Hello. The attacker reads the SNI and knows the victim wants example.com. To read the traffic it now has to pretend to be example.com.",
            facts: [["SNI", "example.com"], ["Received by", "The attacker"], ["Attacker's goal", "Decrypt and relay"]],
            events: [k.c(0.0045, "teal", "HELLO", ["SNI example.com"], { data: [clientHello("example.com", ["h2", "http/1.1"], SEED + 300)], info: "Client Hello (SNI=example.com)" })],
          },
          {
            title: "A fake certificate",
            desc: "Self-made, not signed by a trusted authority",
            detail: "The attacker completes the key exchange with its own key share, so it can decrypt what the laptop sends. But it must also send a certificate for example.com, and no trusted authority will issue one to it. It sends a certificate it signed itself.",
            facts: [["Key exchange", "Works (attacker's key)"], ["Certificate", "Self-signed, example.com"], ["Signed by", "No trusted root"]],
            quiz: {
              q: "Why can't the attacker just copy example.com's real certificate?",
              options: ["Certificates are encrypted", "It would also need the real server's private key to sign the handshake", "Certificates expire every minute", "The browser caches it"],
              answer: 1,
              why: "A certificate is public. The CertificateVerify signature needs the matching private key, which only the real server has.",
            },
            events: [
              k.s(0.0089, "red", "FAKE", ["Server Hello", "fake certificate"], {
                info: "Server Hello, Change Cipher Spec, Application Data, Application Data",
                data: [tls({ records: [
                  { type: "handshake", fields: [serverHello(SEED + 300)] },
                  ccs,
                  { type: "appdata", encrypted: 42, what: "EncryptedExtensions (encrypted)" },
                  { type: "appdata", encrypted: 820, what: "Certificate (encrypted)", note: "Encrypted: a self-signed certificate for example.com made by the attacker." },
                  { type: "appdata", encrypted: 97, what: "CertificateVerify (encrypted)" },
                  { type: "appdata", encrypted: 53, what: "Finished (encrypted)" },
                ] })],
              }),
            ],
          },
          {
            title: "The browser blocks it",
            desc: "Alert, then reset",
            detail: "The browser cannot build a chain from this certificate to any root it trusts. It sends an encrypted alert (unknown_ca) and drops the connection. No HTTP request was ever sent, so no cookies or passwords leaked. Because example.com uses HSTS, the warning page has no \"proceed anyway\" button.",
            facts: [["Alert", "unknown_ca (48), encrypted"], ["Browser shows", "NET::ERR_CERT_AUTHORITY_INVALID"], ["HTTP sent", "Nothing"]],
            events: [
              k.c(0.0105, "red", "ALERT", ["unknown_ca"], { data: [tls({ records: [{ type: "appdata", encrypted: 19, what: "Alert: unknown_ca (encrypted)", note: "A 2-byte alert plus inner type and 16-byte tag. Encrypted with the handshake keys." }] })], info: "Application Data (Alert)" }),
              k.c(0.0106, "slate", "RST", ["drop it"], { flags: "RA", info: "52330 → 443 [RST, ACK]" }),
              note("client", "YOUR CONNECTION IS NOT PRIVATE", "red"),
            ],
          },
        ],
        outro: {
          title: "Attack stopped by the certificate",
          text: "The attacker could intercept packets and even finish a key exchange, but it could not prove it was example.com. Certificate checks turn an invisible interception into a loud error, and HSTS removes the button that lets users walk into the trap.",
          facts: [["Attack", "ARP spoofing + fake certificate"], ["Defence", "Certificate chain to a trusted root"], ["HSTS adds", "No click-through"], ["Data leaked", "Only the SNI"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "TLS 1.3 handshake",
      items: [["Client Hello", "Suites, SNI, key share"], ["Server Hello", "Chosen suite, key share"], ["EncryptedExtensions", "ALPN and other settings"], ["Certificate + Verify", "Identity and proof of key"], ["Finished", "Both sides confirm the handshake"]],
    },
    {
      title: "What a network can see",
      items: [["IP + port", "Yes"], ["SNI (site name)", "Yes (unless ECH)"], ["URL path, headers", "No"], ["Cookies, body", "No"], ["Sizes and timing", "Yes"]],
    },
    {
      title: "Numbers to know",
      items: [["Port", "443"], ["Record header", "5 bytes"], ["GCM tag", "16 bytes"], ["HSTS typical", "max-age=31536000 (1 year)"]],
    },
  ],
});
