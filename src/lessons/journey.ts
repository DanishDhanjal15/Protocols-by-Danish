import { defineLesson, note, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec } from "@/lib/packet";
import { text } from "@/lib/bytes";
import { arp, BROADCAST_MAC, dhcp, dhcpOpt, dns, eth, ext, hsMsg, ipv4, tcp, TcpOpt, tls, udp, vec } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

const L = ADDR.laptop;
const R = ADDR.router;
const W = ADDR.web;
const D = ADDR.dns;
const ISP_MAC = "00:1a:2b:3c:4d:5e";
const XID = 0x77a1c302;

// ---------------------------------------------------------------- tiny TCP conversation helper (captured on the laptop)

const FLAG_TXT: Record<string, string> = { S: "SYN", A: "ACK", P: "PSH", F: "FIN", R: "RST" };
function conv(sport: number, cBase: number, sBase: number) {
  let cs = 0, ss = 0, idC = 0x4c10, idS = 0;
  const go = (fromClient: boolean, flags: string, payload?: LayerSpec, opts?: TcpOpt[]) => {
    const len = payload ? build(payload).bytes.length : 0;
    const seq = fromClient ? cs : ss;
    const ack = fromClient ? ss : cs;
    const hasA = flags.includes("A");
    const sp = fromClient ? sport : 443, dp = fromClient ? 443 : sport;
    const t = tcp({ sport: sp, dport: dp, seq, ack: hasA ? ack : undefined, flags, win: flags.includes("S") ? 64240 : 502, opts, seqBase: fromClient ? cBase : sBase, ackBase: hasA ? (fromClient ? sBase : cBase) : undefined });
    const packet = build(...(fromClient ? up(W, { id: idC++ }) : down(W, { id: idS++ })), t, ...(payload ? [payload] : []));
    const bump = len + (flags.includes("S") || flags.includes("F") ? 1 : 0);
    if (fromClient) cs += bump; else ss += bump;
    const names = ["F", "S", "R", "P", "A"].filter((f) => flags.includes(f)).map((f) => FLAG_TXT[f]).join(", ");
    const info = `${sp} → ${dp} [${names}] Seq=${seq}${hasA ? ` Ack=${ack}` : ""} Len=${len}`;
    return { packet, info, seq, ack, len };
  };
  return { c: (f: string, p?: LayerSpec, o?: TcpOpt[]) => go(true, f, p, o), s: (f: string, p?: LayerSpec, o?: TcpOpt[]) => go(false, f, p, o) };
}

// ---------------------------------------------------------------- TLS 1.3 records

function clientHello(seed: number, psk = false): LayerSpec {
  const sni = "example.com";
  const exts: FieldSpec[] = [
    ext(0, "server_name", [vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name" }, vec("Host name", 2, [{ name: "Name", bytes: text(sni), value: sni }], sni)], sni)], sni, "SNI: the site name, in clear text, so the server can pick the right certificate."),
    ext(10, "supported_groups", [vec("Groups", 2, [{ name: "x25519", u16: 0x001d, value: "x25519" }], "x25519")], "x25519"),
    ext(13, "signature_algorithms", [vec("Algorithms", 2, [{ name: "ecdsa_secp256r1_sha256", u16: 0x0403 }, { name: "rsa_pss_rsae_sha256", u16: 0x0804 }], "2 algorithms")], "2 algorithms"),
    ext(16, "application_layer_protocol_negotiation", [vec("Protocols", 2, [vec("Protocol", 1, [{ name: "Name", text: "h2", value: "h2" }], "h2"), vec("Protocol", 1, [{ name: "Name", text: "http/1.1", value: "http/1.1" }], "http/1.1")], "h2, http/1.1")], "h2, http/1.1", "ALPN: which application protocol to speak inside TLS."),
    ext(43, "supported_versions", [vec("Versions", 1, [{ name: "TLS 1.3", u16: 0x0304, value: "0x0304" }], "TLS 1.3")], "TLS 1.3"),
    ext(51, "key_share", [vec("Client shares", 2, [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 2, opaque: true }], "32 bytes")], "x25519 key")], "x25519 key", "The browser’s half of the key exchange."),
  ];
  if (psk) {
    exts.push(ext(45, "psk_key_exchange_modes", [vec("Modes", 1, [{ name: "psk_dhe_ke", u8: 1, value: "1 (PSK with fresh key exchange)" }], "psk_dhe_ke")], "psk_dhe_ke"));
    exts.push(ext(41, "pre_shared_key", [
      vec("Identities", 2, [vec("Identity", 2, [{ name: "Session ticket", random: 192, seed: seed + 3, opaque: true }], "192-byte ticket"), { name: "Obfuscated ticket age", u32: 0x5b3f11a2 }], "1 ticket"),
      vec("Binders", 2, [vec("Binder", 1, [{ name: "HMAC", random: 32, seed: seed + 4, opaque: true }], "32 bytes")], "1 binder"),
    ], "session ticket", "The ticket the server gave last time. Must be the last extension."));
  }
  return tls({
    records: [{
      type: "handshake", version: 0x0301,
      fields: [hsMsg("client_hello", "Client Hello", [
        { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)", note: "Frozen for compatibility; the real version is in supported_versions." },
        { name: "Random", random: 32, seed, opaque: true },
        vec("Session ID", 1, [{ name: "Legacy session ID", random: 32, seed: seed + 1 }]),
        vec("Cipher suites", 2, [{ name: "TLS_AES_128_GCM_SHA256", u16: 0x1301 }, { name: "TLS_AES_256_GCM_SHA384", u16: 0x1302 }, { name: "TLS_CHACHA20_POLY1305_SHA256", u16: 0x1303 }], "3 suites"),
        vec("Compression methods", 1, [{ name: "null", u8: 0 }], "null"),
        vec("Extensions", 2, exts, `${exts.length} extensions`),
      ])],
    }],
  });
}

function serverFlight(seed: number, encLen: number, psk: boolean): LayerSpec {
  const exts: FieldSpec[] = [
    ext(43, "supported_versions", [{ name: "Version", u16: 0x0304, value: "TLS 1.3" }], "TLS 1.3"),
    ext(51, "key_share", [{ name: "Group", u16: 0x001d, value: "x25519" }, vec("Key exchange", 2, [{ name: "Public key", random: 32, seed: seed + 1, opaque: true }], "32 bytes")], "x25519 key"),
  ];
  if (psk) exts.push(ext(41, "pre_shared_key", [{ name: "Selected identity", u16: 0, value: "0 (your ticket is accepted)" }], "ticket 0 accepted"));
  return tls({
    records: [
      { type: "handshake", fields: [hsMsg("server_hello", "Server Hello", [
        { name: "Legacy version", u16: 0x0303, value: "TLS 1.2 (0x0303)" },
        { name: "Random", random: 32, seed, opaque: true },
        vec("Session ID", 1, [{ name: "Echoed session ID", random: 32, seed: seed - 99 }]),
        { name: "Cipher suite", u16: 0x1301, value: "TLS_AES_128_GCM_SHA256" },
        { name: "Compression", u8: 0, value: "null" },
        vec("Extensions", 2, exts, `${exts.length} extensions`),
      ])] },
      { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1, note: "A dummy kept for old middleboxes; TLS 1.3 ignores it." }] },
      { type: "appdata", encrypted: encLen, what: psk ? "Encrypted: EncryptedExtensions, Finished (no certificate needed)" : "Encrypted: EncryptedExtensions, Certificate, CertificateVerify, Finished" },
    ],
  });
}

const clientFinished = tls({ records: [{ type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] }, { type: "appdata", encrypted: 53, what: "Encrypted Finished" }] });
const app = (n: number, what: string) => tls({ records: [{ type: "appdata", encrypted: n, what }] });

// ---------------------------------------------------------------- first visit packets

const synOpts: TcpOpt[] = [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }];
const SP = 51544;
const C = conv(SP, 0x1f2e3d00, 0x6a5b4c00);
const v1 = {
  syn: C.c("S", undefined, synOpts),
  synack: C.s("SA", undefined, synOpts),
  ack: C.c("A"),
  ch: C.c("PA", clientHello(301)),
  sf: C.s("PA", serverFlight(401, 1250, false)),
  cf: C.c("PA", clientFinished),
  get: C.c("PA", app(92, "Encrypted HTTP/2 HEADERS: GET / , :authority example.com")),
  resp: C.s("PA", app(1380, "Encrypted HTTP/2 HEADERS 200 + DATA (the HTML)")),
};
const v1ack = C.c("A");
const v1b = {
  css: C.c("PA", app(64, "Encrypted HTTP/2 HEADERS: GET /style.css")),
  cssResp: C.s("PA", app(920, "Encrypted HTTP/2 HEADERS 200 + DATA (CSS)")),
};
const v1close = {
  cn: C.c("PA", app(19, "Encrypted alert: close_notify")),
  fin: C.c("FA"),
  sfin: C.s("FA"),
  last: C.c("A"),
};
// the same ACK as it leaves the router: NAT rewrote the source address and port
const NAT_PORT = 40001;
const natAck = build(
  eth({ src: "b0:be:76:12:4c:02", dst: ISP_MAC }),
  ipv4({ src: ADDR.routerWan, dst: W, ttl: 63, id: 0x4c17 }),
  tcp({ sport: NAT_PORT, dport: 443, seq: v1ack.seq, ack: v1ack.ack, flags: "A", win: 502, seqBase: 0x1f2e3d00, ackBase: 0x6a5b4c00 })
);

// ---------------------------------------------------------------- second visit packets

const C2 = conv(51602, 0x2a7c0000, 0x5d110000);
const v2 = {
  syn: C2.c("S", undefined, synOpts),
  synack: C2.s("SA", undefined, synOpts),
  ack: C2.c("A"),
  ch: C2.c("PA", clientHello(501, true)),
  sf: C2.s("PA", serverFlight(601, 96, true)),
  cf: C2.c("PA", clientFinished),
  get: C2.c("PA", app(118, "Encrypted HTTP/2 HEADERS: GET / , if-none-match \"abc123\"")),
  resp: C2.s("PA", app(58, "Encrypted HTTP/2 HEADERS: 304 Not Modified")),
};

export default defineLesson({
  id: "journey",
  name: "Type google.com",
  full: "What happens when you type a web address and press Enter",
  group: "journey",
  layer: 7,
  difficulty: 1,
  tagline: "The classic interview question, packet by packet.",
  description:
    "Pressing Enter in the address bar sets off a chain of protocols: DHCP and ARP get the laptop onto the network, DNS turns the name into an address, TCP opens a connection, TLS makes it private, and HTTP fetches the page. This lesson walks the whole chain once (using example.com in the packets), then shows what a second visit skips thanks to caches.",
  facts: [
    ["Protocols", "DHCP, ARP, DNS, TCP, TLS, HTTP, NAT"],
    ["Layers", "From 2 (Ethernet) to 7 (HTTP)"],
    ["First page", "About 0.1 s on a good link"],
    ["Round trips", "DNS 1, TCP 1, TLS 1, HTTP 1"],
    ["Second visit", "Caches skip DNS, ARP and the certificate"],
    ["Site in packets", "example.com"],
  ],
  ports: "UDP 67/68, UDP 53, TCP 443",
  keywords: ["interview", "google.com", "browser", "what happens when", "end to end", "dhcp", "arp", "dns", "tcp", "tls", "https", "http", "nat", "cache", "session resumption"],
  related: ["dhcp", "arp", "dns", "tcp", "tls", "http", "nat"],
  devices: [
    { id: "client", kind: "laptop", label: "Laptop", sub: L, x: 8, y: 62 },
    { id: "router", kind: "router", label: "Wi-Fi router", sub: `${R} / ${ADDR.routerWan}`, x: 30, y: 62 },
    { id: "isp", kind: "isp", label: "ISP", x: 54, y: 40 },
    { id: "dns", kind: "dns", label: "DNS resolver", sub: D, x: 78, y: 18 },
    { id: "server", kind: "web", label: "Web server", sub: `example.com ${W}`, x: 88, y: 68 },
  ],
  links: [["client", "router"], ["router", "isp"], ["isp", "dns"], ["isp", "server"]],
  legend: [
    ["blue", "Getting set up: DHCP, ARP, DNS"],
    ["green", "Handshakes and ACKs"],
    ["teal", "TLS (encryption)"],
    ["amber", "Requests from the browser"],
    ["violet", "Answers from the server"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "First visit, end to end",
      summary: "From an empty laptop to a rendered page: DHCP, ARP, DNS, TCP, TLS, HTTP and NAT, one step each.",
      kind: "normal",
      steps: [
        {
          title: "Get an address",
          desc: "DHCP: who am I on this network?",
          detail:
            "The laptop has just joined the Wi-Fi. Before it can send anything it needs an IP address, the router’s address and a DNS server. It had this network before, so it skips straight to asking for its old address with a broadcast REQUEST, and the router confirms with ACK. The full four-message version is in the DHCP lesson.",
          facts: [["Got", `${L}/24`], ["Gateway", R], ["DNS server", D]],
          quiz: {
            q: "Why is the first packet a broadcast?",
            options: ["Broadcasts are faster", "The laptop has no address yet and doesn’t know the server", "To reach Google directly", "Wi-Fi only allows broadcasts"],
            answer: 1,
            why: "Without an address the laptop can only shout to everyone on the local network. The DHCP server answers.",
          },
          events: [
            pkt("client", "router", "blue", "DHCP REQ", [`may I keep ${L}?`], {
              time: 0, info: `DHCP Request - Transaction ID 0x${XID.toString(16)}`,
              packet: build(eth({ src: ADDR.laptopMac, dst: BROADCAST_MAC }), ipv4({ src: "0.0.0.0", dst: "255.255.255.255", id: 0, df: false }), udp({ sport: 68, dport: 67 }), dhcp({ op: 1, xid: XID, chaddr: ADDR.laptopMac, broadcast: true, options: [dhcpOpt.msgType(3), dhcpOpt.requestedIp(L), dhcpOpt.paramList(1, 3, 6, 15)] })),
            }),
            pkt("router", "client", "green", "DHCP ACK", [`${L} is yours`], {
              time: 0.003, info: `DHCP ACK - Transaction ID 0x${XID.toString(16)}`,
              packet: build(eth({ src: ADDR.routerMac, dst: BROADCAST_MAC }), ipv4({ src: R, dst: "255.255.255.255", id: 0, df: false }), udp({ sport: 67, dport: 68 }), dhcp({ op: 2, xid: XID, chaddr: ADDR.laptopMac, broadcast: true, yiaddr: L, options: [dhcpOpt.msgType(5), dhcpOpt.serverId(R), dhcpOpt.lease(86400), dhcpOpt.subnet("255.255.255.0"), dhcpOpt.router(R), dhcpOpt.dns(D)] })),
            }),
          ],
        },
        {
          title: "Find the router’s MAC",
          desc: "ARP: who has 192.168.1.1?",
          detail:
            "Every packet to the internet goes to the router first, but Wi-Fi and Ethernet frames need a MAC address, not an IP. The laptop broadcasts an ARP request for 192.168.1.1 and the router replies with its MAC. The laptop caches this for later. See the ARP lesson.",
          facts: [["Asked", `Who has ${R}?`], ["Answer", ADDR.routerMac], ["Cached", "For minutes"]],
          events: [
            pkt("client", "router", "blue", "ARP", [`who has ${R}?`], { time: 0.004, info: `Who has ${R}? Tell ${L}`, packet: build(eth({ src: ADDR.laptopMac, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: ADDR.laptopMac, senderIp: L, targetIp: R })) }),
            pkt("router", "client", "green", "ARP", [`${R} is at …4c:01`], { time: 0.005, info: `${R} is at ${ADDR.routerMac}`, packet: build(eth({ src: ADDR.routerMac, dst: ADDR.laptopMac }), arp({ op: 2, senderMac: ADDR.routerMac, senderIp: R, targetMac: ADDR.laptopMac, targetIp: L })) }),
          ],
        },
        {
          title: "Name to address",
          desc: "DNS: what is example.com’s IP?",
          detail:
            "The browser knows a name, but packets need an IP address. It asks the DNS resolver from DHCP with a small UDP query to port 53. The resolver may have to ask the root, .com and example.com’s own servers, then it answers: 203.0.113.10. The DNS lesson shows the full walk.",
          facts: [["Query", "example.com A?"], ["Answer", W], ["Cache for", "3600 s (TTL)"]],
          quiz: {
            q: "Which transport does this DNS question use?",
            options: ["TCP port 443", "UDP port 53", "UDP port 67", "ICMP"],
            answer: 1,
            why: "A normal DNS lookup is one small UDP datagram each way, to port 53. TCP is only used for big answers or zone transfers.",
          },
          events: [
            pkt("client", "dns", "blue", "DNS", ["example.com A?"], { time: 0.006, info: "Standard query 0x8e21 A example.com", packet: build(...up(D, { id: 0x9a01 }), udp({ sport: 53122, dport: 53 }), dns({ id: 0x8e21, qd: [{ name: "example.com", type: "A" }] })) }),
            pkt("dns", "client", "violet", "DNS", [`A ${W}`], { time: 0.03, info: `Standard query response 0x8e21 A example.com A ${W}`, packet: build(...down(D, { id: 0x31aa }), udp({ sport: 53, dport: 53122 }), dns({ id: 0x8e21, response: true, ra: true, qd: [{ name: "example.com", type: "A" }], an: [{ name: "example.com", type: "A", ttl: 3600, data: W }] })) }),
          ],
        },
        {
          title: "Open a connection",
          desc: "TCP three-way handshake to port 443",
          detail:
            "HTTPS runs on TCP port 443. The laptop sends SYN, the server answers SYN-ACK, the laptop confirms with ACK. Now both sides agree on starting sequence numbers and can send data reliably. That costs one round trip (17 ms here). Full detail in the TCP lesson.",
          facts: [["To", `${W} : 443`], ["From port", `${SP} (temporary)`], ["Cost", "1 round trip"]],
          events: [
            pkt("client", "server", "green", "SYN", ["port 443"], { time: 0.031, info: v1.syn.info, packet: v1.syn.packet }),
            pkt("server", "client", "green", "SYN-ACK", [], { time: 0.048, info: v1.synack.info, packet: v1.synack.packet }),
            pkt("client", "server", "green", "ACK", [], { time: 0.049, info: v1.ack.info, packet: v1.ack.packet }),
          ],
        },
        {
          title: "Make it private",
          desc: "TLS 1.3 handshake",
          detail:
            "The browser sends a Client Hello with the site name (SNI, still readable), the ciphers it supports and its half of a key exchange. The server replies with its half, and from then on everything is encrypted, including its certificate, which proves it really is example.com. One round trip later both sides share keys. See the TLS lesson.",
          facts: [["SNI", "example.com (visible)"], ["Cipher", "TLS_AES_128_GCM_SHA256"], ["Cost", "1 round trip"]],
          quiz: {
            q: "After the handshake, what can someone on the café Wi-Fi still see?",
            options: ["The full URL and page", "The server IP, the site name (SNI) and data sizes", "Nothing at all", "Your passwords"],
            answer: 1,
            why: "TLS hides the path, headers and content, but the IP address, the SNI in the Client Hello and the sizes and timing of records stay visible.",
          },
          events: [
            pkt("client", "server", "teal", "C.HELLO", ["SNI example.com", "key share"], { time: 0.05, info: "Client Hello (SNI=example.com)", packet: v1.ch.packet }),
            pkt("server", "client", "teal", "S.HELLO", ["key share", "+ certificate (encrypted)"], { time: 0.067, info: "Server Hello, Change Cipher Spec, Application Data", packet: v1.sf.packet }),
            pkt("client", "server", "teal", "FINISHED", [], { time: 0.069, info: "Change Cipher Spec, Application Data", packet: v1.cf.packet }),
          ],
        },
        {
          title: "Ask for the page",
          desc: "HTTP GET, inside TLS",
          detail:
            "Now the browser sends the actual request: GET / for example.com, using HTTP/2 as agreed through ALPN. On the wire it is just an encrypted Application Data record; the method, path, cookies and headers are all inside. The HTTP lesson shows what those headers look like.",
          facts: [["Request", "GET / (HTTP/2)"], ["On the wire", `${v1.get.len} bytes of TLS`], ["Visible", "Only size and timing"]],
          events: [pkt("client", "server", "amber", "GET /", ["encrypted"], { time: 0.07, info: `${v1.get.info}  Application Data`, packet: v1.get.packet })],
        },
        {
          title: "The page arrives",
          desc: "200 OK with the HTML",
          detail:
            "The server answers with status 200 and the HTML of the page, again inside encrypted records. A small page fits in one segment; bigger ones arrive as many segments that TCP puts back in order.",
          facts: [["Status", "200 OK"], ["Body", "HTML"], ["Time so far", "About 90 ms"]],
          events: [
            pkt("server", "client", "violet", "200 OK", ["HTML (encrypted)"], { time: 0.088, info: `${v1.resp.info}  Application Data`, packet: v1.resp.packet }),
          ],
        },
        {
          title: "NAT at the router",
          desc: "Private address in, public address out",
          detail:
            "Every packet the laptop sent used its private address 192.168.1.10, which means nothing on the internet. The router rewrites the source to its public address 198.51.100.7 and a port of its own, remembers the mapping, and reverses it for replies. Here is the laptop’s ACK on both sides of the router. See the NAT lesson.",
          facts: [["Inside", `${L}:${SP}`], ["Outside", `${ADDR.routerWan}:${NAT_PORT}`], ["Changed", "Source IP, port, checksums"]],
          quiz: {
            q: "What does the web server think the client’s address is?",
            options: [L, ADDR.routerWan, "0.0.0.0", "The laptop’s MAC address"],
            answer: 1,
            why: "The server only ever sees the router’s public address. The router’s NAT table maps replies back to the laptop.",
          },
          events: [
            pkt("client", "router", "green", "ACK", [`from ${L}:${SP}`], { time: 0.089, info: v1ack.info, packet: v1ack.packet }),
            note("router", `NAT → ${ADDR.routerWan}:${NAT_PORT}`, "blue"),
            pkt("router", "server", "green", "ACK", [`from ${ADDR.routerWan}:${NAT_PORT}`], { time: 0.0891, info: `${NAT_PORT} → 443 [ACK] Seq=${v1ack.seq} Ack=${v1ack.ack} Len=0`, packet: natAck }),
          ],
        },
        {
          title: "Render the page",
          desc: "Parse HTML, fetch what it needs",
          detail:
            "The browser reads the HTML and finds it needs a stylesheet. It asks for /style.css on the same connection, with no new DNS, TCP or TLS. Real pages pull dozens of files, images and scripts this way, often from other servers that each need their own DNS lookup and handshakes. Then it lays out and paints the page.",
          facts: [["Extra request", "GET /style.css"], ["Reuses", "Same TCP + TLS connection"], ["Then", "Layout and paint"]],
          events: [
            pkt("client", "server", "amber", "GET .css", ["encrypted"], { time: 0.095, info: `${v1b.css.info}  Application Data`, packet: v1b.css.packet }),
            pkt("server", "client", "violet", "200 OK", ["CSS (encrypted)"], { time: 0.112, info: `${v1b.cssResp.info}  Application Data`, packet: v1b.cssResp.packet }),
            note("client", "PAGE PAINTED", "green"),
          ],
        },
        {
          title: "Close the connection",
          desc: "TLS close_notify, then TCP FIN",
          detail:
            "Browsers keep connections open for a while in case you click a link. When the tab is idle the browser sends an encrypted close_notify alert so the server knows the data ended cleanly, then TCP closes each direction with FIN and ACK.",
          facts: [["TLS", "close_notify alert"], ["TCP", "FIN → FIN → ACK"], ["After", "About 10 s idle"]],
          events: [
            pkt("client", "server", "slate", "CLOSE", ["close_notify"], { time: 10, info: `${v1close.cn.info}  Encrypted Alert`, packet: v1close.cn.packet }),
            pkt("client", "server", "slate", "FIN", [], { time: 10.0001, parallel: true, info: v1close.fin.info, packet: v1close.fin.packet }),
            pkt("server", "client", "slate", "FIN", [], { time: 10.017, info: v1close.sfin.info, packet: v1close.sfin.packet }),
            pkt("client", "server", "green", "ACK", [], { time: 10.018, info: v1close.last.info, packet: v1close.last.packet }),
          ],
        },
      ],
      outro: {
        title: "From Enter to page in about 0.1 s",
        text: "DHCP and ARP got the laptop onto the network, DNS found the server, TCP and TLS built a private connection in two round trips, HTTP fetched the page, and NAT at the router let a private address talk to the internet. Each step has its own lesson if you want the full story.",
        facts: [["Round trips before data", "DNS 1 + TCP 1 + TLS 1"], ["Encrypted", "Everything after the Server Hello"], ["Visible to others", "IPs, SNI, sizes"], ["Next", "Try the second visit"]],
      },
    },
    {
      id: "second-visit",
      name: "Second visit: caches",
      summary: "A minute later you open the site again: the DNS and ARP caches skip lookups, and TLS resumption skips the certificate.",
      kind: "normal",
      steps: [
        {
          title: "Nothing to look up",
          desc: "DHCP lease, ARP cache and DNS cache are all still fresh",
          detail:
            "The laptop still has its DHCP lease, its ARP cache still knows the router’s MAC, and the DNS answer for example.com has a TTL of 3600 s, so the browser already knows 203.0.113.10. Three whole exchanges are skipped and not a single packet is sent before the TCP SYN.",
          facts: [["DHCP", "Lease valid (24 h)"], ["ARP", "Cached"], ["DNS", "Cached until TTL runs out"]],
          quiz: {
            q: "When will the laptop ask DNS about example.com again?",
            options: ["On every page load", "When the cached answer’s TTL (3600 s) runs out", "Never", "Only after a reboot"],
            answer: 1,
            why: "Caches keep an answer only for its TTL. After that the name is looked up again, in case the address changed.",
          },
          events: [note("client", "ARP + DNS CACHE HIT", "green")],
        },
        {
          title: "TCP handshake",
          desc: "Still needed: a new connection",
          detail: "The old connection was closed, so a new TCP handshake is needed. It still costs one round trip.",
          facts: [["To", `${W} : 443`], ["Cost", "1 round trip"], ["Could skip with", "TCP Fast Open or QUIC"]],
          events: [
            pkt("client", "server", "green", "SYN", ["port 443"], { time: 0, info: v2.syn.info, packet: v2.syn.packet }),
            pkt("server", "client", "green", "SYN-ACK", [], { time: 0.017, info: v2.synack.info, packet: v2.synack.packet }),
            pkt("client", "server", "green", "ACK", [], { time: 0.018, info: v2.ack.info, packet: v2.ack.packet }),
          ],
        },
        {
          title: "Resume the TLS session",
          desc: "Show last visit’s ticket instead of a certificate",
          detail:
            "Last time the server sent the browser a session ticket. Now the Client Hello carries that ticket in a pre_shared_key extension. The server accepts it, so there is no certificate to send or check, and the encrypted part of the server’s reply shrinks from about 1250 bytes to about 100. A fresh key exchange still happens so old traffic stays safe.",
          facts: [["Extension", "pre_shared_key (ticket)"], ["Server sends", "No certificate"], ["Encrypted reply", "≈ 96 bytes vs 1250"]],
          quiz: {
            q: "What does the server skip thanks to the ticket?",
            options: ["The key exchange", "Sending and proving its certificate", "The TCP handshake", "Encryption"],
            answer: 1,
            why: "The ticket proves the two sides already authenticated last time, so the certificate and its signature aren’t needed again.",
          },
          events: [
            pkt("client", "server", "teal", "C.HELLO", ["+ session ticket"], { time: 0.019, info: "Client Hello (SNI=example.com, PSK)", packet: v2.ch.packet }),
            pkt("server", "client", "teal", "S.HELLO", ["ticket accepted", "no certificate"], { time: 0.036, info: "Server Hello, Change Cipher Spec, Application Data", packet: v2.sf.packet }),
            pkt("client", "server", "teal", "FINISHED", [], { time: 0.037, info: "Change Cipher Spec, Application Data", packet: v2.cf.packet }),
          ],
        },
        {
          title: "304 Not Modified",
          desc: "The browser cache saves the download",
          detail:
            "The browser still has the page in its own cache, so it asks “send it only if it changed since version abc123” (If-None-Match). Nothing changed, so the server answers 304 Not Modified with no body, and the browser shows its saved copy.",
          facts: [["Request", "GET / + If-None-Match"], ["Answer", "304, no body"], ["Saved", "The whole HTML download"]],
          events: [
            pkt("client", "server", "amber", "GET /", ["if changed"], { time: 0.038, info: `${v2.get.info}  Application Data`, packet: v2.get.packet }),
            pkt("server", "client", "violet", "304", ["not modified"], { time: 0.055, info: `${v2.resp.info}  Application Data`, packet: v2.resp.packet }),
            note("client", "SHOWN FROM CACHE", "green"),
          ],
        },
      ],
      outro: {
        title: "Faster the second time",
        text: "Caches did most of the work: no DHCP, ARP or DNS traffic, a shorter TLS handshake without the certificate, and a 304 instead of the full page. The page appeared in about 55 ms instead of 90.",
        facts: [["Skipped", "DHCP, ARP, DNS"], ["TLS", "Resumed with a ticket"], ["HTTP", "304 Not Modified"], ["Time", "≈ 55 ms"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "The chain",
      items: [["1 DHCP", "Get IP, gateway, DNS"], ["2 ARP", "Gateway IP → MAC"], ["3 DNS", "Name → IP (UDP 53)"], ["4 TCP", "Handshake to 443"], ["5 TLS", "Keys + certificate"], ["6 HTTP", "GET the page"], ["NAT", "Private ↔ public at the router"]],
    },
    {
      title: "Caches that save time",
      items: [["DNS cache", "Until the record’s TTL"], ["ARP cache", "Minutes"], ["TLS session ticket", "Skips the certificate"], ["HTTP cache", "304 Not Modified or no request at all"]],
    },
    {
      title: "Ports",
      items: [["UDP 67/68", "DHCP"], ["UDP 53", "DNS"], ["TCP 443", "HTTPS"], ["UDP 443", "HTTP/3 (QUIC)"]],
    },
  ],
});
