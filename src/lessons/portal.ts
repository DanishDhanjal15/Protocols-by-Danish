import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, textLayer } from "@/lib/packet";
import { BROADCAST_MAC, dhcp, dhcpOpt, eth, ext, hsMsg, ipv4, tcp, TcpOpt, tls, udp, vec } from "@/lib/proto";
import { text } from "@/lib/bytes";
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
    c(t + rtt + 0.0002, "green", "ACK", ["ack=1", "connected"]),
  ];
  return { c, s, open, next };
}

// ---------------------------------------------------------------- TLS 1.3 hellos (for the HTTPS what-if)

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
      ext(0, "server_name", [vec("Server name list", 2, [{ name: "Name type", u8: 0, value: "host_name (0)" }, vec("Host name", 2, [{ name: "Name", text: host }], host)])], host, "The browser wants example.com and will accept only a certificate for that name."),
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

// ---------------------------------------------------------------- network

const LAPTOP = "10.20.0.37";
const GW = "10.20.0.1";
const PORTAL = "10.20.0.2";
const CHECK = "203.0.113.80"; // connectivity-check server (documentation address)
const SITE = ADDR.web;
const GW_MAC = "00:0c:29:4d:20:01";
const PORTAL_MAC = "00:0c:29:4d:20:02";
const LMAC = ADDR.laptopMac;
const API = "https://portal.hotel.example/api/captive";
const toGw = (dst: string) => [eth({ src: LMAC, dst: GW_MAC }), ipv4({ src: LAPTOP, dst })];
const fromGw = (src: string, ttl = 64) => [eth({ src: GW_MAC, dst: LMAC }), ipv4({ src, dst: LAPTOP, ttl })];
const toPortal = [eth({ src: LMAC, dst: PORTAL_MAC }), ipv4({ src: LAPTOP, dst: PORTAL })];
const fromPortal = [eth({ src: PORTAL_MAC, dst: LMAC }), ipv4({ src: PORTAL, dst: LAPTOP })];

const devices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: LAPTOP, x: 9, y: 62 },
  { id: "gw", kind: "router" as const, label: "Hotel gateway", sub: GW, x: 33, y: 62 },
  { id: "portal", kind: "web" as const, label: "Login portal", sub: PORTAL, x: 33, y: 20 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 60, y: 45 },
  { id: "check", kind: "web" as const, label: "Connectivity check", sub: CHECK, x: 88, y: 25 },
  { id: "site", kind: "web" as const, label: "example.com", sub: SITE, x: 88, y: 72 },
];
const links: [string, string][] = [["client", "gw"], ["gw", "portal"], ["gw", "internet"], ["internet", "check"], ["internet", "site"]];

// ---------------------------------------------------------------- content

const XID = 0x5a17c0de;
const opt114: ReturnType<typeof dhcpOpt.raw> = dhcpOpt.raw(114, "Captive-Portal (RFC 8910)", text(API), API, "Tells the device up front: this network has a captive portal, and here is its API (RFC 8908).");
const dhcpPkt = (type: number, fromClient: boolean, extra: ReturnType<typeof dhcpOpt.raw>[]) =>
  build(
    eth({ src: fromClient ? LMAC : GW_MAC, dst: fromClient ? BROADCAST_MAC : LMAC }),
    ipv4({ src: fromClient ? "0.0.0.0" : GW, dst: fromClient ? "255.255.255.255" : LAPTOP, ttl: fromClient ? 64 : 64 }),
    udp({ sport: fromClient ? 68 : 67, dport: fromClient ? 67 : 68 }),
    dhcp({ op: fromClient ? 1 : 2, xid: XID, chaddr: LMAC, yiaddr: fromClient ? undefined : LAPTOP, siaddr: fromClient ? undefined : GW, broadcast: false, options: [dhcpOpt.msgType(type), ...extra] }),
  );
const offerOpts = [dhcpOpt.serverId(GW), dhcpOpt.lease(14400), dhcpOpt.subnet("255.255.255.0"), dhcpOpt.router(GW), dhcpOpt.dns(GW), opt114];

const PROBE_HOST = "connectivitycheck.gstatic.com";
const probe = () => textLayer({
  id: "http", name: "HTTP", blankLine: true,
  lines: ["GET /generate_204 HTTP/1.1", `Host: ${PROBE_HOST}`, "User-Agent: Dalvik/2.1.0 (Linux; U; Android 15)", "Connection: Keep-Alive", "Accept-Encoding: gzip"],
  notes: { 0: "A page whose only correct answer is 204 No Content. Anything else means something is in the way." },
});
const LOGIN = `<!doctype html><html><head><title>Hotel Wi-Fi</title></head><body>
<h1>Welcome to Hotel Example</h1>
<form method="post" action="/accept">
Room <input name="room"> Last name <input name="last_name">
<label><input type="checkbox" name="accept_terms"> I accept the terms</label>
<button>Connect</button>
</form></body></html>
`;
const FORM = "room=412&last_name=Guest&accept_terms=on";
const blen = (s: string) => new TextEncoder().encode(s).length;
const ONLINE = "<!doctype html><html><body><h1>You are online. Enjoy your stay!</h1></body></html>\n";

export default defineLesson({
  id: "portal",
  name: "Captive portal",
  full: "Captive portal detection and login (hotel Wi-Fi)",
  group: "web",
  layer: 7,
  difficulty: 2,
  tagline: "Why hotel Wi-Fi pops up a login page before the internet works.",
  description:
    "On hotel, airport and café Wi-Fi you get an address straight away but no internet. The network hijacks your plain HTTP requests and sends you to a login page. Phones and laptops detect this with a tiny probe request and open the page for you.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Detection", "Plain HTTP probe, expects 204"],
    ["Trap", "302 redirect to the portal"],
    ["Announcement", "DHCP option 114 (RFC 8910)"],
    ["API", "RFC 8908 captive portal API"],
    ["Breaks", "HTTPS (certificate errors)"],
  ],
  ports: "67/68 (DHCP), 80 (probe), 443 (portal API)",
  rfc: "RFC 8910, RFC 8908, RFC 8952",
  keywords: ["captive portal", "hotel wifi", "generate_204", "204 no content", "302", "login page", "dhcp option 114", "hotspot", "connectivity check"],
  related: ["dhcp", "http", "https", "dns"],
  devices,
  links,
  legend: [
    ["blue", "DHCP and probes"],
    ["amber", "Requests from the laptop"],
    ["violet", "Portal pages"],
    ["green", "Success, TCP ACKs"],
    ["red", "Hijacked or blocked"],
  ],
  scenarios: [
    (() => {
      // probe connection is answered by the gateway, pretending to be the check server
      const p1 = conn({ a: "client", b: "gw", cport: 41500, sport: 80, cBase: 0x1c000000, sBase: 0x2c000000, cl: toGw(CHECK), sv: fromGw(CHECK) });
      const lp = conn({ a: "client", b: "portal", cport: 41502, sport: 80, cBase: 0x3c000000, sBase: 0x4c000000, cl: toPortal, sv: fromPortal });
      const p2 = conn({ a: "client", b: "check", cport: 41510, sport: 80, cBase: 0x5c000000, sBase: 0x6c000000, cl: toGw(CHECK), sv: fromGw(CHECK, 56) });
      const r302 = textLayer({
        id: "http", name: "HTTP", blankLine: true,
        lines: ["HTTP/1.1 302 Found", "Location: http://portal.hotel.example/login?url=http%3A%2F%2Fconnectivitycheck.gstatic.com%2Fgenerate_204", "Cache-Control: no-store", "Content-Length: 0", "Connection: close"],
        notes: { 0: "Not 204, so the phone knows it is trapped.", 1: "Where the login page is. Sent by the gateway, not by the real check server." },
      });
      const loginReq = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["GET /login?url=http%3A%2F%2Fconnectivitycheck.gstatic.com%2Fgenerate_204 HTTP/1.1", "Host: portal.hotel.example", "User-Agent: Mozilla/5.0 (Linux; Android 15) CaptivePortalLogin"] });
      const loginResp = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["HTTP/1.1 200 OK", "Content-Type: text/html; charset=utf-8", `Content-Length: ${blen(LOGIN)}`, "Cache-Control: no-store"], body: { text: LOGIN, what: "Login page" } });
      const post = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["POST /accept HTTP/1.1", "Host: portal.hotel.example", "Content-Type: application/x-www-form-urlencoded", `Content-Length: ${blen(FORM)}`], body: { text: FORM, what: "Form data" }, notes: { 0: "POST: sending data, here the filled-in form." } });
      const postResp = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["HTTP/1.1 200 OK", "Content-Type: text/html", `Content-Length: ${blen(ONLINE)}`], body: { text: ONLINE } });
      const r204 = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["HTTP/1.1 204 No Content", "Date: Thu, 19 Nov 2026 21:04:33 GMT", "Content-Length: 0"], notes: { 0: "The expected answer: the real check server reached, nothing in the way." } });
      return {
        id: "normal",
        name: "Checking in to hotel Wi-Fi",
        summary: "The phone joins the Wi-Fi, notices it is trapped, shows the login page, and gets online after accepting the terms.",
        kind: "normal" as const,
        steps: [
          {
            title: "Get an address",
            desc: "DHCP, with option 114",
            detail: "The laptop joins the hotel Wi-Fi and runs DHCP as usual: Discover, Offer, Request, Ack. It gets 10.20.0.37 at once. Modern networks also include option 114 (RFC 8910), which says \"there is a captive portal here\" and gives the URL of its API.",
            facts: [["Address", LAPTOP], ["Gateway, DNS", GW], ["Option 114", API]],
            quiz: {
              q: "The laptop has an IP address and a gateway. Can it reach the internet now?",
              options: ["Yes, DHCP finished", "Not yet: the gateway blocks unknown devices until they log in", "Only for DNS over TCP", "Only on IPv6"],
              answer: 1,
              why: "A captive network hands out addresses freely but only forwards traffic for devices that passed the portal.",
            },
            events: [
              pkt("client", "gw", "blue", "DISCOVER", ["anyone?"], { time: 0, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: dhcpPkt(1, true, [dhcpOpt.paramList(1, 3, 6, 15, 114)]) }),
              pkt("gw", "client", "blue", "OFFER", [LAPTOP, "+ option 114"], { time: 0.0021, info: `DHCP Offer - Transaction ID 0x${XID.toString(16)}`, packet: dhcpPkt(2, false, offerOpts) }),
              pkt("client", "gw", "blue", "REQUEST", [LAPTOP], { time: 0.0025, info: `DHCP Request - Transaction ID 0x${XID.toString(16)}`, packet: dhcpPkt(3, true, [dhcpOpt.requestedIp(LAPTOP), dhcpOpt.serverId(GW), dhcpOpt.paramList(1, 3, 6, 15, 114)]) }),
              pkt("gw", "client", "blue", "ACK", [LAPTOP, "+ option 114"], { time: 0.0046, info: `DHCP ACK - Transaction ID 0x${XID.toString(16)}`, packet: dhcpPkt(5, false, offerOpts) }),
            ],
          },
          {
            title: "The probe",
            desc: "GET /generate_204 over plain HTTP",
            detail: "Right after joining, the operating system checks whether the internet really works. It fetches a known URL that should answer 204 No Content with an empty body. (Option 114's API could tell it directly; many devices still use the probe, and both are shown here.) DNS for the check host has already answered 203.0.113.80.",
            facts: [["URL", `http://${PROBE_HOST}/generate_204`], ["Expected", "204 No Content"], ["Others", "Apple: captive.apple.com, Windows: msftconnecttest.com"]],
            events: [...p1.open(1.0, 0.0012), p1.c(1.0015, "blue", "PROBE", ["GET /generate_204"], { data: [probe()], info: "GET /generate_204 HTTP/1.1" })],
          },
          {
            title: "Hijacked: 302",
            desc: "The gateway answers instead",
            detail: "The gateway sees an HTTP request from a device that has not logged in. It does not forward it. It answers itself, faking the check server's IP address, with 302 Found and a Location pointing at the login page. The answer is not 204, so the OS knows it is behind a captive portal and opens a login window.",
            facts: [["Answered by", "The hotel gateway"], ["Source IP shown", `${CHECK} (faked)`], ["OS reaction", "Pops up the login window"]],
            quiz: {
              q: "Why does the check use plain http:// and not https://?",
              options: ["HTTPS is slower", "A gateway can rewrite plain HTTP, but faking an HTTPS answer causes a certificate error instead of a clean redirect", "HTTPS needs a login", "Port 443 is blocked everywhere"],
              answer: 1,
              why: "The probe wants to be redirected so it can find the portal. With HTTPS the gateway cannot produce a valid certificate, so the redirect would fail.",
            },
            events: [p1.s(1.0027, "red", "302", ["to the portal"], { data: [r302], info: "HTTP/1.1 302 Found" }), note("client", "CAPTIVE PORTAL DETECTED", "amber")],
          },
          {
            title: "The login page",
            desc: "Served by the portal on the hotel LAN",
            detail: "The login window follows the Location URL to the portal server, which is on the hotel's own network and reachable without logging in. It returns a small HTML form asking for a room number, last name and agreement to the terms.",
            facts: [["Portal", `${PORTAL}:80`], ["Reachable before login", "Yes (allow-listed)"], ["Form fields", "room, last_name, accept_terms"]],
            events: [
              ...lp.open(1.2, 0.0008),
              lp.c(1.2011, "amber", "GET", ["/login"], { data: [loginReq], info: "GET /login HTTP/1.1" }),
              lp.s(1.2034, "violet", "200 OK", ["login form"], { data: [loginResp], info: "HTTP/1.1 200 OK (text/html)" }),
            ],
          },
          {
            title: "Accept the terms",
            desc: "POST /accept",
            detail: "The guest fills in the form and taps Connect. The browser POSTs the form fields. The portal checks the room and last name, then tells the gateway to let this laptop's MAC address through. That one change is what opens the internet.",
            facts: [["Method", "POST"], ["Body", FORM], ["Gateway rule", `Allow ${LMAC}`]],
            events: [
              lp.c(24.3, "amber", "POST", ["room=412", "accept_terms=on"], { data: [post], info: "POST /accept HTTP/1.1 (application/x-www-form-urlencoded)" }),
              lp.s(24.31, "violet", "200 OK", ["you are online"], { data: [postResp], info: "HTTP/1.1 200 OK (text/html)" }),
              note("gw", `ALLOW ${LMAC}`, "green"),
            ],
          },
          {
            title: "Probe again: 204",
            desc: "This time the real server answers",
            detail: "The OS repeats the probe. Now the gateway forwards it, and the real check server answers 204 No Content with an empty body. The OS closes the login window and marks the network as connected.",
            facts: [["Answer", "204 No Content"], ["From", `The real ${CHECK}`], ["Status", "Online"]],
            quiz: {
              q: "How can you tell from the packet that this 204 really came from the internet?",
              options: ["Its status is 204", "Its TTL is lower: it crossed several routers", "It is bigger", "You can't"],
              answer: 1,
              why: "The gateway's fake answers left with TTL 64. This one arrives with TTL 56, having crossed routers on the internet. The 204 itself is the main proof too.",
            },
            events: [
              ...p2.open(24.5, 0.03),
              p2.c(24.5303, "blue", "PROBE", ["GET /generate_204"], { data: [probe()], info: "GET /generate_204 HTTP/1.1" }),
              p2.s(24.5605, "green", "204", ["No Content"], { data: [r204], info: "HTTP/1.1 204 No Content" }),
              note("client", "CONNECTED", "green"),
            ],
          },
        ],
        outro: {
          title: "Checked in",
          text: "DHCP gave an address, a plain HTTP probe was hijacked with a 302, the OS showed the portal, a POST accepted the terms, and the gateway allow-listed the laptop's MAC. The second probe got the real 204. RFC 8910 and RFC 8908 let devices skip the guessing and ask the network directly.",
          facts: [["Detection", "Probe ≠ 204"], ["Unlock key", "MAC address on the allow list"], ["Modern way", "Option 114 + portal API"]],
        },
      };
    })(),
    (() => {
      const k = conn({ a: "client", b: "gw", cport: 41600, sport: 443, cBase: 0x7c000000, sBase: 0x8c000000, cl: toGw(SITE), sv: fromGw(SITE) });
      return {
        id: "https-trap",
        name: "An HTTPS site before logging in",
        summary: "The guest opens https://example.com before logging in. The gateway cannot redirect it cleanly and the browser shows a certificate warning.",
        kind: "failure" as const,
        steps: [
          {
            title: "Straight to HTTPS",
            desc: "The gateway grabs the connection",
            detail: "Before the login window appears, the guest opens a bookmark to https://example.com. The gateway intercepts the TCP connection to port 443 and answers it itself, as it did for the probe.",
            facts: [["Target", `${SITE}:443`], ["Answered by", "The gateway"], ["Logged in?", "No"]],
            events: [...k.open(0, 0.0012), k.c(0.0015, "amber", "HELLO", ["SNI example.com"], { data: [clientHello("example.com", 9600)], info: "Client Hello (SNI=example.com)" })],
          },
          {
            title: "Wrong certificate",
            desc: "The gateway can only show its own",
            detail: "To redirect, the gateway would have to speak TLS as example.com. It has no certificate for that name, so it sends its own certificate for portal.hotel.example. The browser sees the name does not match and stops with a warning. The 302 inside never gets read.",
            facts: [["Certificate for", "portal.hotel.example"], ["Wanted", "example.com"], ["Browser shows", "NET::ERR_CERT_COMMON_NAME_INVALID"]],
            quiz: {
              q: "Should the guest click \"proceed anyway\"?",
              options: ["Yes, it is just the hotel", "No; the browser cannot tell a harmless portal from an attacker. Let the OS open the portal instead", "Yes, if the padlock is green", "Only on Wi-Fi"],
              answer: 1,
              why: "This is exactly what a man-in-the-middle attack looks like. The safe path is to open any plain http:// page or let the OS detect the portal.",
            },
            events: [
              k.s(0.0028, "red", "WRONG CERT", ["portal.hotel.example"], {
                info: "Server Hello, Change Cipher Spec, Application Data",
                data: [tls({ records: [
                  { type: "handshake", fields: [serverHello(9600)] },
                  { type: "ccs", fields: [{ name: "Change cipher spec", u8: 1 }] },
                  { type: "appdata", encrypted: 1060, what: "EncryptedExtensions, Certificate, CertificateVerify, Finished (encrypted)", note: "Encrypted: a valid certificate, but for portal.hotel.example, not example.com." },
                ] })],
              }),
              k.c(0.0042, "red", "ALERT", ["bad_certificate"], { data: [tls({ records: [{ type: "appdata", encrypted: 19, what: "Alert: bad_certificate (encrypted)" }] })], info: "Application Data (Alert)" }),
              k.c(0.0043, "slate", "RST", [], { flags: "RA", info: "41600 → 443 [RST, ACK]" }),
              note("client", "CERTIFICATE WARNING", "red"),
            ],
          },
          {
            title: "Why probes use HTTP",
            desc: "Only plain HTTP can be redirected cleanly",
            detail: "This failure is the reason operating systems probe with plain http:// URLs. A captive network can rewrite an HTTP answer into a working 302, but it can never fake an HTTPS answer without a certificate error. RFC 8910 and RFC 8908 fix this properly: the network announces its portal, so nothing needs hijacking.",
            facts: [["HTTP probe", "Redirect works"], ["HTTPS", "Certificate error, by design"], ["Proper fix", "DHCP option 114 + portal API"]],
            events: [note("client", "USE THE OS LOGIN WINDOW", "blue")],
          },
        ],
        outro: {
          title: "HTTPS refuses to be hijacked",
          text: "TLS is designed so nobody in the middle can answer for a site. That protects you from attackers, and it also stops captive portals from redirecting HTTPS pages. Plain HTTP probes and the newer announced-portal standards solve this without weakening TLS.",
          facts: [["Error", "Name mismatch"], ["Not a bug", "TLS working as designed"], ["Standards", "RFC 8908, 8910, 8952"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "Probe URLs",
      items: [["Android", "connectivitycheck.gstatic.com/generate_204 → 204"], ["Apple", "captive.apple.com/hotspot-detect.html → \"Success\""], ["Windows", "www.msftconnecttest.com/connecttest.txt → text"], ["Firefox", "detectportal.firefox.com/canonical.html"]],
    },
    {
      title: "Status codes in play",
      items: [["204 No Content", "Online, nothing in the way"], ["302 Found", "Redirected to the portal"], ["511 Network Authentication Required", "The standard code for portals (RFC 6585)"]],
    },
    {
      title: "Standards",
      items: [["RFC 8910", "DHCP option 114 / RA option 37: portal URI"], ["RFC 8908", "Captive portal API (JSON over HTTPS)"], ["RFC 8952", "Captive portal architecture"]],
    },
  ],
});
