import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, proto, textLayer } from "@/lib/packet";
import { eth, ipv4, tcp, TcpOpt } from "@/lib/proto";
import { ip4 } from "@/lib/bytes";
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

// ---------------------------------------------------------------- SOCKS5 messages (RFC 1928, RFC 1929)

const socks = (summary: string, fields: FieldSpec[]) => proto({ id: "socks", name: "SOCKS", osi: 5, summary: `SOCKS5: ${summary}`, fields });
const ver5: FieldSpec = { name: "Version", u8: 5, value: "5 (SOCKS5)" };

const greeting = socks("Version identifier / method selection message", [
  ver5,
  { name: "Number of methods", u8: 2 },
  { name: "Method", u8: 0x00, value: "0x00 (no authentication)" },
  { name: "Method", u8: 0x02, value: "0x02 (username/password)", note: "RFC 1929 login." },
]);
const methodSel = socks("Method selection: username/password", [ver5, { name: "Chosen method", u8: 0x02, value: "0x02 (username/password)", note: "The server insists on a login. 0xFF would mean none of your methods are acceptable." }]);
const authReq = (user: string, pass: string) => socks("Username/password authentication request", [
  { name: "Sub-negotiation version", u8: 1, value: "1 (RFC 1929)", note: "Version of the login sub-protocol, not of SOCKS." },
  { name: "Username length", u8: user.length },
  { name: "Username", text: user },
  { name: "Password length", u8: pass.length },
  { name: "Password", text: pass, note: "Sent in clear text. Anyone between the laptop and the proxy can read it." },
]);
const authReply = (ok: boolean) => socks(`Authentication ${ok ? "success" : "failure"}`, [
  { name: "Sub-negotiation version", u8: 1 },
  { name: "Status", u8: ok ? 0 : 1, value: ok ? "0 (success)" : "1 (failure)", note: ok ? "Any value other than 0 is a failure." : "Wrong username or password. The server must now close the connection." },
]);
const connectReq = (host: string, port: number) => socks(`Command: CONNECT ${host}:${port}`, [
  ver5,
  { name: "Command", u8: 1, value: "1 (CONNECT)", note: "1 CONNECT, 2 BIND, 3 UDP ASSOCIATE." },
  { name: "Reserved", u8: 0 },
  { name: "Address type", u8: 3, value: "3 (domain name)", note: "1 IPv4, 3 domain name, 4 IPv6. A name lets the proxy do the DNS lookup." },
  { name: "Name length", u8: host.length },
  { name: "Domain name", text: host },
  { name: "Port", u16: port },
]);
const connectReply = (bnd: string, port: number) => socks("Command response: succeeded", [
  ver5,
  { name: "Reply", u8: 0, value: "0 (succeeded)", note: "Other codes: 1 general failure, 2 not allowed, 4 host unreachable, 5 connection refused…" },
  { name: "Reserved", u8: 0 },
  { name: "Address type", u8: 1, value: "1 (IPv4)" },
  { name: "Bound address", bytes: ip4(bnd), value: bnd, note: "The address the proxy uses for the outgoing connection." },
  { name: "Bound port", u16: port },
]);

// ---------------------------------------------------------------- network

const S = ADDR.web;
const SX = "198.51.100.30";
const SX_MAC = "00:16:3e:2b:10:80";
const GW_MAC = "00:00:5e:00:01:1e";
const sxOut = [eth({ src: SX_MAC, dst: GW_MAC }), ipv4({ src: SX, dst: S })];
const sxIn = [eth({ src: GW_MAC, dst: SX_MAC }), ipv4({ src: S, dst: SX, ttl: 58 })];
const RTT = 0.022; // laptop ↔ SOCKS server
const RTT2 = 0.012; // SOCKS server ↔ web server

const devices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: ADDR.laptop, x: 9, y: 62 },
  { id: "router", kind: "router" as const, label: "Home router", sub: ADDR.router, x: 28, y: 62 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 50, y: 40 },
  { id: "socks", kind: "proxy" as const, label: "SOCKS5 server", sub: `${SX}:1080`, x: 72, y: 20 },
  { id: "server", kind: "web" as const, label: "example.com", sub: S, x: 88, y: 68 },
];
const links: [string, string][] = [["client", "router"], ["router", "internet"], ["internet", "socks"], ["internet", "server"]];

const GET = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["GET / HTTP/1.1", "Host: example.com", "User-Agent: curl/8.9.1", "Accept: */*"] });
const HTML = "<!doctype html><html><body><h1>Hello through SOCKS</h1></body></html>\n";
const OK = textLayer({ id: "http", name: "HTTP", blankLine: true, lines: ["HTTP/1.1 200 OK", "Content-Type: text/html", `Content-Length: ${new TextEncoder().encode(HTML).length}`], body: { text: HTML, what: "HTML body" } });

export default defineLesson({
  id: "socks",
  name: "SOCKS5",
  full: "SOCKS Protocol Version 5",
  group: "vpn",
  layer: 5,
  difficulty: 2,
  tagline: "A tiny binary handshake, then a relay for any TCP connection.",
  description:
    "SOCKS5 is a general-purpose proxy. The client connects to the SOCKS server, picks a login method, logs in, and asks it to connect to a host and port. After a one-line reply, the server simply copies bytes both ways, so it works for any TCP protocol, not just HTTP.",
  facts: [
    ["Layer", "Session (Layer 5)"],
    ["Transport", "TCP, port 1080"],
    ["Login", "None, username/password, GSSAPI"],
    ["Targets", "IPv4, IPv6 or a domain name"],
    ["Encryption", "None of its own"],
    ["Defined in", "RFC 1928, RFC 1929"],
  ],
  ports: "1080",
  rfc: "RFC 1928, RFC 1929",
  keywords: ["socks", "socks5", "proxy", "1080", "username password", "connect", "ssh -D", "tor", "remote dns"],
  related: ["proxy", "tcp", "http", "dns"],
  devices,
  links,
  legend: [
    ["green", "TCP handshakes and ACKs"],
    ["blue", "SOCKS negotiation"],
    ["teal", "Login"],
    ["amber", "Data from the laptop"],
    ["violet", "Data from the website"],
  ],
  scenarios: [
    (() => {
      const a = conn({ a: "client", b: "socks", cport: 52710, sport: 1080, cBase: 0x0a0b0c00, sBase: 0x1a1b1c00, cl: up(SX), sv: down(SX) });
      const b = conn({ a: "socks", b: "server", cport: 40188, sport: 80, cBase: 0x2a2b2c00, sBase: 0x3a3b3c00, cl: sxOut, sv: sxIn });
      return {
        id: "normal",
        name: "Log in and connect by name",
        summary: "curl --socks5-hostname logs in to a SOCKS5 server and fetches example.com through it.",
        kind: "normal" as const,
        steps: [
          {
            title: "Greeting",
            desc: "Version 5, two login methods offered",
            detail: "After connecting to port 1080, the client sends three to four bytes: version 5, how many login methods it knows, and the list. Here it offers 0x00 (no login) and 0x02 (username and password).",
            facts: [["Bytes", "05 02 00 02"], ["Methods", "No auth, username/password"], ["Port", "1080"]],
            events: [...a.open(0, RTT), a.c(0.0223, "blue", "HELLO", ["ver 5", "methods 00, 02"], { data: [greeting], info: "Version: 5, Methods: no auth, username/password" })],
          },
          {
            title: "Method selection",
            desc: "The server picks username/password",
            detail: "The server answers with just two bytes: version 5 and the method it chose. This server requires a login, so it picks 0x02.",
            facts: [["Bytes", "05 02"], ["Chosen", "0x02 username/password"], ["0xFF would mean", "No acceptable method"]],
            quiz: {
              q: "What must the client send next?",
              options: ["The CONNECT request", "Its username and password", "A TLS Client Hello", "Nothing; the tunnel is open"],
              answer: 1,
              why: "Method 0x02 means a username/password exchange (RFC 1929) must happen before any command.",
            },
            events: [a.s(0.0445, "blue", "METHOD", ["05 02", "login please"], { data: [methodSel], info: "Version: 5, Accepted method: username/password" })],
          },
          {
            title: "Username and password",
            desc: "RFC 1929 login, in clear text",
            detail: "The client sends a version byte of 1, then the username and password, each with a one-byte length in front. The server checks them and replies 01 00: success. Note that the password is not encrypted at all.",
            facts: [["Username", "danish"], ["Reply", "01 00 = success"], ["Encrypted", "No"]],
            quiz: {
              q: "The username is \"danish\". What is the byte right before it?",
              options: ["0x00", "0x05", "0x06", "0x01"],
              answer: 2,
              why: "Each string has a one-byte length prefix, and \"danish\" is 6 bytes long.",
            },
            events: [
              a.c(0.0447, "teal", "LOGIN", ["danish / ******"], { data: [authReq("danish", "s3cret")], info: "Username/password authentication: danish" }),
              a.s(0.0668, "teal", "OK", ["01 00", "success"], { data: [authReply(true)], info: "Authentication: success" }),
            ],
          },
          {
            title: "CONNECT example.com:80",
            desc: "By name, so the proxy does the DNS",
            detail: "The client asks the server to CONNECT to example.com port 80, giving a domain name (address type 3) instead of an IP. The SOCKS server looks up the name itself and opens its own TCP connection. The reply says success and which address and port the server is using.",
            facts: [["Command", "1 CONNECT"], ["Address type", "3 (domain name)"], ["Bound", `${SX}:40188`]],
            quiz: {
              q: "Why might you want the proxy, not your laptop, to resolve example.com?",
              options: ["It is faster to type", "So your local network and DNS server never see which site you visit", "SOCKS cannot carry IP addresses", "To get IPv6"],
              answer: 1,
              why: "With a domain name in the request, the DNS lookup happens at the proxy, so no DNS query leaks from the laptop.",
            },
            events: [
              a.c(0.067, "blue", "CONNECT", ["example.com:80", "by name"], { data: [connectReq("example.com", 80)], info: "Command: CONNECT, Remote: example.com:80" }),
              ...b.open(0.0782, RTT2),
              a.s(0.1125, "green", "SUCCESS", ["05 00", `bound ${SX}:40188`], { data: [connectReply(SX, 40188)], info: "Command response: succeeded" }),
            ],
          },
          {
            title: "Data flows",
            desc: "The SOCKS server just copies bytes",
            detail: "From now on SOCKS adds nothing. The laptop sends a normal HTTP request into the connection; the SOCKS server copies it to example.com and copies the reply back. It would work the same for SSH, SMTP or any TCP protocol.",
            facts: [["Overhead", "None after the handshake"], ["Works for", "Any TCP protocol"], ["Website sees", `${SX} as the client`]],
            events: [
              a.c(0.1127, "amber", "GET", ["GET /", "into the tunnel"], { data: [GET], info: "GET / HTTP/1.1" }),
              b.c(0.1238, "amber", "GET", ["copied"], { data: [GET], info: "GET / HTTP/1.1" }),
              b.s(0.1359, "violet", "200 OK", ["to SOCKS"], { data: [OK], info: "HTTP/1.1 200 OK (text/html)" }),
              a.s(0.1471, "violet", "200 OK", ["copied back"], { data: [OK], info: "HTTP/1.1 200 OK (text/html)" }),
              a.c(0.1473, "green", "ACK", []),
            ],
          },
        ],
        outro: {
          title: "A dumb pipe with a smart start",
          text: "Six small binary messages (greeting, method choice, login, login result, connect, reply) set up the relay. After that SOCKS is invisible. It hides your address from the website, but adds no encryption, so put TLS inside it or run it over SSH (ssh -D).",
          facts: [["Handshake", "3 round trips"], ["Login", "RFC 1929, clear text"], ["Common uses", "ssh -D, Tor, browser proxy settings"]],
        },
      };
    })(),
    (() => {
      const a = conn({ a: "client", b: "socks", cport: 52730, sport: 1080, cBase: 0x4a4b4c00, sBase: 0x5a5b5c00, cl: up(SX), sv: down(SX) });
      return {
        id: "bad-login",
        name: "Wrong password",
        summary: "The login fails and the SOCKS server closes the connection.",
        kind: "failure" as const,
        steps: [
          {
            title: "Greeting and method",
            desc: "Same start as before",
            detail: "The client connects, offers no-auth and username/password, and the server picks username/password.",
            facts: [["Client offers", "00, 02"], ["Server picks", "02"], ["Next", "Login"]],
            events: [
              ...a.open(0, RTT),
              a.c(0.0223, "blue", "HELLO", ["ver 5", "methods 00, 02"], { data: [greeting], info: "Version: 5, Methods: no auth, username/password" }),
              a.s(0.0445, "blue", "METHOD", ["05 02"], { data: [methodSel], info: "Version: 5, Accepted method: username/password" }),
            ],
          },
          {
            title: "Wrong password",
            desc: "Status 1: failure",
            detail: "This time the password is mistyped. The server replies 01 01. RFC 1929 says that after a failure the server must close the connection, so it sends FIN straight away. curl reports that the SOCKS5 login failed.",
            facts: [["Reply", "01 01 = failure"], ["Then", "Server closes (FIN)"], ["curl says", "User was rejected by the SOCKS5 server"]],
            quiz: {
              q: "Can the client simply try another password on the same connection?",
              options: ["Yes, up to three times", "No, the server must close the connection after a failure", "Yes, by sending the greeting again", "Only with method 0x00"],
              answer: 1,
              why: "RFC 1929 requires the server to close the connection after a failed login. The client has to reconnect and start over.",
            },
            events: [
              a.c(0.0447, "teal", "LOGIN", ["danish / ******"], { data: [authReq("danish", "secret")], info: "Username/password authentication: danish" }),
              a.s(0.0668, "red", "FAIL", ["01 01", "rejected"], { data: [authReply(false)], info: "Authentication: failure" }),
              a.s(0.0669, "slate", "FIN", ["closing"], { flags: "FA", parallel: true }),
              a.c(0.067, "slate", "FIN", [], { flags: "FA" }),
              a.s(0.0891, "green", "ACK", []),
              note("client", "SOCKS LOGIN REJECTED", "red"),
            ],
          },
        ],
        outro: {
          title: "Login failed, connection closed",
          text: "A failed RFC 1929 login ends the connection; no CONNECT is ever attempted. Because the password crossed the internet in clear text, a wrong one and a right one are equally visible to an eavesdropper.",
          facts: [["Failure reply", "01 01"], ["Then", "TCP close"], ["Lesson", "Wrap SOCKS in SSH or TLS"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "Methods",
      items: [["0x00", "No authentication"], ["0x01", "GSSAPI"], ["0x02", "Username/password"], ["0xFF", "No acceptable method"]],
    },
    {
      title: "Commands and address types",
      items: [["CMD 1", "CONNECT"], ["CMD 2", "BIND (incoming)"], ["CMD 3", "UDP ASSOCIATE"], ["ATYP 1 / 3 / 4", "IPv4 / domain name / IPv6"]],
    },
    {
      title: "Reply codes",
      items: [["0", "Succeeded"], ["1", "General failure"], ["2", "Not allowed by rules"], ["4", "Host unreachable"], ["5", "Connection refused"]],
    },
  ],
});
