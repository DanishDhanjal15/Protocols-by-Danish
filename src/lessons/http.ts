import { Color, defineLesson, note, PacketEvent, pkt } from "@/lib/lesson";
import { build, LayerSpec, textLayer } from "@/lib/packet";
import { tcp, TcpOpt } from "@/lib/proto";
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
  /** three-way handshake as captured on the client: SYN, SYN-ACK one round trip later, ACK at once */
  const open = (t: number, rtt: number): PacketEvent[] => [
    c(t, "green", "SYN", ["seq=0", `to port ${o.sport}`], { flags: "S" }),
    s(t + rtt, "green", "SYN-ACK", ["seq=0 ack=1"], { flags: "SA" }),
    c(t + rtt + 0.0002, "green", "ACK", ["ack=1", "connected"]),
  ];
  return { c, s, open, next };
}

// ---------------------------------------------------------------- content

const S = ADDR.web;
const RTT = 0.034;
const DATE = "Date: Thu, 19 Nov 2026 09:30:12 GMT";
const UA = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0";

const HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Example Domain</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<h1>Hello from example.com</h1>
<p>This page came to you over plain HTTP/1.1.</p>
</body>
</html>
`;
const CSS = `body { font-family: sans-serif; margin: 2em; }
h1 { color: #1a5fb4; }
`;
const NOT_FOUND = `<!doctype html>
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1><p>No page lives at /old-page.</p></body>
</html>
`;
const len = (s: string) => new TextEncoder().encode(s).length;

const req = (path: string, accept: string, extra: string[] = []) =>
  textLayer({
    id: "http", name: "HTTP", blankLine: true,
    lines: [`GET ${path} HTTP/1.1`, "Host: example.com", UA, `Accept: ${accept}`, "Accept-Language: en-IN,en;q=0.8", "Accept-Encoding: gzip, deflate", "Connection: keep-alive", ...extra],
    notes: {
      0: "Method, path and version. GET means: please send me this resource.",
      1: "Which website. One IP address can host many sites, so this header is required in HTTP/1.1.",
      2: "Which browser is asking.",
      3: "Which formats the browser can handle, in order of preference (q = weight).",
      6: "Keep the TCP connection open after this response. This is the default in HTTP/1.1.",
    },
  });

const resp = (status: string, type: string, body: string, extra: string[] = []) =>
  textLayer({
    id: "http", name: "HTTP", blankLine: true,
    lines: [`HTTP/1.1 ${status}`, DATE, "Server: nginx/1.26.2", `Content-Type: ${type}`, `Content-Length: ${len(body)}`, ...extra],
    body: { text: body, what: type.startsWith("text/html") ? "HTML body" : "Body" },
    notes: {
      0: "Version, status code and reason phrase.",
      3: "What kind of data the body holds, so the browser knows how to show it.",
      4: "Exactly how many bytes of body follow the blank line. That is how the browser knows where this response ends on a kept-alive connection.",
    },
  });

const devs = homeToServer();

export default defineLesson({
  id: "http",
  name: "HTTP/1.1",
  full: "Hypertext Transfer Protocol 1.1",
  group: "web",
  layer: 7,
  difficulty: 1,
  tagline: "The plain-text request and response behind every web page.",
  description:
    "HTTP is how a browser asks a web server for a page and how the server answers. HTTP/1.1 is plain text: a request line, some headers, a blank line, and an optional body. One TCP connection can carry many requests one after another.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP, port 80"],
    ["Format", "Plain text lines ending in CRLF"],
    ["Model", "Request → response"],
    ["Reuse", "Keep-alive connections"],
    ["Defined in", "RFC 9110, RFC 9112"],
  ],
  ports: "80 (HTTP), 443 (HTTPS)",
  rfc: "RFC 9110 / RFC 9112",
  keywords: ["get", "post", "status code", "headers", "keep-alive", "404", "301", "redirect", "content-length", "web"],
  related: ["tcp", "https", "http2", "dns", "proxy"],
  ...devs,
  legend: [
    ["green", "TCP handshake and ACKs"],
    ["amber", "Requests from the browser"],
    ["violet", "Responses from the server"],
    ["blue", "Redirects"],
    ["red", "Errors"],
  ],
  scenarios: [
    (() => {
      const k = conn({ a: "client", b: "server", cport: 52100, sport: 80, cBase: 0x2c1a4e00, sBase: 0x7b0d9100, cl: up(S), sv: down(S) });
      const r1 = req("/", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", ["Upgrade-Insecure-Requests: 1"]);
      const r2 = req("/style.css", "text/css,*/*;q=0.1", ["Referer: http://example.com/"]);
      const p1 = resp("200 OK", "text/html; charset=utf-8", HTML, ["Last-Modified: Mon, 02 Nov 2026 08:00:00 GMT", "Cache-Control: max-age=300", "Connection: keep-alive"]);
      const p2 = resp("200 OK", "text/css", CSS, ["Cache-Control: max-age=86400", "Connection: keep-alive"]);
      const hs = k.open(0, RTT);
      return {
        id: "normal",
        name: "Loading a page and its stylesheet",
        summary: "The browser opens one TCP connection, fetches the HTML, then reuses the same connection for the CSS file.",
        kind: "normal" as const,
        steps: [
          {
            title: "Open a TCP connection",
            desc: "Three-way handshake to port 80",
            detail: "DNS has already turned example.com into 203.0.113.10. Before HTTP can say anything, the browser needs a TCP connection to port 80, the standard port for plain HTTP. That takes one round trip.",
            facts: [["Server", `${S}:80`], ["Browser port", "52100 (temporary)"], ["Cost", "1 round trip (34 ms)"]],
            quiz: {
              q: "Why can't the browser send the GET request in its very first packet?",
              options: ["HTTP needs a TCP connection first", "The server must send a welcome message first", "DNS must run again", "HTTP requests must be encrypted"],
              answer: 0,
              why: "HTTP/1.1 runs on top of TCP. The handshake must finish before any request bytes are sent.",
            },
            events: hs,
          },
          {
            title: "Send the GET request",
            desc: "A request line and headers, in plain text",
            detail: "The browser writes its request as readable text. The first line says GET, the path / and the version. Each header is a Name: value line. A blank line ends the headers; a GET has no body.",
            facts: [["Method", "GET"], ["Path", "/"], ["Ends with", "An empty line (CRLF CRLF)"]],
            quiz: {
              q: "The server hosts 50 websites on one IP address. How does it know which one the browser wants?",
              options: ["From the destination port", "From the Host header", "From the User-Agent header", "It guesses from the path"],
              answer: 1,
              why: "The Host header names the website. It is what lets many sites share a single IP address.",
            },
            events: [k.c(0.0346, "amber", "GET /", ["HTTP/1.1", "Host: example.com"], { data: [r1], info: "GET / HTTP/1.1" })],
          },
          {
            title: "200 OK with the HTML",
            desc: "Status line, headers, blank line, body",
            detail: `The server answers with status 200 OK. Its headers say the body is HTML and exactly ${len(HTML)} bytes long. The page itself follows the blank line as ordinary text. The browser ACKs the segment.`,
            facts: [["Status", "200 OK"], ["Content-Type", "text/html"], ["Content-Length", `${len(HTML)} bytes`]],
            quiz: {
              q: "The connection stays open after this response. How does the browser know the HTML has fully arrived?",
              options: ["The server closes the connection", "It counts bytes until Content-Length is reached", "It waits for </html>", "It waits one second"],
              answer: 1,
              why: "Content-Length tells the browser exactly where the body ends, so the same connection can carry the next response.",
            },
            events: [
              k.s(0.0712, "violet", "200 OK", ["text/html", `${len(HTML)} bytes`], { data: [p1], info: "HTTP/1.1 200 OK  (text/html)" }),
              k.c(0.0714, "green", "ACK", ["got it"]),
            ],
          },
          {
            title: "Read the HTML, ask for CSS",
            desc: "Same connection, second request",
            detail: "While reading the HTML the browser finds <link rel=\"stylesheet\" href=\"/style.css\">. Because the server said keep-alive, it sends the second request on the same TCP connection. No new handshake is needed, which saves a full round trip.",
            facts: [["Path", "/style.css"], ["New handshake?", "No: keep-alive"], ["Referer", "http://example.com/"]],
            quiz: {
              q: "What does the browser send next to fetch /style.css?",
              options: ["A new SYN to port 80", "A GET /style.css on the same connection", "A DNS query for style.css", "Nothing; the CSS was inside the HTML"],
              answer: 1,
              why: "HTTP/1.1 keeps the connection open by default, so the browser reuses it right away.",
            },
            events: [k.c(0.0731, "amber", "GET CSS", ["/style.css", "same connection"], { data: [r2], info: "GET /style.css HTTP/1.1" })],
          },
          {
            title: "200 OK with the stylesheet",
            desc: "One request, one response, in order",
            detail: "The CSS comes back with Content-Type text/css. In HTTP/1.1 responses on one connection come back strictly in the order the requests were sent. Browsers open up to six connections per site to fetch several files at once.",
            facts: [["Status", "200 OK"], ["Content-Type", "text/css"], ["Cache", "max-age=86400 (one day)"]],
            events: [
              k.s(0.1093, "violet", "200 OK", ["text/css", `${len(CSS)} bytes`], { data: [p2], info: "HTTP/1.1 200 OK  (text/css)" }),
              k.c(0.1095, "green", "ACK", ["got it"]),
            ],
          },
          {
            title: "The browser renders",
            desc: "HTML plus CSS becomes a page",
            detail: "With the HTML and its stylesheet in hand, the browser builds the page and paints it on screen. The connection stays idle for a while in case more requests come; the server closes it after its keep-alive timeout.",
            facts: [["Requests", "2"], ["TCP connections", "1"], ["Page ready after", "~110 ms"]],
            events: [note("client", "PAGE RENDERED", "green"), note("server", "KEEP-ALIVE IDLE", "blue")],
          },
        ],
        outro: {
          title: "One connection, two files",
          text: "The browser opened one TCP connection, sent a GET, read a 200 OK with HTML, and reused the same connection for the stylesheet. Every byte was plain text, which is easy to read and also easy for anyone on the path to read, which is why the web moved to HTTPS.",
          facts: [["Round trips", "3 (handshake + 2 requests)"], ["Status codes", "200, 200"], ["Encryption", "None"], ["Total", "~110 ms"]],
        },
      };
    })(),
    (() => {
      const k = conn({ a: "client", b: "server", cport: 52140, sport: 80, cBase: 0x3d2b5f00, sBase: 0x8c1ea200, cl: up(S), sv: down(S) });
      const hs = k.open(0, RTT);
      const r = req("/old-page", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
      const p = resp("404 Not Found", "text/html; charset=utf-8", NOT_FOUND, ["Connection: keep-alive"]);
      return {
        id: "not-found",
        name: "404 Not Found",
        summary: "The browser asks for a page that was deleted; the server says so with status 404.",
        kind: "failure" as const,
        steps: [
          {
            title: "Connect and ask",
            desc: "GET /old-page",
            detail: "A bookmark points to /old-page. The browser connects to port 80 as usual and sends a GET for that path. Nothing about the request looks different.",
            facts: [["Path", "/old-page"], ["Server", `${S}:80`], ["Method", "GET"]],
            events: [...hs, k.c(0.0346, "amber", "GET", ["/old-page"], { data: [r], info: "GET /old-page HTTP/1.1" })],
          },
          {
            title: "404 Not Found",
            desc: "The server has nothing at that path",
            detail: "The server looks for /old-page and finds nothing, so it replies with status 404. A 404 is still a complete, normal HTTP response with headers and a body; the body is the friendly error page you see.",
            facts: [["Status", "404 Not Found"], ["Class", "4xx = the client asked for something wrong"], ["Body", `${len(NOT_FOUND)} bytes of HTML`]],
            quiz: {
              q: "Which status code family means the server itself failed, not the request?",
              options: ["2xx", "3xx", "4xx", "5xx"],
              answer: 3,
              why: "4xx codes blame the request (404 Not Found, 403 Forbidden). 5xx codes mean the server broke (500, 502, 503).",
            },
            events: [
              k.s(0.0712, "red", "404", ["Not Found"], { data: [p], info: "HTTP/1.1 404 Not Found  (text/html)" }),
              k.c(0.0714, "green", "ACK", []),
              note("client", "404 NOT FOUND", "red"),
            ],
          },
        ],
        outro: {
          title: "A clean error",
          text: "HTTP errors travel as ordinary responses. The TCP connection is fine and can be reused; only the status code says something went wrong. The first digit tells you who is to blame.",
          facts: [["Status", "404"], ["Connection", "Still open"], ["Families", "1xx info, 2xx ok, 3xx redirect, 4xx client, 5xx server"]],
        },
      };
    })(),
    (() => {
      const k = conn({ a: "client", b: "server", cport: 52160, sport: 80, cBase: 0x4e3c6000, sBase: 0x9d2fb300, cl: up(S), sv: down(S) });
      const k2 = conn({ a: "client", b: "server", cport: 52162, sport: 443, cBase: 0x5f4d7100, sBase: 0xae40c400, cl: up(S), sv: down(S) });
      const hs = k.open(0, RTT);
      const r = req("/", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", ["Upgrade-Insecure-Requests: 1"]);
      const moved = `<html><head><title>301 Moved Permanently</title></head><body><a href="https://example.com/">Moved here</a></body></html>\n`;
      const p = resp("301 Moved Permanently", "text/html", moved, ["Location: https://example.com/", "Connection: keep-alive"]);
      return {
        id: "redirect",
        name: "301 redirect to HTTPS",
        summary: "Someone types example.com without https://; the server sends the browser to the secure address.",
        kind: "failure" as const,
        steps: [
          {
            title: "Plain HTTP first",
            desc: "Typing a bare name means http://",
            detail: "When you type example.com with no scheme, many browsers try plain http:// on port 80 first. The request goes out unencrypted.",
            facts: [["URL", "http://example.com/"], ["Port", "80"], ["Encrypted", "No"]],
            events: [...hs, k.c(0.0346, "amber", "GET /", ["http://", "port 80"], { data: [r], info: "GET / HTTP/1.1" })],
          },
          {
            title: "301 Moved Permanently",
            desc: "Location: https://example.com/",
            detail: "The server refuses to serve the page over plain HTTP. It replies 301 with a Location header that holds the new address. 301 means permanent, so the browser may remember it and skip the HTTP step next time.",
            facts: [["Status", "301 Moved Permanently"], ["Location", "https://example.com/"], ["Temporary version", "302 / 307"]],
            quiz: {
              q: "What will the browser do after reading the Location header?",
              options: ["Show the 301 page to the user", "Open a new connection to port 443 and use HTTPS", "Resend the same request on port 80", "Ask DNS for a new IP"],
              answer: 1,
              why: "A 3xx with Location tells the browser to go there instead. https:// means TLS on port 443, so it needs a new TCP connection.",
            },
            events: [
              k.s(0.0712, "blue", "301", ["Location:", "https://…"], { data: [p], info: "HTTP/1.1 301 Moved Permanently" }),
              k.c(0.0714, "green", "ACK", []),
            ],
          },
          {
            title: "Follow to HTTPS",
            desc: "New connection to port 443",
            detail: "The browser opens a fresh TCP connection to port 443 and will start a TLS handshake there. That first plain request is a weak spot: an attacker could tamper with it. HSTS fixes this by telling the browser to always use HTTPS for this site from now on.",
            facts: [["New port", "443"], ["Next", "TLS handshake"], ["Fix for the weak spot", "HSTS"]],
            events: [...k2.open(0.072, RTT), note("client", "REDIRECTED TO HTTPS", "blue")],
          },
        ],
        outro: {
          title: "Sent to the secure door",
          text: "A 301 redirect costs a full extra round trip and leaves the first request unprotected. Sites send an HSTS header over HTTPS, and browsers ship a preload list, so the browser goes straight to https:// next time.",
          facts: [["Redirect codes", "301, 302, 303, 307, 308"], ["Header", "Location"], ["Better", "HSTS + preload"]],
        },
      };
    })(),
  ],
  cheatsheet: [
    {
      title: "Methods",
      items: [["GET", "Fetch a resource"], ["POST", "Send data (forms, uploads)"], ["PUT / PATCH", "Replace / change a resource"], ["DELETE", "Remove a resource"], ["HEAD", "Like GET, headers only"]],
    },
    {
      title: "Status codes",
      items: [["200 OK", "Here it is"], ["204 No Content", "Done, nothing to send"], ["301 / 302", "Moved (permanent / temporary)"], ["304 Not Modified", "Your cached copy is still good"], ["404 Not Found", "Nothing at that path"], ["500 / 502 / 503", "Server error / bad gateway / unavailable"]],
    },
    {
      title: "Headers to know",
      items: [["Host", "Which website (required)"], ["Content-Type", "What the body is"], ["Content-Length", "How long the body is"], ["Connection: keep-alive", "Reuse the TCP connection"], ["Location", "Where to go (redirects)"], ["Cache-Control", "How long to keep a copy"]],
    },
  ],
});
