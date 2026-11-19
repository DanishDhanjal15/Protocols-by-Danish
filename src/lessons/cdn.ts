import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, LayerSpec, textLayer } from "@/lib/packet";
import { dns, eth, ipv4, tcp, udp } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

const ANY = "203.0.113.80"; // anycast address announced by every PoP
const BOM = "198.51.100.21"; // Mumbai edge's own (unicast) address for origin fetches
const ORIGIN = ADDR.web;
const BOM_MAC = "00:25:90:4b:00:21";
const BOM_GW = "00:25:90:4b:ff:01";
const PATH = "/img/hero.jpg";

const len = (s: LayerSpec) => build(s).bytes.length;

const REQ = [`GET ${PATH} HTTP/1.1`, "Host: www.example.com", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Accept: image/avif,image/webp,*/*"];
const req = () => textLayer({ id: "http", name: "HTTP", lines: REQ, blankLine: true });
const REQ_LEN = len(req());

const ORIGIN_REQ = [`GET ${PATH} HTTP/1.1`, "Host: www.example.com", "Via: 1.1 cache-bom-04", "X-Forwarded-For: 198.51.100.7", "Accept-Encoding: gzip"];
const originReq = () => textLayer({ id: "http", name: "HTTP", lines: ORIGIN_REQ, blankLine: true, notes: { 2: "The edge says who it is.", 3: "The real visitor's public address, for the origin's logs." } });
const OREQ_LEN = len(originReq());

const ORIGIN_RESP = [
  "HTTP/1.1 200 OK", "Content-Type: image/jpeg", "Content-Length: 84211", "Cache-Control: public, max-age=86400",
  "ETag: \"5e1f-hero\"", "Last-Modified: Mon, 16 Nov 2026 08:00:00 GMT",
];
const originResp = () =>
  textLayer({
    id: "http", name: "HTTP", lines: ORIGIN_RESP, blankLine: true,
    notes: { 3: "public: shared caches like a CDN may store it. max-age=86400: it stays fresh for one day." , 4: "A fingerprint of this version, used later to ask “has it changed?”." },
    body: { opaque: 1100, what: "First part of the JPEG" },
  });

const edgeResp = (hit: boolean, age: number, pop = "bom-04") =>
  textLayer({
    id: "http", name: "HTTP", body: { opaque: 1100, what: "First part of the JPEG" }, blankLine: true,
    lines: ["HTTP/1.1 200 OK", "Content-Type: image/jpeg", "Content-Length: 84211", "Cache-Control: public, max-age=86400", `Age: ${age}`, `X-Cache: ${hit ? "HIT" : "MISS"}`, `X-Served-By: cache-${pop}`],
    notes: {
      4: age ? `The copy has been sitting in the edge cache for ${age} seconds.` : "0: fresh from the origin a moment ago.",
      5: hit ? "HIT: the edge had it and answered without asking the origin." : "MISS: the edge did not have it and fetched it from the origin first.",
      6: "Which cache server answered (a CDN-specific header).",
    },
  });


const t = (n: number) => Number(n.toFixed(4));

// laptop ↔ anycast edge, captured on the laptop
const toEdge = (sport: number, seq: number, ack: number, flags: string, ...rest: LayerSpec[]) =>
  build(...up(ANY), tcp({ sport, dport: 80, seq, ack, flags, win: 502, seqBase: 0x5d10a000, ackBase: 0x77e04000, opts: flags === "S" ? [{ mss: 1460 }, "nop", { ws: 7 }, "sackOk" as const] : undefined }), ...rest);
const fromEdge = (sport: number, seq: number, ack: number, flags: string, ...rest: LayerSpec[]) =>
  build(...down(ANY, { ttl: 60 }), tcp({ sport: 80, dport: sport, seq, ack, flags, win: 509, seqBase: 0x77e04000, ackBase: 0x5d10a000, opts: flags === "SA" ? [{ mss: 1460 }, "nop", { ws: 7 }, "sackOk" as const] : undefined }), ...rest);

// phone ↔ edge
const phoneUp = (...rest: LayerSpec[]) => build(eth({ src: ADDR.phoneMac, dst: ADDR.routerMac }), ipv4({ src: ADDR.phone, dst: ANY, ttl: 64 }), ...rest);
const phoneDown = (...rest: LayerSpec[]) => build(eth({ src: ADDR.routerMac, dst: ADDR.phoneMac }), ipv4({ src: ANY, dst: ADDR.phone, ttl: 60 }), ...rest);

// edge ↔ origin, captured at the edge (connection already open and reused)
const edgeToOrigin = (...rest: LayerSpec[]) => build(eth({ src: BOM_MAC, dst: BOM_GW }), ipv4({ src: BOM, dst: ORIGIN, ttl: 64 }), ...rest);
const originToEdge = (...rest: LayerSpec[]) => build(eth({ src: BOM_GW, dst: BOM_MAC }), ipv4({ src: ORIGIN, dst: BOM, ttl: 49 }), ...rest);

const SP = 52110;

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop, Mumbai", sub: ADDR.laptop, x: 8, y: 40 },
  { id: "phone", kind: "phone", label: "Phone, Mumbai", sub: ADDR.phone, x: 8, y: 80 },
  { id: "dns", kind: "dns", label: "DNS resolver", sub: ADDR.dns, x: 30, y: 16 },
  { id: "bom", kind: "cdn", label: "Edge, Mumbai", sub: `${ANY} (anycast)`, x: 40, y: 58 },
  { id: "maa", kind: "cdn", label: "Edge, Chennai", sub: `${ANY} (anycast)`, x: 58, y: 84 },
  { id: "origin", kind: "web", label: "Origin, Frankfurt", sub: ORIGIN, x: 90, y: 40 },
];
const links: [string, string][] = [["client", "dns"], ["client", "bom"], ["phone", "bom"], ["bom", "origin"], ["maa", "origin"]];

const downDevices = devices;
const downLinks: [string, string][] = [...links, ["client", "maa"]];

export default defineLesson({
  id: "cdn",
  name: "CDN",
  full: "Content Delivery Network and anycast",
  group: "web",
  layer: 7,
  difficulty: 2,
  tagline: "Copies of a website parked close to you, all on one IP address.",
  description:
    "A content delivery network keeps copies of a site's files in cache servers (edges) spread across many cities. With anycast, every city's edge announces the same IP address, so the internet's routing sends you to the nearest one. The first visitor's request fills the cache; everyone after that is served locally in milliseconds.",
  facts: [
    ["Layer", "Application (HTTP) + routing (BGP anycast)"],
    ["Transport", "TCP 80/443, QUIC 443"],
    ["Cache control", "Cache-Control, Age, ETag"],
    ["Routing trick", "Anycast: one IP, many places"],
    ["Typical gain", "200 ms → 5 ms per round trip"],
    ["Defined in", "RFC 9111 (HTTP caching), RFC 4786 (anycast)"],
  ],
  ports: "TCP 80, 443; UDP 443 (QUIC)",
  rfc: "RFC 9111, RFC 4786",
  keywords: ["cdn", "anycast", "edge", "pop", "cache", "hit", "miss", "age", "cache-control", "origin", "x-cache"],
  related: ["http", "dns", "bgp", "tls"],
  devices,
  links,
  legend: [
    ["blue", "DNS lookup"],
    ["green", "TCP handshake"],
    ["amber", "Requests"],
    ["violet", "Responses"],
    ["red", "Failures"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Cache miss, then cache hit",
      summary: "The laptop fetches an image through the Mumbai edge. It's a miss, so the edge pulls it from Frankfurt. Half an hour later the phone gets the cached copy.",
      kind: "normal",
      steps: [
        {
          title: "Look up the name",
          desc: "DNS points to a CDN, not the origin",
          detail:
            `The site owner pointed www.example.com at the CDN with a CNAME. The CDN's name resolves to ${ANY}. That single address is announced from every city where the CDN has an edge, so the answer is the same for a user in Mumbai or in Paris.`,
          facts: [["Name", "www.example.com"], ["CNAME", "www.example.com.cdn.example.net"], ["Address", `${ANY} (anycast)`]],
          events: [
            pkt("client", "dns", "blue", "QUERY", ["www.example.com A?"], {
              time: 0, info: "Standard query 0x3a71 A www.example.com",
              packet: build(...up(ADDR.dns), udp({ sport: 60433, dport: 53 }), dns({ id: 0x3a71, qd: [{ name: "www.example.com", type: "A" }] })),
            }),
            pkt("dns", "client", "blue", "ANSWER", ["CNAME → CDN", ANY], {
              time: 0.006, info: `Standard query response 0x3a71 A www.example.com CNAME www.example.com.cdn.example.net A ${ANY}`,
              packet: build(...down(ADDR.dns, { ttl: 62 }), udp({ sport: 53, dport: 60433 }), dns({
                id: 0x3a71, response: true, ra: true, qd: [{ name: "www.example.com", type: "A" }],
                an: [
                  { name: "www.example.com", type: "CNAME", ttl: 3600, data: "www.example.com.cdn.example.net", note: "The site hands the name over to the CDN." },
                  { name: "www.example.com.cdn.example.net", type: "A", ttl: 300, data: ANY, note: "An anycast address: the same everywhere in the world." },
                ],
              })),
            }),
          ],
        },
        {
          title: "Reach the nearest edge",
          desc: "Anycast picks Mumbai",
          detail:
            `Every edge announces ${ANY} with BGP. Routers simply follow the shortest path they know, which for a laptop in Mumbai ends at the Mumbai edge. The handshake takes 4 ms instead of about 140 ms to Frankfurt.`,
          facts: [["Destination", `${ANY}`], ["Answered by", "Mumbai edge"], ["Round trip", "4 ms"]],
          quiz: {
            q: `Paris and Mumbai users both connect to ${ANY}. Which server answers the Paris user?`,
            options: ["The Mumbai edge", "The origin in Frankfurt", "The nearest edge to Paris", "Whichever edge is least busy, chosen by DNS"],
            answer: 2,
            why: "With anycast, BGP routing delivers each packet to the closest place announcing that address.",
          },
          events: [
            pkt("client", "bom", "green", "SYN", [`to ${ANY}`], {
              time: 0.007, info: `${SP} → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=128 SACK_PERM`,
              packet: toEdge(SP, 0, 0, "S"),
            }),
            pkt("bom", "client", "green", "SYN-ACK", ["from Mumbai"], {
              time: 0.011, info: `80 → ${SP} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 WS=128 SACK_PERM`,
              packet: fromEdge(SP, 0, 1, "SA"),
            }),
            pkt("client", "bom", "green", "ACK", ["connected"], {
              time: 0.0111, info: `${SP} → 80 [ACK] Seq=1 Ack=1 Win=502 Len=0`,
              packet: toEdge(SP, 1, 1, "A"),
            }),
          ],
        },
        {
          title: "Ask for the image",
          desc: "The edge checks its cache: MISS",
          detail:
            `The browser asks for ${PATH}. The edge looks the URL up in its cache and finds nothing, because nobody near Mumbai has asked for this image yet. That is a cache miss. (We show plain HTTP so the headers are visible; with HTTPS the same headers travel inside TLS.)`,
          facts: [["Request", `GET ${PATH}`], ["Cache key", "Host + path"], ["Result", "MISS"]],
          events: [
            pkt("client", "bom", "amber", "GET", [PATH], {
              time: 0.0112, info: `GET ${PATH} HTTP/1.1`,
              packet: toEdge(SP, 1, 1, "PA", req()),
            }),
            note("bom", "CACHE MISS", "amber"),
          ],
        },
        {
          title: "Fetch from the origin",
          desc: "Mumbai asks Frankfurt",
          detail:
            "The edge sends its own request to the origin over a connection it keeps open, so there is no new handshake. The origin answers 200 OK with Cache-Control: public, max-age=86400, which gives every cache permission to keep the image for one day.",
          facts: [["Edge → origin", `${BOM} → ${ORIGIN}`], ["Round trip", "≈ 130 ms"], ["Cache-Control", "public, max-age=86400"]],
          quiz: {
            q: "What would happen if the origin had sent Cache-Control: private?",
            options: ["The edge caches it for longer", "The edge must not store it; every user goes to the origin", "The browser refuses the image", "The edge encrypts it"],
            answer: 1,
            why: "private means only the user's own browser may keep it. Shared caches such as a CDN must not.",
          },
          events: [
            pkt("bom", "origin", "amber", "GET", ["cache fill"], {
              time: 0.0115, info: `GET ${PATH} HTTP/1.1`,
              packet: edgeToOrigin(tcp({ sport: 40812, dport: 80, seq: 1, ack: 1, flags: "PA", win: 1024, seqBase: 0x10203040, ackBase: 0xa0b0c0d0 }), originReq()),
            }),
            pkt("origin", "bom", "violet", "200 OK", ["max-age=86400"], {
              time: 0.1418, info: "HTTP/1.1 200 OK (image/jpeg)",
              packet: originToEdge(tcp({ sport: 80, dport: 40812, seq: 1, ack: 1 + OREQ_LEN, flags: "A", win: 1024, seqBase: 0xa0b0c0d0, ackBase: 0x10203040 }), originResp()),
            }),
            note("bom", "STORED FOR 1 DAY", "green"),
          ],
        },
        {
          title: "Serve the laptop",
          desc: "X-Cache: MISS, Age: 0",
          detail:
            "The edge stores a copy and streams the image to the laptop at the same time. Its response adds X-Cache: MISS and Age: 0, so anyone debugging can see the copy came straight from the origin. This first visitor paid the trip to Frankfurt once.",
          facts: [["X-Cache", "MISS"], ["Age", "0 seconds"], ["Total time", "≈ 146 ms"]],
          events: [
            pkt("bom", "client", "violet", "200 OK", ["X-Cache: MISS", "Age: 0"], {
              time: 0.146, info: "HTTP/1.1 200 OK (image/jpeg) X-Cache: MISS",
              packet: fromEdge(SP, 1, 1 + REQ_LEN, "A", edgeResp(false, 0)),
            }),
          ],
        },
        {
          title: "The next visitor: HIT",
          desc: "Thirty minutes later, from the phone",
          detail:
            "Half an hour later the phone opens the same page and reaches the same Mumbai edge. The copy is 1800 seconds old, well within its 86400-second life, so the edge answers straight from its cache. The origin hears nothing at all.",
          facts: [["X-Cache", "HIT"], ["Age", "1800 s (30 min)"], ["Response time", "≈ 4 ms"]],
          quiz: {
            q: "The copy is 1800 s old with max-age=86400. When must the edge check with the origin again?",
            options: ["Now", "After another 84600 seconds", "After 1800 more seconds", "Never"],
            answer: 1,
            why: "The copy stays fresh until Age reaches max-age: 86400 − 1800 = 84600 seconds from now. Then the edge revalidates, usually with If-None-Match and the ETag.",
          },
          events: [
            pkt("phone", "bom", "amber", "GET", [PATH], {
              time: 1800.0, info: `GET ${PATH} HTTP/1.1`,
              packet: phoneUp(tcp({ sport: 41877, dport: 80, seq: 1, ack: 1, flags: "PA", win: 502, seqBase: 0x2c4e6000, ackBase: 0x6f00b000 }), req()),
            }),
            note("bom", "CACHE HIT", "green"),
            pkt("bom", "phone", "violet", "200 OK", ["X-Cache: HIT", "Age: 1800"], {
              time: 1800.004, info: "HTTP/1.1 200 OK (image/jpeg) X-Cache: HIT",
              packet: phoneDown(tcp({ sport: 80, dport: 41877, seq: 1, ack: 1 + REQ_LEN, flags: "A", win: 509, seqBase: 0x6f00b000, ackBase: 0x2c4e6000 }), edgeResp(true, 1800)),
            }),
          ],
        },
      ],
      outro: {
        title: "Fetched once, served many times",
        text: "Anycast sent both devices to the Mumbai edge. The first request missed and was filled from Frankfurt; the second was a hit served in 4 ms. Cache-Control told the edge how long it may keep the copy, and Age and X-Cache show what happened.",
        facts: [["First visit", "MISS, ≈ 146 ms"], ["Later visits", "HIT, ≈ 4 ms"], ["Origin requests", "1"], ["Saved per hit", "≈ 140 ms and one origin request"]],
      },
    },
    {
      id: "edge-down",
      name: "The Mumbai edge goes down",
      summary: "The nearest edge fails. Its anycast route disappears and users are carried to Chennai without changing any address.",
      kind: "failure",
      devices: downDevices,
      links: downLinks,
      steps: [
        {
          title: "Mumbai fails",
          desc: "A SYN goes nowhere",
          detail:
            "The Mumbai edge loses power in the middle of the evening. The laptop's SYN still follows the old route to Mumbai and is lost. The browser waits for its retransmission timer, which starts at one second.",
          facts: [["Destination", ANY], ["Mumbai edge", "Down"], ["SYN timer", "1 s, then 2 s"]],
          events: [
            pkt("client", "bom", "red", "SYN", ["to Mumbai", "no answer"], {
              time: 0, lost: true, info: `${SP + 1} → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=128 SACK_PERM`,
              packet: toEdge(SP + 1, 0, 0, "S"),
            }),
            note("bom", "EDGE DOWN", "red"),
          ],
        },
        {
          title: "The route disappears",
          desc: "BGP withdraws Mumbai's anycast route",
          detail:
            `Mumbai's routers stop hearing from the edge (health checks fail, or its BGP session times out) and withdraw its announcement of ${ANY}. Routers in the region now only know the paths to the other edges, and the best of those leads to Chennai.`,
          facts: [["Withdrawn", `${ANY} via Mumbai`], ["Next best", "Chennai"], ["Takes", "A few seconds"]],
          quiz: {
            q: "Does the laptop need a new IP address from DNS to reach Chennai?",
            options: ["Yes, DNS must be updated first", `No, ${ANY} now simply routes to Chennai`, "Yes, the browser must be restarted", "No, it keeps talking to Mumbai"],
            answer: 1,
            why: "With anycast the address never changes. Only the route to it does, so failover doesn't wait for DNS caches to expire.",
          },
          events: [
            pkt("client", "bom", "red", "SYN", ["retry after 1 s", "still lost"], {
              time: 1.0, lost: true, info: `[TCP Retransmission] ${SP + 1} → 80 [SYN] Seq=0 Win=64240 Len=0`,
              packet: toEdge(SP + 1, 0, 0, "S"),
            }),
            note("maa", `NOW BEST PATH TO ${ANY}`, "blue"),
          ],
        },
        {
          title: "Chennai answers",
          desc: "Same address, different city",
          detail:
            `The third SYN, two seconds later, follows the new route to Chennai. The Chennai edge answers from ${ANY} just as Mumbai would have. The round trip is now 22 ms instead of 4 ms, but the site works.`,
          facts: [["Answered by", "Chennai edge"], ["Round trip", "22 ms"], ["Downtime seen", "≈ 3 s"]],
          events: [
            pkt("client", "maa", "green", "SYN", ["retry after 2 s"], {
              time: 3.0, info: `[TCP Retransmission] ${SP + 1} → 80 [SYN] Seq=0 Win=64240 Len=0`,
              packet: toEdge(SP + 1, 0, 0, "S"),
            }),
            pkt("maa", "client", "green", "SYN-ACK", ["from Chennai"], {
              time: 3.022, info: `80 → ${SP + 1} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 WS=128 SACK_PERM`,
              packet: fromEdge(SP + 1, 0, 1, "SA"),
            }),
            pkt("client", "maa", "green", "ACK", ["connected"], {
              time: 3.0221, info: `${SP + 1} → 80 [ACK] Seq=1 Ack=1 Win=502 Len=0`,
              packet: toEdge(SP + 1, 1, 1, "A"),
            }),
          ],
        },
        {
          title: "Served from Chennai",
          desc: "A popular file is cached there too",
          detail:
            "The image is popular, so Chennai already has its own copy and serves it as a HIT. If it hadn't, Chennai would fetch it from the origin just as Mumbai did earlier. Users only noticed a three-second pause.",
          facts: [["X-Cache", "HIT"], ["X-Served-By", "cache-maa-02"], ["Origin load", "Unchanged"]],
          events: [
            pkt("client", "maa", "amber", "GET", [PATH], {
              time: t(3.0222), info: `GET ${PATH} HTTP/1.1`,
              packet: toEdge(SP + 1, 1, 1, "PA", req()),
            }),
            pkt("maa", "client", "violet", "200 OK", ["X-Cache: HIT", "Chennai"], {
              time: 3.0443, info: "HTTP/1.1 200 OK (image/jpeg) X-Cache: HIT",
              packet: fromEdge(SP + 1, 1, 1 + REQ_LEN, "A", edgeResp(true, 5230, "maa-02")),
            }),
            note("client", "PAGE LOADS", "green"),
          ],
        },
      ],
      outro: {
        title: "Failover by routing",
        text: "When the Mumbai edge died, BGP stopped advertising its anycast route and the very same IP address led to Chennai. Users saw a short pause instead of an outage, and nobody had to wait for DNS to change.",
        facts: [["Failover", "BGP route withdrawal"], ["Address change", "None"], ["Pause", "≈ 3 s (SYN retries)"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Headers to know",
      items: [["Cache-Control: max-age=N", "Fresh for N seconds"], ["public / private", "Shared caches may / may not store it"], ["no-store", "Never keep a copy"], ["Age", "Seconds the copy has been cached"], ["ETag", "Version fingerprint for revalidation"], ["X-Cache", "HIT or MISS (CDN-specific)"]],
    },
    {
      title: "Words",
      items: [["Edge / PoP", "Cache servers in a city"], ["Origin", "The site's real server"], ["Anycast", "Same IP announced from many places"], ["Cache fill", "Edge fetching from origin on a miss"], ["Hit ratio", "Share of requests served from cache"]],
    },
  ],
});
