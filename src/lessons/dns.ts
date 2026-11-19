import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build } from "@/lib/packet";
import { dns, dnsName, DnsRR, eth, ipv4, udp } from "@/lib/proto";
import { u32 } from "@/lib/bytes";
import { ADDR, down, up } from "./_common";

// Addresses. The root and .com servers are the real, well-known ones (what `dig +trace` shows);
// everything about example.com uses documentation ranges.
const RES = ADDR.dns; // ISP's recursive resolver
const ROOT = "198.41.0.4"; // a.root-servers.net
const TLD = "192.5.6.30"; // a.gtld-servers.net
const AUTH = "198.51.100.53"; // ns1.example.com
const WEB = ADDR.web; // example.com A
const RES_MAC = "00:16:3e:d0:53:01";
const GW_MAC = "00:1c:73:ee:10:01";
const EVIL = "198.18.66.6";
const LPORT = 52114; // laptop's source port

const t = (n: number) => Number(n.toFixed(3));
const opt = (doBit = false): DnsRR => ({ name: ".", type: "OPT", cls: 1232, ttl: doBit ? 0x8000 : 0 });

// packets captured on the resolver's uplink
const resOut = (dst: string, sport: number, id: number) => [
  eth({ src: RES_MAC, dst: GW_MAC }),
  ipv4({ src: RES, dst, ttl: 64, id }),
  udp({ sport, dport: 53 }),
];
const resIn = (src: string, dport: number, id: number, ttl = 52) => [
  eth({ src: GW_MAC, dst: RES_MAC }),
  ipv4({ src, dst: RES, ttl, id }),
  udp({ sport: 53, dport }),
];

const soa = (mname: string, rname: string, serial: number, minimum: number) => [
  ...dnsName(mname), ...dnsName(rname), ...u32(serial), ...u32(7200), ...u32(3600), ...u32(1209600), ...u32(minimum),
];

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: ADDR.laptop, x: 9, y: 62 },
  { id: "resolver", kind: "dns", label: "ISP resolver", sub: RES, x: 33, y: 62 },
  { id: "internet", kind: "cloud", label: "Internet", x: 56, y: 40 },
  { id: "root", kind: "dns", label: "Root server", sub: `a.root · ${ROOT}`, x: 86, y: 17 },
  { id: "tld", kind: "dns", label: ".com server", sub: `a.gtld · ${TLD}`, x: 88, y: 50 },
  { id: "auth", kind: "dns", label: "ns1.example.com", sub: AUTH, x: 86, y: 82 },
];
const links: [string, string][] = [
  ["client", "resolver"],
  ["resolver", "internet"],
  ["internet", "root"],
  ["internet", "tld"],
  ["internet", "auth"],
];

const attackDevices: Device[] = [
  ...devices,
  { id: "attacker", kind: "attacker", label: "Attacker", sub: "198.18.7.7", x: 30, y: 20 },
];
const attackLinks: [string, string][] = [...links, ["attacker", "internet"]];

const Q = { name: "example.com", type: "A" };
const ANSWER: DnsRR = { name: "example.com", type: "A", ttl: 3600, data: WEB, note: "The address, and how long it may be cached: one hour." };

export default defineLesson({
  id: "dns",
  name: "DNS",
  full: "Domain Name System",
  group: "naming",
  layer: 7,
  difficulty: 1,
  tagline: "The internet's phone book, looked up one level at a time.",
  description:
    "DNS turns names like example.com into IP addresses. Your laptop asks one recursive resolver, which walks the tree from the root servers to the .com servers to the domain's own server, then caches the answer so the next lookup is instant.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "UDP 53 (TCP 53 for big answers)"],
    ["Header", "12 bytes"],
    ["Root servers", "13 names, 1,900+ anycast sites"],
    ["Caching", "Every record has a TTL"],
    ["Defined in", "RFC 1034, RFC 1035"],
  ],
  ports: "UDP/TCP 53",
  rfc: "RFC 1034, RFC 1035, RFC 2308, RFC 5452",
  keywords: ["dns", "resolver", "recursive", "root", "tld", "authoritative", "ttl", "cache", "nxdomain", "glue", "referral", "poisoning", "kaminsky"],
  related: ["doh", "dnssec", "udp", "cdn"],
  devices,
  links,
  legend: [
    ["blue", "Queries"],
    ["green", "Answers"],
    ["violet", "Referrals (ask someone else)"],
    ["red", "Errors and forged replies"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "First lookup of example.com, then from cache",
      summary: "The resolver walks root → .com → example.com, answers the laptop, and serves the next lookup from its cache.",
      kind: "normal",
      steps: [
        {
          title: "Ask the resolver",
          desc: "The laptop sends one small question",
          detail:
            "The browser needs the address of example.com. The laptop sends a 40-something byte UDP packet to its configured resolver, the ISP's server at 192.0.2.53. The RD (recursion desired) flag means: please do the whole lookup for me and come back with the final answer.",
          facts: [["To", `${RES}, UDP port 53`], ["Question", "example.com, type A (IPv4)"], ["Flag", "RD = 1"]],
          quiz: {
            q: "The resolver has an empty cache. Who does it ask first?",
            options: ["The .com servers", "A root server", "ns1.example.com", "The home router"],
            answer: 1,
            why: "With nothing cached, the only addresses a resolver knows are the root servers' (from its built-in hints file). Everything starts at the root.",
          },
          events: [
            pkt("client", "resolver", "blue", "QUERY", ["example.com A?", "id 0x3f1a"], {
              time: 0, info: "Standard query 0x3f1a A example.com",
              packet: build(...up(RES, { id: 0x7a21 }), udp({ sport: LPORT, dport: 53 }), dns({ id: 0x3f1a, qd: [Q] })),
            }),
          ],
        },
        {
          title: "Ask a root server",
          desc: "The root doesn't know, but knows who runs .com",
          detail:
            "The resolver asks a root server the same question, without RD, because it wants a pointer, not a favour. The root replies with a referral: no answer, but the NS records for .com in the authority section, plus their IP addresses in the additional section. Those addresses are called glue, and they save the resolver another lookup.",
          facts: [["Root server", `a.root-servers.net, ${ROOT}`], ["Reply", "Referral: com. NS a.gtld-servers.net"], ["Glue", `a.gtld-servers.net A ${TLD}`]],
          quiz: {
            q: "Why does the root include the IP address of a.gtld-servers.net in its reply?",
            options: ["To save the resolver a separate lookup of that name", "Because the root is authoritative for gtld-servers.net", "To encrypt the reply", "It is required by UDP"],
            answer: 0,
            why: "Without glue the resolver would have to look up a.gtld-servers.net before it could ask anything about .com. Glue gives it the address directly.",
          },
          events: [
            pkt("resolver", "root", "blue", "QUERY", ["example.com A?", "no RD"], {
              time: 0.006, info: "Standard query 0x9b27 A example.com OPT",
              packet: build(...resOut(ROOT, 41877, 0x1101), dns({ id: 0x9b27, rd: false, qd: [Q], ar: [opt()] })),
            }),
            pkt("root", "resolver", "violet", "REFERRAL", ["ask .com servers", "+ glue"], {
              time: 0.018, info: "Standard query response 0x9b27 A example.com NS a.gtld-servers.net NS b.gtld-servers.net A 192.5.6.30 A 192.33.14.30 OPT",
              packet: build(...resIn(ROOT, 41877, 0x6c02), dns({
                id: 0x9b27, response: true, rd: false, qd: [Q],
                ns: [
                  { name: "com", type: "NS", ttl: 172800, data: "a.gtld-servers.net", note: "Who is responsible for .com. Valid for two days." },
                  { name: "com", type: "NS", ttl: 172800, data: "b.gtld-servers.net" },
                ],
                ar: [
                  { name: "a.gtld-servers.net", type: "A", ttl: 172800, data: TLD, note: "Glue: the address of the server named above." },
                  { name: "b.gtld-servers.net", type: "A", ttl: 172800, data: "192.33.14.30" },
                  opt(),
                ],
              })),
            }),
          ],
        },
        {
          title: "Ask the .com server",
          desc: "Another referral, one level down",
          detail:
            "Next the resolver asks a.gtld-servers.net. The .com registry doesn't store example.com's addresses either, but it knows which name servers the domain owner registered: ns1 and ns2.example.com. Because those names sit inside example.com itself, glue is essential here, or the resolver would go round in circles.",
          facts: [["Server", `a.gtld-servers.net, ${TLD}`], ["Reply", "example.com NS ns1/ns2.example.com"], ["Glue", `ns1.example.com A ${AUTH}`]],
          events: [
            pkt("resolver", "tld", "blue", "QUERY", ["example.com A?"], {
              time: 0.019, info: "Standard query 0xe00d A example.com OPT",
              packet: build(...resOut(TLD, 60219, 0x1102), dns({ id: 0xe00d, rd: false, qd: [Q], ar: [opt()] })),
            }),
            pkt("tld", "resolver", "violet", "REFERRAL", ["ask ns1.example.com", "+ glue"], {
              time: 0.045, info: "Standard query response 0xe00d A example.com NS ns1.example.com NS ns2.example.com A 198.51.100.53 A 198.51.100.54 OPT",
              packet: build(...resIn(TLD, 60219, 0x2f9e, 50), dns({
                id: 0xe00d, response: true, rd: false, qd: [Q],
                ns: [
                  { name: "example.com", type: "NS", ttl: 172800, data: "ns1.example.com", note: "The domain's own name servers, as registered with the .com registry." },
                  { name: "example.com", type: "NS", ttl: 172800, data: "ns2.example.com" },
                ],
                ar: [
                  { name: "ns1.example.com", type: "A", ttl: 172800, data: AUTH, note: "Glue. Without it, finding ns1.example.com would need example.com's servers: a loop." },
                  { name: "ns2.example.com", type: "A", ttl: 172800, data: "198.51.100.54" },
                  opt(),
                ],
              })),
            }),
          ],
        },
        {
          title: "Ask example.com's server",
          desc: "The authoritative answer",
          detail:
            "Finally the resolver asks ns1.example.com, the server the domain owner runs. This one really knows: it replies with the A record and sets the AA (authoritative answer) flag. The TTL of 3600 seconds says the answer may be reused for an hour.",
          facts: [["Server", `ns1.example.com, ${AUTH}`], ["Answer", `example.com A ${WEB}`], ["Flags", "AA = 1, TTL 3600 s"]],
          quiz: {
            q: "Which flag shows this answer came straight from the domain's own server?",
            options: ["RD", "RA", "AA", "TC"],
            answer: 2,
            why: "AA (authoritative answer) is set only by a server that is responsible for the zone. Answers from a cache never carry it.",
          },
          events: [
            pkt("resolver", "auth", "blue", "QUERY", ["example.com A?"], {
              time: 0.046, info: "Standard query 0x51c4 A example.com OPT",
              packet: build(...resOut(AUTH, 38506, 0x1103), dns({ id: 0x51c4, rd: false, qd: [Q], ar: [opt()] })),
            }),
            pkt("auth", "resolver", "green", "ANSWER", [`A ${WEB}`, "AA, TTL 3600"], {
              time: 0.084, info: `Standard query response 0x51c4 A example.com A ${WEB} OPT`,
              packet: build(...resIn(AUTH, 38506, 0x88b1, 55), dns({ id: 0x51c4, response: true, rd: false, aa: true, qd: [Q], an: [ANSWER], ar: [opt()] })),
            }),
          ],
        },
        {
          title: "Answer the laptop",
          desc: "Same question id, final answer, cached",
          detail:
            "The resolver stores the answer and every referral in its cache, then replies to the laptop. The reply repeats the laptop's transaction id 0x3f1a and the question, so the laptop can match it. RA (recursion available) shows the resolver did the walking. The whole walk took 90 ms.",
          facts: [["Transaction id", "0x3f1a (matches the query)"], ["Flags", "RD, RA (no AA: it came from the resolver)"], ["Total time", "90 ms"]],
          quiz: {
            q: "Another customer asks for example.com 60 seconds later. What TTL will they see?",
            options: ["3600", "3540", "60", "0, it must be fetched again"],
            answer: 1,
            why: "A cache counts the TTL down. After 60 seconds, 3600 − 60 = 3540 seconds of life are left.",
          },
          events: [
            pkt("resolver", "client", "green", "ANSWER", [`A ${WEB}`, "TTL 3600"], {
              time: 0.09, info: `Standard query response 0x3f1a A example.com A ${WEB}`,
              packet: build(...down(RES, { ttl: 63, id: 0xc311 }), udp({ sport: 53, dport: LPORT }), dns({ id: 0x3f1a, response: true, ra: true, qd: [Q], an: [ANSWER] })),
            }),
            note("resolver", "CACHED FOR 1 HOUR", "green"),
          ],
        },
        {
          title: "Second lookup, from cache",
          desc: "One minute later: no walk at all",
          detail:
            "A minute later the laptop asks again (the browser's own cache was cleared). This time the resolver already has the answer, so it replies in about 4 ms without contacting any other server. The TTL has counted down to 3540. This caching is why DNS can serve billions of lookups a day.",
          facts: [["Servers contacted", "None"], ["TTL left", "3540 s"], ["Time", "4 ms instead of 90 ms"]],
          events: [
            pkt("client", "resolver", "blue", "QUERY", ["example.com A?", "id 0x8d02"], {
              time: 60, info: "Standard query 0x8d02 A example.com",
              packet: build(...up(RES, { id: 0x7b90 }), udp({ sport: 58731, dport: 53 }), dns({ id: 0x8d02, qd: [Q] })),
            }),
            pkt("resolver", "client", "green", "CACHED", [`A ${WEB}`, "TTL 3540"], {
              time: 60.004, info: `Standard query response 0x8d02 A example.com A ${WEB}`,
              packet: build(...down(RES, { ttl: 63, id: 0xc4a0 }), udp({ sport: 53, dport: 58731 }), dns({ id: 0x8d02, response: true, ra: true, qd: [Q], an: [{ ...ANSWER, ttl: 3540, note: "Counted down from 3600 while in the cache." }] })),
            }),
            note("resolver", "CACHE HIT", "green"),
          ],
        },
      ],
      outro: {
        title: "Name resolved",
        text: "One question from the laptop became three questions from the resolver: root, .com, then example.com's own server. Each level pointed one step closer, and the final answer was cached so the next lookup needed no outside traffic at all.",
        facts: [["Packets", "10"], ["First lookup", "90 ms"], ["Cached lookup", "4 ms"], ["Answer", `example.com → ${WEB}`]],
      },
    },
    {
      id: "nxdomain",
      name: "A typo: NXDOMAIN",
      summary: "Someone types wwww.example.com; the domain's server says the name does not exist.",
      kind: "failure",
      steps: [
        {
          title: "Ask for a typo",
          desc: "wwww.example.com, with four w's",
          detail:
            "A user mistypes the address. The laptop sends the question to the resolver as usual. DNS has no idea it's a typo; it just looks the name up.",
          facts: [["Question", "wwww.example.com A"], ["To", RES], ["Transaction id", "0x6b5e"]],
          events: [
            pkt("client", "resolver", "blue", "QUERY", ["wwww.example.com A?"], {
              time: 0, info: "Standard query 0x6b5e A wwww.example.com",
              packet: build(...up(RES, { id: 0x7c01 }), udp({ sport: 50991, dport: 53 }), dns({ id: 0x6b5e, qd: [{ name: "wwww.example.com", type: "A" }] })),
            }),
          ],
        },
        {
          title: "Skip straight to ns1",
          desc: "Cached referrals save two trips",
          detail:
            "The resolver still has the NS records for example.com in its cache (they live for two days), so it skips the root and .com and asks ns1.example.com directly. The server has no such name and replies NXDOMAIN (rcode 3). It adds its SOA record so the resolver knows how long it may remember this \"no\".",
          facts: [["Rcode", "3 = NXDOMAIN"], ["Authority", "SOA of example.com"], ["Negative TTL", "300 s (SOA minimum)"]],
          quiz: {
            q: "Why did the resolver not ask the root this time?",
            options: ["Roots don't answer typos", "It still had example.com's NS records cached", "The laptop told it where to go", "NXDOMAIN lookups skip the root"],
            answer: 1,
            why: "Referrals are cached like any record. The NS set for example.com had a 2-day TTL, so the resolver could go straight to the domain's own server.",
          },
          events: [
            pkt("resolver", "auth", "blue", "QUERY", ["wwww.example.com A?"], {
              time: 0.005, info: "Standard query 0x2ad7 A wwww.example.com OPT",
              packet: build(...resOut(AUTH, 49102, 0x1201), dns({ id: 0x2ad7, rd: false, qd: [{ name: "wwww.example.com", type: "A" }], ar: [opt()] })),
            }),
            pkt("auth", "resolver", "red", "NXDOMAIN", ["no such name", "+ SOA"], {
              time: 0.043, info: "Standard query response 0x2ad7 No such name A wwww.example.com SOA ns1.example.com OPT",
              packet: build(...resIn(AUTH, 49102, 0x88c4, 55), dns({
                id: 0x2ad7, response: true, rd: false, aa: true, rcode: 3, qd: [{ name: "wwww.example.com", type: "A" }],
                ns: [{
                  name: "example.com", type: "SOA", ttl: 300, rdata: soa("ns1.example.com", "hostmaster.example.com", 2026111901, 300),
                  value: "ns1.example.com hostmaster.example.com 2026111901 7200 3600 1209600 300",
                  note: "Start of authority. Its last number (minimum) sets how long a \"no\" may be cached.",
                }],
                ar: [opt()],
              })),
            }),
          ],
        },
        {
          title: "Tell the laptop",
          desc: "The \"no\" is cached too",
          detail:
            "The resolver passes NXDOMAIN back to the laptop and caches the negative answer for 300 seconds, so a flood of the same typo doesn't hit ns1 again. The browser shows a \"site can't be reached\" page with DNS_PROBE_FINISHED_NXDOMAIN.",
          facts: [["Rcode", "NXDOMAIN"], ["Browser shows", "DNS_PROBE_FINISHED_NXDOMAIN"], ["Cached for", "300 s (RFC 2308)"]],
          quiz: {
            q: "Is NXDOMAIN a network failure?",
            options: ["Yes, the server timed out", "No, it is a definite answer: the name does not exist", "Yes, the packet was corrupted", "No, it means try TCP instead"],
            answer: 1,
            why: "NXDOMAIN is a successful lookup with a negative result. A timeout or SERVFAIL would be the network or server failing.",
          },
          events: [
            pkt("resolver", "client", "red", "NXDOMAIN", ["wwww.example.com", "does not exist"], {
              time: 0.048, info: "Standard query response 0x6b5e No such name A wwww.example.com SOA ns1.example.com",
              packet: build(...down(RES, { ttl: 63, id: 0xc5d2 }), udp({ sport: 53, dport: 50991 }), dns({
                id: 0x6b5e, response: true, ra: true, rcode: 3, qd: [{ name: "wwww.example.com", type: "A" }],
                ns: [{ name: "example.com", type: "SOA", ttl: 295, rdata: soa("ns1.example.com", "hostmaster.example.com", 2026111901, 300), value: "ns1.example.com hostmaster.example.com 2026111901 7200 3600 1209600 300" }],
              })),
            }),
            note("client", "SITE CAN'T BE REACHED", "red"),
          ],
        },
      ],
      outro: {
        title: "A clean \"no\"",
        text: "NXDOMAIN is an authoritative statement that a name does not exist. It travels with the zone's SOA record, whose minimum field tells resolvers how long to cache the negative answer.",
        facts: [["Rcode", "3 (NXDOMAIN)"], ["Proof", "SOA in the authority section"], ["Negative caching", "RFC 2308"]],
      },
    },
    {
      id: "poisoning",
      name: "Cache poisoning attempt",
      summary: "An attacker races the real server with forged replies; random ids, random ports and DNSSEC stop it.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "Trigger a lookup",
          desc: "The attacker makes the resolver go out",
          detail:
            "To poison a cache, an attacker must slip a fake answer in while the resolver is waiting for a real one. So first it asks the resolver for www.example.com, a name not yet cached. The resolver sends its query to ns1.example.com from a random port with a random transaction id.",
          facts: [["Query id", "0x8c41 (random 16 bits)"], ["Source port", "53817 (random)"], ["Window", "About 38 ms until the real reply"]],
          events: [
            pkt("attacker", "resolver", "red", "QUERY", ["www.example.com A?"], {
              time: 0, info: "Standard query 0x0a0a A www.example.com",
              packet: build(eth({ src: GW_MAC, dst: RES_MAC }), ipv4({ src: "198.18.7.7", dst: RES, ttl: 55, id: 0x4100 }), udp({ sport: 40404, dport: 53 }), dns({ id: 0x0a0a, qd: [{ name: "www.example.com", type: "A" }] })),
            }),
            pkt("resolver", "auth", "blue", "QUERY", ["www.example.com A?", "id 0x8c41, port 53817"], {
              time: 0.002, info: "Standard query 0x8c41 A www.example.com OPT",
              packet: build(...resOut(AUTH, 53817, 0x1301), dns({ id: 0x8c41, rd: false, qd: [{ name: "www.example.com", type: "A" }], ar: [opt(true)] })),
            }),
          ],
        },
        {
          title: "Flood of forgeries",
          desc: "Fake answers that pretend to be ns1",
          detail:
            "The attacker sends many replies with the source address forged as ns1.example.com, each pointing www.example.com at its own server. It cannot see the resolver's query, so it must guess both the transaction id and the destination port. The resolver drops every reply where either one doesn't match a query it is waiting for.",
          facts: [["Forged source", `${AUTH} (ns1)`], ["Fake answer", `A ${EVIL}`], ["Guesses needed", "65,536 ids × ~28,000 ports"]],
          quiz: {
            q: "A forged reply has the right port but id 0x8c40 instead of 0x8c41. What does the resolver do?",
            options: ["Accepts it, the port matched", "Drops it", "Asks ns1 to confirm", "Caches it for a shorter time"],
            answer: 1,
            why: "Both the id and the port (and the question) must match. One bit off means it is not the reply the resolver is waiting for.",
          },
          events: [
            pkt("attacker", "resolver", "red", "FORGED", ["id 0x1234, port 33000", "wrong port"], {
              time: 0.004, info: `Standard query response 0x1234 A www.example.com A ${EVIL}`,
              packet: build(...resIn(AUTH, 33000, 0x0001, 58), dns({ id: 0x1234, response: true, rd: false, aa: true, qd: [{ name: "www.example.com", type: "A" }], an: [{ name: "www.example.com", type: "A", ttl: 86400, data: EVIL, note: "The attacker's address, with a long TTL to stay cached." }] })),
            }),
            pkt("attacker", "resolver", "red", "FORGED", ["id 0x8c40, port 53817", "wrong id"], {
              time: 0.004, parallel: true, info: `Standard query response 0x8c40 A www.example.com A ${EVIL}`,
              packet: build(...resIn(AUTH, 53817, 0x0002, 58), dns({ id: 0x8c40, response: true, rd: false, aa: true, qd: [{ name: "www.example.com", type: "A" }], an: [{ name: "www.example.com", type: "A", ttl: 86400, data: EVIL }] })),
            }),
            pkt("attacker", "resolver", "red", "FORGED", ["id 0x77e1, port 41002", "both wrong"], {
              time: 0.005, parallel: true, info: `Standard query response 0x77e1 A www.example.com A ${EVIL}`,
              packet: build(...resIn(AUTH, 41002, 0x0003, 58), dns({ id: 0x77e1, response: true, rd: false, aa: true, qd: [{ name: "www.example.com", type: "A" }], an: [{ name: "www.example.com", type: "A", ttl: 86400, data: EVIL }] })),
            }),
            note("resolver", "ID / PORT MISMATCH: DROPPED", "green"),
          ],
        },
        {
          title: "The real answer wins",
          desc: "Matching id and port: accepted",
          detail:
            "The genuine reply from ns1 arrives with id 0x8c41 on port 53817 and is accepted. Once a query is answered, later forgeries have nothing to match. Before 2008 resolvers used a fixed source port, so only the 16-bit id had to be guessed; Dan Kaminsky showed that was breakable in seconds. Random ports multiply the work by tens of thousands.",
          facts: [["Accepted", `www.example.com A ${WEB}`], ["Attacker's odds", "About 1 in 1.8 billion per packet"], ["Rule", "RFC 5452"]],
          events: [
            pkt("auth", "resolver", "green", "ANSWER", [`A ${WEB}`, "id + port match"], {
              time: 0.04, info: `Standard query response 0x8c41 A www.example.com A ${WEB} OPT`,
              packet: build(...resIn(AUTH, 53817, 0x88d0, 55), dns({ id: 0x8c41, response: true, rd: false, aa: true, qd: [{ name: "www.example.com", type: "A" }], an: [{ name: "www.example.com", type: "A", ttl: 3600, data: WEB }], ar: [opt(true)] })),
            }),
            pkt("resolver", "attacker", "green", "ANSWER", [`A ${WEB}`, "the real one"], {
              time: 0.041, info: `Standard query response 0x0a0a A www.example.com A ${WEB}`,
              packet: build(...resOut("198.18.7.7", 53, 0x1302).slice(0, 2), udp({ sport: 53, dport: 40404 }), dns({ id: 0x0a0a, response: true, ra: true, qd: [{ name: "www.example.com", type: "A" }], an: [{ name: "www.example.com", type: "A", ttl: 3600, data: WEB }] })),
            }),
          ],
        },
        {
          title: "DNSSEC: the last wall",
          desc: "Even a lucky guess fails the signature",
          detail:
            "Randomness only makes forgery unlikely. DNSSEC makes it useless: the zone signs its records, and a validating resolver checks each answer's RRSIG against keys chained up to the root. A forged A record has no valid signature, so it would be thrown away with SERVFAIL instead of cached.",
          facts: [["Random id", "16 bits"], ["Random port", "About 15 bits"], ["DNSSEC", "Signature check, cannot be guessed"]],
          quiz: {
            q: "Which defence still works if the attacker can see the resolver's queries (for example, on the same network path)?",
            options: ["Random transaction ids", "Random source ports", "DNSSEC signatures", "A long TTL"],
            answer: 2,
            why: "An on-path attacker can read the id and port and copy them. Only a cryptographic signature it cannot produce still exposes the forgery.",
          },
          events: [note("resolver", "SIGNED ANSWERS ONLY", "blue")],
        },
      ],
      outro: {
        title: "Poisoning failed",
        text: "Cache poisoning needs a forged reply to match a pending query. Random transaction ids and random source ports turn that into a guess of about 31 bits, and DNSSEC signatures make even a correct guess worthless.",
        facts: [["Attack", "Off-path cache poisoning"], ["Defences", "Random id + port, 0x20 case mixing, DNSSEC"], ["Standard", "RFC 5452, RFC 4033"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Record types",
      items: [["A / AAAA", "IPv4 / IPv6 address"], ["NS", "Name servers for a zone"], ["CNAME", "Alias to another name"], ["MX", "Mail server, with preference"], ["SOA", "Zone details, negative TTL"], ["TXT", "Free text (SPF, verification)"]],
    },
    {
      title: "Header flags and codes",
      items: [["QR", "0 query, 1 response"], ["AA", "Authoritative answer"], ["RD / RA", "Recursion desired / available"], ["TC", "Truncated: retry over TCP"], ["NOERROR (0)", "Success"], ["SERVFAIL (2) / NXDOMAIN (3)", "Server failed / name doesn't exist"]],
    },
    {
      title: "Numbers to know",
      items: [["Port", "53 (UDP and TCP)"], ["Header", "12 bytes"], ["EDNS UDP size", "1232 bytes (safe default)"], ["Name limits", "63 bytes per label, 255 per name"], ["Root servers", "a. to m.root-servers.net"]],
    },
  ],
});
