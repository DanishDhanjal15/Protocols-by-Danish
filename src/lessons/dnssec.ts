import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, LayerSpec } from "@/lib/packet";
import { Bytes, rand, u16, u32 } from "@/lib/bytes";
import { dns, DnsRR, dnsName, eth, ipv4, udp } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

// ------------------------------------------------------------------ addresses
const RES = ADDR.dns; // validating resolver 192.0.2.53
const ROOT = "198.51.100.4";
const TLD = "192.0.2.30";
const TLD2 = "192.0.2.31";
const AUTH = "203.0.113.53";
const RES_MAC = "00:16:3e:44:05:53";
const GW_MAC = "00:16:3e:44:05:01";
const FAKE = "198.51.100.66";

// ------------------------------------------------------------------ keys (algorithm 13 = ECDSA P-256 with SHA-256)
const ALG = 13;
const KEYS = {
  rootKsk: 47131, rootZsk: 61050,
  comKsk: 19718, comZsk: 26838,
  exKsk: 31589, exZsk: 4820,
};
const INCEPTION = Date.UTC(2026, 10, 12) / 1000; // 2026-11-12
const EXPIRATION = Date.UTC(2026, 11, 3) / 1000; // 2026-12-03
const TYPE: Record<string, number> = { A: 1, NS: 2, DS: 43, DNSKEY: 48 };

const dnskey = (owner: string, flags: 256 | 257, tag: number, seed: number, ttl: number): DnsRR => ({
  name: owner, type: "DNSKEY", ttl,
  rdata: [...u16(flags), 3, ALG, ...rand(64, seed)],
  data: `${flags} 3 ${ALG} <64-byte P-256 public key> ; ${flags === 257 ? "KSK" : "ZSK"} id ${tag}`,
  note: `Flags ${flags} (${flags === 257 ? "zone key + secure entry point: the key-signing key" : "zone key: the zone-signing key"}), protocol 3 (always), algorithm 13 (ECDSA P-256/SHA-256), then the 64-byte public key (x and y of a curve point).`,
});

const rrsig = (owner: string, covered: string, labels: number, origTtl: number, tag: number, signer: string, seed: number): DnsRR => ({
  name: owner, type: "RRSIG", ttl: origTtl,
  rdata: [...u16(TYPE[covered]), ALG, labels, ...u32(origTtl), ...u32(EXPIRATION), ...u32(INCEPTION), ...u16(tag), ...dnsName(signer), ...rand(64, seed)],
  data: `${covered} ${ALG} ${labels} ${origTtl} 20261203000000 20261112000000 ${tag} ${signer} <64-byte signature>`,
  note: `Signature over the ${owner} ${covered} records: type covered, algorithm, label count, original TTL, valid 12 Nov to 3 Dec 2026, key tag ${tag} of the signing key in ${signer}, signer name, then the 64-byte ECDSA signature (r and s).`,
});

const ds = (owner: string, tag: number, seed: number): DnsRR => ({
  name: owner, type: "DS", ttl: 86400,
  rdata: [...u16(tag), ALG, 2, ...rand(32, seed)],
  data: `${tag} ${ALG} 2 <32-byte SHA-256 digest>`,
  note: `Delegation signer: key tag ${tag}, algorithm 13, digest type 2 (SHA-256), then the hash of the child zone’s key-signing key. Published in the parent zone.`,
});

const opt = (doBit: boolean, rdata?: Bytes, value?: string): DnsRR => ({
  name: "", type: "OPT", ttl: doBit ? 0x8000 : 0, cls: 1232, rdata, value: value ?? (doBit ? "UDP size 1232, DO" : "UDP size 1232"),
  note: doBit ? "EDNS with the DO bit (DNSSEC OK): please include RRSIG and other DNSSEC records." : undefined,
});

// ------------------------------------------------------------------ packet helpers
const resOut = (dst: string, sport: number, d: LayerSpec) =>
  build(eth({ src: RES_MAC, dst: GW_MAC }), ipv4({ src: RES, dst, ttl: 64, id: sport & 0xffff }), udp({ sport, dport: 53 }), d);
const resIn = (src: string, dport: number, d: LayerSpec, ttl = 55) =>
  build(eth({ src: GW_MAC, dst: RES_MAC }), ipv4({ src, dst: RES, ttl, id: dport ^ 0x5a5a }), udp({ sport: 53, dport }), d);

const Q = { name: "example.com", type: "A" };
const SP_CLIENT = 53117;

const clientQuery = (id: number) =>
  build(...up(RES), udp({ sport: SP_CLIENT, dport: 53 }), dns({ id, ad: true, qd: [Q], ar: [opt(false)] }));

// iterative queries from the resolver: RD off, DO on
const iterQ = (id: number, name: string, type: string) => dns({ id, rd: false, qd: [{ name, type }], ar: [opt(true)] });

const rootReferral = (id: number) => dns({
  id, response: true, rd: false, qd: [Q],
  ns: [
    { name: "com", type: "NS", ttl: 172800, data: "a.gtld-servers.net" },
    { name: "com", type: "NS", ttl: 172800, data: "b.gtld-servers.net" },
    ds("com", KEYS.comKsk, 11),
    rrsig("com", "DS", 1, 86400, KEYS.rootZsk, ".", 12),
  ],
  ar: [
    { name: "a.gtld-servers.net", type: "A", ttl: 172800, data: TLD, note: "Glue: the address of the .com server, so the resolver can reach it." },
    { name: "b.gtld-servers.net", type: "A", ttl: 172800, data: TLD2 },
    opt(true),
  ],
});

const rootKeys = (id: number) => dns({
  id, response: true, rd: false, aa: true, qd: [{ name: ".", type: "DNSKEY" }],
  an: [dnskey(".", 257, KEYS.rootKsk, 21, 172800), dnskey(".", 256, KEYS.rootZsk, 22, 172800), rrsig(".", "DNSKEY", 0, 172800, KEYS.rootKsk, ".", 23)],
  ar: [opt(true)],
});

const comReferral = (id: number) => dns({
  id, response: true, rd: false, qd: [Q],
  ns: [
    { name: "example.com", type: "NS", ttl: 172800, data: "ns1.example.com" },
    ds("example.com", KEYS.exKsk, 31),
    rrsig("example.com", "DS", 2, 86400, KEYS.comZsk, "com", 32),
  ],
  ar: [{ name: "ns1.example.com", type: "A", ttl: 172800, data: AUTH, note: "Glue for the example.com name server." }, opt(true)],
});

const comKeys = (id: number) => dns({
  id, response: true, rd: false, aa: true, qd: [{ name: "com", type: "DNSKEY" }],
  an: [dnskey("com", 257, KEYS.comKsk, 41, 86400), dnskey("com", 256, KEYS.comZsk, 42, 86400), rrsig("com", "DNSKEY", 1, 86400, KEYS.comKsk, "com", 43)],
  ar: [opt(true)],
});

const exAnswer = (id: number, addr: string) => dns({
  id, response: true, rd: false, aa: true, qd: [Q],
  an: [{ name: "example.com", type: "A", ttl: 300, data: addr }, rrsig("example.com", "A", 2, 300, KEYS.exZsk, "example.com", 51)],
  ar: [opt(true)],
});

const exKeys = (id: number) => dns({
  id, response: true, rd: false, aa: true, qd: [{ name: "example.com", type: "DNSKEY" }],
  an: [dnskey("example.com", 257, KEYS.exKsk, 61, 3600), dnskey("example.com", 256, KEYS.exZsk, 62, 3600), rrsig("example.com", "DNSKEY", 2, 3600, KEYS.exKsk, "example.com", 63)],
  ar: [opt(true)],
});

// ------------------------------------------------------------------ devices
const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: ADDR.laptop, x: 8, y: 50 },
  { id: "resolver", kind: "dns", label: "Validating resolver", sub: RES, x: 32, y: 50 },
  { id: "internet", kind: "cloud", label: "Internet", x: 57, y: 50 },
  { id: "root", kind: "dns", label: "Root server", sub: ROOT, x: 88, y: 17 },
  { id: "tld", kind: "dns", label: ".com server", sub: TLD, x: 88, y: 50 },
  { id: "auth", kind: "dns", label: "example.com DNS", sub: AUTH, x: 88, y: 83 },
];
const links: [string, string][] = [["client", "resolver"], ["resolver", "internet"], ["internet", "root"], ["internet", "tld"], ["internet", "auth"]];
const attackDevices: Device[] = [...devices, { id: "attacker", kind: "attacker", label: "On-path attacker", sub: "rewrites replies", x: 50, y: 82 }];
const attackLinks: [string, string][] = [...links, ["attacker", "resolver"], ["attacker", "internet"]];

const t = (n: number) => Number(n.toFixed(4));

export default defineLesson({
  id: "dnssec",
  name: "DNSSEC",
  full: "DNS Security Extensions",
  group: "naming",
  layer: 7,
  difficulty: 3,
  tagline: "Signed DNS answers, checked link by link from the root.",
  description:
    "DNSSEC adds digital signatures to DNS records. A validating resolver checks each signature with the zone’s public key, and checks that key with a hash published by the parent zone, all the way up to the root. A forged or altered answer fails the check and is thrown away.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "UDP/TCP 53, needs EDNS"],
    ["New records", "DNSKEY, RRSIG, DS, NSEC/NSEC3"],
    ["Common algorithm", "13: ECDSA P-256 / SHA-256"],
    ["Trust starts at", "The root key-signing key"],
    ["Defined in", "RFC 4033, 4034, 4035"],
  ],
  ports: "UDP/TCP 53",
  rfc: "RFC 4033–4035",
  keywords: ["dnssec", "rrsig", "dnskey", "ds", "chain of trust", "ksk", "zsk", "ad flag", "servfail", "bogus", "trust anchor", "validation"],
  related: ["dns", "doh", "tls"],
  devices,
  links,
  legend: [
    ["blue", "Queries"],
    ["violet", "Referrals and answers"],
    ["teal", "Keys and signatures"],
    ["green", "Validated answer"],
    ["red", "Tampered or failed"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Validating example.com from the root down",
      summary: "The resolver fetches signatures and keys at each level and only then returns the answer with the AD flag.",
      kind: "normal",
      steps: [
        {
          title: "Laptop asks",
          desc: "A normal query with the AD bit",
          detail: "The laptop asks its resolver for example.com, type A. It sets the AD bit in the query to say “tell me if you validated this”. The laptop does no crypto itself; it trusts the resolver to do the checking.",
          facts: [["Question", "example.com A"], ["Flags", "RD, AD"], ["Resolver", `${RES} (validating)`]],
          events: [
            pkt("client", "resolver", "blue", "QUERY", ["example.com A", "AD please"], {
              time: 0, info: "Standard query 0x1d3c A example.com OPT",
              packet: clientQuery(0x1d3c),
            }),
          ],
        },
        {
          title: "Root: referral plus DS",
          desc: "Go to .com, and here is .com’s key hash",
          detail: "The resolver asks a root server with the DO bit on. The root doesn’t know example.com, so it refers the resolver to the .com servers. With the referral comes a DS record (a SHA-256 hash of .com’s key-signing key) and an RRSIG over it, made with the root’s zone-signing key. The resolver also fetches the root’s DNSKEY set to check that signature. Note: the real root still uses RSA (algorithm 8); here every zone uses algorithm 13 to keep packets small.",
          facts: [["Referral", "com NS a/b.gtld-servers.net"], ["DS com", `${KEYS.comKsk} 13 2 (SHA-256)`], ["Root keys", `KSK ${KEYS.rootKsk}, ZSK ${KEYS.rootZsk}`]],
          quiz: {
            q: "Why does the root send a DS record for .com along with the referral?",
            options: ["To make the packet bigger", "So the resolver can later check that .com’s key is the right one", "It contains .com’s IP address", "It replaces the NS records"],
            answer: 1,
            why: "DS is the parent vouching for the child: a signed hash of the child’s key. It is the link that joins the two zones.",
          },
          events: [
            pkt("resolver", "root", "blue", "QUERY", ["example.com A", "DO bit"], {
              time: 0.0005, info: "Standard query 0xa41f A example.com OPT",
              packet: resOut(ROOT, 41933, iterQ(0xa41f, "example.com", "A")),
            }),
            pkt("root", "resolver", "violet", "REFERRAL", ["→ .com", "+ DS + RRSIG"], {
              time: 0.0125, info: "Standard query response 0xa41f A example.com NS a.gtld-servers.net NS b.gtld-servers.net DS RRSIG A 192.0.2.30 A 192.0.2.31 OPT",
              packet: resIn(ROOT, 41933, rootReferral(0xa41f)),
            }),
            pkt("resolver", "root", "teal", "DNSKEY?", [". DNSKEY"], {
              time: 0.013, info: "Standard query 0x63e2 DNSKEY <Root> OPT",
              packet: resOut(ROOT, 52210, iterQ(0x63e2, ".", "DNSKEY")),
            }),
            pkt("root", "resolver", "teal", "DNSKEY", ["KSK + ZSK", "+ RRSIG"], {
              time: 0.025, info: "Standard query response 0x63e2 DNSKEY <Root> DNSKEY DNSKEY RRSIG OPT",
              packet: resIn(ROOT, 52210, rootKeys(0x63e2)),
            }),
          ],
        },
        {
          title: ".com: referral plus DS",
          desc: "Same pattern, one level down",
          detail: `The .com server refers the resolver to ns1.example.com and includes the DS record for example.com, signed by .com’s zone-signing key (${KEYS.comZsk}). The resolver fetches .com’s DNSKEY set so it has that key, plus the key-signing key ${KEYS.comKsk} that the root’s DS points to.`,
          facts: [["Referral", `example.com NS ns1.example.com (${AUTH})`], ["DS example.com", `${KEYS.exKsk} 13 2`], ["com keys", `KSK ${KEYS.comKsk}, ZSK ${KEYS.comZsk}`]],
          events: [
            pkt("resolver", "tld", "blue", "QUERY", ["example.com A"], {
              time: 0.0255, info: "Standard query 0x0c95 A example.com OPT",
              packet: resOut(TLD, 60177, iterQ(0x0c95, "example.com", "A")),
            }),
            pkt("tld", "resolver", "violet", "REFERRAL", ["→ ns1.example.com", "+ DS + RRSIG"], {
              time: 0.0435, info: `Standard query response 0x0c95 A example.com NS ns1.example.com DS RRSIG A ${AUTH} OPT`,
              packet: resIn(TLD, 60177, comReferral(0x0c95)),
            }),
            pkt("resolver", "tld", "teal", "DNSKEY?", ["com DNSKEY"], {
              time: 0.044, info: "Standard query 0xd7a1 DNSKEY com OPT",
              packet: resOut(TLD, 38841, iterQ(0xd7a1, "com", "DNSKEY")),
            }),
            pkt("tld", "resolver", "teal", "DNSKEY", ["KSK + ZSK", "+ RRSIG"], {
              time: 0.062, info: "Standard query response 0xd7a1 DNSKEY com DNSKEY DNSKEY RRSIG OPT",
              packet: resIn(TLD, 38841, comKeys(0xd7a1)),
            }),
          ],
        },
        {
          title: "example.com: signed answer",
          desc: "The A record and its RRSIG",
          detail: `The example.com server answers with the A record ${ADDR.web} and an RRSIG over it, made by its zone-signing key ${KEYS.exZsk}. The resolver also fetches example.com’s DNSKEY set, which holds that zone-signing key and the key-signing key whose hash sits in the .com zone.`,
          facts: [["Answer", `example.com A ${ADDR.web}, TTL 300`], ["Signed by", `ZSK ${KEYS.exZsk}`], ["RRSIG valid", "12 Nov – 3 Dec 2026"]],
          quiz: {
            q: "Which example.com key signed the A record?",
            options: ["The key-signing key (flags 257)", "The zone-signing key (flags 256)", "The root key", "The .com key"],
            answer: 1,
            why: "The zone-signing key signs everyday records. The key-signing key only signs the DNSKEY set, which lets the ZSK be changed without asking the parent to update the DS.",
          },
          events: [
            pkt("resolver", "auth", "blue", "QUERY", ["example.com A"], {
              time: 0.0625, info: "Standard query 0x4b08 A example.com OPT",
              packet: resOut(AUTH, 47002, iterQ(0x4b08, "example.com", "A")),
            }),
            pkt("auth", "resolver", "violet", "ANSWER", [`A ${ADDR.web}`, "+ RRSIG"], {
              time: 0.0905, info: `Standard query response 0x4b08 A example.com A ${ADDR.web} RRSIG OPT`,
              packet: resIn(AUTH, 47002, exAnswer(0x4b08, ADDR.web), 52),
            }),
            pkt("resolver", "auth", "teal", "DNSKEY?", ["example.com DNSKEY"], {
              time: 0.091, info: "Standard query 0x91fe DNSKEY example.com OPT",
              packet: resOut(AUTH, 55640, iterQ(0x91fe, "example.com", "DNSKEY")),
            }),
            pkt("auth", "resolver", "teal", "DNSKEY", ["KSK + ZSK", "+ RRSIG"], {
              time: 0.119, info: "Standard query response 0x91fe DNSKEY example.com DNSKEY DNSKEY RRSIG OPT",
              packet: resIn(AUTH, 55640, exKeys(0x91fe), 52),
            }),
          ],
        },
        {
          title: "Walk the chain of trust",
          desc: "From the built-in root key down to the A record",
          detail: `The resolver ships with the root key-signing key ${KEYS.rootKsk} as its trust anchor. That key verifies the root DNSKEY set, so the root ZSK is trusted; it verifies the DS for .com; that hash matches .com’s KSK, which verifies .com’s keys; .com’s ZSK verifies the DS for example.com; that matches example.com’s KSK, which verifies its ZSK; and the ZSK verifies the A record. Every link holds, so the answer is “secure”.`,
          facts: [["Trust anchor", `Root KSK ${KEYS.rootKsk}`], ["Links checked", "9 (3 zones × 3)"], ["Result", "Secure"]],
          quiz: {
            q: "The resolver has the DS record for example.com. What must it check it against?",
            options: ["The A record", "A hash of example.com’s key-signing key from its DNSKEY set", "The .com NS records", "The root’s DS record"],
            answer: 1,
            why: "The resolver hashes example.com’s KSK itself and compares with the DS from .com. A match proves the parent vouches for that key.",
          },
          events: [
            note("resolver", "ROOT KEY ✓ → .COM DS ✓", "blue"),
            note("resolver", ".COM KEYS ✓ → EXAMPLE.COM DS ✓", "blue"),
            note("resolver", "ZSK ✓ → A RECORD ✓", "green"),
          ],
        },
        {
          title: "Answer with AD",
          desc: "Authenticated Data flag set",
          detail: `The resolver returns example.com A ${ADDR.web} to the laptop with the AD flag set, meaning “I validated this”. It caches the keys and DS records, so later lookups in .com or example.com skip most of this work. The laptop didn’t set DO, so it doesn’t receive the signatures themselves.`,
          facts: [["Answer", `A ${ADDR.web}`], ["Flags", "QR, RD, RA, AD"], ["Total time", "120 ms (cold cache)"]],
          quiz: {
            q: "The laptop is on a public café Wi-Fi. Can it fully trust the AD flag?",
            options: ["Yes, AD is signed", "Only if the path to the resolver is trusted, e.g. encrypted with DoH or DoT", "No, AD is never useful", "Only for A records"],
            answer: 1,
            why: "The AD flag itself is not signed. Someone between the laptop and the resolver could set it, so the stub needs a secure channel or its own validation.",
          },
          events: [
            pkt("resolver", "client", "green", "ANSWER", [`A ${ADDR.web}`, "AD = validated"], {
              time: 0.1195, info: `Standard query response 0x1d3c A example.com A ${ADDR.web} OPT`,
              packet: build(...down(RES, { ttl: 63 }), udp({ sport: 53, dport: SP_CLIENT }), dns({ id: 0x1d3c, response: true, ra: true, ad: true, qd: [Q], an: [{ name: "example.com", type: "A", ttl: 300, data: ADDR.web }], ar: [opt(false)] })),
            }),
            note("client", "SECURE (AD)", "green"),
          ],
        },
      ],
      outro: {
        title: "A verified answer",
        text: "Each zone signed its records with its own key, and each parent published a hash of its child’s key. Starting from one built-in root key, the resolver checked every link and handed back an answer marked AD.",
        facts: [["Queries by resolver", "6 (3 referrals/answers + 3 DNSKEY)"], ["Record types", "DNSKEY, RRSIG, DS"], ["Algorithm", "13: ECDSA P-256"], ["Flag", "AD = authenticated data"]],
      },
    },
    {
      id: "tampered",
      name: "A tampered answer becomes SERVFAIL",
      summary: "Someone on the path rewrites the A record. The signature no longer matches and the resolver refuses to answer.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "Ask again",
          desc: "Keys and DS already cached",
          detail: "A day later the A record has expired from the cache, but the keys and DS records are still cached. So the resolver asks example.com’s server directly, with the DO bit set.",
          facts: [["Cached", "Root, .com and example.com keys"], ["Query", "example.com A, DO"], ["Attacker", "Sits on the path to the resolver"]],
          events: [
            pkt("client", "resolver", "blue", "QUERY", ["example.com A"], {
              time: 0, info: "Standard query 0x7720 A example.com OPT",
              packet: clientQuery(0x7720),
            }),
            pkt("resolver", "auth", "blue", "QUERY", ["example.com A", "DO bit"], {
              time: 0.0005, info: "Standard query 0xe03b A example.com OPT",
              packet: resOut(AUTH, 49311, iterQ(0xe03b, "example.com", "A")),
            }),
          ],
        },
        {
          title: "The answer is altered",
          desc: `A changed to ${FAKE}`,
          detail: `An attacker on the path catches the real reply and rewrites the address to ${FAKE}, a server they control. They keep the original RRSIG, because they can’t make a new valid one without example.com’s private key. Without DNSSEC this would work perfectly.`,
          facts: [["Real address", ADDR.web], ["Forged address", FAKE], ["RRSIG", "Original, unchanged"]],
          quiz: {
            q: "What can the attacker NOT do?",
            options: ["Change the IP address", "Keep the old signature", "Make a valid signature for the new address", "Send the packet to the resolver"],
            answer: 2,
            why: "Signing needs example.com’s private zone-signing key, which never leaves the zone owner. Without it, any change breaks the signature.",
          },
          events: [
            note("attacker", "REWRITES A RECORD", "red"),
            pkt("attacker", "resolver", "red", "ANSWER", [`A ${FAKE}`, "old RRSIG"], {
              time: 0.0285, info: `Standard query response 0xe03b A example.com A ${FAKE} RRSIG OPT`,
              packet: resIn(AUTH, 49311, exAnswer(0xe03b, FAKE), 52),
            }),
          ],
        },
        {
          title: "Signature check fails",
          desc: "Bogus: the hash doesn’t match",
          detail: `The resolver hashes the A record it received (${FAKE}) and checks the RRSIG with example.com’s ZSK ${KEYS.exZsk}. The signature was made over ${ADDR.web}, so ECDSA verification fails. The answer is marked bogus and is not cached.`,
          facts: [["Key used", `ZSK ${KEYS.exZsk} (cached)`], ["Signed data", `A ${ADDR.web}`], ["Received", `A ${FAKE} → bogus`]],
          quiz: {
            q: "What does a validating resolver do with a bogus answer?",
            options: ["Passes it on without AD", "Returns SERVFAIL", "Returns NXDOMAIN", "Retries over HTTP"],
            answer: 1,
            why: "A bogus answer is worse than none. The resolver may retry other servers, but if every answer fails it returns SERVFAIL.",
          },
          events: [note("resolver", "RRSIG INVALID: BOGUS", "red")],
        },
        {
          title: "SERVFAIL",
          desc: "No answer is better than a wrong one",
          detail: "The laptop gets SERVFAIL with an Extended DNS Error, code 6 “DNSSEC Bogus”, explaining why. The browser can’t reach example.com, but it was not sent to the attacker’s server. An admin can query again with the CD (checking disabled) bit to see the raw, bogus data while debugging.",
          facts: [["RCODE", "2 (SERVFAIL)"], ["Extended error", "6: DNSSEC Bogus"], ["Debug", "dig +cd example.com"]],
          quiz: {
            q: "The same attack against a resolver that does NOT validate would…",
            options: ["Also give SERVFAIL", "Give the fake address to the laptop", "Give NXDOMAIN", "Be blocked by UDP"],
            answer: 1,
            why: "Signatures only help if someone checks them. A non-validating resolver ignores the RRSIG and passes the forged address on.",
          },
          events: [
            pkt("resolver", "client", "red", "SERVFAIL", ["EDE 6: bogus"], {
              time: 0.029, info: "Standard query response 0x7720 Server failure A example.com OPT",
              packet: build(...down(RES, { ttl: 63 }), udp({ sport: 53, dport: SP_CLIENT }), dns({
                id: 0x7720, response: true, ra: true, rcode: 2, qd: [Q],
                ar: [opt(false, [0x00, 0x0f, 0x00, 0x02, 0x00, 0x06], "UDP size 1232, EDE 6 (DNSSEC Bogus)")],
              })),
            }),
            note("client", "SERVFAIL, NOT FOOLED", "amber"),
          ],
        },
      ],
      outro: {
        title: "Tampering detected",
        text: "Changing even one byte of a signed record breaks its signature. The validating resolver spotted the mismatch, refused to cache or pass on the forged address, and told the laptop SERVFAIL instead.",
        facts: [["Attack", "On-path rewrite of the A record"], ["Detected by", "RRSIG check with the ZSK"], ["Result", "SERVFAIL + EDE 6"], ["Without DNSSEC", "Laptop sent to the fake server"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Record types",
      items: [["DNSKEY (48)", "A zone’s public keys: KSK (257) and ZSK (256)"], ["RRSIG (46)", "Signature over one set of records"], ["DS (43)", "Hash of the child’s KSK, kept in the parent"], ["NSEC / NSEC3", "Signed proof that a name does not exist"]],
    },
    {
      title: "Flags and bits",
      items: [["DO", "EDNS bit: send me DNSSEC records"], ["AD", "Answer was validated"], ["CD", "Checking disabled: don’t validate"], ["SERVFAIL", "Validation failed (or other server error)"]],
    },
    {
      title: "Numbers to know",
      items: [["Algorithm 13", "ECDSA P-256, 64-byte keys and signatures"], ["Algorithm 8", "RSA/SHA-256 (the root uses this)"], ["Digest type 2", "SHA-256, 32 bytes"], ["EDE 6", "DNSSEC Bogus (RFC 8914)"]],
    },
  ],
});
