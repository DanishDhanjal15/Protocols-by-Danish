import { defineLesson, note, pkt, Step } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { BROADCAST_MAC, eth, ipv4, tcp } from "@/lib/proto";
import { Bytes, hex, ip4, rand, text, toHex } from "@/lib/bytes";
import { ADDR } from "./_common";

// ------------------------------------------------------------------ addresses

const R_MAC = "b0:be:76:12:4c:02"; // router's WAN port
const B_MAC = "00:90:1a:a2:33:10"; // the ISP's access concentrator (BRAS)
const SID = 0x1a2b; // session id handed out in PADS
const WAN_IP = ADDR.routerWan; // 198.51.100.7
const BRAS_IP = "198.51.100.1";
const DNS1 = "192.0.2.53";
const DNS2 = "192.0.2.54";
const USER = "danish@isp.example";
const AC_NAME = "bras-01.isp.example";
const HOST_UNIQ = hex("5d 1c 00 00 2a 7f 00 00");
const COOKIE = rand(16, 4401);
const MAGIC_R = hex("3e 8a 15 c2");
const MAGIC_B = hex("71 0b 9d 44");

const h4 = (n: number) => `0x${n.toString(16).padStart(4, "0")}`;
const h2 = (n: number) => `0x${n.toString(16).padStart(2, "0")}`;
const t = (n: number) => Number(n.toFixed(4));
const specLen = (specs: FieldSpec[]) => specs.map(field).flatMap((f) => f.bytes).length;

// ------------------------------------------------------------------ PPPoE discovery (EtherType 0x8863)

const DISC_CODES = { PADI: 0x09, PADO: 0x07, PADR: 0x19, PADS: 0x65, PADT: 0xa7 } as const;
type DiscCode = keyof typeof DISC_CODES;
const DISC_MEANING: Record<DiscCode, string> = {
  PADI: "Active Discovery Initiation",
  PADO: "Active Discovery Offer",
  PADR: "Active Discovery Request",
  PADS: "Active Discovery Session-confirmation",
  PADT: "Active Discovery Terminate",
};

function tag(type: number, name: string, data: Bytes, value: string, note?: string): FieldSpec {
  return {
    name: `Tag: ${name}`,
    value,
    note,
    fields: [
      { name: "Tag type", u16: type, value: `${h4(type)} (${name})` },
      { name: "Tag length", u16: data.length },
      ...(data.length ? [{ name: "Tag value", bytes: data, value }] : []),
    ],
  };
}

const svcName = () => tag(0x0101, "Service-Name", [], "(any service)", "Empty means: any service is fine.");
const acName = () => tag(0x0102, "AC-Name", text(AC_NAME), AC_NAME, "The name of the access concentrator that is answering.");
const hostUniq = () => tag(0x0103, "Host-Uniq", HOST_UNIQ, toHex(HOST_UNIQ, ""), "A value the router picks so it can match replies to its own request. The server must echo it.");
const acCookie = () => tag(0x0104, "AC-Cookie", COOKIE, "16 bytes", "Opaque value from the server. The router must send it back in PADR, which protects against fake floods.");

function disc(code: DiscCode, sid: number, tags: FieldSpec[]): LayerSpec {
  return proto({
    id: "pppoed",
    name: "PPPoE Discovery",
    osi: 2,
    ethertype: 0x8863,
    summary: `PPP-over-Ethernet Discovery, Code ${code}, Session ID ${h4(sid)}`,
    fields: [
      { name: "Version, type", u8: 0x11, value: "1, 1", note: "Always 0x11 for PPPoE." },
      { name: "Code", u8: DISC_CODES[code], value: `${h2(DISC_CODES[code])} (${code}, ${DISC_MEANING[code]})` },
      { name: "Session ID", u16: sid, value: h4(sid), note: sid ? "The session this message belongs to." : "Zero: no session exists yet." },
      { name: "Payload length", u16: specLen(tags), value: `${specLen(tags)} bytes`, note: "Length of the tags that follow." },
      ...tags,
    ],
  });
}

// ------------------------------------------------------------------ PPPoE session (EtherType 0x8864) + PPP

function sess(sid = SID): LayerSpec {
  return {
    kind: "pppoes",
    ethertype: 0x8864,
    build: (payload) => ({
      id: "pppoes",
      name: "PPPoE Session",
      osi: 2,
      summary: `PPP-over-Ethernet Session, Session ID ${h4(sid)}, Payload Length ${payload.length}`,
      fields: [
        field({ name: "Version, type", u8: 0x11, value: "1, 1" }),
        field({ name: "Code", u8: 0, value: "0x00 (Session data)", note: "Code is always zero once the session is up." }),
        field({ name: "Session ID", u16: sid, value: h4(sid), note: "Agreed in PADS. With the two MAC addresses it identifies this session." }),
        field({ name: "Payload length", u16: payload.length, value: `${payload.length} bytes`, note: "The PPP frame that follows, including its 2-byte protocol field." }),
      ],
    }),
  };
}

const PPP_PROTOS: Record<number, string> = { 0xc021: "LCP", 0xc223: "CHAP", 0x8021: "IPCP", 0x0021: "IPv4" };
const ppp = (p: number): LayerSpec =>
  proto({
    id: "ppp",
    name: "PPP",
    osi: 2,
    summary: `Point-to-Point Protocol, Protocol: ${PPP_PROTOS[p]} (${h4(p)})`,
    fields: [{ name: "Protocol", u16: p, value: `${h4(p)} (${PPP_PROTOS[p]})`, note: "Which protocol is inside. PPPoE drops PPP’s usual address and control bytes (FF 03)." }],
  });

const LCP_CODES: Record<number, string> = { 1: "Configure-Request", 2: "Configure-Ack", 3: "Configure-Nak", 4: "Configure-Reject", 5: "Terminate-Request", 6: "Terminate-Ack" };
const CHAP_CODES: Record<number, string> = { 1: "Challenge", 2: "Response", 3: "Success", 4: "Failure" };

/** LCP / IPCP / CHAP packet: code(1) identifier(1) length(2) + body */
function ctl(kind: "lcp" | "ipcp" | "chap", code: number, ident: number, body: FieldSpec[]): LayerSpec {
  const names = kind === "chap" ? CHAP_CODES : LCP_CODES;
  const full = kind === "lcp" ? "Link Control Protocol" : kind === "ipcp" ? "Internet Protocol Control Protocol" : "Challenge Handshake Authentication Protocol";
  const len = 4 + specLen(body);
  return proto({
    id: kind,
    name: kind.toUpperCase(),
    osi: kind === "ipcp" ? 3 : 2,
    summary: `${full}, ${names[code]}, Identifier ${ident}`,
    fields: [
      { name: "Code", u8: code, value: `${code} (${names[code]})` },
      { name: "Identifier", u8: ident, note: "Matches a reply to its request." },
      { name: "Length", u16: len, value: `${len} bytes`, note: "This whole packet: code, identifier, length and body." },
      ...body,
    ],
  });
}

function opt(type: number, name: string, data: Bytes, value: string, note?: string): FieldSpec {
  return {
    name: `Option: ${name}`,
    value,
    note,
    fields: [
      { name: "Type", u8: type, value: `${type} (${name})` },
      { name: "Length", u8: 2 + data.length },
      { name: "Data", bytes: data, value },
    ],
  };
}

const mru = () => opt(1, "Maximum-Receive-Unit", hex("05d4"), "1492", "1500-byte Ethernet minus 8 bytes of PPPoE and PPP headers.");
const magic = (m: Bytes) => opt(5, "Magic-Number", m, `0x${toHex(m, "")}`, "A random number. If a side ever sees its own number come back, the line is looped.");
const authChap = () => opt(3, "Authentication-Protocol", hex("c223 05"), "CHAP with MD5", "The ISP says: prove who you are with CHAP, using MD5.");
const ipAddr = (ip: string) => opt(3, "IP-Address", ip4(ip), ip);
const dns1 = (ip: string) => opt(129, "Primary-DNS-Address", ip4(ip), ip);
const dns2 = (ip: string) => opt(131, "Secondary-DNS-Address", ip4(ip), ip);

const routerLcp = () => [mru(), magic(MAGIC_R)];
const brasLcp = () => [mru(), authChap(), magic(MAGIC_B)];
const challenge = () => [
  { name: "Value size", u8: 16 },
  { name: "Challenge value", bytes: rand(16, 911), value: "16 random bytes", note: "Fresh for every login, so an old answer can’t be replayed." },
  { name: "Name", text: AC_NAME, value: AC_NAME },
];
const response = (seed: number) => [
  { name: "Value size", u8: 16 },
  { name: "Response value", bytes: rand(16, seed), value: "MD5 hash", note: "MD5(identifier + password + challenge). The password itself never crosses the wire." },
  { name: "Name", text: USER, value: USER, note: "The broadband username." },
];

// ------------------------------------------------------------------ frames

const toBras = (...inner: LayerSpec[]) => build(eth({ src: R_MAC, dst: B_MAC }), sess(), ...inner);
const toRouter = (...inner: LayerSpec[]) => build(eth({ src: B_MAC, dst: R_MAC }), sess(), ...inner);

const discovery = (base: number): Step["events"] => [
  pkt("router", "bras", "blue", "PADI", ["broadcast", "any ISP out there?"], {
    time: t(base), info: "Active Discovery Initiation (PADI)",
    packet: build(eth({ src: R_MAC, dst: BROADCAST_MAC }), disc("PADI", 0, [svcName(), hostUniq()])),
  }),
  pkt("bras", "router", "blue", "PADO", [AC_NAME, "I can serve you"], {
    time: t(base + 0.003), info: `Active Discovery Offer (PADO) AC-Name='${AC_NAME}'`,
    packet: build(eth({ src: B_MAC, dst: R_MAC }), disc("PADO", 0, [acName(), svcName(), hostUniq(), acCookie()])),
  }),
];
const sessionSetup = (base: number): Step["events"] => [
  pkt("router", "bras", "blue", "PADR", ["I pick you", "cookie echoed"], {
    time: t(base), info: "Active Discovery Request (PADR)",
    packet: build(eth({ src: R_MAC, dst: B_MAC }), disc("PADR", 0, [svcName(), hostUniq(), acCookie()])),
  }),
  pkt("bras", "router", "green", "PADS", [`session ${h4(SID)}`], {
    time: t(base + 0.003), info: `Active Discovery Session-confirmation (PADS) Session ID ${h4(SID)}`,
    packet: build(eth({ src: B_MAC, dst: R_MAC }), disc("PADS", SID, [svcName(), hostUniq()])),
  }),
];
const lcpEvents = (base: number): Step["events"] => [
  pkt("router", "bras", "blue", "LCP REQ", ["MRU 1492", "magic 3e8a15c2"], {
    time: t(base), info: "Configuration Request id=1",
    packet: toBras(ppp(0xc021), ctl("lcp", 1, 1, routerLcp())),
  }),
  pkt("bras", "router", "blue", "LCP REQ", ["MRU 1492", "auth: CHAP MD5"], {
    time: t(base + 0.0005), parallel: true, info: "Configuration Request id=12",
    packet: toRouter(ppp(0xc021), ctl("lcp", 1, 12, brasLcp())),
  }),
  pkt("bras", "router", "green", "LCP ACK", ["your options OK"], {
    time: t(base + 0.003), info: "Configuration Ack id=1",
    packet: toRouter(ppp(0xc021), ctl("lcp", 2, 1, routerLcp())),
  }),
  pkt("router", "bras", "green", "LCP ACK", ["yours OK too"], {
    time: t(base + 0.0035), parallel: true, info: "Configuration Ack id=12",
    packet: toBras(ppp(0xc021), ctl("lcp", 2, 12, brasLcp())),
  }),
];
const chapStart = (base: number, seed: number): Step["events"] => [
  pkt("bras", "router", "teal", "CHALLENGE", ["16 random bytes"], {
    time: t(base), info: `Challenge (NAME='${AC_NAME}', VALUE=0x${toHex(rand(16, 911), "").slice(0, 16)}…)`,
    packet: toRouter(ppp(0xc223), ctl("chap", 1, 1, challenge())),
  }),
  pkt("router", "bras", "teal", "RESPONSE", ["MD5 hash", USER], {
    time: t(base + 0.004), info: `Response (NAME='${USER}', VALUE=0x${toHex(rand(16, seed), "").slice(0, 16)}…)`,
    packet: toBras(ppp(0xc223), ctl("chap", 2, 1, response(seed))),
  }),
];

// ------------------------------------------------------------------ devices

const devices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: ADDR.laptop, x: 8, y: 66 },
  { id: "router", kind: "router" as const, label: "Home router", sub: "PPPoE client", x: 28, y: 66 },
  { id: "modem", kind: "switch" as const, label: "Fibre ONT", sub: "bridges Ethernet", x: 48, y: 66 },
  { id: "bras", kind: "isp" as const, label: "ISP BRAS", sub: AC_NAME.split(".")[0], x: 68, y: 50 },
  { id: "radius", kind: "auth" as const, label: "RADIUS", sub: "user accounts", x: 88, y: 76 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 88, y: 24 },
];
const links: [string, string][] = [
  ["client", "router"],
  ["router", "modem"],
  ["modem", "bras"],
  ["bras", "radius"],
  ["bras", "internet"],
];

const WEB = ADDR.web;

export default defineLesson({
  id: "pppoe",
  name: "PPPoE",
  full: "Point-to-Point Protocol over Ethernet",
  group: "lan",
  layer: 2,
  difficulty: 2,
  tagline: "How your home router logs in to the broadband network.",
  description:
    "Many fibre and DSL providers make your router log in before it gets online. PPPoE finds the ISP’s access concentrator over Ethernet, then runs PPP inside it to agree link settings, check your username and password, and hand out your public IP address and DNS servers.",
  facts: [
    ["Layer", "Data link (Layer 2)"],
    ["EtherTypes", "0x8863 discovery, 0x8864 session"],
    ["Login", "CHAP or PAP inside PPP"],
    ["Overhead", "8 bytes (MTU 1492)"],
    ["Defined in", "RFC 2516 (PPPoE), RFC 1661 (PPP)"],
  ],
  ports: "No ports: EtherTypes 0x8863 and 0x8864",
  rfc: "RFC 2516, RFC 1661, RFC 1994, RFC 1332",
  keywords: ["pppoe", "ppp", "broadband", "padi", "pado", "padr", "pads", "padt", "lcp", "chap", "ipcp", "bras", "mtu 1492", "fibre", "dsl"],
  related: ["ethernet", "dhcp", "radius", "ip", "tcp"],
  devices,
  links,
  legend: [
    ["blue", "Discovery and link setup"],
    ["teal", "Login (CHAP)"],
    ["green", "Accepted"],
    ["amber", "Your internet traffic"],
    ["slate", "Hanging up"],
    ["red", "Errors"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "The router dials in",
      summary: "The router finds the ISP, logs in with CHAP, gets a public IP, carries traffic, then hangs up.",
      kind: "normal",
      steps: [
        {
          title: "Shout for an ISP",
          desc: "PADI broadcast, then a PADO offer",
          detail:
            "The router doesn’t know the ISP’s MAC address yet, so it broadcasts a PADI on the WAN port. Every access concentrator that hears it can reply with a PADO. The router’s Host-Uniq tag comes back unchanged so it knows the offer answers its own request.",
          facts: [["PADI to", "ff:ff:ff:ff:ff:ff"], ["EtherType", "0x8863 (Discovery)"], ["Session ID", "0 (none yet)"]],
          quiz: {
            q: "The PADI goes to the broadcast address. Why?",
            options: ["Broadcasts are faster", "The router doesn’t know any ISP MAC address yet", "PPPoE has no unicast", "To reach the RADIUS server directly"],
            answer: 1,
            why: "Just like DHCP, the first message is broadcast because the router has no idea who will answer. Replies are unicast.",
          },
          events: discovery(0),
        },
        {
          title: "Pick an offer",
          desc: "PADR request, PADS gives a session ID",
          detail: `The router picks the first offer and sends a unicast PADR, echoing the AC-Cookie to prove it really saw the PADO. The concentrator answers with PADS, which carries a session ID, here ${h4(SID)}. From now on every frame uses EtherType 0x8864 and that ID.`,
          facts: [["Chosen AC", AC_NAME], ["Session ID", h4(SID)], ["Discovery took", "4 frames, about 7 ms"]],
          quiz: {
            q: "What Session ID does the PADR itself carry?",
            options: ["0", h4(SID), "The Host-Uniq value", "0xffff"],
            answer: 0,
            why: "The session ID is only created by the PADS reply, so every discovery message before it carries 0.",
          },
          events: sessionSetup(0.006),
        },
        {
          title: "Agree link settings",
          desc: "LCP Configure-Request and Ack, both ways",
          detail:
            "Now PPP starts inside the session. Each side sends an LCP Configure-Request with the options it wants, and the other side acknowledges them. The ISP asks for a 1492-byte MRU and says the login will use CHAP with MD5. Each side also picks a random magic number to detect looped lines.",
          facts: [["PPP protocol", "0xc021 (LCP)"], ["MRU", "1492 bytes"], ["Login method", "CHAP (MD5)"]],
          quiz: {
            q: "Why is the MRU 1492 and not 1500?",
            options: ["The ISP is saving bandwidth", "PPPoE and PPP headers take 8 bytes of every 1500-byte Ethernet frame", "1492 is a CHAP rule", "Fibre can’t carry 1500 bytes"],
            answer: 1,
            why: "6 bytes of PPPoE header plus 2 bytes of PPP protocol field sit inside the 1500-byte Ethernet payload, leaving 1492 for IP.",
          },
          events: lcpEvents(0.012),
        },
        {
          title: "Prove who you are",
          desc: "CHAP challenge, response, success",
          detail:
            "The concentrator sends 16 random bytes. The router hashes the identifier, its broadband password and the challenge with MD5, and sends only the hash plus the username. The concentrator asks the RADIUS server, which does the same sum with the stored password. They match, so the answer is Success.",
          facts: [["PPP protocol", "0xc223 (CHAP)"], ["Password sent?", "No, only an MD5 hash"], ["Checked by", "RADIUS server"]],
          quiz: {
            q: "Someone captures the CHAP Response. Can they log in later by replaying it?",
            options: ["Yes, it is the password", "No, the next login uses a new random challenge", "Only on the same day", "Yes, if they spoof the MAC"],
            answer: 1,
            why: "The hash depends on the challenge, which is fresh every time. An old response won’t match a new challenge.",
          },
          events: [
            ...chapStart(0.017, 5150),
            note("radius", "PASSWORD MATCHES", "green"),
            pkt("bras", "router", "green", "SUCCESS", ["welcome"], {
              time: 0.031, info: "Success (MESSAGE='Welcome to Example ISP')",
              packet: toRouter(ppp(0xc223), ctl("chap", 3, 1, [{ name: "Message", text: "Welcome to Example ISP", value: "Welcome to Example ISP" }])),
            }),
          ],
        },
        {
          title: "Get an IP address",
          desc: "IPCP hands out the public IP and DNS",
          detail: `There is no DHCP here. The router asks with IPCP for address 0.0.0.0 and DNS 0.0.0.0, which means “please tell me”. The concentrator answers with a Configure-Nak that fills in ${WAN_IP} and DNS servers ${DNS1} and ${DNS2}. The router asks again with those values and gets an Ack.`,
          facts: [["Public IP", WAN_IP], ["DNS", `${DNS1}, ${DNS2}`], ["ISP side", BRAS_IP]],
          quiz: {
            q: "The router asks for IP 0.0.0.0. What does the concentrator send back?",
            options: ["Configure-Ack with 0.0.0.0", `Configure-Nak suggesting ${WAN_IP}`, "Configure-Reject", "A DHCP Offer"],
            answer: 1,
            why: "A Nak means “not that value, use this one instead”. The router then repeats its request with the suggested address.",
          },
          events: [
            pkt("bras", "router", "blue", "IPCP REQ", [`my IP ${BRAS_IP}`], {
              time: 0.032, info: `Configuration Request id=1 IP=${BRAS_IP}`,
              packet: toRouter(ppp(0x8021), ctl("ipcp", 1, 1, [ipAddr(BRAS_IP)])),
            }),
            pkt("router", "bras", "blue", "IPCP REQ", ["IP 0.0.0.0?", "DNS 0.0.0.0?"], {
              time: 0.0325, parallel: true, info: "Configuration Request id=1 IP=0.0.0.0 DNS1=0.0.0.0 DNS2=0.0.0.0",
              packet: toBras(ppp(0x8021), ctl("ipcp", 1, 1, [ipAddr("0.0.0.0"), dns1("0.0.0.0"), dns2("0.0.0.0")])),
            }),
            pkt("router", "bras", "green", "IPCP ACK", ["OK"], {
              time: 0.034, info: `Configuration Ack id=1 IP=${BRAS_IP}`,
              packet: toBras(ppp(0x8021), ctl("ipcp", 2, 1, [ipAddr(BRAS_IP)])),
            }),
            pkt("bras", "router", "blue", "IPCP NAK", [`use ${WAN_IP}`, `DNS ${DNS1}`], {
              time: 0.0345, parallel: true, info: `Configuration Nak id=1 IP=${WAN_IP} DNS1=${DNS1} DNS2=${DNS2}`,
              packet: toRouter(ppp(0x8021), ctl("ipcp", 3, 1, [ipAddr(WAN_IP), dns1(DNS1), dns2(DNS2)])),
            }),
            pkt("router", "bras", "blue", "IPCP REQ", [`IP ${WAN_IP}`], {
              time: 0.036, info: `Configuration Request id=2 IP=${WAN_IP} DNS1=${DNS1} DNS2=${DNS2}`,
              packet: toBras(ppp(0x8021), ctl("ipcp", 1, 2, [ipAddr(WAN_IP), dns1(DNS1), dns2(DNS2)])),
            }),
            pkt("bras", "router", "green", "IPCP ACK", ["agreed"], {
              time: 0.039, info: `Configuration Ack id=2 IP=${WAN_IP} DNS1=${DNS1} DNS2=${DNS2}`,
              packet: toRouter(ppp(0x8021), ctl("ipcp", 2, 2, [ipAddr(WAN_IP), dns1(DNS1), dns2(DNS2)])),
            }),
            note("router", `ONLINE: ${WAN_IP}`, "green"),
          ],
        },
        {
          title: "Carry real traffic",
          desc: "IP packets inside PPP inside PPPoE",
          detail: `The laptop opens a web connection. The router swaps the laptop’s private address for ${WAN_IP} and wraps the packet in a PPP header (protocol 0x0021) and a PPPoE session header. It also lowers the TCP MSS to 1452 so full-size segments still fit in 1492 bytes.`,
          facts: [["Stack", "Ethernet → PPPoE → PPP → IPv4 → TCP"], ["Extra bytes", "8 per packet"], ["TCP MSS", "1452 (clamped)"]],
          quiz: {
            q: "The MTU is 1492. What is the largest TCP payload (MSS) that fits?",
            options: ["1460", "1452", "1492", "1500"],
            answer: 1,
            why: "1492 minus 20 bytes of IP header minus 20 bytes of TCP header leaves 1452.",
          },
          events: [
            pkt("router", "internet", "amber", "SYN", ["over PPPoE", "MSS 1452"], {
              time: 0.5, info: "51234 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1452",
              packet: toBras(ppp(0x0021), ipv4({ src: WAN_IP, dst: WEB, ttl: 63, id: 0x4b10 }), tcp({ sport: 51234, dport: 443, seq: 0, flags: "S", opts: [{ mss: 1452 }, "nop", "nop", "sackOk", "nop", { ws: 7 }], seqBase: 0x2c41a900 })),
            }),
            pkt("internet", "router", "amber", "SYN-ACK", ["back to", WAN_IP], {
              time: 0.521, info: "443 → 51234 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1452",
              packet: toRouter(ppp(0x0021), ipv4({ src: WEB, dst: WAN_IP, ttl: 55, id: 0x0000 }), tcp({ sport: 443, dport: 51234, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1452 }, "nop", "nop", "sackOk", "nop", { ws: 7 }], seqBase: 0x7710be00, ackBase: 0x2c41a900 })),
            }),
          ],
        },
        {
          title: "Hang up",
          desc: "LCP Terminate, then PADT",
          detail:
            "When the router reboots or the user disconnects, PPP closes politely with an LCP Terminate-Request and Terminate-Ack. Then the router sends PADT to tear down the PPPoE session itself, so the ISP can free the session ID and the public IP.",
          facts: [["PPP close", "Terminate-Request / Ack"], ["PPPoE close", "PADT (code 0xa7)"], ["Freed", `Session ${h4(SID)}, IP ${WAN_IP}`]],
          events: [
            pkt("router", "bras", "slate", "LCP TERM", ["user request"], {
              time: 60, info: "Termination Request id=2",
              packet: toBras(ppp(0xc021), ctl("lcp", 5, 2, [{ name: "Data", text: "User request", value: "User request" }])),
            }),
            pkt("bras", "router", "slate", "TERM ACK", ["bye"], {
              time: 60.003, info: "Termination Ack id=2",
              packet: toRouter(ppp(0xc021), ctl("lcp", 6, 2, [])),
            }),
            pkt("router", "bras", "slate", "PADT", [`end ${h4(SID)}`], {
              time: 60.004, info: `Active Discovery Terminate (PADT) Session ID ${h4(SID)}`,
              packet: build(eth({ src: R_MAC, dst: B_MAC }), disc("PADT", SID, [])),
            }),
          ],
        },
      ],
      outro: {
        title: "Logged in, used, logged out",
        text: "PPPoE found the ISP with four discovery frames, then PPP set up the link with LCP, checked the password with CHAP and handed out an address with IPCP. Every packet after that carried 8 extra bytes, which is why PPPoE links use a 1492-byte MTU.",
        facts: [["Discovery", "PADI → PADO → PADR → PADS"], ["PPP phases", "LCP → CHAP → IPCP"], ["Public IP", WAN_IP], ["MTU", "1492"]],
      },
    },
    {
      id: "chap-fail",
      name: "Wrong broadband password",
      summary: "The router finds the ISP fine, but its CHAP response doesn’t match and the session is torn down.",
      kind: "failure",
      steps: [
        {
          title: "Session comes up",
          desc: "Discovery and LCP work as normal",
          detail:
            "Discovery and LCP don’t check any password, so everything looks normal at first. The router gets a session ID and agrees the link options, including CHAP as the login method.",
          facts: [["Discovery", "OK"], ["Session ID", h4(SID)], ["LCP", "Agreed"]],
          events: [...sessionSetup(0), ...lcpEvents(0.006)],
        },
        {
          title: "Answer the challenge",
          desc: "The hash is built from the wrong password",
          detail:
            "Someone typed the password with a typo into the router’s settings. The router still hashes it with the challenge and sends the result. Nothing in the packet looks wrong, because the password is never sent itself.",
          facts: [["Username", USER], ["Password", "Wrong (typo)"], ["Hash", "Doesn’t match"]],
          quiz: {
            q: "How does the ISP find out the password is wrong?",
            options: ["It decrypts the password from the response", "It computes the expected hash and compares", "The router says so", "LCP reports it"],
            answer: 1,
            why: "RADIUS computes MD5 over the same identifier, challenge and the stored password. A different result means a different password.",
          },
          events: [...chapStart(0.012, 6262), note("radius", "HASH MISMATCH", "red")],
        },
        {
          title: "Rejected",
          desc: "CHAP Failure, then the session is closed",
          detail:
            "The concentrator sends CHAP Failure, closes PPP with an LCP Terminate-Request, and ends the PPPoE session with PADT. The router shows an authentication error (often “PPP authentication failed”) and retries after a pause. Repeated failures may get the line blocked for a while.",
          facts: [["CHAP code", "4 (Failure)"], ["Then", "LCP Terminate + PADT"], ["Router shows", "Authentication failed"]],
          quiz: {
            q: "Who sends the PADT this time?",
            options: ["The router", "The ISP’s concentrator", "The RADIUS server", "Nobody, it times out"],
            answer: 1,
            why: "The ISP decided the login failed, so it ends the session it created. Either side may send PADT.",
          },
          events: [
            pkt("bras", "router", "red", "FAILURE", ["wrong password"], {
              time: 0.03, info: "Failure (MESSAGE='Authentication failed')",
              packet: toRouter(ppp(0xc223), ctl("chap", 4, 1, [{ name: "Message", text: "Authentication failed", value: "Authentication failed" }])),
            }),
            pkt("bras", "router", "slate", "LCP TERM", ["closing link"], {
              time: 0.031, info: "Termination Request id=13",
              packet: toRouter(ppp(0xc021), ctl("lcp", 5, 13, [{ name: "Data", text: "Authentication failed", value: "Authentication failed" }])),
            }),
            pkt("router", "bras", "slate", "TERM ACK", ["ok"], {
              time: 0.034, info: "Termination Ack id=13",
              packet: toBras(ppp(0xc021), ctl("lcp", 6, 13, [])),
            }),
            pkt("bras", "router", "slate", "PADT", [`end ${h4(SID)}`], {
              time: 0.035, info: `Active Discovery Terminate (PADT) Session ID ${h4(SID)}`,
              packet: build(eth({ src: B_MAC, dst: R_MAC }), disc("PADT", SID, [tag(0x0203, "Generic-Error", text("Authentication failed"), "Authentication failed", "A human-readable reason for ending the session.")])),
            }),
            note("router", "PPP AUTH FAILED", "red"),
          ],
        },
      ],
      outro: {
        title: "No internet until the password is fixed",
        text: "Discovery and LCP succeed without any password, so a wrong password only shows up at the CHAP step. The ISP answers with Failure and tears everything down. Because CHAP never sends the password, the fix is always on the router: re-enter the exact username and password from the ISP.",
        facts: [["Failed at", "CHAP Response"], ["Error", "CHAP Failure (code 4)"], ["Fix", "Re-enter credentials on the router"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Discovery codes (0x8863)",
      items: [["PADI 0x09", "Router broadcasts: who can serve me?"], ["PADO 0x07", "Concentrator offers"], ["PADR 0x19", "Router picks one"], ["PADS 0x65", "Session ID confirmed"], ["PADT 0xa7", "Session ended (either side)"]],
    },
    {
      title: "PPP protocols (0x8864)",
      items: [["0xc021 LCP", "Link options: MRU, auth method, magic number"], ["0xc223 CHAP", "Challenge/response login"], ["0xc023 PAP", "Plain-text login (avoid)"], ["0x8021 IPCP", "IP address and DNS"], ["0x0021", "An IPv4 packet"]],
    },
    {
      title: "Numbers to know",
      items: [["PPPoE + PPP overhead", "8 bytes"], ["MTU / MRU", "1492"], ["TCP MSS", "1452"], ["Common tags", "Service-Name 0x0101, AC-Name 0x0102, Host-Uniq 0x0103, AC-Cookie 0x0104"]],
    },
  ],
});
