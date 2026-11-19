import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { ipv4, tcp, TcpOpt, udp } from "@/lib/proto";

// Radio (RRC) and NAS messages are shown with simplified, byte-aligned fields: real RRC is
// ASN.1 PER bit-packed. NAS 5GMM headers, IE sizes and the GTP-U/IP/UDP/TCP bytes are real.

// ---------------------------------------------------------------- addresses

const GNB = "192.0.2.10"; // tower's N3 (user plane) address
const UPF = "192.0.2.20";
const UE_IP = "10.45.0.7"; // handed to the phone in the PDU session
const NAT_IP = "198.51.100.200";
const WEB = "203.0.113.10";
const TEID_UL = 0x0000a1b2; // chosen by the UPF: gNB puts it on uplink packets
const TEID_DL = 0x00c0ffee; // chosen by the gNB: UPF puts it on downlink packets

// ---------------------------------------------------------------- simplified radio + NAS layers

const rrc = (name: string, fields: FieldSpec[], summary?: string): LayerSpec =>
  proto({ id: "rrc", name: `RRC ${name}`, osi: 3, summary: summary ?? `NR RRC ${name} (simplified)`, fields });

const nas = (name: string, fields: FieldSpec[], summary?: string): LayerSpec =>
  proto({ id: "nas", name: `5G NAS ${name}`, osi: 3, summary: summary ?? `NAS-5GS ${name}`, fields });

const EPD: FieldSpec = { name: "Extended protocol discriminator", u8: 0x7e, value: "0x7e (5G mobility management)" };
const plainHdr: FieldSpec = { name: "Security header type", u8: 0x00, value: "0 (plain, not protected)", note: "Nothing is protected yet: no keys exist." };
const msgType = (t: number, name: string): FieldSpec => ({ name: "Message type", u8: t, value: `0x${t.toString(16)} (${name})` });

/** A protected NAS message: outer header + MAC + sequence number, then the inner message. */
const protectedNas = (name: string, hdr: number, sqn: number, inner: FieldSpec[], seed: number): LayerSpec =>
  nas(name, [
    EPD,
    { name: "Security header type", u8: hdr, value: hdr === 3 ? "3 (integrity protected, new context)" : hdr === 4 ? "4 (integrity + ciphered, new context)" : "2 (integrity protected and ciphered)" },
    { name: "Message authentication code", random: 4, seed, opaque: true, note: "A 32-bit integrity tag: any change to the message is detected." },
    { name: "Sequence number", u8: sqn, note: "Counts NAS messages so old ones can’t be replayed." },
    ...inner,
  ]);

const ciphered = (n: number, what: string, seed: number): FieldSpec => ({ name: what, random: n, seed, opaque: true, note: "Encrypted with the new NAS key (5G-EA2, AES based). Only the phone and the AMF can read it." });

// SUCI: the concealed subscription identifier (ECIES profile A)
const suci = (seed: number): FieldSpec => {
  const body: FieldSpec[] = [
    { name: "SUPI format, identity type", u8: 0x01, value: "IMSI-based, SUCI", note: "The identity is concealed: this is a SUCI, not the raw IMSI." },
    { name: "MCC / MNC", bytes: "00f110", value: "001 / 01 (test network)", note: "The home network code stays readable so the network knows whose key to use." },
    { name: "Routing indicator", bytes: "f0ff", value: "0" },
    { name: "Protection scheme", u8: 0x01, value: "1 (ECIES profile A, X25519)" },
    { name: "Home network public key ID", u8: 0x01 },
    {
      name: "Scheme output", value: "45 bytes", opaque: true, note: "The phone number part of the identity (MSIN), encrypted with the home network’s public key. A fresh ephemeral key makes it different every time.",
      fields: [
        { name: "Ephemeral public key", random: 32, seed, opaque: true },
        { name: "Encrypted MSIN", random: 5, seed: seed + 1, opaque: true },
        { name: "MAC tag", random: 8, seed: seed + 2, opaque: true },
      ],
    },
  ];
  const len = body.map(field).flatMap((f) => f.bytes).length;
  return { name: "5GS mobile identity", value: "SUCI (concealed)", fields: [{ name: "Length", u16: len }, ...body] };
};

const regRequest = () =>
  nas("Registration Request", [
    EPD, plainHdr, msgType(0x41, "Registration request"),
    { name: "ngKSI, registration type", u8: 0x79, value: "no key yet (7), initial registration", note: "ngKSI 7 means “I have no security keys with you yet”." },
    suci(801),
    { name: "UE security capability", bytes: "2e02f0f0", value: "5G-EA0–3, 5G-IA0–3", note: "Which encryption and integrity algorithms the phone supports." },
  ], "Registration request (SUCI)");

const authRequest = (seed: number) =>
  nas("Authentication Request", [
    EPD, plainHdr, msgType(0x56, "Authentication request"),
    { name: "ngKSI", u8: 0x00, value: "0", note: "The label the keys from this run will get." },
    { name: "ABBA", bytes: "020000", value: "0x0000" },
    { name: "RAND", fields: [{ name: "IEI", u8: 0x21 }, { name: "Random challenge", random: 16, seed, opaque: true }], value: "16 random bytes", note: "A fresh challenge. Only a SIM with the right secret key K can compute the answer." },
    { name: "AUTN", fields: [{ name: "IEI", u8: 0x20 }, { name: "Length", u8: 16 }, { name: "Authentication token", random: 16, seed: seed + 1, opaque: true }], value: "16 bytes", note: "Proves the NETWORK knows K too, and carries a sequence number so old challenges can’t be replayed." },
  ]);

// ---------------------------------------------------------------- GTP-U

function gtpu(teid: number, dir: string): LayerSpec {
  return {
    kind: "gtpu",
    build: (payload) => ({
      id: "gtpu",
      name: "GTP-U",
      osi: 4,
      summary: `GPRS Tunnelling Protocol (user plane), TEID 0x${teid.toString(16).padStart(8, "0")}, ${dir}`,
      fields: [
        field({ name: "Flags", u8: 0x30, value: "0x30: version 1, GTP, no extra fields", note: "Version 1, protocol type GTP, and no sequence number or extension headers, so the header is 8 bytes." }),
        field({ name: "Message type", u8: 0xff, value: "255 (G-PDU: carries a user packet)" }),
        field({ name: "Length", u16: payload.length, value: `${payload.length} bytes`, note: "Bytes after this 8-byte header: the whole inner IP packet." }),
        field({ name: "TEID", u32: teid, value: `0x${teid.toString(16).padStart(8, "0")}`, note: "Tunnel endpoint ID: tells the receiver which phone and session this packet belongs to." }),
      ],
    }),
  };
}

const synOpts: TcpOpt[] = [{ mss: 1340 }, "sackOk", "nop", { ws: 7 }];
const ulSyn = build(
  ipv4({ src: GNB, dst: UPF, ttl: 64, id: 0x0001, dscp: 0 }),
  udp({ sport: 2152, dport: 2152, zeroChecksum: true }),
  gtpu(TEID_UL, "uplink"),
  ipv4({ src: UE_IP, dst: WEB, ttl: 64, id: 0x5a01 }),
  tcp({ sport: 40188, dport: 443, seq: 0, flags: "S", opts: synOpts, seqBase: 0x3e8a0000 })
);
const natSyn = build(ipv4({ src: NAT_IP, dst: WEB, ttl: 63, id: 0x5a01 }), tcp({ sport: 61002, dport: 443, seq: 0, flags: "S", opts: synOpts, seqBase: 0x3e8a0000 }));
const webSynAck = build(ipv4({ src: WEB, dst: NAT_IP, ttl: 54, id: 0 }), tcp({ sport: 443, dport: 61002, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }], seqBase: 0x7710c000, ackBase: 0x3e8a0000 }));
const dlSynAck = build(
  ipv4({ src: UPF, dst: GNB, ttl: 64, id: 0x0002 }),
  udp({ sport: 2152, dport: 2152, zeroChecksum: true }),
  gtpu(TEID_DL, "downlink"),
  ipv4({ src: WEB, dst: UE_IP, ttl: 53, id: 0 }),
  tcp({ sport: 443, dport: 40188, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }], seqBase: 0x7710c000, ackBase: 0x3e8a0000 })
);

// ---------------------------------------------------------------- old 4G (LTE) identity messages for the what-if

const lteIdentityRequest = build(proto({ id: "nas", name: "LTE NAS Identity Request", osi: 3, summary: "NAS-EPS Identity request (IMSI)", fields: [
  { name: "Security header, protocol", u8: 0x07, value: "plain, EPS mobility management" },
  { name: "Message type", u8: 0x55, value: "0x55 (Identity request)" },
  { name: "Identity type", u8: 0x01, value: "1 (IMSI)", note: "“Tell me your permanent identity.” Allowed before any security in 4G." },
] }));
const lteIdentityResponse = build(proto({ id: "nas", name: "LTE NAS Identity Response", osi: 3, summary: "NAS-EPS Identity response IMSI 001010123456789", fields: [
  { name: "Security header, protocol", u8: 0x07, value: "plain, EPS mobility management" },
  { name: "Message type", u8: 0x56, value: "0x56 (Identity response)" },
  { name: "Mobile identity", value: "IMSI 001010123456789", note: "Digits packed two per byte, low nibble first. Anyone listening can read the subscriber’s permanent ID.", fields: [
    { name: "Length", u8: 8 },
    { name: "Digit 1, odd, type IMSI", u8: 0x09 },
    { name: "Digits 2–15", bytes: "10101032547698", value: "0101 0123 456789" },
  ] },
] }));
const nr5gIdentityRequest = build(nas("Identity Request", [EPD, plainHdr, msgType(0x5b, "Identity request"), { name: "Identity type", u8: 0x01, value: "1 (SUCI)", note: "In 5G the phone answers with the concealed SUCI, never the raw IMSI." }]));
const nr5gIdentityResponse = build(nas("Identity Response", [EPD, plainHdr, msgType(0x5c, "Identity response"), suci(1901)], "Identity response (SUCI)"));
const fakeAuth = build(authRequest(2001));
const authFail = build(nas("Authentication Failure", [EPD, plainHdr, msgType(0x59, "Authentication failure"), { name: "5GMM cause", u8: 0x14, value: "20 (MAC failure)", note: "The AUTN didn’t check out: this “network” doesn’t know the SIM’s key." }]));

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "phone", kind: "phone", label: "Phone", sub: "SIM: 001-01", x: 8, y: 62 },
  { id: "gnb", kind: "tower", label: "5G tower (gNB)", sub: GNB, x: 30, y: 62 },
  { id: "amf", kind: "server", label: "AMF (core control)", x: 54, y: 25 },
  { id: "ausf", kind: "auth", label: "AUSF / UDM (home)", sub: "holds the SIM’s key", x: 85, y: 22 },
  { id: "upf", kind: "server", label: "UPF (core user plane)", sub: UPF, x: 62, y: 74 },
  { id: "web", kind: "web", label: "Web server", sub: WEB, x: 90, y: 74 },
];
const links: [string, string][] = [["phone", "gnb"], ["gnb", "amf"], ["amf", "ausf"], ["gnb", "upf"], ["upf", "web"]];

const catcherDevices: Device[] = [
  { id: "phone", kind: "phone", label: "Phone", x: 8, y: 62 },
  { id: "fake", kind: "attacker", label: "Fake base station", sub: "IMSI catcher", x: 34, y: 25 },
  { id: "gnb", kind: "tower", label: "Real tower", x: 36, y: 78 },
  { id: "amf", kind: "server", label: "AMF (core)", x: 64, y: 62 },
  { id: "ausf", kind: "auth", label: "AUSF / UDM (home)", x: 89, y: 40 },
];
const catcherLinks: [string, string][] = [["phone", "fake"], ["phone", "gnb"], ["gnb", "amf"], ["amf", "ausf"]];

export default defineLesson({
  id: "cellular",
  name: "4G / 5G",
  full: "Cellular attach: RRC, NAS registration, AKA and GTP-U",
  group: "india",
  layer: 3,
  difficulty: 3,
  tagline: "What your phone says to the tower before the first byte of data.",
  description:
    "Before a phone can use mobile data it has to set up a radio link, register with the core network, prove its SIM is genuine (and check the network is genuine too), switch on encryption and get an IP address. After that, every packet it sends is wrapped in a GTP-U tunnel from the tower to the core.",
  facts: [
    ["Radio control", "RRC (phone ↔ tower)"],
    ["Core signalling", "NAS (phone ↔ AMF)"],
    ["Authentication", "5G-AKA, mutual"],
    ["Identity on air", "SUCI (concealed)"],
    ["User data tunnel", "GTP-U, UDP 2152"],
    ["Specs", "3GPP TS 38.331, 24.501, 33.501, 29.281"],
  ],
  ports: "GTP-U: UDP 2152",
  rfc: "3GPP TS 24.501 / 29.281",
  keywords: ["5g", "4g", "lte", "nr", "rrc", "nas", "amf", "upf", "gnb", "aka", "suci", "supi", "imsi", "gtp", "gtp-u", "teid", "imsi catcher", "stingray", "pdu session", "mobile data", "jio", "airtel"],
  related: ["ip", "udp", "tcp", "journey"],
  devices,
  links,
  linktype: 101,
  legend: [
    ["blue", "Radio and registration signalling"],
    ["teal", "Authentication and security"],
    ["green", "Accepted / set up"],
    ["amber", "User data"],
    ["red", "Attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Switch on, register, browse",
      summary: "A phone connects to a 5G cell, registers with a concealed identity, authenticates, gets an IP and sends its first packet through a GTP-U tunnel.",
      kind: "normal",
      steps: [
        {
          title: "Radio connection",
          desc: "RRC Setup Request and RRC Setup",
          detail:
            "The phone picks the strongest cell it can hear and, after a short random-access exchange, asks the tower (gNB) for a signalling connection. It uses a random identity because the network doesn’t know it yet. The tower answers with RRC Setup: the radio settings for this phone’s control channel.",
          facts: [["Between", "Phone ↔ gNB only"], ["Phone identity", "39-bit random value"], ["Cause", "mo-Signalling"]],
          events: [
            pkt("phone", "gnb", "blue", "RRC REQ", ["setup please"], {
              time: 0, info: "RRC Setup Request (simplified)",
              packet: build(rrc("Setup Request", [
                { name: "Message", u8: 0x00, value: "RRCSetupRequest" },
                { name: "UE identity", random: 5, seed: 71, value: "39-bit random value", note: "Temporary random tag; the real identity comes later inside NAS." },
                { name: "Establishment cause", u8: 0x03, value: "mo-Signalling", note: "Why the phone wants to connect: to send signalling, not data." },
              ])),
            }),
            pkt("gnb", "phone", "blue", "RRC SETUP", ["your radio config"], {
              time: 0.008, info: "RRC Setup (simplified)",
              packet: build(rrc("Setup", [{ name: "Message", u8: 0x01, value: "RRCSetup" }, { name: "Radio bearer config", random: 40, seed: 72, value: "40 bytes", note: "Settings for signalling radio bearer 1 (shown as raw bytes)." }])),
            }),
          ],
        },
        {
          title: "Register, identity hidden",
          desc: "NAS Registration Request with a SUCI",
          detail:
            "Inside RRC Setup Complete the phone sends its first NAS message, which the tower passes on to the AMF in the core. It needs to say who it is, but its permanent ID (SUPI, which is IMSI-based) would be readable by anyone with a radio. So the SIM encrypts the subscriber part with the home network’s public key and sends a SUCI, which looks different every time.",
          facts: [["NAS to", "AMF, via the tower"], ["Identity", "SUCI, ECIES profile A"], ["Readable part", "Country 001, network 01"]],
          quiz: {
            q: "Which part of the SUCI can a listener still read?",
            options: ["The full IMSI", "The country and network codes", "The phone number", "Nothing at all"],
            answer: 1,
            why: "MCC/MNC stay in clear so any network can route the request to the right home operator. The subscriber number itself is encrypted.",
          },
          events: [
            pkt("phone", "amf", "blue", "REGISTER", ["SUCI (concealed)", "via the tower"], {
              time: 0.012, info: "RRC Setup Complete, Registration request",
              packet: build(rrc("Setup Complete", [{ name: "Message", u8: 0x02, value: "RRCSetupComplete" }, { name: "Selected PLMN", u8: 1 }, { name: "Dedicated NAS message length", u8: 0, value: "(follows)" }]), regRequest()),
            }),
          ],
        },
        {
          title: "Prove both sides",
          desc: "5G-AKA challenge and response",
          detail:
            "The AMF asks the home network (AUSF and UDM) to decrypt the SUCI and make a challenge. Only the SIM and the home network know the secret key K. The phone gets a random RAND and an AUTN token: the SIM checks AUTN to confirm the network really knows K, then computes RES* from RAND, which proves the SIM knows K too. The key itself is never sent.",
          facts: [["Challenge", "RAND (16 bytes)"], ["Network proof", "AUTN, checked by the SIM"], ["Phone proof", "RES* (16 bytes)"]],
          quiz: {
            q: "Why does the phone check AUTN before answering?",
            options: ["To pick a radio channel", "To make sure the network is genuine, not a fake tower", "To get its IP address", "To decrypt the SUCI"],
            answer: 1,
            why: "AKA is mutual. A fake base station doesn’t know K, so it can’t make a valid AUTN, and the SIM refuses to go on.",
          },
          events: [
            note("ausf", "SUCI → SUPI, MAKE CHALLENGE", "blue"),
            pkt("amf", "phone", "teal", "AUTH REQ", ["RAND + AUTN"], { time: 0.06, info: "Authentication request", packet: build(authRequest(901)) }),
            pkt("phone", "amf", "teal", "AUTH RESP", ["RES*"], {
              time: 0.075, info: "Authentication response",
              packet: build(nas("Authentication Response", [EPD, plainHdr, msgType(0x57, "Authentication response"), { name: "RES*", fields: [{ name: "IEI", u8: 0x2d }, { name: "Length", u8: 16 }, { name: "Response", random: 16, seed: 903, opaque: true }], value: "16 bytes", note: "Computed by the SIM from RAND and K. The network compares it with the value it expects." }])),
            }),
          ],
        },
        {
          title: "Switch on encryption",
          desc: "NAS Security Mode Command and Complete",
          detail:
            "Both sides now derive the same keys from K and RAND. The AMF picks the algorithms (here 5G-EA2 for encryption, 5G-IA2 for integrity) and sends Security Mode Command, already integrity protected. It repeats the phone’s own capability list back so the phone can spot an attacker who tried to downgrade it. From the phone’s reply on, NAS messages are encrypted.",
          facts: [["Ciphering", "5G-EA2 (AES based)"], ["Integrity", "5G-IA2"], ["From now on", "NAS encrypted"]],
          events: [
            pkt("amf", "phone", "teal", "SEC MODE", ["EA2 + IA2"], {
              time: 0.09, info: "Security mode command",
              packet: build(protectedNas("Security Mode Command", 3, 0, [EPD, plainHdr, msgType(0x5d, "Security mode command"), { name: "Selected algorithms", u8: 0x22, value: "5G-EA2, 5G-IA2" }, { name: "ngKSI", u8: 0x00 }, { name: "Replayed UE security capability", bytes: "02f0f0", value: "EA0–3, IA0–3", note: "Echo of what the phone said, to catch downgrade attacks." }], 904)),
            }),
            pkt("phone", "amf", "teal", "SEC DONE", ["encrypted from here"], {
              time: 0.1, info: "Security mode complete (ciphered)",
              packet: build(protectedNas("Security Mode Complete", 4, 0, [ciphered(34, "Ciphered: Security mode complete + full registration request", 905)], 906)),
            }),
          ],
        },
        {
          title: "Registered",
          desc: "A temporary ID replaces the real one",
          detail:
            "The AMF accepts the registration and gives the phone a 5G-GUTI, a temporary ID that it will use instead of any permanent identity from now on and that the network changes from time to time. The Registration Accept is encrypted, so listeners can’t link the GUTI to the person.",
          facts: [["Message", "Registration Accept (ciphered)"], ["New ID", "5G-GUTI (temporary)"], ["Phone replies", "Registration Complete"]],
          events: [
            pkt("amf", "phone", "green", "ACCEPT", ["5G-GUTI inside"], { time: 0.13, info: "Registration accept (ciphered)", packet: build(protectedNas("Registration Accept", 2, 1, [ciphered(62, "Ciphered: Registration accept with 5G-GUTI, allowed slices, timers", 907)], 908)) }),
            pkt("phone", "amf", "green", "COMPLETE", [], { time: 0.14, info: "Registration complete (ciphered)", packet: build(protectedNas("Registration Complete", 2, 1, [ciphered(3, "Ciphered: Registration complete", 909)], 910)) }),
          ],
        },
        {
          title: "Get an IP: PDU session",
          desc: "A data session and a tunnel are built",
          detail:
            "To use data the phone asks for a PDU session on a data network name such as “internet”. The core picks a UPF, gives the phone the IP address 10.45.0.7, and sets up a tunnel between the tower and the UPF. Each side picks a tunnel ID (TEID) that the other side must put on packets sent to it.",
          facts: [["Phone IP", UE_IP], ["Uplink TEID", `0x${TEID_UL.toString(16).padStart(8, "0")} (UPF’s)`], ["Downlink TEID", `0x${TEID_DL.toString(16).padStart(8, "0")} (gNB’s)`]],
          quiz: {
            q: "A downlink packet arrives at the tower with TEID 0x00c0ffee. What does the TEID tell the tower?",
            options: ["The website’s address", "Which phone and session the packet is for", "The radio frequency", "The packet’s priority"],
            answer: 1,
            why: "The inner IP packet is for 10.45.0.7, but the tower works with tunnels: the TEID it chose for this session maps straight to one phone.",
          },
          events: [
            pkt("phone", "amf", "blue", "PDU REQ", ["DNN “internet”"], { time: 0.2, info: "UL NAS transport, PDU session establishment request (ciphered)", packet: build(protectedNas("UL NAS Transport", 2, 2, [ciphered(48, "Ciphered: PDU session establishment request, DNN internet, IPv4", 911)], 912)) }),
            note("upf", "SESSION + TEIDs SET UP", "blue"),
            pkt("amf", "phone", "green", "PDU ACCEPT", [`IP ${UE_IP}`], { time: 0.26, info: "DL NAS transport, PDU session establishment accept (ciphered)", packet: build(protectedNas("DL NAS Transport", 2, 2, [ciphered(96, "Ciphered: PDU session establishment accept, address 10.45.0.7, QoS rules", 913)], 914)) }),
          ],
        },
        {
          title: "Data through GTP-U",
          desc: "The phone’s packet, wrapped for the trip",
          detail:
            "The phone opens a web connection. Over the air its IP packet is protected by the radio layers; at the tower it is wrapped in GTP-U: a new outer IP header (tower to UPF), UDP port 2152, and an 8-byte GTP header with the TEID. The UPF strips the wrapper, swaps the private address for a public one (NAT) and sends it to the internet. Replies come back the same way with the downlink TEID.",
          facts: [["Outer", `${GNB} → ${UPF}, UDP 2152`], ["GTP header", "8 bytes: flags, type 255, length, TEID"], ["Overhead", "36 bytes (IP 20 + UDP 8 + GTP 8)"]],
          quiz: {
            q: "The inner TCP SYN is 60 bytes. How big is the whole packet between the tower and the UPF?",
            options: ["60 bytes", "68 bytes", "96 bytes", "1500 bytes"],
            answer: 2,
            why: "Outer IPv4 (20) + UDP (8) + GTP-U (8) adds 36 bytes to the 60-byte inner packet: 96 bytes.",
          },
          events: [
            pkt("gnb", "upf", "amber", "GTP-U", ["TEID 0xa1b2", "inner: SYN :443"], { time: 0.5, info: `GTP <TCP> 40188 → 443 [SYN] (TEID 0x${TEID_UL.toString(16)})`, packet: ulSyn }),
            pkt("upf", "web", "amber", "SYN", ["after NAT"], { time: 0.501, info: "61002 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1340", packet: natSyn }),
            pkt("web", "upf", "green", "SYN-ACK", [], { time: 0.521, info: "443 → 61002 [SYN, ACK] Seq=0 Ack=1", packet: webSynAck }),
            pkt("upf", "gnb", "green", "GTP-U", ["TEID 0xc0ffee", "inner: SYN-ACK"], { time: 0.522, info: `GTP <TCP> 443 → 40188 [SYN, ACK] (TEID 0x${TEID_DL.toString(16)})`, packet: dlSynAck }),
          ],
        },
      ],
      outro: {
        title: "Online over 5G",
        text: "The phone set up a radio link, registered with a concealed identity, authenticated mutually with AKA, switched on NAS encryption, and got an IP address. Its packets then travelled from the tower to the core inside GTP-U, tagged by tunnel IDs.",
        facts: [["Signalling", "RRC + NAS"], ["Auth", "5G-AKA (mutual)"], ["Tunnel", "GTP-U, UDP 2152, 8-byte header"], ["Took", "About 0.3 s to register"]],
      },
    },
    {
      id: "imsi-catcher",
      name: "IMSI catcher (fake base station)",
      summary: "A fake tower asks phones for their identity. 4G phones could leak the IMSI; 5G phones only give a concealed SUCI and reject the fake network.",
      kind: "attack",
      devices: catcherDevices,
      links: catcherLinks,
      steps: [
        {
          title: "A louder fake tower",
          desc: "Phones move to the strongest cell",
          detail:
            "An attacker runs a small fake base station that broadcasts the same network code as a real operator, but louder. Nearby phones see it as the best cell and connect to it. At the start of a connection, before any keys exist, a phone has to answer some questions without being able to check who is asking.",
          facts: [["Attacker", "Software radio + laptop"], ["Trick", "Stronger signal, real network code"], ["Goal", "Learn who is nearby"]],
          events: [
            note("fake", "BROADCASTING 001-01", "red"),
            pkt("phone", "fake", "blue", "RRC REQ", ["setup please"], { time: 0, info: "RRC Setup Request (simplified)", packet: build(rrc("Setup Request", [{ name: "Message", u8: 0x00, value: "RRCSetupRequest" }, { name: "UE identity", random: 5, seed: 1801, value: "39-bit random value" }, { name: "Establishment cause", u8: 0x03, value: "mo-Signalling" }])) }),
          ],
        },
        {
          title: "Old 4G: IMSI in the clear",
          desc: "Identity Request, answered with the IMSI",
          detail:
            "In 4G (and 2G/3G) a network may send an Identity Request for the IMSI before security starts, and the phone must answer in plain text. The fake tower does exactly that and records the permanent subscriber ID, which can be tied to a person. This is how classic IMSI catchers track people.",
          facts: [["Asked for", "IMSI"], ["Answer", "001010123456789, plain"], ["Weakness", "No protection before security"]],
          quiz: {
            q: "Why can’t a 4G phone just refuse to send its IMSI?",
            options: ["It doesn’t know it", "Before security starts it can’t tell a fake tower from a real one, and real networks sometimes need the IMSI", "The SIM blocks it", "It can; it always refuses"],
            answer: 1,
            why: "A real network may lose track of a phone’s temporary ID and legitimately ask for the IMSI. Without keys yet, the phone can’t tell who is asking.",
          },
          events: [
            pkt("fake", "phone", "red", "ID REQ", ["your IMSI?"], { time: 0.02, info: "Identity request (IMSI)", packet: lteIdentityRequest }),
            pkt("phone", "fake", "red", "ID RESP", ["IMSI 001010123456789"], { time: 0.03, info: "Identity response (IMSI)", packet: lteIdentityResponse }),
            note("fake", "IMSI CAPTURED (4G)", "red"),
          ],
        },
        {
          title: "5G: only a SUCI",
          desc: "The identity is encrypted for the home network",
          detail:
            "A 5G phone answers an Identity Request with a SUCI. The subscriber part is encrypted with the home operator’s public key and a fresh random key each time, so the fake tower gets a blob that changes on every request and can’t be decrypted or linked to the last one.",
          facts: [["Answer", "SUCI, new each time"], ["Can decrypt", "Only the home network (UDM)"], ["Attacker learns", "Country + operator only"]],
          quiz: {
            q: "The attacker asks twice and gets two SUCIs. Can it tell they’re the same phone?",
            options: ["Yes, they are identical", "No, each uses a fresh ephemeral key so they look unrelated", "Yes, from the MAC tag", "Only if it also knows the phone’s secret key K"],
            answer: 1,
            why: "ECIES uses a new ephemeral key pair for every SUCI, so the encrypted output is different each time.",
          },
          events: [
            pkt("fake", "phone", "red", "ID REQ", ["your identity?"], { time: 1, info: "Identity request (SUCI)", packet: nr5gIdentityRequest }),
            pkt("phone", "fake", "teal", "ID RESP", ["SUCI (concealed)"], { time: 1.01, info: "Identity response (SUCI)", packet: nr5gIdentityResponse }),
            note("fake", "GOT NOISE", "green"),
          ],
        },
        {
          title: "Fake challenge fails",
          desc: "The SIM rejects a network without the key",
          detail:
            "To go further the fake tower would need to authenticate. It sends an Authentication Request with made-up RAND and AUTN, but it doesn’t know the SIM’s secret key, so the SIM’s check of AUTN fails. The phone replies Authentication Failure (MAC failure), drops the fake cell and moves to the real tower.",
          facts: [["Phone says", "Authentication failure, cause 20"], ["Reason", "AUTN doesn’t verify"], ["Then", "Phone moves to the real cell"]],
          events: [
            pkt("fake", "phone", "red", "AUTH REQ", ["fake RAND/AUTN"], { time: 1.05, info: "Authentication request", packet: fakeAuth }),
            pkt("phone", "fake", "teal", "AUTH FAIL", ["MAC failure"], { time: 1.06, info: "Authentication failure (MAC failure)", packet: authFail }),
            note("phone", "FAKE CELL BARRED", "green"),
            pkt("phone", "gnb", "blue", "RRC REQ", ["to the real tower"], { time: 1.5, info: "RRC Setup Request (simplified)", packet: build(rrc("Setup Request", [{ name: "Message", u8: 0x00, value: "RRCSetupRequest" }, { name: "UE identity", random: 5, seed: 1802, value: "39-bit random value" }, { name: "Establishment cause", u8: 0x03, value: "mo-Signalling" }])) }),
          ],
        },
      ],
      outro: {
        title: "5G closes the IMSI leak",
        text: "Fake base stations exploit the moment before security starts. 4G phones could be made to reveal their IMSI then; 5G phones send only a SUCI encrypted for the home network, and mutual AKA stops the fake network from going any further.",
        facts: [["4G weakness", "IMSI on request, in clear"], ["5G fix", "SUCI concealment"], ["Also", "Mutual auth with AUTN"], ["Remaining risk", "Downgrade to 4G/2G"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Who is who",
      items: [["UE", "The phone + SIM"], ["gNB", "5G base station (eNB in 4G)"], ["AMF", "Handles registration and mobility"], ["AUSF / UDM", "Home authentication, subscriber data"], ["UPF", "Forwards user data, NAT, charging"]],
    },
    {
      title: "Identities",
      items: [["SUPI / IMSI", "Permanent subscriber ID"], ["SUCI", "Concealed SUPI, sent over the air"], ["5G-GUTI", "Temporary ID given after registration"], ["TEID", "Tunnel ID in GTP-U"]],
    },
    {
      title: "Numbers to know",
      items: [["GTP-U port", "UDP 2152"], ["GTP-U header", "8 bytes (flags 0x30, type 255)"], ["RAND / RES*", "16 bytes each"], ["NAS 5GMM EPD", "0x7E"]],
    },
  ],
});
