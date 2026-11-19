import { defineLesson, note, pkt } from "@/lib/lesson";
import { build, field, FieldSpec, proto } from "@/lib/packet";
import { eth, ipv4, tcp, udp } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

// ---------------------------------------------------------------- helpers (IKEv2, RFC 7296)

const GW = ADDR.server2; // VPN gateway 203.0.113.40
const FILES = "10.20.0.15"; // file server inside the office
const VIP = "10.99.0.7"; // inner address the gateway hands the laptop
const SPI_I = "8f3a1c5e7b2d9046";
const SPI_R = "c41e77a0935b2d18";
const ESP_OUT = 0xc7a3e912; // SPI the gateway chose: laptop → gateway
const ESP_IN = 0x5d20b6f4; // SPI the laptop chose: gateway → laptop
const GW_IN_MAC = "00:16:3e:5a:01:40";
const FILES_MAC = "00:16:3e:20:00:15";

const blen = (fs: FieldSpec[]) => fs.map(field).flatMap((f) => f.bytes).length;

const PN: Record<number, string> = {
  0: "None", 33: "Security Association", 34: "Key Exchange", 35: "Identification - Initiator", 36: "Identification - Responder",
  37: "Certificate", 38: "Certificate Request", 39: "Authentication", 40: "Nonce", 41: "Notify", 43: "Vendor ID",
  44: "Traffic Selector - Initiator", 45: "Traffic Selector - Responder", 46: "Encrypted and Authenticated",
};
const EXCH: Record<number, string> = { 34: "IKE_SA_INIT", 35: "IKE_AUTH" };

/** Generic payload header (next payload, critical bit, length) + body */
const gp = (name: string, next: number, body: FieldSpec[], note?: string): FieldSpec => ({
  name: `Payload: ${name}`,
  value: `${4 + blen(body)} bytes`,
  note,
  fields: [
    { name: "Next payload", u8: next, value: `${next} (${PN[next]})`, note: "Which payload comes after this one. 0 means this is the last." },
    { name: "Critical bit, reserved", u8: 0, value: "0 (not critical)" },
    { name: "Payload length", u16: 4 + blen(body), value: `${4 + blen(body)} bytes`, note: "This 4-byte header plus the body." },
    ...body,
  ],
});

/** Transform substructure: last(0)/more(3), reserved, length, type, reserved, id, [key length attribute] */
const tf = (last: boolean, type: number, typeName: string, id: number, idName: string, keyBits?: number): FieldSpec => ({
  name: `Transform: ${typeName} = ${idName}`,
  value: idName,
  fields: [
    { name: "Last substructure", u8: last ? 0 : 3, value: last ? "0 (last transform)" : "3 (more transforms follow)" },
    { name: "Reserved", u8: 0 },
    { name: "Transform length", u16: keyBits ? 12 : 8 },
    { name: "Transform type", u8: type, value: `${type} (${typeName})` },
    { name: "Reserved", u8: 0 },
    { name: "Transform ID", u16: id, value: `${id} (${idName})` },
    ...(keyBits ? [{ name: "Attribute: Key length", bytes: [0x80, 0x0e, (keyBits >> 8) & 255, keyBits & 255], value: `${keyBits} bits`, note: "Type/value attribute (format bit set, type 14)." } as FieldSpec] : []),
  ],
});

const proposal = (num: number, protoId: number, transforms: FieldSpec[], spi?: number): FieldSpec => {
  const spiF: FieldSpec[] = spi !== undefined ? [{ name: "SPI", u32: spi, value: `0x${spi.toString(16)}`, note: "The ESP SPI this side wants to receive with." }] : [];
  return {
    name: `Proposal ${num}: ${protoId === 1 ? "IKE" : "ESP"}`,
    value: `${transforms.length} transforms`,
    fields: [
      { name: "Last substructure", u8: 0, value: "0 (last proposal)" },
      { name: "Reserved", u8: 0 },
      { name: "Proposal length", u16: 8 + blen(spiF) + blen(transforms) },
      { name: "Proposal number", u8: num },
      { name: "Protocol ID", u8: protoId, value: protoId === 1 ? "1 (IKE)" : "3 (ESP)" },
      { name: "SPI size", u8: spi !== undefined ? 4 : 0 },
      { name: "Number of transforms", u8: transforms.length },
      ...spiF,
      ...transforms,
    ],
  };
};

const modernIke = () => proposal(1, 1, [
  tf(false, 1, "Encryption", 20, "AES-GCM-16", 256),
  tf(false, 2, "PRF", 5, "PRF_HMAC_SHA2_256"),
  tf(true, 4, "Key exchange (DH group)", 31, "Curve25519"),
]);

const notify = (type: number, name: string, data: FieldSpec[]): FieldSpec[] => [
  { name: "Protocol ID", u8: 0, value: "0 (about the IKE SA)" },
  { name: "SPI size", u8: 0 },
  { name: "Notify message type", u16: type, value: `${type} (${name})` },
  ...data,
];

const ike = (o: { nonEsp?: boolean; next: number; exch: number; resp: boolean; msgId: number; spiR?: string; payloads: FieldSpec[]; summary: string }) => {
  const total = 28 + blen(o.payloads);
  return proto({
    id: "isakmp",
    name: "IKEv2",
    osi: 5,
    summary: o.summary,
    fields: [
      ...(o.nonEsp ? [{ name: "Non-ESP marker", zero: 4, value: "0x00000000", note: "Four zero bytes. On port 4500 they say “this is IKE, not ESP” (an ESP SPI is never zero)." } as FieldSpec] : []),
      { name: "Initiator SPI", bytes: SPI_I, value: `0x${SPI_I}`, note: "Random 8-byte ID the laptop picked for this IKE session." },
      { name: "Responder SPI", bytes: o.spiR ?? "0000000000000000", value: `0x${o.spiR ?? "0000000000000000"}`, note: o.spiR ? "The gateway’s 8-byte ID for the session." : "Zero: the gateway hasn’t picked one yet." },
      { name: "Next payload", u8: o.next, value: `${o.next} (${PN[o.next]})`, note: "Type of the first payload." },
      { name: "Version", u8: 0x20, value: "2.0", note: "Major version 2, minor 0." },
      { name: "Exchange type", u8: o.exch, value: `${o.exch} (${EXCH[o.exch]})` },
      { name: "Flags", u8: o.resp ? 0x20 : 0x08, value: o.resp ? "0x20 (Response)" : "0x08 (Initiator)", note: o.resp ? "Response bit set; sent by the side that did not start the session." : "Initiator bit: sent by the side that started the session." },
      { name: "Message ID", u32: o.msgId, note: "Counts request/response pairs, so replies match requests and replays are spotted." },
      { name: "Length", u32: total, value: `${total} bytes`, note: "Whole IKE message: 28-byte header plus payloads." },
      ...o.payloads,
    ],
  });
};

const ike500 = () => udp({ sport: 500, dport: 500 });

const natHash = (seed: number): FieldSpec => ({ name: "Notification data (SHA-1)", random: 20, seed, value: "20-byte hash", note: "SHA-1 of the SPIs plus an IP address and port. If the other side computes something different, a NAT changed the address." });

const initReq = () => ike({
  next: 33, exch: 34, resp: false, msgId: 0,
  summary: "IKE_SA_INIT MID=00 Initiator Request",
  payloads: [
    gp("Security Association", 34, [modernIke()], "The offer: which crypto the laptop is willing to use."),
    gp("Key Exchange", 40, [
      { name: "Key exchange method", u16: 31, value: "31 (Curve25519)" },
      { name: "Reserved", u16: 0 },
      { name: "Key exchange data", random: 32, seed: 501, value: "32-byte public key", note: "The laptop’s fresh X25519 public value." },
    ]),
    gp("Nonce", 41, [{ name: "Nonce data", random: 32, seed: 502, value: "32 random bytes", note: "Fresh randomness mixed into the keys." }]),
    gp("Notify", 41, notify(16388, "NAT_DETECTION_SOURCE_IP", [natHash(503)]), "Hash of the laptop’s own address and port: 192.168.1.10:500."),
    gp("Notify", 0, notify(16389, "NAT_DETECTION_DESTINATION_IP", [natHash(504)]), "Hash of the address and port the laptop is sending to."),
  ],
});

const initResp = () => ike({
  next: 33, exch: 34, resp: true, msgId: 0, spiR: SPI_R,
  summary: "IKE_SA_INIT MID=00 Responder Response",
  payloads: [
    gp("Security Association", 34, [modernIke()], "The gateway picks exactly one proposal and echoes it back."),
    gp("Key Exchange", 40, [
      { name: "Key exchange method", u16: 31, value: "31 (Curve25519)" },
      { name: "Reserved", u16: 0 },
      { name: "Key exchange data", random: 32, seed: 511, value: "32-byte public key", note: "The gateway’s X25519 public value." },
    ]),
    gp("Nonce", 41, [{ name: "Nonce data", random: 32, seed: 512, value: "32 random bytes" }]),
    gp("Notify", 41, notify(16388, "NAT_DETECTION_SOURCE_IP", [natHash(513)])),
    gp("Notify", 41, notify(16389, "NAT_DETECTION_DESTINATION_IP", [natHash(514)]), "Hash of the address the gateway actually saw: 198.51.100.7, not 192.168.1.10. Mismatch means NAT."),
    gp("Notify", 0, notify(16430, "IKEV2_FRAGMENTATION_SUPPORTED", []), "Big encrypted messages may be split into IKE fragments (RFC 7383)."),
  ],
});

const sk = (first: number, enc: number, seed: number, what: string): FieldSpec =>
  gp("Encrypted and Authenticated", first, [
    { name: "Initialization vector", random: 8, seed, value: "8 bytes", note: "AES-GCM needs a fresh 8-byte IV per message." },
    { name: "Encrypted payloads", random: enc, seed: seed + 1, opaque: true, value: `${enc} bytes`, note: what },
    { name: "Integrity checksum (ICV)", random: 16, seed: seed + 2, opaque: true, value: "16-byte GCM tag", note: "Any change to the message breaks this tag." },
  ], "Everything after the first exchange lives inside this one payload. The Next payload field names the first payload hidden inside.");

const esp = (spi: number, seq: number, enc: number, seed: number, what: string) =>
  proto({
    id: "esp",
    name: "ESP",
    osi: 3,
    summary: `Encapsulating Security Payload (SPI=0x${spi.toString(16)}, Seq=${seq})`,
    fields: [
      { name: "SPI", u32: spi, value: `0x${spi.toString(16)}`, note: "Which IPsec security association (keys) the receiver must use. Never zero, which is how it differs from the non-ESP marker." },
      { name: "Sequence number", u32: seq, note: "Counts up by one per packet; the receiver drops repeats (anti-replay)." },
      { name: "IV", random: 8, seed, value: "8 bytes" },
      { name: "Encrypted payload", random: enc, seed: seed + 1, opaque: true, value: `${enc} bytes`, note: what },
      { name: "ICV", random: 16, seed: seed + 2, opaque: true, value: "16-byte GCM tag", note: "Integrity check over SPI, sequence number and ciphertext." },
    ],
  });

const devices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: ADDR.laptop, x: 9, y: 62 },
  { id: "router", kind: "router" as const, label: "Home router (NAT)", sub: ADDR.routerWan, x: 30, y: 62 },
  { id: "internet", kind: "cloud" as const, label: "Internet", x: 52, y: 32 },
  { id: "vpn", kind: "vpn" as const, label: "VPN gateway", sub: GW, x: 72, y: 62 },
  { id: "files", kind: "nas" as const, label: "File server", sub: FILES, x: 91, y: 62 },
];
const links: [string, string][] = [["client", "router"], ["router", "internet"], ["internet", "vpn"], ["vpn", "files"]];

export default defineLesson({
  id: "ipsec",
  name: "IPsec / IKEv2",
  full: "IP Security with Internet Key Exchange version 2",
  group: "vpn",
  layer: 3,
  difficulty: 3,
  tagline: "Agree on keys with IKEv2, then encrypt every IP packet with ESP.",
  description:
    "IPsec protects whole IP packets. IKEv2 first agrees on crypto, swaps Diffie-Hellman keys and proves who each side is. After that ESP carries the real traffic, encrypted and numbered, wrapped in UDP 4500 when a NAT is in the way.",
  facts: [
    ["Layer", "Network (Layer 3)"],
    ["Key exchange", "IKEv2 on UDP 500 / 4500"],
    ["Data", "ESP (IP protocol 50) or ESP-in-UDP"],
    ["IKE header", "28 bytes"],
    ["ESP header", "8 bytes + IV + tag"],
    ["Defined in", "RFC 7296, RFC 4303, RFC 3948"],
  ],
  ports: "UDP 500 (IKE), UDP 4500 (NAT traversal), IP protocol 50 (ESP)",
  rfc: "RFC 7296",
  keywords: ["ikev2", "esp", "nat-t", "nat traversal", "spi", "security association", "vpn", "no_proposal_chosen", "site to site"],
  related: ["wireguard", "tls", "udp", "ip"],
  devices,
  links,
  legend: [
    ["teal", "IKE key exchange"],
    ["green", "Authenticated, tunnel up"],
    ["amber", "Laptop traffic (ESP)"],
    ["violet", "Office traffic back"],
    ["red", "Errors"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Remote worker connects to the office",
      summary: "The laptop builds an IKEv2 session from behind a home NAT, then reaches a file server through ESP.",
      kind: "normal",
      steps: [
        {
          title: "IKE_SA_INIT request",
          desc: "Offer crypto, send a public key and a nonce",
          detail:
            "The laptop opens with one UDP packet to port 500. It holds three key payloads: SA (the crypto it will accept), KE (its Curve25519 public key) and Nonce (fresh random bytes). Two Notify payloads carry hashes of its own address and port, so the gateway can tell whether a NAT rewrote them.",
          facts: [["Exchange", "IKE_SA_INIT (34)"], ["Offer", "AES-GCM-256, SHA2-256, Curve25519"], ["Port", "UDP 500 → 500"]],
          events: [
            pkt("client", "vpn", "teal", "SA_INIT", ["SA, KE, Nonce", "NAT hashes"], {
              time: 0, info: "IKE_SA_INIT MID=00 Initiator Request",
              packet: build(...up(GW), ike500(), initReq()),
            }),
          ],
        },
        {
          title: "IKE_SA_INIT response",
          desc: "Gateway picks the crypto and spots the NAT",
          detail:
            "The gateway accepts the proposal, sends its own public key and nonce, and fills in its Responder SPI. Both sides can now compute the same shared secret with X25519 and derive keys. The gateway’s NAT hash is built from 198.51.100.7, the address it really saw, so the laptop learns a NAT sits in between.",
          facts: [["Responder SPI", `0x${SPI_R}`], ["Shared secret", "X25519, never sent"], ["NAT found", "Yes: hashes differ"]],
          quiz: {
            q: "The NAT hashes don’t match. What will the two sides do next?",
            options: ["Give up: IPsec can’t cross NAT", "Move to UDP 4500 and wrap ESP in UDP", "Switch to TCP 443", "Send ESP as IP protocol 50 anyway"],
            answer: 1,
            why: "Plain ESP has no ports, so a home NAT can’t track it. NAT traversal moves IKE to port 4500 and puts ESP inside UDP 4500 too.",
          },
          events: [
            pkt("vpn", "client", "teal", "SA_INIT", ["SA, KE, Nonce", "NAT detected"], {
              time: 0.038, info: "IKE_SA_INIT MID=00 Responder Response",
              packet: build(...down(GW), ike500(), initResp()),
            }),
            note("client", "NAT DETECTED", "blue"),
          ],
        },
        {
          title: "IKE_AUTH, encrypted",
          desc: "Prove identities and set up the ESP tunnel",
          detail:
            "From now on IKE is encrypted inside an SK payload and runs on UDP 4500, so it starts with the 4-byte non-ESP marker. Hidden inside are the laptop’s identity, certificate and AUTH signature, a request for an inner address, and an ESP proposal with traffic selectors. The gateway answers with its own certificate and AUTH, gives the laptop 10.99.0.7 and picks an ESP SPI.",
          facts: [["Inside request", "IDi, CERT, AUTH, CP, SA, TSi, TSr"], ["Inner IP", VIP], ["Port", "UDP 4500 (NAT-T)"]],
          quiz: {
            q: "Why does this IKE message start with four zero bytes?",
            options: ["Padding for alignment", "To say it is IKE, not ESP, on the shared port 4500", "It is an empty SPI", "A version number"],
            answer: 1,
            why: "IKE and ESP share UDP 4500. ESP starts with a non-zero SPI, so four zero bytes mark the packet as IKE.",
          },
          events: [
            pkt("client", "vpn", "teal", "IKE_AUTH", ["encrypted SK", "cert + signature"], {
              time: 0.04, info: "IKE_AUTH MID=01 Initiator Request",
              packet: build(...up(GW), udp({ sport: 4500, dport: 4500 }), ike({
                nonEsp: true, next: 46, exch: 35, resp: false, msgId: 1, spiR: SPI_R, summary: "IKE_AUTH MID=01 Initiator Request",
                payloads: [sk(35, 1100, 521, "IDi, CERT (laptop certificate), CERTREQ, AUTH (signature), CP (please give me an address), SA (ESP proposal, SPI 0x5d20b6f4), TSi, TSr.")],
              })),
            }),
            pkt("vpn", "client", "green", "IKE_AUTH", ["encrypted SK", "IP 10.99.0.7"], {
              time: 0.081, info: "IKE_AUTH MID=01 Responder Response",
              packet: build(...down(GW), udp({ sport: 4500, dport: 4500 }), ike({
                nonEsp: true, next: 46, exch: 35, resp: true, msgId: 1, spiR: SPI_R, summary: "IKE_AUTH MID=01 Responder Response",
                payloads: [sk(36, 1060, 531, "IDr, CERT (gateway certificate), AUTH, CP (your address is 10.99.0.7, DNS 10.20.0.53), SA (ESP, SPI 0xc7a3e912), TSi, TSr (10.20.0.0/16).")],
              })),
            }),
            note("client", "TUNNEL UP", "green"),
          ],
        },
        {
          title: "ESP: traffic goes out",
          desc: "A whole IP packet, encrypted inside UDP 4500",
          detail:
            "The laptop wants to open a file share at 10.20.0.15. It builds a normal packet from 10.99.0.7, encrypts it whole with AES-GCM, and adds an ESP header with the gateway’s SPI and sequence number 1. The gateway decrypts it and forwards the plain packet inside the office.",
          facts: [["SPI", `0x${ESP_OUT.toString(16)}`], ["Sequence", "1"], ["Inner packet", `${VIP} → ${FILES}:445`]],
          quiz: {
            q: "What can a coffee-shop eavesdropper learn from this packet?",
            options: ["The file name being opened", "The inner IP addresses", "Only the outer addresses, ports, SPI and size", "Nothing at all, not even the size"],
            answer: 2,
            why: "The inner packet is encrypted. The outer IP and UDP headers, the SPI, the sequence number and the length are still visible.",
          },
          events: [
            pkt("client", "vpn", "amber", "ESP", ["SPI c7a3e912 seq 1", "inner: SMB to 10.20.0.15"], {
              time: 0.09, info: `ESP (SPI=0x${ESP_OUT.toString(16)})`,
              packet: build(...up(GW), udp({ sport: 4500, dport: 4500 }), esp(ESP_OUT, 1, 224, 541, "Inner IPv4 10.99.0.7 → 10.20.0.15, TCP 445, SMB2 request, then ESP padding, pad length and next header (4 = IPv4).")),
            }),
            pkt("vpn", "files", "amber", "SMB", ["decrypted", `${VIP} → ${FILES}`], {
              time: 0.091, info: "49812 → 445 [PSH, ACK] Len=150 (SMB2 request)",
              packet: build(eth({ src: GW_IN_MAC, dst: FILES_MAC }), ipv4({ src: VIP, dst: FILES, ttl: 63 }), tcp({ sport: 49812, dport: 445, seq: 1, ack: 1, flags: "PA", win: 502, seqBase: 0x2a10c000, ackBase: 0x7713e000 }), proto({ id: "smb", name: "SMB2", fields: [{ name: "SMB2 request", random: 150, seed: 545, value: "150 bytes", note: "File-sharing request, not decoded here." }] })),
            }),
          ],
        },
        {
          title: "Reply and keepalive",
          desc: "Traffic back, and a tiny packet to keep the NAT open",
          detail:
            "The file server’s answer is encrypted by the gateway with the laptop’s SPI and sent back over UDP 4500. When the tunnel is quiet, the laptop sends a one-byte NAT-keepalive (0xFF) every 20 seconds so the home router doesn’t forget the port mapping.",
          facts: [["Reply SPI", `0x${ESP_IN.toString(16)}`], ["Keepalive", "1 byte 0xFF on UDP 4500"], ["Interval", "About 20 s"]],
          events: [
            pkt("files", "vpn", "violet", "SMB", ["reply, plain inside office"], {
              time: 0.092, info: "445 → 49812 [PSH, ACK] Len=180 (SMB2 response)",
              packet: build(eth({ src: FILES_MAC, dst: GW_IN_MAC }), ipv4({ src: FILES, dst: VIP }), tcp({ sport: 445, dport: 49812, seq: 1, ack: 151, flags: "PA", win: 509, seqBase: 0x7713e000, ackBase: 0x2a10c000 }), proto({ id: "smb", name: "SMB2", fields: [{ name: "SMB2 response", random: 180, seed: 546, value: "180 bytes" }] })),
            }),
            pkt("vpn", "client", "violet", "ESP", ["SPI 5d20b6f4 seq 1"], {
              time: 0.128, info: `ESP (SPI=0x${ESP_IN.toString(16)})`,
              packet: build(...down(GW), udp({ sport: 4500, dport: 4500 }), esp(ESP_IN, 1, 256, 551, "Inner IPv4 10.20.0.15 → 10.99.0.7, TCP, SMB2 response, padding, next header 4.")),
            }),
            pkt("client", "vpn", "slate", "KEEPALIVE", ["0xFF", "keep NAT open"], {
              time: 20.128, info: "NAT-keepalive",
              packet: build(...up(GW), udp({ sport: 4500, dport: 4500 }), proto({ id: "natka", name: "NAT-keepalive", osi: 5, fields: [{ name: "Keepalive", u8: 0xff, value: "0xFF", note: "RFC 3948: a single 0xFF byte. The receiver throws it away." }] })),
            }),
          ],
        },
      ],
      outro: {
        title: "Tunnel working",
        text: "Two round trips of IKEv2 agreed on crypto, swapped keys, proved both identities and created a pair of ESP security associations. Every office packet now travels as encrypted ESP inside UDP 4500, so it gets through the home NAT.",
        facts: [["IKE round trips", "2"], ["ESP SAs", "2 (one each way)"], ["NAT traversal", "UDP 4500 + keepalives"], ["Cipher", "AES-GCM-256"]],
      },
    },
    {
      id: "no-proposal",
      name: "Proposal mismatch",
      summary: "An old client offers only 3DES and a weak DH group; the gateway refuses with NO_PROPOSAL_CHOSEN.",
      kind: "failure",
      steps: [
        {
          title: "An old-fashioned offer",
          desc: "3DES, SHA-1 and 1024-bit DH",
          detail:
            "This laptop has a config copied from an old guide. Its only proposal is 3DES encryption, HMAC-SHA1-96 integrity, a SHA-1 PRF and DH group 2 (1024-bit MODP). Its KE payload is therefore 128 bytes long instead of 32.",
          facts: [["Encryption", "3DES (ID 3)"], ["DH group", "2 (MODP-1024)"], ["KE size", "128 bytes"]],
          events: [
            pkt("client", "vpn", "teal", "SA_INIT", ["3DES, SHA1, MODP1024"], {
              time: 0, info: "IKE_SA_INIT MID=00 Initiator Request",
              packet: build(...up(GW), ike500(), ike({
                next: 33, exch: 34, resp: false, msgId: 0, summary: "IKE_SA_INIT MID=00 Initiator Request",
                payloads: [
                  gp("Security Association", 34, [proposal(1, 1, [
                    tf(false, 1, "Encryption", 3, "ENCR_3DES"),
                    tf(false, 2, "PRF", 2, "PRF_HMAC_SHA1"),
                    tf(false, 3, "Integrity", 2, "AUTH_HMAC_SHA1_96"),
                    tf(true, 4, "Key exchange (DH group)", 2, "MODP 1024-bit"),
                  ])]),
                  gp("Key Exchange", 40, [
                    { name: "Key exchange method", u16: 2, value: "2 (MODP 1024-bit)" },
                    { name: "Reserved", u16: 0 },
                    { name: "Key exchange data", random: 128, seed: 561, value: "128 bytes" },
                  ]),
                  gp("Nonce", 0, [{ name: "Nonce data", random: 32, seed: 562, value: "32 random bytes" }]),
                ],
              })),
            }),
          ],
        },
        {
          title: "NO_PROPOSAL_CHOSEN",
          desc: "The gateway accepts none of it",
          detail:
            "The gateway only allows AES-GCM with Curve25519 or strong MODP groups, so nothing in the offer matches. It answers with a single Notify payload, type 14 NO_PROPOSAL_CHOSEN, and keeps no state. The fix is on the client: update its proposal list, not weaken the gateway.",
          facts: [["Notify type", "14 (NO_PROPOSAL_CHOSEN)"], ["Responder SPI", "0 (no session made)"], ["Fix", "Modern proposals on the client"]],
          quiz: {
            q: "Which payloads will the gateway’s reply contain?",
            options: ["SA, KE and Nonce with its own choice", "Just one Notify: NO_PROPOSAL_CHOSEN", "An encrypted SK payload", "Nothing; it stays silent"],
            answer: 1,
            why: "With no acceptable proposal there is nothing to negotiate, so the reply is a lone error Notify.",
          },
          events: [
            pkt("vpn", "client", "red", "NOTIFY", ["NO_PROPOSAL_CHOSEN"], {
              time: 0.037, info: "IKE_SA_INIT MID=00 Responder Response (NO_PROPOSAL_CHOSEN)",
              packet: build(...down(GW), ike500(), ike({
                next: 41, exch: 34, resp: true, msgId: 0, summary: "IKE_SA_INIT MID=00 Responder Response",
                payloads: [gp("Notify", 0, [
                  { name: "Protocol ID", u8: 0, value: "0" },
                  { name: "SPI size", u8: 0 },
                  { name: "Notify message type", u16: 14, value: "14 (NO_PROPOSAL_CHOSEN)", note: "Error types are below 16384; status types start at 16384." },
                ])],
              })),
            }),
            note("client", "NO PROPOSAL CHOSEN", "red"),
          ],
        },
      ],
      outro: {
        title: "Refused at the first message",
        text: "Both IKE peers must share at least one full set of algorithms. When they don’t, the responder sends NO_PROPOSAL_CHOSEN and nothing is set up. Logs on both sides usually list the offered and allowed transforms, which makes this easy to fix.",
        facts: [["Packets", "2"], ["Error", "Notify 14"], ["Common cause", "Old or mismatched crypto settings"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Exchanges",
      items: [["IKE_SA_INIT (34)", "Crypto offer, DH keys, nonces, NAT hashes"], ["IKE_AUTH (35)", "Identities, certificates, first ESP SA"], ["CREATE_CHILD_SA (36)", "More SAs or rekeying"], ["INFORMATIONAL (37)", "Delete, errors, liveness checks"]],
    },
    {
      title: "Payload types",
      items: [["33 SA / 34 KE / 40 Nonce", "Negotiation"], ["35 IDi / 36 IDr / 39 AUTH", "Who you are, and proof"], ["44 TSi / 45 TSr", "Which traffic goes in the tunnel"], ["41 Notify / 46 SK", "Messages / encrypted container"]],
    },
    {
      title: "Numbers to know",
      items: [["UDP 500", "IKE"], ["UDP 4500", "IKE + ESP when NAT is found"], ["IP proto 50 / 51", "ESP / AH"], ["Notify 14", "NO_PROPOSAL_CHOSEN"], ["Non-ESP marker", "4 zero bytes"]],
    },
  ],
});
