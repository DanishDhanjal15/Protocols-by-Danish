import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, field, FieldSpec, proto } from "@/lib/packet";
import { Bytes, hex, text } from "@/lib/bytes";
import { eth, ipv4, udp } from "@/lib/proto";

// ---------------------------------------------------------------- tiny BER encoder (ASN.1 Basic Encoding Rules)

const bytesOf = (specs: FieldSpec[]): Bytes => specs.map(field).flatMap((f) => f.bytes);

/** BER length: short form below 128, long form (0x81 / 0x82 + length) above. */
const berLen = (n: number): Bytes => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, (n >> 8) & 0xff, n & 0xff]);

const tagNames: Record<number, string> = {
  0x02: "INTEGER", 0x04: "OCTET STRING", 0x05: "NULL", 0x06: "OBJECT IDENTIFIER", 0x30: "SEQUENCE",
  0x40: "IpAddress", 0x41: "Counter32", 0x43: "TimeTicks",
  0xa0: "GetRequest-PDU", 0xa2: "GetResponse-PDU", 0xa3: "SetRequest-PDU", 0xa7: "SNMPv2-Trap-PDU",
};

/** A primitive TLV: Type, Length, Value. */
function leaf(name: string, tag: number, value: Bytes, shown: string, note?: string): FieldSpec {
  return {
    name,
    value: shown,
    note,
    fields: [
      { name: "Type", bytes: [tag], value: `0x${tag.toString(16).padStart(2, "0")} (${tagNames[tag] ?? "?"})` },
      { name: "Length", bytes: berLen(value.length), value: String(value.length) },
      ...(value.length ? [{ name: "Value", bytes: value, value: shown }] : []),
    ],
  };
}

/** A constructed TLV whose value is other TLVs. */
function cons(name: string, tag: number, children: FieldSpec[], shown?: string, note?: string): FieldSpec {
  const inner = bytesOf(children);
  return {
    name,
    value: shown ?? `${inner.length + 1 + berLen(inner.length).length} bytes`,
    note,
    fields: [
      { name: "Type", bytes: [tag], value: `0x${tag.toString(16).padStart(2, "0")} (${tagNames[tag] ?? "?"})` },
      { name: "Length", bytes: berLen(inner.length), value: String(inner.length) },
      ...children,
    ],
  };
}

/** Minimal two's-complement big-endian bytes for a non-negative number (adds 0x00 if the top bit is set). */
function uintBytes(n: number): Bytes {
  const out: Bytes = [];
  let v = n;
  do {
    out.unshift(v % 256);
    v = Math.floor(v / 256);
  } while (v > 0);
  if (out[0] & 0x80) out.unshift(0);
  return out;
}

/** OID encoding: first two arcs as 40·a+b, then each arc in base-128 with the high bit as "more follows". */
function oidBytes(dotted: string): Bytes {
  const arcs = dotted.split(".").map(Number);
  const all = [40 * arcs[0] + arcs[1], ...arcs.slice(2)];
  return all.flatMap((a) => {
    const groups: number[] = [a & 0x7f];
    let v = a >>> 7;
    while (v > 0) {
      groups.unshift((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    return groups;
  });
}

const int = (name: string, n: number, note?: string, shown?: string) => leaf(name, 0x02, uintBytes(n), shown ?? String(n), note);
const octets = (name: string, s: string, note?: string) => leaf(name, 0x04, text(s), JSON.stringify(s), note);
const oid = (name: string, dotted: string, label: string, note?: string) => leaf(name, 0x06, oidBytes(dotted), `${dotted} (${label})`, note);
const nul = (name = "Value") => leaf(name, 0x05, [], "NULL", "Empty placeholder: a GetRequest only names what it wants.");

const varbind = (dotted: string, label: string, value: FieldSpec, note?: string) =>
  cons(`Varbind: ${label}`, 0x30, [oid("Name (OID)", dotted, label), value], label, note);

// ---------------------------------------------------------------- the objects we ask about

const OID = {
  sysUpTime: "1.3.6.1.2.1.1.3.0",
  ifInOctets: "1.3.6.1.2.1.2.2.1.10.2",
  snmpTrapOID: "1.3.6.1.6.3.1.1.4.1.0",
  linkDown: "1.3.6.1.6.3.1.1.5.3",
  ifIndex: "1.3.6.1.2.1.2.2.1.1.2",
  ifAdminStatus: "1.3.6.1.2.1.2.2.1.7.2",
  ifOperStatus: "1.3.6.1.2.1.2.2.1.8.2",
  sysName: "1.3.6.1.2.1.1.5.0",
};

const UPTIME = 123456789; // hundredths of a second ≈ 14 days 6 h
const INOCTETS = 3141592653; // top bit set: needs a leading 0x00

function snmpV2(community: string, pduTag: number, pduName: string, reqId: number, binds: FieldSpec[], summary: string) {
  return proto({
    id: "snmp",
    name: "SNMP",
    summary,
    fields: [
      cons("SNMP message", 0x30, [
        int("Version", 1, "1 means SNMPv2c (0 would be v1, 3 is v3).", "1 (v2c)"),
        octets("Community", community, "The “password”, sent in plain text for anyone on the path to read."),
        cons(pduName, pduTag, [
          int("Request ID", reqId, "Matches a response to its request."),
          int("Error status", 0, "0 = noError.", "0 (noError)"),
          int("Error index", 0, "Which varbind caused an error, if any."),
          cons("Variable bindings", 0x30, binds, `${binds.length} varbind(s)`),
        ]),
      ], `${pduName}`),
    ],
  });
}

// ---------------------------------------------------------------- addresses

const NMS = "192.168.10.5";
const RTR = "192.168.10.1";
const NMS_MAC = "00:50:56:a1:10:05";
const RTR_MAC = "00:1e:bd:4c:22:01";
const ATT_MAC = "00:0c:29:13:37:99";
const NPORT = 50123;

const toRouter = (sport = NPORT, id = 0x2a11) => [eth({ src: NMS_MAC, dst: RTR_MAC }), ipv4({ src: NMS, dst: RTR, ttl: 64, id, df: false }), udp({ sport, dport: 161 })];
const toNms = (dport = NPORT, sport = 161, id = 0x0c31) => [eth({ src: RTR_MAC, dst: NMS_MAC }), ipv4({ src: RTR, dst: NMS, ttl: 255, id, df: false }), udp({ sport, dport })];

const getReq = (community: string, reqId: number) =>
  build(
    ...toRouter(),
    snmpV2(community, 0xa0, "GetRequest-PDU", reqId, [varbind(OID.sysUpTime, "sysUpTime.0", nul()), varbind(OID.ifInOctets, "ifInOctets.2", nul())], `get-request ${OID.sysUpTime} ${OID.ifInOctets}`)
  );

const getResp = build(
  ...toNms(),
  snmpV2("public", 0xa2, "GetResponse-PDU", 1804289383, [
    varbind(OID.sysUpTime, "sysUpTime.0", leaf("Value", 0x43, uintBytes(UPTIME), `${UPTIME} (14 days, 6:56:07.89)`, "TimeTicks: hundredths of a second since the agent started.")),
    varbind(OID.ifInOctets, "ifInOctets.2", leaf("Value", 0x41, uintBytes(INOCTETS), `${INOCTETS}`, "Counter32: bytes received on interface 2. The top bit is set, so BER adds a 0x00 byte to keep it positive.")),
  ], "get-response sysUpTime.0 ifInOctets.2")
);

const trap = build(
  ...toNms(162, 49152, 0x0c40),
  snmpV2("public", 0xa7, "SNMPv2-Trap-PDU", 1957747793, [
    varbind(OID.sysUpTime, "sysUpTime.0", leaf("Value", 0x43, uintBytes(UPTIME + 18000), `${UPTIME + 18000}`, "When the event happened, in uptime ticks.")),
    varbind(OID.snmpTrapOID, "snmpTrapOID.0", oid("Value", OID.linkDown, "linkDown"), "Every v2 trap says which event it is in its second varbind."),
    varbind(OID.ifIndex, "ifIndex.2", int("Value", 2)),
    varbind(OID.ifAdminStatus, "ifAdminStatus.2", int("Value", 1, "1 = up: nobody turned it off on purpose.", "1 (up)")),
    varbind(OID.ifOperStatus, "ifOperStatus.2", int("Value", 2, "2 = down: the link itself failed.", "2 (down)")),
  ], "snmpV2-trap linkDown ifIndex 2")
);

// ---------------------------------------------------------------- SNMPv3 (USM, authPriv)

const ENGINE = "80001f88805a3c1e9b7d6f20a4";

function snmpV3(o: { msgId: number; flags: number; user: string; boots: number; time: number; authed: boolean; encLen: number; summary: string }) {
  const usm = cons("USM security parameters", 0x30, [
    leaf("Authoritative engine ID", 0x04, hex(ENGINE), `0x${ENGINE}`, "Unique ID of the router’s SNMP engine."),
    int("Engine boots", o.boots, "How many times the engine restarted. With engine time it stops replayed messages."),
    int("Engine time", o.time, "Seconds since the last boot. Messages more than 150 s off are rejected."),
    octets("User name", o.user, "The only readable identity on the wire. No password is sent."),
    o.authed
      ? { ...leaf("Authentication parameters", 0x04, field({ name: "x", random: 24, seed: o.msgId }).bytes, "24-byte HMAC", "HMAC-SHA-256 (truncated to 192 bits) over the whole message. Any change breaks it."), opaque: true }
      : leaf("Authentication parameters", 0x04, [], "empty"),
    o.authed ? { ...leaf("Privacy parameters", 0x04, field({ name: "x", random: 8, seed: o.msgId + 1 }).bytes, "8-byte salt", "Salt for AES-128 encryption of the PDU."), opaque: true } : leaf("Privacy parameters", 0x04, [], "empty"),
  ]);
  const usmBytes = field(usm).bytes;
  const encrypted = field({ name: "x", random: o.encLen, seed: o.msgId + 2 }).bytes;
  return proto({
    id: "snmp",
    name: "SNMPv3",
    summary: o.summary,
    fields: [
      cons("SNMPv3 message", 0x30, [
        int("Version", 3, "3 means SNMPv3.", "3 (v3)"),
        cons("Header data", 0x30, [
          int("Message ID", o.msgId),
          int("Max size", 65507),
          leaf("Flags", 0x04, [o.flags], o.flags === 0x07 ? "0x07 (auth, priv, reportable)" : "0x03 (auth, priv)", "Bit 0 auth, bit 1 privacy (encryption), bit 2 reportable."),
          int("Security model", 3, "3 = User-based Security Model (USM).", "3 (USM)"),
        ]),
        leaf("Security parameters", 0x04, usmBytes, `user "${o.user}"`, "An OCTET STRING that wraps the USM sequence below."),
        { ...leaf("Encrypted scoped PDU", 0x04, encrypted, `${o.encLen} bytes`, "The GetRequest (OIDs and all) encrypted with AES. Without the key it is noise."), opaque: true },
      ], "SNMPv3 message"),
    ],
  });
}

const v3Req = build(...toRouter(50200, 0x2b01), snmpV3({ msgId: 811, flags: 0x07, user: "nms-ops", boots: 7, time: 1234567, authed: true, encLen: 62, summary: "encryptedPDU: privKey Unknown (SNMPv3 authPriv)" }));
const v3Resp = build(...toNms(50200, 161, 0x0c55), snmpV3({ msgId: 811, flags: 0x03, user: "nms-ops", boots: 7, time: 1234568, authed: true, encLen: 74, summary: "encryptedPDU: privKey Unknown (SNMPv3 authPriv)" }));

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "nms", kind: "server", label: "Monitoring server", sub: NMS, x: 12, y: 60 },
  { id: "switch", kind: "switch", label: "Core switch", x: 42, y: 60 },
  { id: "router", kind: "router", label: "Branch router", sub: `${RTR} (agent)`, x: 72, y: 60 },
  { id: "wan", kind: "cloud", label: "WAN link", sub: "interface 2", x: 90, y: 25 },
];
const links: [string, string][] = [["nms", "switch"], ["switch", "router"], ["router", "wan"]];

const attackDevices: Device[] = [...devices, { id: "attacker", kind: "attacker", label: "Sniffer", sub: "192.168.10.66", x: 42, y: 22 }];
const attackLinks: [string, string][] = [...links, ["attacker", "switch"]];

export default defineLesson({
  id: "snmp",
  name: "SNMP",
  full: "Simple Network Management Protocol",
  group: "iot",
  layer: 7,
  difficulty: 2,
  tagline: "How network teams read counters from every router and switch.",
  description:
    "SNMP lets a monitoring server ask a device for numbered values (uptime, bytes on a port, CPU load) and lets the device shout when something breaks. Every value has an OID, a dotted address in a big shared tree, and messages are packed in ASN.1 BER, a compact type-length-value format.",
  facts: [
    ["Layer", "Application (over UDP)"],
    ["Ports", "UDP 161 queries, 162 traps"],
    ["Encoding", "ASN.1 BER (type-length-value)"],
    ["Versions", "v1, v2c (community), v3 (users + crypto)"],
    ["Data model", "MIB, addressed by OIDs"],
    ["Defined in", "RFC 3416, v3 in RFC 3414"],
  ],
  ports: "UDP 161 (agent), UDP 162 (traps)",
  rfc: "RFC 3416",
  keywords: ["mib", "oid", "community", "public", "trap", "get", "ber", "asn.1", "snmpv3", "usm", "authpriv", "monitoring", "sysuptime", "ifinoctets"],
  related: ["syslog", "udp", "netflow"],
  devices,
  links,
  legend: [
    ["blue", "Queries from the monitoring server"],
    ["violet", "Answers from the router"],
    ["pink", "Traps (unasked alerts)"],
    ["teal", "SNMPv3 encrypted"],
    ["red", "Problems and attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Polling a router and getting a trap",
      summary: "The monitoring server reads uptime and a traffic counter, then the router reports a link failure on its own.",
      kind: "normal",
      steps: [
        {
          title: "GetRequest",
          desc: "Ask for two values by OID",
          detail:
            "Every few minutes the monitoring server asks the router for sysUpTime.0 (1.3.6.1.2.1.1.3.0) and ifInOctets.2 (bytes received on interface 2). The message is SNMPv2c: a version number, the community string “public”, and a GetRequest PDU with a request ID and a list of variable bindings. Each binding is an OID with an empty NULL value to be filled in.",
          facts: [["To", `${RTR} : 161`], ["Community", "public (plain text)"], ["OIDs", "sysUpTime.0, ifInOctets.2"]],
          quiz: {
            q: "The OID starts 1.3.6.1… How is “1.3” stored in BER?",
            options: ["Two bytes: 01 03", "One byte: 0x2B (40×1 + 3)", "As the text “1.3”", "It is left out"],
            answer: 1,
            why: "BER packs the first two arcs into one byte as 40 × first + second, so 1.3 becomes 43 = 0x2B. That’s why SNMP OIDs on the wire start with 2B 06 01.",
          },
          events: [
            pkt("nms", "router", "blue", "GET", ["sysUpTime.0", "ifInOctets.2"], {
              time: 0, info: `get-request ${OID.sysUpTime} ${OID.ifInOctets}`, packet: getReq("public", 1804289383),
            }),
          ],
        },
        {
          title: "GetResponse",
          desc: "Values filled in, with types",
          detail:
            "The router’s agent looks up both OIDs and returns the same request ID with the values filled in. sysUpTime is a TimeTicks (hundredths of a second), ifInOctets is a Counter32. The counter 3,141,592,653 has its top bit set, so BER adds a leading 0x00 byte to keep it from being read as negative.",
          facts: [["sysUpTime", `${UPTIME} ticks ≈ 14 days`], ["ifInOctets.2", `${INOCTETS} bytes`], ["Round trip", "Under 2 ms on the LAN"]],
          quiz: {
            q: "Five minutes later ifInOctets.2 reads 3,179,092,653. What was the average traffic in?",
            options: ["About 1 Mbit/s", "About 125 kbit/s", "About 37.5 Mbit/s", "You can’t tell from counters"],
            answer: 0,
            why: "The counter grew by 37,500,000 bytes in 300 s: 125,000 bytes/s, which is 1,000,000 bits per second. Graphs are drawn from exactly this kind of difference.",
          },
          events: [
            pkt("router", "nms", "violet", "RESPONSE", ["uptime 14 days", "in: 3.14 GB"], {
              time: 0.0014, info: "get-response 1.3.6.1.2.1.1.3.0 1.3.6.1.2.1.2.2.1.10.2", packet: getResp,
            }),
          ],
        },
        {
          title: "The link goes down",
          desc: "The router sends a trap unasked",
          detail:
            "Three minutes later the WAN cable on interface 2 fails. The router doesn’t wait to be asked: it sends an SNMPv2-Trap to the monitoring server on UDP port 162. The varbinds say when (sysUpTime), what happened (snmpTrapOID = linkDown) and which port (ifIndex 2, admin up, operationally down).",
          facts: [["To", `${NMS} : 162`], ["Event", "linkDown (1.3.6.1.6.3.1.1.5.3)"], ["Status", "Admin up, oper down"]],
          quiz: {
            q: "ifAdminStatus is up(1) but ifOperStatus is down(2). What does that tell the engineer?",
            options: ["Someone shut the port on purpose", "The port should be up but the link failed", "The router rebooted", "SNMP is misconfigured"],
            answer: 1,
            why: "Admin status is what the configuration wants; oper status is reality. Up but down means a fault: cable, optics or the far end.",
          },
          events: [
            note("wan", "CABLE CUT", "red"),
            pkt("router", "nms", "pink", "TRAP", ["linkDown", "ifIndex 2"], { time: 180.2, info: "snmpV2-trap 1.3.6.1.2.1.1.3.0 1.3.6.1.6.3.1.1.4.1.0 …", packet: trap }),
            note("nms", "ALERT: WAN DOWN", "red"),
          ],
        },
        {
          title: "Traps aren’t acknowledged",
          desc: "Fire and forget over UDP",
          detail:
            "A trap gets no reply, so if it is lost the alert is simply gone. That is why monitoring systems keep polling too: the next GetRequest would show ifOperStatus down anyway. SNMPv2c also has an Inform message, which is a trap that the receiver must acknowledge.",
          facts: [["Reply to trap", "None"], ["Safer option", "InformRequest (acknowledged)"], ["Backup", "Regular polling"]],
          events: [note("nms", "POLL CONFIRMS: OPER DOWN", "amber")],
        },
      ],
      outro: {
        title: "Polled and alerted",
        text: "The monitoring server read two numbered values from the router with a single GetRequest, and the router pushed a trap the moment a link failed. Every value lived at an OID and every byte was a type-length-value triple.",
        facts: [["Messages", "Get, Response, Trap"], ["Ports", "161 polls, 162 traps"], ["Encoding", "BER TLV"], ["Security", "Community string only (v2c)"]],
      },
    },
    {
      id: "wrong-community",
      name: "Wrong community string",
      summary: "A typo in the community string means the router silently ignores the request.",
      kind: "failure",
      steps: [
        {
          title: "Ask with the wrong string",
          desc: "Community “pubilc” instead of “public”",
          detail:
            "A new monitoring config has a typo in the community string. The packet is perfectly formed, but the router compares the community to its list and finds no match.",
          facts: [["Community", "pubilc (typo)"], ["To", `${RTR} : 161`], ["Format", "Valid SNMPv2c"]],
          events: [pkt("nms", "router", "blue", "GET", ["community pubilc"], { time: 0, info: `get-request ${OID.sysUpTime} ${OID.ifInOctets}`, packet: getReq("pubilc", 846930886) })],
        },
        {
          title: "Silence, then retries",
          desc: "No error comes back",
          detail:
            "SNMPv2c agents don’t reply to a bad community at all, so the attacker (or the confused admin) learns nothing. The manager retries after a timeout, then reports “No response from 192.168.10.1”. The router may count it in snmpInBadCommunityNames or send an authenticationFailure trap.",
          facts: [["Router reply", "None"], ["Manager", "Timeout after retries"], ["Counter", "snmpInBadCommunityNames +1"]],
          quiz: {
            q: "Why doesn’t the router answer “wrong password”?",
            options: ["UDP can’t carry errors", "Silence gives a password-guesser no hint", "It answers on port 162 instead", "It does, with error status 5"],
            answer: 1,
            why: "Replying would confirm that an SNMP agent is there and that the guess was wrong. Silence makes guessing slower and blind.",
          },
          events: [
            note("router", "BAD COMMUNITY: DROPPED", "red"),
            pkt("nms", "router", "blue", "GET", ["retry"], { time: 1, info: `get-request ${OID.sysUpTime} ${OID.ifInOctets}`, packet: getReq("pubilc", 846930886) }),
            note("nms", "NO RESPONSE (TIMEOUT)", "red"),
          ],
        },
      ],
      outro: {
        title: "Timed out",
        text: "A wrong community string looks exactly like a dead device: no answer at all. When SNMP times out, check the community, the agent’s allowed-manager list and any firewall on UDP 161 before assuming the device is down.",
        facts: [["Symptom", "Timeout"], ["Cause", "Community mismatch"], ["Check", "Config, ACL, UDP 161 reachability"]],
      },
    },
    {
      id: "v3",
      name: "Sniffed community vs SNMPv3 authPriv",
      summary: "An attacker reads the community string off the wire; SNMPv3 with authentication and encryption leaves nothing useful.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "Community in plain text",
          desc: "Anyone on the path can read it",
          detail:
            "An attacker with access to a mirror port (or a compromised machine on the same network) captures the v2c GetRequest. The community string sits in the clear a few bytes into the packet, along with every OID and later every value.",
          facts: [["Seen by attacker", "Community “public”, OIDs, values"], ["Encryption", "None"], ["Integrity check", "None"]],
          quiz: {
            q: "What can the attacker do with a captured read-write community string?",
            options: ["Nothing; it’s hashed", "Send SetRequests that change the router’s config", "Only read uptime", "Decrypt TLS traffic"],
            answer: 1,
            why: "In v1 and v2c the community string is the whole authentication. A write community lets anyone send SetRequests, for example to shut interfaces.",
          },
          events: [
            pkt("nms", "router", "blue", "GET", ["community public"], { time: 0, info: `get-request ${OID.sysUpTime} ${OID.ifInOctets}`, packet: getReq("public", 1804289383) }),
            pkt("nms", "attacker", "red", "COPY", ["mirrored to sniffer"], { time: 0, parallel: true, info: `get-request ${OID.sysUpTime} ${OID.ifInOctets}`, packet: getReq("public", 1804289383) }),
            note("attacker", "COMMUNITY: public", "red"),
          ],
        },
        {
          title: "Switch to SNMPv3 authPriv",
          desc: "A user name, an HMAC and an encrypted PDU",
          detail:
            "With SNMPv3 the message carries a user name, a security header and an encrypted scoped PDU. authPriv means two keys derived from the user’s passwords: one signs the whole message with an HMAC so it can’t be changed or forged, the other encrypts the PDU with AES. The OIDs are now hidden.",
          facts: [["Security level", "authPriv (flags 0x07)"], ["Auth", "HMAC-SHA-256"], ["Privacy", "AES-128"]],
          quiz: {
            q: "What can the sniffer still read in this SNMPv3 request?",
            options: ["The password", "The OIDs being asked for", "The user name and engine ID", "Nothing at all"],
            answer: 2,
            why: "The header and USM fields stay readable so the router knows which keys to use. Passwords are never sent, and the PDU is encrypted.",
          },
          events: [
            pkt("nms", "router", "teal", "GET v3", ["user nms-ops", "PDU encrypted"], { time: 10, info: "encryptedPDU: privKey Unknown", packet: v3Req }),
            pkt("nms", "attacker", "red", "COPY", ["only noise"], { time: 10, parallel: true, info: "encryptedPDU: privKey Unknown", packet: v3Req }),
          ],
        },
        {
          title: "Encrypted response",
          desc: "Values hidden too",
          detail:
            "The router checks the HMAC, checks that engine boots and time are fresh (which blocks replayed packets), decrypts, answers, and encrypts the reply the same way. The sniffer sees two blobs of noise and a user name.",
          facts: [["Replay window", "± 150 s engine time"], ["Seen by attacker", "User name, sizes"], ["Tamper check", "HMAC on every message"]],
          events: [
            pkt("router", "nms", "teal", "RESPONSE v3", ["encrypted values"], { time: 10.002, info: "encryptedPDU: privKey Unknown", packet: v3Resp }),
            note("attacker", "NOTHING USEFUL", "green"),
          ],
        },
      ],
      outro: {
        title: "Use SNMPv3 with authPriv",
        text: "Community strings are passwords sent in clear text, so v1 and v2c should only run on isolated management networks, read-only, with ACLs. SNMPv3 with authPriv signs and encrypts every message and is the right choice anywhere else.",
        facts: [["v2c risk", "Clear-text community"], ["v3 noAuthNoPriv", "User name only"], ["v3 authNoPriv", "Signed, not hidden"], ["v3 authPriv", "Signed and encrypted"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "PDU types (BER tag)",
      items: [["0xA0", "GetRequest"], ["0xA1", "GetNextRequest (walks the tree)"], ["0xA2", "Response"], ["0xA3", "SetRequest"], ["0xA5", "GetBulkRequest"], ["0xA6 / 0xA7", "InformRequest / SNMPv2-Trap"]],
    },
    {
      title: "Useful OIDs",
      items: [["1.3.6.1.2.1.1.3.0", "sysUpTime"], ["1.3.6.1.2.1.1.5.0", "sysName"], ["1.3.6.1.2.1.2.2.1.10.n", "ifInOctets on interface n"], ["1.3.6.1.2.1.2.2.1.8.n", "ifOperStatus (1 up, 2 down)"], ["1.3.6.1.6.3.1.1.5.3", "linkDown trap"]],
    },
    {
      title: "BER types",
      items: [["0x02", "INTEGER"], ["0x04", "OCTET STRING"], ["0x05", "NULL"], ["0x06", "OBJECT IDENTIFIER"], ["0x30", "SEQUENCE"], ["0x41 / 0x43", "Counter32 / TimeTicks"]],
    },
  ],
});
