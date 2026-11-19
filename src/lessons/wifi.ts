import { Device, defineLesson, note, pkt, Step } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, opaque, proto } from "@/lib/packet";
import { mac, rand, u16le, u64 } from "@/lib/bytes";
import { ADDR } from "./_common";

// ------------------------------------------------------------------ 802.11 helpers
// Exported so the WPA3 lesson can reuse the same real frame layouts.

export const STA = ADDR.laptopMac;
export const BSSID = ADDR.routerMac;
export const BCAST = "ff:ff:ff:ff:ff:ff";
export const SSID = "HomeNet";

const hx = (n: number, w = 4) => `0x${n.toString(16).padStart(w, "0")}`;
const le64 = (n: bigint) => u64(n).reverse();
const t = (n: number) => Number(n.toFixed(4));

const MGMT_SUB: Record<number, string> = {
  0: "Association Request", 1: "Association Response", 4: "Probe Request", 5: "Probe Response", 8: "Beacon",
  11: "Authentication", 12: "Deauthentication", 13: "Action",
};

/** 802.11 MAC header: frame control, duration, three addresses, sequence control (24 bytes). */
export function wlan(o: { type: 0 | 2; subtype: number; a1: string; a2: string; a3: string; seq: number; flags?: number; dur?: number }): LayerSpec {
  const fc0 = (o.subtype << 4) | (o.type << 2);
  const flags = o.flags ?? 0;
  const kind = o.type === 0 ? MGMT_SUB[o.subtype] ?? "Management" : "Data";
  const flagNames = ([[0x01, "To DS"], [0x02, "From DS"], [0x08, "Retry"], [0x40, "Protected"]] as [number, string][])
    .filter(([b]) => flags & b)
    .map(([, n]) => n);
  const bcast = o.a1.toLowerCase() === BCAST;
  const dur = o.dur ?? (bcast ? 0 : 44);
  const toDs = (flags & 1) === 1, fromDs = (flags & 2) === 2;
  const names =
    o.type === 0 ? ["Receiver address", "Transmitter address", "BSSID"]
      : toDs ? ["Receiver (BSSID)", "Source address", "Destination address"]
        : fromDs ? ["Destination address", "Transmitter (BSSID)", "Source address"]
          : ["Destination address", "Source address", "BSSID"];
  const notes = [
    bcast ? "Broadcast: every radio on this channel listens." : "The radio that should pick this frame up.",
    "The radio that sent it.",
    o.type === 0 ? "The network's ID: the access point's own MAC address." : "The third address says where the data really comes from or goes to.",
  ];
  return proto({
    id: "wlan", name: "IEEE 802.11", osi: 2,
    summary: `IEEE 802.11 ${kind}${flagNames.length ? ` (${flagNames.join(", ")})` : ""}, SN=${o.seq}`,
    fields: [
      {
        name: "Frame control", value: `${kind}${flagNames.length ? ", " + flagNames.join(", ") : ""}`,
        fields: [
          { name: "Type / subtype", u8: fc0, value: `${hx(fc0, 2)}: ${o.type === 0 ? "Management" : "Data"}, ${kind}`, note: o.type === 0 ? "Type 0 is management: frames that find, join and leave networks." : "Type 2 is data: frames that carry real traffic." },
          { name: "Flags", u8: flags, value: flagNames.join(", ") || "none", note: flags & 0x40 ? "Protected: the body is encrypted with CCMP." : toDs ? "To DS: going from a station into the network." : fromDs ? "From DS: coming out of the network to a station." : "No flags set." },
        ],
      },
      { name: "Duration", bytes: u16le(dur), value: `${dur} µs`, note: bcast ? "Zero for broadcasts: nobody sends an acknowledgement." : "Time the air stays reserved for the ACK that follows. Other radios wait." },
      { name: names[0], bytes: mac(o.a1), value: o.a1, note: notes[0] },
      { name: names[1], bytes: mac(o.a2), value: o.a2, note: notes[1] },
      { name: names[2], bytes: mac(o.a3), value: o.a3, note: notes[2] },
      { name: "Sequence control", bytes: u16le(o.seq << 4), value: `seq ${o.seq}, fragment 0`, note: "A counter per sender, so a frame resent after a missed ACK is not delivered twice. 802.11 numbers are little-endian." },
    ],
  });
}

/** Information element: id(1) + length(1) + data */
export const ie = (id: number, name: string, data: FieldSpec[], value?: string, note?: string): FieldSpec => {
  const len = data.map(field).flatMap((f) => f.bytes).length;
  return {
    name: `Tag: ${name}`, value: value ?? `${len} bytes`, note,
    fields: [{ name: "Element ID", u8: id, value: `${id} (${name})` }, { name: "Length", u8: len }, ...data],
  };
};

export const ssidIE = (s = SSID) => ie(0, "SSID", [{ name: "SSID", text: s, value: s }], s, "The network name people see in the Wi-Fi list.");
export const ratesIE = () =>
  ie(1, "Supported Rates", [{ name: "Rates", bytes: [0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24], value: "1(B) 2(B) 5.5(B) 11(B) 6 9 12 18 Mbit/s" }], undefined, "Speeds this radio can use. (B) marks basic rates every station must support.");
export const dsIE = (ch = 6) => ie(3, "DS Parameter set", [{ name: "Current channel", u8: ch }], `channel ${ch}`, "The channel the access point is on.");
const timIE = () =>
  ie(5, "TIM", [{ name: "DTIM count", u8: 0 }, { name: "DTIM period", u8: 1 }, { name: "Bitmap control", u8: 0 }, { name: "Partial virtual bitmap", u8: 0 }], "DTIM 0 of 1", "Traffic Indication Map: tells sleeping devices whether the access point holds frames for them.");

const AKM_NAMES: Record<number, string> = { 2: "PSK", 6: "PSK-SHA256", 8: "SAE" };
/** RSN element (WPA2/WPA3 security parameters). caps: 0x0080 = PMF capable, 0x00c0 = PMF required */
export const rsnIE = (akms: number[], caps = 0) => {
  const pmf = caps & 0x40 ? "PMF required" : caps & 0x80 ? "PMF capable" : "no PMF";
  return ie(48, "RSN Information", [
    { name: "Version", bytes: u16le(1), value: "1" },
    { name: "Group cipher suite", bytes: [0x00, 0x0f, 0xac, 0x04], value: "00-0f-ac:4 (AES-CCMP)", note: "Cipher for broadcast traffic." },
    { name: "Pairwise cipher count", bytes: u16le(1), value: "1" },
    { name: "Pairwise cipher suite", bytes: [0x00, 0x0f, 0xac, 0x04], value: "00-0f-ac:4 (AES-CCMP)", note: "Cipher for traffic between this one device and the access point." },
    { name: "AKM suite count", bytes: u16le(akms.length), value: String(akms.length) },
    ...akms.map((a): FieldSpec => ({ name: "AKM suite", bytes: [0x00, 0x0f, 0xac, a], value: `00-0f-ac:${a} (${AKM_NAMES[a] ?? "?"})`, note: a === 8 ? "Simultaneous Authentication of Equals: WPA3-Personal." : "Pre-shared key: a password everyone on the network shares (WPA2-Personal)." })),
    { name: "RSN capabilities", bytes: u16le(caps), value: `${hx(caps)} (${pmf})`, note: "Bit 7 = management frame protection capable, bit 6 = required (802.11w)." },
  ], `${akms.map((a) => AKM_NAMES[a]).join(" + ")}, CCMP, ${pmf}`, "Robust Security Network element: which ciphers and which login method (AKM) this network uses.");
};

/** Management frame body: fixed parameters then tagged parameters. */
export const mgmt = (name: string, fixed: FieldSpec[], tags: FieldSpec[] = []): LayerSpec =>
  proto({
    id: "wlan.mgt", name: `802.11 ${name}`, osi: 2,
    fields: [
      ...(fixed.length ? [{ name: "Fixed parameters", fields: fixed } as FieldSpec] : []),
      ...(tags.length ? [{ name: "Tagged parameters", fields: tags } as FieldSpec] : []),
    ],
  });

export const CAP = (v = 0x0411): FieldSpec => ({ name: "Capabilities", bytes: u16le(v), value: `${hx(v)} (ESS, Privacy, short slot)`, note: "ESS: this is an access point network. Privacy: a key is needed to join." });

export const beaconBody = (rsn: FieldSpec, ts: bigint) =>
  mgmt("Beacon", [
    { name: "Timestamp", bytes: le64(ts), value: `${ts} µs`, note: "The access point's clock, so stations can stay in step with it." },
    { name: "Beacon interval", bytes: u16le(100), value: "100 TU (102.4 ms)", note: "A beacon goes out about ten times a second." },
    CAP(),
  ], [ssidIE(), ratesIE(), dsIE(), timIE(), rsn]);

export const probeRespBody = (rsn: FieldSpec, ts: bigint) =>
  mgmt("Probe Response", [
    { name: "Timestamp", bytes: le64(ts), value: `${ts} µs` },
    { name: "Beacon interval", bytes: u16le(100), value: "100 TU (102.4 ms)" },
    CAP(),
  ], [ssidIE(), ratesIE(), dsIE(), rsn]);

export const authBody = (alg: number, seq: number, status = 0, extra: FieldSpec[] = []) =>
  mgmt("Authentication", [
    { name: "Authentication algorithm", bytes: u16le(alg), value: `${alg} (${alg === 0 ? "Open System" : alg === 3 ? "SAE" : "?"})`, note: alg === 0 ? "Open System: no password check here. The real check comes later in the 4-way handshake." : "SAE: a password-based key exchange that resists guessing." },
    { name: "Transaction sequence", bytes: u16le(seq), value: String(seq), note: alg === 3 ? (seq === 1 ? "1 = Commit." : "2 = Confirm.") : seq === 1 ? "1 = request." : "2 = reply." },
    { name: "Status code", bytes: u16le(status), value: status === 0 ? "0 (Successful)" : String(status) },
    ...extra,
  ]);

export const assocReqBody = (rsn: FieldSpec) =>
  mgmt("Association Request", [CAP(0x0431), { name: "Listen interval", bytes: u16le(10), value: "10 beacons", note: "How often the laptop promises to wake up and check for buffered frames when it dozes." }], [ssidIE(), ratesIE(), rsn]);

export const assocRespBody = (aid = 1, status = 0) =>
  mgmt("Association Response", [
    CAP(),
    { name: "Status code", bytes: u16le(status), value: status === 0 ? "0 (Successful)" : String(status) },
    { name: "Association ID", bytes: u16le(0xc000 | aid), value: `${aid}`, note: "A small number the access point gives this station (top two bits are always set)." },
  ], [ratesIE()]);

export const deauthBody = (reason: number, why: string) =>
  mgmt("Deauthentication", [{ name: "Reason code", bytes: u16le(reason), value: `${reason} (${why})` }]);

export const llc = (type = 0x888e) =>
  proto({
    id: "llc", name: "Logical-Link Control", osi: 2,
    summary: `LLC/SNAP, type ${hx(type)}`,
    fields: [
      { name: "DSAP", u8: 0xaa, value: "0xaa (SNAP)" },
      { name: "SSAP", u8: 0xaa, value: "0xaa (SNAP)" },
      { name: "Control", u8: 0x03, value: "0x03 (unnumbered)" },
      { name: "Organization code", bytes: [0, 0, 0], value: "00:00:00 (encapsulated Ethernet)" },
      { name: "Type", u16: type, value: `${hx(type)} (${type === 0x888e ? "802.1X / EAPOL" : type === 0x0800 ? "IPv4" : "?"})`, note: "Plays the role of the EtherType: what is inside." },
    ],
  });

const KEYINFO_BASE: Record<number, number> = { 1: 0x0088, 2: 0x0108, 3: 0x13c8, 4: 0x0308 };
const KEYINFO_TEXT: Record<number, string> = {
  1: "Pairwise, Ack",
  2: "Pairwise, MIC",
  3: "Pairwise, Install, Ack, MIC, Secure, Encrypted key data",
  4: "Pairwise, MIC, Secure",
};
export const ANONCE_SEED = 4101;
export const SNONCE_SEED = 4202;

/** EAPOL-Key frame (one of the four handshake messages). ver 2 = HMAC-SHA1/AES (WPA2), 0 = AKM-defined (SAE). */
export function eapolKey(o: { msg: 1 | 2 | 3 | 4; replay: number; ver?: 0 | 2; nonceSeed?: number; micSeed?: number; keyData?: FieldSpec[] }): LayerSpec {
  const ver = o.ver ?? 2;
  const info = KEYINFO_BASE[o.msg] | ver;
  const nonce: FieldSpec =
    o.msg === 1 || o.msg === 3 ? { name: "Key nonce (ANonce)", bytes: rand(32, o.nonceSeed ?? ANONCE_SEED), value: "32 random bytes", note: "The access point's fresh random number. It mixes into the session key." }
      : o.msg === 2 ? { name: "Key nonce (SNonce)", bytes: rand(32, o.nonceSeed ?? SNONCE_SEED), value: "32 random bytes", note: "The laptop's fresh random number." }
        : { name: "Key nonce", zero: 32, value: "0 (unused)" };
  const mic: FieldSpec = o.msg === 1
    ? { name: "Key MIC", zero: 16, value: "0 (none yet)", note: "Message 1 has no MIC: no keys exist yet." }
    : { name: "Key MIC", bytes: rand(16, o.micSeed ?? 5000 + o.msg), value: "16 bytes", note: "A keyed checksum over this whole frame, made with the KCK (part of the session key). Only someone who knows the password can make a valid one." };
  const kd = o.keyData ?? [];
  const kdLen = kd.map(field).flatMap((f) => f.bytes).length;
  const body: FieldSpec[] = [
    { name: "Key descriptor type", u8: 2, value: "2 (EAPOL RSN Key)" },
    { name: "Key information", u16: info, value: `${hx(info)} (${KEYINFO_TEXT[o.msg]}, version ${ver})`, note: ver === 2 ? "Version 2: HMAC-SHA1 for the MIC, AES for key wrap." : "Version 0: the AKM (here SAE) decides the algorithms." },
    { name: "Key length", u16: o.msg === 1 || o.msg === 3 ? 16 : 0, note: "16 bytes: the CCMP temporal key." },
    { name: "Replay counter", u64: o.replay, note: "Goes up with every new message from the access point, so an old copy can't be played back." },
    nonce,
    { name: "Key IV", zero: 16, value: "0" },
    { name: "Key RSC", zero: 8, value: "0", note: "Starting packet number for the group key." },
    { name: "Key ID", zero: 8, value: "0 (reserved)" },
    mic,
    { name: "Key data length", u16: kdLen },
    ...kd,
  ];
  const bodyLen = body.map(field).flatMap((f) => f.bytes).length;
  return proto({
    id: "eapol", name: "802.1X Authentication", osi: 2,
    summary: `EAPOL Key (Message ${o.msg} of 4)`,
    fields: [
      { name: "Version", u8: 2, value: "2 (802.1X-2004)" },
      { name: "Type", u8: 3, value: "3 (Key)" },
      { name: "Length", u16: bodyLen, value: `${bodyLen} bytes` },
      ...body,
    ],
  });
}

export const m2KeyData = (akm: number, caps = 0): FieldSpec[] => [rsnIE([akm], caps)];
export const m3KeyData = (): FieldSpec[] => [
  { name: "Key data (encrypted)", random: 56, opaque: true, value: "56 bytes", note: "The RSN element and the GTK (group key for broadcasts), wrapped with the KEK so only the laptop can unwrap it." },
];

/** CCMP header (8 bytes) + encrypted body + 8-byte MIC as trailer */
export const ccmp = (pn: number) =>
  proto({
    id: "ccmp", name: "CCMP", osi: 2,
    summary: `CCMP, PN ${pn}`,
    fields: [
      {
        name: "CCMP header", value: `PN ${pn}, key 0`,
        fields: [
          { name: "PN0", u8: pn & 0xff },
          { name: "PN1", u8: (pn >>> 8) & 0xff },
          { name: "Reserved", u8: 0 },
          { name: "Key ID / ExtIV", u8: 0x20, value: "0x20 (key 0, ExtIV set)", note: "ExtIV must be set for CCMP." },
          { name: "PN2–PN5", bytes: [(pn >>> 16) & 0xff, (pn >>> 24) & 0xff, 0, 0], value: "high bytes of PN" },
        ],
        note: "Packet number: goes up by one each frame. A receiver drops any frame whose PN is not higher than the last one, which stops replays.",
      },
    ],
    trailer: [{ name: "CCMP MIC", random: 8, value: "8 bytes", note: "Integrity tag. If one bit of the frame is changed, the check fails and the frame is dropped." }],
  });

// ------------------------------------------------------------------ lesson data

const RSN_AP = rsnIE([2], 0x0000);

const toAp = (sub: number, seq: number, flags = 0) => wlan({ type: 0, subtype: sub, a1: BSSID, a2: STA, a3: BSSID, seq, flags });
const toSta = (sub: number, seq: number, flags = 0) => wlan({ type: 0, subtype: sub, a1: STA, a2: BSSID, a3: BSSID, seq, flags });
const dataUp = (seq: number, flags = 0x01) => wlan({ type: 2, subtype: 0, a1: BSSID, a2: STA, a3: BSSID, seq, flags });
const dataDown = (seq: number, flags = 0x02) => wlan({ type: 2, subtype: 0, a1: STA, a2: BSSID, a3: BSSID, seq, flags });

const beacon = (time: number, rsn = RSN_AP, seq = 2310): Step["events"][number] =>
  pkt("ap", "client", "blue", "BEACON", [`SSID ${SSID}`, "WPA2, channel 6"], {
    time, info: `Beacon frame, SN=${seq}, FN=0, Flags=........, BI=100, SSID="${SSID}"`,
    packet: build(wlan({ type: 0, subtype: 8, a1: BCAST, a2: BSSID, a3: BSSID, seq }), beaconBody(rsn, BigInt(91234567890) + BigInt(Math.round(time * 1e6)))),
  });

const joinEvents = (base: number, rsn = RSN_AP, s0 = 120, a0 = 2312) => [
  pkt("client", "ap", "blue", "AUTH", ["Open System", "seq 1"], {
    time: t(base), info: `Authentication, SN=${s0}, Open System, seq 1`,
    packet: build(toAp(11, s0), authBody(0, 1)),
  }),
  pkt("ap", "client", "green", "AUTH", ["Open System", "seq 2, success"], {
    time: t(base + 0.0004), info: `Authentication, SN=${a0}, Open System, seq 2, Successful`,
    packet: build(toSta(11, a0), authBody(0, 2)),
  }),
  pkt("client", "ap", "blue", "ASSOC REQ", [`SSID ${SSID}`, "PSK + CCMP"], {
    time: t(base + 0.0012), info: `Association Request, SN=${s0 + 1}, SSID="${SSID}"`,
    packet: build(toAp(0, s0 + 1), assocReqBody(rsn)),
  }),
  pkt("ap", "client", "green", "ASSOC RESP", ["success", "AID 1"], {
    time: t(base + 0.0018), info: `Association Response, SN=${a0 + 1}, Status=Successful, AID=1`,
    packet: build(toSta(1, a0 + 1), assocRespBody(1)),
  }),
];

const m1 = (time: number, replay = 1, seq = 0, nonceSeed = ANONCE_SEED) =>
  pkt("ap", "client", "teal", "EAPOL 1/4", ["ANonce", "no MIC"], {
    time, info: `Key (Message 1 of 4), replay counter ${replay}`,
    packet: build(dataDown(seq), llc(), eapolKey({ msg: 1, replay, nonceSeed })),
  });
const m2 = (time: number, replay = 1, seq = 0, micSeed = 5002, caps = 0) =>
  pkt("client", "ap", "teal", "EAPOL 2/4", ["SNonce", "+ MIC"], {
    time, info: `Key (Message 2 of 4), replay counter ${replay}`,
    packet: build(dataUp(seq), llc(), eapolKey({ msg: 2, replay, micSeed, keyData: m2KeyData(2, caps) })),
  });

const encData = (time: number, up: boolean, seq: number, pn: number, len: number, lines: string[], info: string) =>
  pkt(up ? "client" : "ap", up ? "ap" : "client", up ? "amber" : "violet", "DATA", lines, {
    time, info,
    packet: build(up ? dataUp(seq, 0x41) : dataDown(seq, 0x42), ccmp(pn), opaque("Encrypted data", len, "LLC + IPv4 + TCP + TLS, all encrypted")),
  });

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: STA, x: 12, y: 64 },
  { id: "ap", kind: "ap", label: "Wi-Fi router", sub: `"${SSID}" ch 6`, x: 52, y: 64 },
  { id: "internet", kind: "cloud", label: "Internet", x: 87, y: 36 },
];
const links: [string, string][] = [["client", "ap"], ["ap", "internet"]];

const attackDevices: Device[] = [...devices, { id: "attacker", kind: "attacker", label: "Attacker", sub: "spoofs the router", x: 30, y: 22 }];
const attackLinks: [string, string][] = [...links, ["attacker", "client"], ["attacker", "ap"]];

export default defineLesson({
  id: "wifi",
  name: "Wi-Fi (WPA2)",
  full: "IEEE 802.11 with WPA2-Personal",
  group: "lan",
  layer: 2,
  difficulty: 2,
  tagline: "How your laptop finds a Wi-Fi network and proves it knows the password.",
  description:
    "Joining a Wi-Fi network takes a short conversation over the air. The laptop hears the access point's beacons, says hello, joins, and then runs the 4-way handshake: both sides prove they know the password without ever sending it, and agree on fresh keys that encrypt every frame afterwards.",
  facts: [
    ["Layer", "Data link (Layer 2)"],
    ["Standard", "IEEE 802.11, WPA2 = 802.11i"],
    ["Key exchange", "EAPOL 4-way handshake"],
    ["Encryption", "AES-CCMP"],
    ["MAC header", "24 bytes (3 addresses)"],
    ["Bands", "2.4, 5 and 6 GHz"],
  ],
  ports: "None (link layer). EAPOL uses EtherType 0x888E",
  rfc: "IEEE 802.11-2020",
  keywords: ["wifi", "wlan", "802.11", "wpa2", "psk", "beacon", "probe", "association", "4-way handshake", "eapol", "anonce", "snonce", "mic", "gtk", "ptk", "ccmp", "deauth", "802.11w", "pmf"],
  related: ["wpa3", "ethernet", "dhcp", "arp"],
  linktype: 105,
  devices,
  links,
  legend: [
    ["blue", "Finding and joining (management)"],
    ["green", "Accepted"],
    ["teal", "4-way handshake (keys)"],
    ["amber", "Encrypted data from the laptop"],
    ["red", "Rejection or attack"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Joining a WPA2 home network",
      summary: "The laptop finds HomeNet, joins it, runs the 4-way handshake and starts sending encrypted frames.",
      kind: "normal",
      steps: [
        {
          title: "Hear the beacon",
          desc: "The access point announces itself ten times a second",
          detail:
            "The router's radio broadcasts a Beacon about every 102 ms. It carries the network name (SSID), the channel, the speeds it supports and an RSN element that says “WPA2, password needed, AES-CCMP”. This is how networks appear in your Wi-Fi list.",
          facts: [["SSID", SSID], ["Channel", "6 (2.4 GHz)"], ["Sent to", "ff:ff:ff:ff:ff:ff (everyone)"]],
          quiz: {
            q: "Which part of the beacon tells the laptop that this network needs a WPA2 password?",
            options: ["The SSID", "The RSN element", "The beacon interval", "The duration field"],
            answer: 1,
            why: "The RSN (Robust Security Network) element lists the cipher (CCMP) and the login method: AKM 2, a pre-shared key.",
          },
          events: [beacon(0), note("client", "HOMENET FOUND", "blue")],
        },
        {
          title: "Ask who's there",
          desc: "Probe Request and Probe Response",
          detail:
            "Instead of waiting for the next beacon, the laptop can ask directly. It sends a Probe Request naming the network it wants, and the access point replies with a Probe Response. It holds almost the same information as a beacon but is sent just to this laptop.",
          facts: [["Request to", "Broadcast"], ["Response to", STA], ["Why", "Faster than waiting for beacons"]],
          events: [
            pkt("client", "ap", "blue", "PROBE REQ", [`"${SSID}"?`], {
              time: 0.05, info: `Probe Request, SN=119, SSID="${SSID}"`,
              packet: build(wlan({ type: 0, subtype: 4, a1: BCAST, a2: STA, a3: BCAST, seq: 119 }), mgmt("Probe Request", [], [ssidIE(), ratesIE()])),
            }),
            pkt("ap", "client", "blue", "PROBE RESP", [`SSID ${SSID}`, "WPA2"], {
              time: 0.0503, info: `Probe Response, SN=2311, BI=100, SSID="${SSID}"`,
              packet: build(toSta(5, 2311), probeRespBody(RSN_AP, BigInt(91234617890))),
            }),
          ],
        },
        {
          title: "Authenticate and associate",
          desc: "Open System auth, then join",
          detail:
            "“Open System authentication” sounds like a security check but isn't: it is a two-frame hello that always succeeds. Then the laptop sends an Association Request saying which security it picked (WPA2-PSK with CCMP), and the router answers with an Association ID. The laptop is now attached, but the router still blocks all its traffic except handshake frames.",
          facts: [["Auth algorithm", "0 (Open System)"], ["Association ID", "1"], ["Traffic allowed", "Only EAPOL so far"]],
          quiz: {
            q: "After the Association Response, can the laptop already send web traffic?",
            options: ["Yes, it is connected", "No, the router only lets EAPOL handshake frames through until keys are agreed", "Only to the router itself", "Only unencrypted HTTP"],
            answer: 1,
            why: "The 802.1X port stays closed until the 4-way handshake proves the password and installs keys.",
          },
          events: joinEvents(0.06),
        },
        {
          title: "Handshake: swap nonces",
          desc: "Messages 1 and 2: ANonce, SNonce and a MIC",
          detail:
            "Both sides already hold the PMK, worked out from the password and the SSID (PBKDF2, 4096 rounds). The router sends a random ANonce. The laptop picks its own SNonce, mixes PMK + ANonce + SNonce + both MAC addresses into the session key (PTK), and sends SNonce with a MIC made from that key. The router builds the same PTK and checks the MIC: if it matches, the laptop must know the password.",
          facts: [["PMK", "PBKDF2(password, SSID)"], ["PTK", "PRF(PMK, ANonce, SNonce, MACs)"], ["Password sent?", "Never"]],
          quiz: {
            q: "The router receives message 2. What does it need to check the MIC?",
            options: ["The password sent in message 2", "Its own PMK plus the SNonce from message 2", "Only the SNonce", "A certificate"],
            answer: 1,
            why: "With the SNonce it can build the same PTK from its own PMK. If the laptop's password were different, its PTK and MIC would not match.",
          },
          events: [m1(0.065, 1, 2314), m2(0.0662, 1, 122)],
        },
        {
          title: "Handshake: install keys",
          desc: "Messages 3 and 4: GTK delivered, keys installed",
          detail:
            "The router replies with message 3. It has its own MIC, proving the router also knows the password, and the GTK (group key for broadcasts) encrypted with part of the PTK. The laptop answers with message 4, and both sides install the keys. The 802.1X port opens.",
          facts: [["GTK", "Group key, for broadcasts"], ["Replay counter", "2"], ["Result", "Keys installed both sides"]],
          events: [
            pkt("ap", "client", "teal", "EAPOL 3/4", ["install keys", "GTK (encrypted)"], {
              time: 0.0675, info: "Key (Message 3 of 4), replay counter 2",
              packet: build(dataDown(2315), llc(), eapolKey({ msg: 3, replay: 2, keyData: m3KeyData() })),
            }),
            pkt("client", "ap", "teal", "EAPOL 4/4", ["done", "+ MIC"], {
              time: 0.0684, info: "Key (Message 4 of 4), replay counter 2",
              packet: build(dataUp(123), llc(), eapolKey({ msg: 4, replay: 2 })),
            }),
            note("client", "CONNECTED, KEYS INSTALLED", "green"),
          ],
        },
        {
          title: "Encrypted data",
          desc: "Every frame now carries a CCMP header",
          detail:
            "From now on data frames have the Protected flag set. After the 24-byte MAC header comes an 8-byte CCMP header with a packet number, then the encrypted contents (LLC, IP, TCP and the rest) and an 8-byte MIC. Someone nearby with a radio can see the MAC addresses and frame sizes, but not what is inside.",
          facts: [["Cipher", "AES-CCMP (128-bit)"], ["Overhead", "8-byte header + 8-byte MIC"], ["Visible to others", "MACs, sizes, timing"]],
          quiz: {
            q: "An attacker records a protected frame and sends it again later. What stops it?",
            options: ["The duration field", "The packet number (PN) must always go up", "The SSID", "Nothing"],
            answer: 1,
            why: "The receiver remembers the last PN. A replayed frame has an old PN and is dropped.",
          },
          events: [
            encData(0.2, true, 124, 1, 92, ["encrypted", "PN 1"], "Data, SN=124, FN=0, Flags=.p.....T (Protected)"),
            encData(0.2312, false, 2316, 1, 1400, ["encrypted", "PN 1"], "Data, SN=2316, FN=0, Flags=.p....F. (Protected)"),
          ],
        },
      ],
      outro: {
        title: "On the network",
        text: "The laptop found HomeNet from its beacon, joined with Open System auth and association, then proved it knew the password in the 4-way handshake without ever sending it. Fresh keys now encrypt every frame with AES-CCMP.",
        facts: [["Frames to join", "10"], ["Time to join", "about 8 ms after the probe"], ["Password on air", "Never"], ["Next", "DHCP to get an IP address"]],
      },
    },
    {
      id: "wrong-password",
      name: "Wrong password",
      summary: "A typo in the password makes the MIC in message 2 wrong. The router stays quiet, retries, then kicks the laptop off.",
      kind: "failure",
      steps: [
        {
          title: "Join as usual",
          desc: "Auth and association still succeed",
          detail:
            "Nothing in Open System authentication or association checks the password, so these succeed even with a typo. The laptop has built its PMK from the wrong password, but nobody knows that yet.",
          facts: [["Typed password", "one letter wrong"], ["Auth", "Succeeds"], ["Association", "Succeeds"]],
          events: joinEvents(0, RSN_AP, 140, 2400),
        },
        {
          title: "MIC check fails",
          desc: "Message 2 arrives with a MIC the router cannot match",
          detail:
            "The router sends ANonce and the laptop answers with SNonce and a MIC. The router builds its PTK from the real password, computes the MIC, and gets a different value. It does not tell the laptop why. It just drops message 2.",
          facts: [["Laptop PTK", "From the wrong password"], ["Router PTK", "From the right password"], ["Message 2", "Silently dropped"]],
          quiz: {
            q: "Why doesn't the router reply “wrong password”?",
            options: ["802.11 has no error codes", "It only knows the MIC didn't match; it has no way to see the password itself", "It's too busy", "It sends the right password instead"],
            answer: 1,
            why: "The password never travels. All the router sees is a MIC that doesn't fit, which could also be a damaged or forged frame.",
          },
          events: [m1(0.005, 1, 2402), m2(0.0062, 1, 142, 6100), note("ap", "MIC MISMATCH", "red")],
        },
        {
          title: "Retry",
          desc: "Message 1 again, with a new replay counter",
          detail:
            "Having got no valid reply, the router waits about a second and sends message 1 again with the replay counter raised to 2. The laptop answers with the same wrong key, so the MIC fails again.",
          facts: [["Replay counter", "2"], ["Wait", "About 1 s"], ["Result", "Same bad MIC"]],
          events: [m1(1.0062, 2, 2403), m2(1.0075, 2, 143, 6101), note("ap", "MIC MISMATCH AGAIN", "red")],
        },
        {
          title: "Kicked off",
          desc: "Deauthentication, reason 15",
          detail:
            "After its retries run out the router sends a Deauthentication frame with reason 15, “4-way handshake timeout”. The laptop's Wi-Fi menu shows “incorrect password”. Many routers also log the failed attempt.",
          facts: [["Frame", "Deauthentication"], ["Reason", "15 (4-way handshake timeout)"], ["User sees", "Incorrect password"]],
          events: [
            pkt("ap", "client", "red", "DEAUTH", ["reason 15", "handshake timeout"], {
              time: 2.008, info: "Deauthentication, SN=2404, Reason code 15 (4-Way Handshake timeout)",
              packet: build(toSta(12, 2404), deauthBody(15, "4-Way Handshake timeout")),
            }),
            note("client", "INCORRECT PASSWORD", "red"),
          ],
        },
      ],
      outro: {
        title: "Wrong password, no connection",
        text: "A wrong password is only noticed in the 4-way handshake, when the MIC in message 2 doesn't match. The router drops it, retries, and finally sends a deauthentication. The password itself never crossed the air.",
        facts: [["Detected at", "Message 2 (MIC)"], ["Router reply", "Silence, then deauth"], ["Reason code", "15"]],
      },
    },
    {
      id: "deauth-attack",
      name: "Deauth attack and 802.11w",
      summary: "An attacker forges deauthentication frames to knock the laptop off. Protected Management Frames make them useless.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "Connected and busy",
          desc: "Normal encrypted traffic",
          detail: "The laptop is joined to HomeNet and sending encrypted frames. In plain WPA2, management frames such as Deauthentication are never encrypted or signed.",
          facts: [["Data frames", "Encrypted (CCMP)"], ["Management frames", "Not protected"], ["PMF (802.11w)", "Off"]],
          events: [encData(0, true, 300, 412, 92, ["encrypted", "PN 412"], "Data, SN=300, FN=0, Flags=.p.....T (Protected)")],
        },
        {
          title: "Forged deauth",
          desc: "The attacker pretends to be the router",
          detail:
            "The attacker sends a Deauthentication frame with the router's MAC address as the sender. With no signature to check, the laptop believes it and disconnects. Repeating this every few seconds keeps the victim off the network, and it can also make the laptop rejoin so the attacker can record a fresh handshake to guess passwords against offline.",
          facts: [["Spoofed sender", BSSID], ["Reason", "7 (class 3 frame from non-associated station)"], ["Cost", "One 26-byte frame"]],
          quiz: {
            q: "Why does the laptop believe the forged frame?",
            options: ["The attacker knows the password", "Without 802.11w, deauth frames have no MIC, so anyone can fake the sender address", "The frame is encrypted", "The router asked the attacker to send it"],
            answer: 1,
            why: "Plain WPA2 protects data frames only. A management frame's sender address is just six bytes anyone can write.",
          },
          events: [
            pkt("attacker", "client", "red", "DEAUTH", ["from: router (fake)", "reason 7"], {
              time: 0.5, info: "Deauthentication, SN=2999, Reason code 7 (Class 3 frame received from nonassociated STA)",
              packet: build(toSta(12, 2999), deauthBody(7, "Class 3 frame received from nonassociated STA")),
            }),
            note("client", "DISCONNECTED", "red"),
          ],
        },
        {
          title: "Rejoin, handshake recorded",
          desc: "The laptop reconnects and the attacker listens",
          detail:
            "The laptop automatically rejoins and runs the 4-way handshake again. The attacker records messages 1 and 2. With the ANonce, SNonce, MACs and the MIC, they can now try millions of password guesses on their own computer, which is why a long, random WPA2 password matters.",
          facts: [["Captured", "ANonce, SNonce, MIC"], ["Attack", "Offline dictionary guessing"], ["Defence", "Long random password, or WPA3"]],
          events: [m1(1.2, 1, 3001), m2(1.2012, 1, 302), note("attacker", "HANDSHAKE CAPTURED", "red")],
        },
        {
          title: "Turn on 802.11w (PMF)",
          desc: "The forged deauth is ignored",
          detail:
            "With Protected Management Frames, real deauth frames from the router are encrypted and carry a MIC, just like data. The forged frame has no Protected flag, so the laptop does not drop the connection. Instead it asks the router over the encrypted link (SA Query) whether it really wants to disconnect. The router answers correctly, and the laptop stays.",
          facts: [["RSN capabilities", "MFPC/MFPR set"], ["Unprotected deauth", "Triggers SA Query, not disconnect"], ["Mandatory in", "WPA3 and Wi-Fi 6E"]],
          quiz: {
            q: "With PMF on, the laptop gets an unprotected deauth claiming to be from the router. What does it do?",
            options: ["Disconnects at once", "Asks the router over the protected link (SA Query) and stays if the router answers", "Sends its password to the router", "Switches channel"],
            answer: 1,
            why: "A real router would protect its deauth. An SA Query exchange proves the encrypted association is still alive.",
          },
          events: [
            pkt("attacker", "client", "red", "DEAUTH", ["from: router (fake)", "not protected"], {
              time: 3, info: "Deauthentication, SN=3050, Reason code 7 (Class 3 frame received from nonassociated STA)",
              packet: build(toSta(12, 3050), deauthBody(7, "Class 3 frame received from nonassociated STA")),
            }),
            note("client", "UNPROTECTED: IGNORED", "green"),
            pkt("client", "ap", "teal", "SA QUERY", ["really you?", "protected"], {
              time: 3.0004, info: "Action, SN=320, Flags=.p...... (Protected), SA Query Request",
              packet: build(toAp(13, 320, 0x40), ccmp(18), opaque("Encrypted action", 4, "Category 8 (SA Query), Action 0 (Request), Transaction ID")),
            }),
            pkt("ap", "client", "green", "SA QUERY", ["yes, still here", "protected"], {
              time: 3.0011, info: "Action, SN=3010, Flags=.p...... (Protected), SA Query Response",
              packet: build(toSta(13, 3010, 0x40), ccmp(22), opaque("Encrypted action", 4, "Category 8 (SA Query), Action 1 (Response), same Transaction ID")),
            }),
            note("client", "STILL CONNECTED", "green"),
          ],
        },
      ],
      outro: {
        title: "Deauth attacks stopped",
        text: "Without 802.11w anyone can forge a deauthentication frame, knock devices off and capture handshakes for offline guessing. Protected Management Frames encrypt and sign these frames, so fakes are ignored and an SA Query confirms the real link.",
        facts: [["Attack", "Forged deauthentication"], ["Defence", "802.11w PMF"], ["Also helps", "WPA3 (PMF is required)"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Frame types (type / subtype)",
      items: [["0/8 Beacon", "Network announcement"], ["0/4, 0/5", "Probe Request / Response"], ["0/11", "Authentication"], ["0/0, 0/1", "Association Request / Response"], ["0/12", "Deauthentication"], ["2/0", "Data"]],
    },
    {
      title: "4-way handshake",
      items: [["Msg 1", "AP → STA: ANonce"], ["Msg 2", "STA → AP: SNonce + MIC"], ["Msg 3", "AP → STA: install, GTK, MIC"], ["Msg 4", "STA → AP: done"], ["PTK", "PRF(PMK, ANonce, SNonce, MACs)"]],
    },
    {
      title: "Numbers to know",
      items: [["MAC header", "24 bytes"], ["CCMP overhead", "16 bytes (8 header + 8 MIC)"], ["Beacon interval", "100 TU = 102.4 ms"], ["EAPOL EtherType", "0x888E"], ["Deauth reason 15", "4-way handshake timeout"]],
    },
  ],
});
