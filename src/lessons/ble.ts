import { defineLesson, note, pkt, Device, PacketEvent } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { Bytes, mac, rand, u16le, u24, u32le } from "@/lib/bytes";

// Bluetooth Low Energy: a fitness band advertises, a phone connects and subscribes to heart-rate
// notifications over GATT/ATT. Captures use LINKTYPE_BLUETOOTH_LE_LL (251):
// access address (4) + PDU header (2) + payload + CRC (3), no radio metadata.

const ADV_AA = 0x8e89bed6;
const ADV_CRC_INIT = 0x555555;
const CONN_AA = 0x5a3c9e71;
const CONN_CRC_INIT = 0x3a7c91;
const MITM_AA = 0x71a35c2e;
const MITM_CRC_INIT = 0x0b5f2d;

const BAND = "c4:7f:51:2a:9b:e3"; // random static (top two bits 11)
const PHONE = "4a:21:9c:33:7e:10"; // resolvable private (top two bits 01)
const FAKE = "c4:7f:51:2a:9b:e3"; // the attacker clones the band's address

const rev8 = (b: number) => {
  let r = 0;
  for (let i = 0; i < 8; i++) if ((b >> i) & 1) r |= 1 << (7 - i);
  return r;
};

/** BLE CRC-24 (poly 0x00065B), data fed LSB first; returned in on-air byte order. */
function bleCrc(data: Bytes, init: number): Bytes {
  let s = init & 0xffffff;
  for (const byte of data)
    for (let i = 0; i < 8; i++) {
      const fb = ((s >> 23) & 1) ^ ((byte >> i) & 1);
      s = (s << 1) & 0xffffff;
      if (fb) s ^= 0x65b;
    }
  return [rev8((s >> 16) & 0xff), rev8((s >> 8) & 0xff), rev8(s & 0xff)];
}

/** Bluetooth device address as sent on air: least significant byte first. */
const addr = (name: string, a: string, note?: string): FieldSpec => ({ name, bytes: mac(a).reverse(), value: a, note: note ?? "Sent least-significant byte first, so it looks reversed in the hex view." });

const ADV_TYPES: Record<number, string> = { 0: "ADV_IND", 3: "SCAN_REQ", 4: "SCAN_RSP", 5: "CONNECT_IND" };
const LLID_NAMES: Record<number, string> = { 1: "continuation / empty", 2: "start of L2CAP message", 3: "LL control" };

/** Link layer: access address + 2-byte header in front, CRC behind. Length is taken from the payload. */
function ll(o: { aa: number; crcInit: number; adv?: { type: number; txAdd: boolean; rxAdd: boolean }; data?: { sn: number; nesn: number; md?: boolean } }): LayerSpec {
  return {
    kind: "btle",
    build: (payload) => {
      let b0: number, hdr: FieldSpec[], sum: string;
      if (o.adv) {
        b0 = o.adv.type | (o.adv.txAdd ? 0x40 : 0) | (o.adv.rxAdd ? 0x80 : 0);
        const name = ADV_TYPES[o.adv.type];
        sum = name;
        hdr = [
          { name: "PDU type, ChSel, TxAdd, RxAdd", u8: b0, value: `${name} (type ${o.adv.type}), TxAdd ${o.adv.txAdd ? "random" : "public"}${o.adv.type >= 3 ? `, RxAdd ${o.adv.rxAdd ? "random" : "public"}` : ""}`, note: "Low 4 bits: PDU type. Bit 6 (TxAdd) and bit 7 (RxAdd) say whether the addresses that follow are random or public." },
          { name: "Length", u8: payload.length, value: `${payload.length} bytes` },
        ];
      } else {
        const d = o.data!;
        b0 = 2 | (d.nesn << 2) | (d.sn << 3) | (d.md ? 0x10 : 0);
        sum = `Data PDU, SN ${d.sn}, NESN ${d.nesn}`;
        hdr = [
          { name: "LLID, NESN, SN, MD", u8: b0, value: `LLID 2, NESN ${d.nesn}, SN ${d.sn}, MD ${d.md ? 1 : 0}`, note: `LLID 2 = ${LLID_NAMES[2]}. SN numbers this packet, NESN is the SN expected next: a 1-bit acknowledgement.` },
          { name: "Length", u8: payload.length, value: `${payload.length} bytes`, note: payload.length > 27 ? "Over 27 bytes: both sides switched on Data Length Extension." : undefined },
        ];
      }
      const crc = bleCrc([b0, payload.length, ...payload], o.crcInit);
      return {
        id: "btle",
        name: "Bluetooth LE Link Layer",
        osi: 2,
        summary: `Bluetooth Low Energy Link Layer, Access Address: 0x${o.aa.toString(16)}, ${sum}`,
        fields: [
          field({ name: "Access address", bytes: u32le(o.aa), value: `0x${o.aa.toString(16)}`, note: o.aa === ADV_AA ? "Fixed for every advertising packet in the world." : "Picked by the phone in CONNECT_IND. Marks packets of this one connection." }),
          field({ name: "PDU header", value: "2 bytes", fields: hdr }),
        ],
        trailer: [field({ name: "CRC", bytes: crc, value: `0x${crc.map((x) => x.toString(16).padStart(2, "0")).join("")}`, note: `24-bit CRC over header and payload, seeded with 0x${o.crcInit.toString(16)}. A bad CRC means the radio heard noise and the packet is ignored.` })],
      };
    },
  };
}

const l2cap = (cid: number, what: string): LayerSpec => ({
  kind: "l2cap",
  build: (payload) => ({
    id: "l2cap", name: "L2CAP", osi: 2, summary: `Bluetooth L2CAP Protocol, CID: ${what}`,
    fields: [
      field({ name: "Length", bytes: u16le(payload.length), value: `${payload.length} bytes`, note: "Little-endian, like everything in Bluetooth." }),
      field({ name: "Channel ID", bytes: u16le(cid), value: `0x${cid.toString(16).padStart(4, "0")} (${what})`, note: cid === 4 ? "0x0004 is always the Attribute Protocol on LE." : "0x0006 is always the Security Manager on LE." }),
    ],
  }),
});

const att = (summary: string, fields: FieldSpec[]) => proto({ id: "att", name: "ATT", osi: 7, summary: `Bluetooth Attribute Protocol, ${summary}`, fields });
const smp = (summary: string, fields: FieldSpec[]) => proto({ id: "smp", name: "SMP", osi: 7, summary: `Bluetooth Security Manager Protocol, ${summary}`, fields });
const h16 = (name: string, v: number, value?: string, note?: string): FieldSpec => ({ name, bytes: u16le(v), value: value ?? `0x${v.toString(16).padStart(4, "0")}`, note });

// ------------------------------------------------------------ advertising PDUs

const advInd = () =>
  build(
    ll({ aa: ADV_AA, crcInit: ADV_CRC_INIT, adv: { type: 0, txAdd: true, rxAdd: false } }),
    proto({
      id: "btle-adv", name: "Advertising data", osi: 2, summary: `ADV_IND, AdvA: ${BAND}, "FitBand", Heart Rate`,
      fields: [
        addr("Advertiser address (AdvA)", BAND),
        {
          name: "AdvData",
          value: "16 bytes, 3 AD structures",
          fields: [
            { name: "Flags", bytes: "020106", value: "LE General Discoverable, BR/EDR not supported", note: "Length 2, type 0x01, value 0x06." },
            { name: "Complete local name", bytes: [0x08, 0x09, ...Array.from(new TextEncoder().encode("FitBand"))], value: "\"FitBand\"", note: "Length 8, type 0x09, then the name in UTF-8." },
            { name: "Complete list of 16-bit service UUIDs", bytes: "03030d18", value: "0x180D (Heart Rate)", note: "Length 3, type 0x03, UUID 0x180D little-endian. Apps filter scans on this." },
          ],
        },
      ],
    })
  );

const scanReq = () =>
  build(
    ll({ aa: ADV_AA, crcInit: ADV_CRC_INIT, adv: { type: 3, txAdd: true, rxAdd: true } }),
    proto({ id: "btle-adv", name: "Scan request", osi: 2, summary: `SCAN_REQ, ScanA: ${PHONE}, AdvA: ${BAND}`, fields: [addr("Scanner address (ScanA)", PHONE, "The phone’s private address. It changes every few minutes so the phone can’t be tracked."), addr("Advertiser address (AdvA)", BAND)] })
  );

const scanRsp = () =>
  build(
    ll({ aa: ADV_AA, crcInit: ADV_CRC_INIT, adv: { type: 4, txAdd: true, rxAdd: false } }),
    proto({
      id: "btle-adv", name: "Scan response", osi: 2, summary: `SCAN_RSP, AdvA: ${BAND}`,
      fields: [
        addr("Advertiser address (AdvA)", BAND),
        {
          name: "ScanRspData",
          value: "7 bytes",
          fields: [
            { name: "Appearance", bytes: "0319c000", value: "0x00C0 (Generic Watch)", note: "Lets the phone show a watch icon." },
            { name: "TX power level", bytes: "020a00", value: "0 dBm", note: "With the received strength, the phone can guess distance." },
          ],
        },
      ],
    })
  );

const connectInd = () =>
  build(
    ll({ aa: ADV_AA, crcInit: ADV_CRC_INIT, adv: { type: 5, txAdd: true, rxAdd: true } }),
    proto({
      id: "btle-adv", name: "Connect indication", osi: 2, summary: `CONNECT_IND, InitA: ${PHONE}, AdvA: ${BAND}`,
      fields: [
        addr("Initiator address (InitA)", PHONE),
        addr("Advertiser address (AdvA)", BAND),
        {
          name: "LLData",
          value: "22 bytes",
          fields: [
            { name: "Access address", bytes: u32le(CONN_AA), value: `0x${CONN_AA.toString(16)}`, note: "Every packet of this connection will start with it." },
            { name: "CRC init", bytes: [CONN_CRC_INIT & 0xff, (CONN_CRC_INIT >> 8) & 0xff, (CONN_CRC_INIT >> 16) & 0xff], value: `0x${CONN_CRC_INIT.toString(16)}`, note: "Random seed for this connection’s CRCs." },
            { name: "Window size", u8: 2, value: "2 (2.5 ms)" },
            h16("Window offset", 15, "15 (18.75 ms)", "When the first connection event may start."),
            h16("Interval", 24, "24 (30 ms)", "A connection event every 30 ms. Units of 1.25 ms."),
            h16("Latency", 0, "0", "The band must answer every event."),
            h16("Timeout", 200, "200 (2 s)", "No packets for 2 s = connection lost. Units of 10 ms."),
            { name: "Channel map", bytes: "ffffffff1f", value: "all 37 data channels", note: "One bit per data channel. Bad Wi-Fi channels can be switched off later." },
            { name: "Hop increment, sleep clock accuracy", u8: 0xa7, value: "hop 7, SCA 5 (31–50 ppm)", note: "Each event jumps 7 channels ahead (mod 37): frequency hopping dodges interference." },
          ],
        },
      ],
    })
  );

// ------------------------------------------------------------ GATT over ATT (data channel)

const dataPkt = (sn: number, nesn: number, cid: number, inner: LayerSpec, aa = CONN_AA, crcInit = CONN_CRC_INIT) =>
  build(ll({ aa, crcInit, data: { sn, nesn } }), l2cap(cid, cid === 4 ? "Attribute Protocol" : "Security Manager"), inner);

const readGroupReq = () =>
  dataPkt(0, 0, 4, att("Read By Group Type Request, Primary Service, Handles: 0x0001..0xffff", [
    { name: "Opcode", u8: 0x10, value: "0x10 (Read By Group Type Request)" },
    h16("Starting handle", 0x0001),
    h16("Ending handle", 0xffff, "0xffff", "Search the whole table."),
    h16("Group type", 0x2800, "0x2800 (Primary Service)", "List every primary service."),
  ]));

const svc = (start: number, end: number, uuid: number, name: string): FieldSpec => ({
  name: `Service ${name}`,
  value: `handles 0x${start.toString(16).padStart(4, "0")}–0x${end.toString(16).padStart(4, "0")}, UUID 0x${uuid.toString(16)}`,
  fields: [h16("Start handle", start), h16("End group handle", end), h16("UUID", uuid, `0x${uuid.toString(16).toUpperCase()} (${name})`)],
});

const readGroupRsp = () =>
  dataPkt(0, 1, 4, att("Read By Group Type Response", [
    { name: "Opcode", u8: 0x11, value: "0x11 (Read By Group Type Response)" },
    { name: "Length", u8: 6, value: "6 bytes per entry", note: "Start handle (2) + end handle (2) + 16-bit UUID (2)." },
    svc(0x0001, 0x0007, 0x1800, "Generic Access"),
    svc(0x0008, 0x000b, 0x1801, "Generic Attribute"),
    svc(0x000c, 0x0011, 0x180d, "Heart Rate"),
  ]));

const writeCccd = () =>
  dataPkt(1, 1, 4, att("Write Request, Handle: 0x000f (Heart Rate Measurement: CCCD)", [
    { name: "Opcode", u8: 0x12, value: "0x12 (Write Request)" },
    h16("Handle", 0x000f, "0x000f (CCCD of Heart Rate Measurement)", "The Client Characteristic Configuration Descriptor sits right after the characteristic’s value."),
    h16("Value", 0x0001, "0x0001 (notifications on)", "Bit 0 = notifications, bit 1 = indications."),
  ]));

const writeRsp = () => dataPkt(1, 0, 4, att("Write Response", [{ name: "Opcode", u8: 0x13, value: "0x13 (Write Response)", note: "No body: the write worked." }]));

const hrNotify = (sn: number, nesn: number, bpm: number) =>
  dataPkt(sn, nesn, 4, att(`Handle Value Notification, Handle: 0x000e (Heart Rate Measurement), ${bpm} bpm`, [
    { name: "Opcode", u8: 0x1b, value: "0x1b (Handle Value Notification)" },
    h16("Handle", 0x000e, "0x000e (Heart Rate Measurement value)"),
    {
      name: "Heart Rate Measurement",
      value: `${bpm} bpm`,
      fields: [
        { name: "Flags", u8: 0x06, value: "0x06: 8-bit value, sensor contact detected", note: "Bit 0 = 0: the rate is one byte. Bits 1–2 = 11: skin contact is supported and detected." },
        { name: "Heart rate", u8: bpm, value: `${bpm} bpm` },
      ],
    },
  ]));

// ------------------------------------------------------------ pairing (SMP)

const IO: Record<number, string> = { 0: "DisplayOnly", 1: "DisplayYesNo", 2: "KeyboardOnly", 3: "NoInputNoOutput", 4: "KeyboardDisplay" };
const pairing = (code: 1 | 2, io: number, authReq: number) =>
  smp(`Pairing ${code === 1 ? "Request" : "Response"}`, [
    { name: "Code", u8: code, value: `0x0${code} (Pairing ${code === 1 ? "Request" : "Response"})` },
    { name: "IO capability", u8: io, value: `0x0${io} (${IO[io]})`, note: "What the device can show or type. Together these decide the pairing method." },
    { name: "OOB data", u8: 0, value: "not present" },
    { name: "AuthReq", u8: authReq, value: `0x${authReq.toString(16).padStart(2, "0")}: bonding${authReq & 0x04 ? ", MITM" : ""}${authReq & 0x08 ? ", Secure Connections" : ""}`, note: "Bit 2 asks for MITM protection, bit 3 for LE Secure Connections (ECDH P-256)." },
    { name: "Max encryption key size", u8: 16, value: "16 bytes" },
    { name: "Initiator key distribution", u8: 0x0d, value: "0x0d (EncKey, LinkKey ignored, IdKey)" },
    { name: "Responder key distribution", u8: 0x0d, value: "0x0d" },
  ]);
const publicKey = (seed: number, who: string) =>
  smp("Pairing Public Key", [
    { name: "Code", u8: 0x0c, value: "0x0c (Pairing Public Key)" },
    { name: "Public key X", random: 32, seed, value: "32 bytes", note: `${who}’s P-256 public key, X coordinate.` },
    { name: "Public key Y", random: 32, seed: seed + 1, value: "32 bytes" },
  ]);
const confirm = () => smp("Pairing Confirm", [{ name: "Code", u8: 0x03, value: "0x03 (Pairing Confirm)" }, { name: "Confirm value", random: 16, seed: 5150, opaque: true, value: "16 bytes", note: "A commitment to a random number, computed with the public keys." }]);
const random = () => smp("Pairing Random", [{ name: "Code", u8: 0x04, value: "0x04 (Pairing Random)" }, { name: "Random value", bytes: rand(16, 5151), value: "16 bytes" }]);
const failed = (reason: number, what: string) => smp(`Pairing Failed: ${what}`, [{ name: "Code", u8: 0x05, value: "0x05 (Pairing Failed)" }, { name: "Reason", u8: reason, value: `0x${reason.toString(16).padStart(2, "0")} (${what})` }]);

// ------------------------------------------------------------ devices

const devices: Device[] = [
  { id: "phone", kind: "phone", label: "Phone", sub: PHONE, x: 12, y: 62 },
  { id: "air", kind: "cloud", label: "2.4 GHz radio", sub: "adv ch 37 · 38 · 39", x: 50, y: 24 },
  { id: "band", kind: "iot", label: "Fitness band", sub: BAND, x: 88, y: 62 },
];
const links: [string, string][] = [["phone", "air"], ["air", "band"]];
const attackDevices: Device[] = [...devices, { id: "attacker", kind: "attacker", label: "MITM relay", sub: `pretends to be ${FAKE.slice(0, 8)}…`, x: 50, y: 80 }];
const attackLinks: [string, string][] = [...links, ["attacker", "air"]];

const LL_ROW = { proto: "LE LL", src: "", dst: "" };
const row = (proto: string, src: string, dst: string) => ({ proto, src, dst });
void LL_ROW;

type Ev = Omit<PacketEvent, "type" | "from" | "to" | "color" | "label" | "lines">;
const adv = (o: Ev) => ({ ...row("LE LL", BAND, "Broadcast"), ...o });

const mitmSmp = (sn: number, nesn: number, inner: LayerSpec) => dataPkt(sn, nesn, 6, inner, MITM_AA, MITM_CRC_INIT);

export default defineLesson({
  id: "ble",
  name: "Bluetooth LE",
  full: "Bluetooth Low Energy (GATT over ATT)",
  group: "iot",
  layer: 2,
  difficulty: 2,
  tagline: "How a fitness band sends your heart rate to your phone.",
  description:
    "Bluetooth Low Energy lets small battery devices talk to phones for months on a coin cell. A device advertises on three fixed channels, a phone connects, and then they swap tiny attribute reads, writes and notifications using GATT.",
  facts: [
    ["Layers", "Link layer (2) up to GATT (7)"],
    ["Radio", "2.4 GHz, 40 channels of 2 MHz"],
    ["Advertising", "Channels 37, 38, 39"],
    ["Advertising address", "0x8E89BED6"],
    ["Max payload", "27 bytes (251 with DLE)"],
    ["Defined in", "Bluetooth Core Spec 5.x, Vol 6"],
  ],
  ports: "No ports: L2CAP channel 0x0004 (ATT), 0x0006 (SMP)",
  rfc: "Bluetooth Core Specification 5.4",
  keywords: ["bluetooth", "ble", "gatt", "att", "advertising", "heart rate", "cccd", "notification", "pairing", "just works", "secure connections", "smp", "wearable"],
  related: ["wifi", "zigbee", "mqtt"],
  linktype: 251,
  devices,
  links,
  legend: [
    ["pink", "Advertising broadcasts"],
    ["blue", "Scanning and GATT requests"],
    ["green", "Responses and connection setup"],
    ["violet", "Heart-rate notifications"],
    ["red", "Attacker and pairing failures"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Pair-free heart rate streaming",
      summary: "The band advertises, the phone connects, finds the Heart Rate service and subscribes to notifications.",
      kind: "normal",
      steps: [
        {
          title: "Advertise on 3 channels",
          desc: "ADV_IND on 37, 38 and 39",
          detail:
            "The band wakes up every 100 ms and sends the same ADV_IND on each of the three advertising channels, which sit in gaps between busy Wi-Fi channels. It contains its address, a Flags field, its name and the Heart Rate service UUID 0x180D. Every advertising packet starts with the same access address, 0x8E89BED6.",
          facts: [["Interval", "100 ms"], ["Channels", "37 (2402 MHz), 38 (2426), 39 (2480)"], ["Payload", "6-byte address + 16 bytes AdvData"]],
          quiz: {
            q: "Why does the band repeat the advert on three channels?",
            options: ["To send three times more data", "So a scanner listening on any one of them hears it, even if one is jammed by Wi-Fi", "Because each channel carries a different part", "To pair with three phones"],
            answer: 1,
            why: "Scanners hop between the three advertising channels. Repeating the same packet on all three makes it likely to be heard despite interference.",
          },
          events: [
            pkt("band", "phone", "pink", "ADV_IND", ["ch 37", "FitBand · 0x180D"], adv({ time: 0, info: `ADV_IND (ch 37), AdvA ${BAND}`, packet: advInd() })),
            pkt("band", "phone", "pink", "ADV_IND", ["ch 38"], adv({ time: 0.0004, info: `ADV_IND (ch 38), AdvA ${BAND}`, packet: advInd() })),
            pkt("band", "phone", "pink", "ADV_IND", ["ch 39"], adv({ time: 0.0008, info: `ADV_IND (ch 39), AdvA ${BAND}`, packet: advInd() })),
          ],
        },
        {
          title: "Ask for more",
          desc: "SCAN_REQ and SCAN_RSP",
          detail:
            "The fitness app is scanning for UUID 0x180D. Right after the next ADV_IND, 150 µs later on the same channel, the phone sends SCAN_REQ. The band answers with SCAN_RSP, which carries extra data that did not fit in the 31-byte advert: its appearance (a watch) and transmit power.",
          facts: [["Gap between packets", "150 µs (T_IFS)"], ["Scan type", "Active"], ["Extra data", "Appearance, TX power"]],
          events: [
            pkt("band", "phone", "pink", "ADV_IND", ["ch 37"], adv({ time: 0.1, info: `ADV_IND (ch 37), AdvA ${BAND}`, packet: advInd() })),
            pkt("phone", "band", "blue", "SCAN_REQ", ["tell me more"], { ...row("LE LL", PHONE, BAND), time: 0.10024, info: `SCAN_REQ, ScanA ${PHONE}, AdvA ${BAND}`, packet: scanReq() }),
            pkt("band", "phone", "green", "SCAN_RSP", ["watch, 0 dBm"], { ...row("LE LL", BAND, PHONE), time: 0.1005, info: `SCAN_RSP, AdvA ${BAND}`, packet: scanRsp() }),
          ],
        },
        {
          title: "Connect",
          desc: "CONNECT_IND sets every parameter",
          detail:
            "When the user taps the band in the app, the phone waits for the next advert and replies with CONNECT_IND. In one 34-byte packet it decides everything: a new access address and CRC seed for the connection, a 30 ms connection interval, the timeout and the channel-hopping pattern. Both then leave the advertising channels.",
          facts: [["New access address", `0x${CONN_AA.toString(16)}`], ["Interval", "30 ms"], ["Hop", "+7 channels per event"]],
          quiz: {
            q: "After CONNECT_IND, which access address will the band’s packets start with?",
            options: ["0x8E89BED6 as before", `0x${CONN_AA.toString(16)}, chosen by the phone`, "The band’s MAC address", "Zero"],
            answer: 1,
            why: "Each connection gets its own random access address from CONNECT_IND, so radios can tell this connection’s packets from everything else in the air.",
          },
          events: [
            pkt("band", "phone", "pink", "ADV_IND", ["ch 37"], adv({ time: 0.2, info: `ADV_IND (ch 37), AdvA ${BAND}`, packet: advInd() })),
            pkt("phone", "band", "green", "CONNECT", ["AA, CRC seed", "30 ms, hop 7"], { ...row("LE LL", PHONE, BAND), time: 0.20024, info: `CONNECT_IND, InitA ${PHONE}, AdvA ${BAND}`, packet: connectInd() }),
            note("band", "CONNECTED", "green"),
          ],
        },
        {
          title: "Find the services",
          desc: "ATT Read By Group Type",
          detail:
            "GATT organises the band’s data as a table of numbered attributes (handles). The phone asks for every primary service (type 0x2800). The answer lists handle ranges: Generic Access, Generic Attribute, and Heart Rate at handles 0x000C to 0x0011. With the default 23-byte ATT packet only three entries fit, so the phone would ask again from 0x0012 for the rest.",
          facts: [["Request", "Read By Group Type (0x10)"], ["Heart Rate service", "Handles 0x000C–0x0011"], ["L2CAP channel", "0x0004 (ATT)"]],
          quiz: {
            q: "Each entry is 6 bytes and an ATT packet is at most 23 bytes. How many services fit in one response?",
            options: ["2", "3", "4", "All of them"],
            answer: 1,
            why: "Opcode (1) + length (1) leaves 21 bytes, and 21 / 6 = 3 whole entries.",
          },
          events: [
            pkt("phone", "band", "blue", "READ GROUP", ["primary services?"], { ...row("ATT", "Central", "Peripheral"), time: 0.2215, info: "Sent Read By Group Type Request, GATT Primary Service Declaration, Handles: 0x0001..0xffff", packet: readGroupReq() }),
            pkt("band", "phone", "green", "SERVICES", ["GAP, GATT,", "Heart Rate 0x000C"], { ...row("ATT", "Peripheral", "Central"), time: 0.22165, info: "Rcvd Read By Group Type Response, Attribute List Length: 3, Generic Access, Generic Attribute, Heart Rate", packet: readGroupRsp() }),
          ],
        },
        {
          title: "Turn on notifications",
          desc: "Write 0x0001 to the CCCD",
          detail:
            "After discovering the Heart Rate Measurement characteristic (value at handle 0x000E, not shown), the phone writes 0x0001 to its Client Characteristic Configuration Descriptor at 0x000F. That tells the band: push new values to me without being asked. The band confirms with a Write Response.",
          facts: [["Handle", "0x000F (CCCD)"], ["Value", "01 00 (notifications on)"], ["Reply", "Write Response (0x13)"]],
          quiz: {
            q: "What would the phone write to the CCCD to stop the updates later?",
            options: ["0x0001", "0x0002", "0x0000", "It must disconnect"],
            answer: 2,
            why: "Clearing both bits (notifications and indications) to 0x0000 turns the updates off.",
          },
          events: [
            pkt("phone", "band", "blue", "WRITE", ["0x000F = 01 00"], { ...row("ATT", "Central", "Peripheral"), time: 0.2515, info: "Sent Write Request, Handle: 0x000f (Heart Rate: Heart Rate Measurement: Client Characteristic Configuration)", packet: writeCccd() }),
            pkt("band", "phone", "green", "WRITE RSP", ["done"], { ...row("ATT", "Peripheral", "Central"), time: 0.2815, info: "Rcvd Write Response, Handle: 0x000f", packet: writeRsp() }),
          ],
        },
        {
          title: "Heart rate arrives",
          desc: "Handle Value Notifications",
          detail:
            "Now, about once a second, the band sends a notification on handle 0x000E with a flags byte and the heart rate. Notifications are not acknowledged at the ATT level; the link layer’s SN/NESN bits already make sure each packet arrives. Between them, the two keep the connection alive with empty packets every 30 ms (hidden here).",
          facts: [["Opcode", "0x1B notification"], ["Payload", "Flags 0x06 + 1 byte bpm"], ["Radio on time", "A few hundred µs per second"]],
          events: [
            pkt("band", "phone", "violet", "NOTIFY", ["72 bpm"], { ...row("ATT", "Peripheral", "Central"), time: 1.2815, info: "Rcvd Handle Value Notification, Handle: 0x000e (Heart Rate Measurement), 72 bpm", packet: hrNotify(0, 1, 72) }),
            pkt("band", "phone", "violet", "NOTIFY", ["74 bpm"], { ...row("ATT", "Peripheral", "Central"), time: 2.2815, info: "Rcvd Handle Value Notification, Handle: 0x000e (Heart Rate Measurement), 74 bpm", packet: hrNotify(1, 0, 74) }),
            note("phone", "♥ 74 BPM", "green"),
          ],
        },
      ],
      outro: {
        title: "Heart rate on screen",
        text: "The band advertised its Heart Rate service, the phone connected with one CONNECT_IND, discovered the service with ATT and switched on notifications by writing to the CCCD. From then on each reading costs the band just one tiny radio packet.",
        facts: [["Access addresses", "0x8E89BED6, then per-connection"], ["GATT service", "0x180D Heart Rate"], ["Notification size", "7-byte ATT, 18-byte air packet"], ["Pairing", "None needed for public heart rate"]],
      },
    },
    {
      id: "mitm",
      name: "Just Works pairing and a MITM",
      summary: "An attacker relays between phone and band. Just Works can’t notice; Numeric Comparison can.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "A fake band answers",
          desc: "The attacker sits in the middle",
          detail:
            "The attacker clones the band’s advert and address and connects to the real band itself. The phone connects to the attacker, thinking it is the band, and starts pairing so the link will be encrypted. The band says it has no display and no buttons (NoInputNoOutput), which forces the Just Works method.",
          facts: [["Phone IO", "DisplayYesNo"], ["Band IO", "NoInputNoOutput"], ["Method chosen", "Just Works"]],
          quiz: {
            q: "With Just Works, what does the user check during pairing?",
            options: ["A 6-digit number on both screens", "A PIN printed on the box", "Nothing at all", "A QR code"],
            answer: 2,
            why: "Just Works has no user step, which is exactly why it can’t detect a man in the middle.",
          },
          events: [
            pkt("phone", "attacker", "blue", "PAIR REQ", ["DisplayYesNo", "MITM + SC wanted"], { ...row("SMP", "Central", "Peripheral"), time: 0, info: "Pairing Request: DisplayYesNo, Bonding, MITM, SecureConnections", packet: mitmSmp(0, 0, pairing(1, 1, 0x0d)) }),
            pkt("attacker", "phone", "red", "PAIR RSP", ["NoInputNoOutput"], { ...row("SMP", "Peripheral", "Central"), time: 0.03, info: "Pairing Response: NoInputNoOutput, Bonding, SecureConnections", packet: mitmSmp(0, 1, pairing(2, 3, 0x09)) }),
            note("attacker", "RELAYING", "red"),
          ],
        },
        {
          title: "Swap public keys",
          desc: "ECDH with the attacker, not the band",
          detail:
            "LE Secure Connections uses elliptic-curve Diffie-Hellman: each side sends a 64-byte P-256 public key. The attacker gives the phone its own key and does the same with the real band, so it ends up with one shared key per side. ECDH stops someone who only listens, but nothing here proves whose key is whose.",
          facts: [["Key", "P-256, 64 bytes (X, Y)"], ["Packet", "69-byte L2CAP (needs DLE)"], ["Passive sniffer", "Defeated"]],
          events: [
            pkt("phone", "attacker", "teal", "PUB KEY", ["phone’s key"], { ...row("SMP", "Central", "Peripheral"), time: 0.06, info: "Pairing Public Key", packet: mitmSmp(1, 1, publicKey(6001, "The phone")) }),
            pkt("attacker", "phone", "red", "PUB KEY", ["attacker’s key!"], { ...row("SMP", "Peripheral", "Central"), time: 0.09, info: "Pairing Public Key", packet: mitmSmp(1, 0, publicKey(6101, "The attacker")) }),
          ],
        },
        {
          title: "Just Works succeeds",
          desc: "Both links are “secure”",
          detail:
            "The confirm and random values check out, because the attacker computed them honestly with the keys it swapped in. The phone shows “Paired”. The attacker now decrypts everything from the band, can change heart-rate values, and can send commands to the band.",
          facts: [["Phone thinks", "Paired with the band"], ["Reality", "Two links via the attacker"], ["Detected", "No"]],
          events: [
            pkt("attacker", "phone", "red", "CONFIRM", ["commitment"], { ...row("SMP", "Peripheral", "Central"), time: 0.12, info: "Pairing Confirm", packet: mitmSmp(0, 0, confirm()) }),
            pkt("phone", "attacker", "teal", "RANDOM", ["phone nonce"], { ...row("SMP", "Central", "Peripheral"), time: 0.15, info: "Pairing Random", packet: mitmSmp(0, 1, random()) }),
            note("phone", "PAIRED (WITH THE ATTACKER)", "red"),
          ],
        },
        {
          title: "Defence: compare numbers",
          desc: "Numeric Comparison catches the swap",
          detail:
            "If the band has a screen and says DisplayYesNo, Secure Connections uses Numeric Comparison: each side turns both public keys and nonces into a 6-digit number and shows it. Because the attacker swapped keys, the phone shows 482913 and the band 107655. The user taps No and the phone aborts with reason 0x0C. If the attacker instead lies that the band has no display, a phone that demands MITM protection refuses Just Works with reason 0x03.",
          facts: [["Phone shows", "482 913"], ["Band shows", "107 655"], ["Result", "Pairing Failed 0x0C"]],
          quiz: {
            q: "Why do the two screens show different numbers when an attacker is in the middle?",
            options: ["The clocks differ", "Each side’s number is computed from the public keys it actually saw, and the attacker swapped them", "Bluetooth adds random noise", "The band has a different PIN"],
            answer: 1,
            why: "The 6-digit value is a hash of both public keys and nonces. With swapped keys, the two hashes cannot match unless the attacker breaks the hash.",
          },
          events: [
            note("phone", "482 913 ?", "amber"),
            note("band", "107 655 ?", "amber"),
            pkt("phone", "attacker", "red", "FAILED", ["0x0C numbers differ"], { ...row("SMP", "Central", "Peripheral"), time: 0.25, info: "Pairing Failed: Numeric Comparison Failed", packet: mitmSmp(1, 1, failed(0x0c, "Numeric Comparison Failed")) }),
            note("phone", "PAIRING REFUSED", "green"),
          ],
        },
      ],
      outro: {
        title: "Encryption needs authentication",
        text: "LE Secure Connections with Just Works still stops passive eavesdroppers, but nothing proves who is on the other end. Numeric Comparison or Passkey Entry ties the keys to what the user sees, so a man in the middle is caught. Old LE Legacy Just Works is weaker still: a recorded pairing can be cracked offline.",
        facts: [["Just Works", "No MITM protection"], ["Numeric Comparison", "Needs a display on both sides"], ["Fail reasons", "0x03 Auth Req, 0x0C Numeric Comparison"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Advertising PDUs",
      items: [["0x0 ADV_IND", "Connectable, scannable advert"], ["0x3 SCAN_REQ", "Scanner asks for more"], ["0x4 SCAN_RSP", "Extra advert data"], ["0x5 CONNECT_IND", "Start a connection"]],
    },
    {
      title: "ATT opcodes",
      items: [["0x10 / 0x11", "Read By Group Type req / rsp"], ["0x08 / 0x09", "Read By Type req / rsp"], ["0x12 / 0x13", "Write req / rsp"], ["0x1B", "Notification (no ack)"], ["0x1D / 0x1E", "Indication / confirmation"]],
    },
    {
      title: "Numbers to know",
      items: [["0x8E89BED6", "Advertising access address"], ["0x180D / 0x2A37", "Heart Rate service / measurement"], ["0x2800 / 0x2902", "Primary service / CCCD"], ["ATT_MTU", "23 bytes default"], ["L2CAP CIDs", "0x0004 ATT, 0x0006 SMP"]],
    },
  ],
});

// keep u24 import used for readers who extend the lesson
void u24;
