import { Color, defineLesson, Device, note, pkt, PacketEvent } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, tcp, TcpOpt, tls } from "@/lib/proto";

// ---------------------------------------------------------------- plant network

const HMI = "192.168.50.10";
const PLC = "192.168.50.20";
const EVIL = "192.168.60.66"; // a compromised PC on the office network
const HMI_MAC = "00:1b:1b:10:20:30";
const PLC_MAC = "00:80:f4:0a:12:5c";
const FW_MAC = "00:0d:b9:44:01:02";
const UNIT = 1;
const r = (n: number) => Number(n.toFixed(4));

// tank PLC registers (holding registers 40001…)
const LEVEL_CM = 742;
const LEVEL_PCT = 618; // tenths of a percent
const HIGH_ALARM = 1100;

// ---------------------------------------------------------------- Modbus/TCP layers

const FC: Record<number, string> = { 3: "Read Holding Registers", 5: "Write Single Coil", 0x83: "Read Holding Registers (exception)" };

/** MBAP header (7 bytes) + PDU. Length counts the unit id + PDU bytes. */
const modbus = (tid: number, pdu: FieldSpec[], summary: string): LayerSpec => {
  const pduLen = build(proto({ id: "x", name: "x", fields: pdu })).bytes.length;
  return proto({
    id: "mbtcp",
    name: "Modbus/TCP",
    summary,
    fields: [
      {
        name: "MBAP header", value: `Trans ${tid}, Len ${pduLen + 1}, Unit ${UNIT}`,
        note: "Modbus Application Protocol header: 7 bytes in front of every Modbus/TCP message.",
        fields: [
          { name: "Transaction ID", u16: tid, note: "Picked by the client; the reply repeats it so answers can be matched." },
          { name: "Protocol ID", u16: 0, value: "0 (Modbus)", note: "Always 0 for Modbus." },
          { name: "Length", u16: pduLen + 1, note: "Bytes that follow: unit ID (1) + PDU." },
          { name: "Unit ID", u8: UNIT, note: "Which device behind a gateway. A PLC reached directly usually ignores it." },
        ],
      },
      { name: "PDU", value: summary, fields: pdu },
    ],
  });
};

const readReq = (tid: number, addr: number, qty: number) =>
  modbus(tid, [
    { name: "Function code", u8: 3, value: "3 (Read Holding Registers)" },
    { name: "Starting address", u16: addr, value: `${addr} (register ${40001 + addr})`, note: "Addresses on the wire start at 0. Register 40001 is address 0." },
    { name: "Quantity", u16: qty, value: `${qty} registers` },
  ], `Query: Trans ${tid}; Unit: ${UNIT}, Func: 3: Read Holding Registers`);

const readResp = (tid: number, regs: [number, string][]) =>
  modbus(tid, [
    { name: "Function code", u8: 3, value: "3 (Read Holding Registers)" },
    { name: "Byte count", u8: regs.length * 2, note: "Two bytes per register." },
    ...regs.map(([v, what], i) => ({ name: `Register ${40001 + i}`, u16: v, value: `${v} (0x${v.toString(16).padStart(4, "0")})`, note: what })),
  ], `Response: Trans ${tid}; Unit: ${UNIT}, Func: 3: Read Holding Registers`);

const writeCoil = (tid: number, on: boolean, resp: boolean) =>
  modbus(tid, [
    { name: "Function code", u8: 5, value: "5 (Write Single Coil)" },
    { name: "Output address", u16: 0, value: "0 (coil 00001: pump run)" },
    { name: "Output value", u16: on ? 0xff00 : 0x0000, value: on ? "0xFF00 (ON)" : "0x0000 (OFF)", note: "Only two values are legal: 0xFF00 = ON, 0x0000 = OFF." },
  ], `${resp ? "Response" : "Query"}: Trans ${tid}; Unit: ${UNIT}, Func: 5: Write Single Coil`);

const exception = (tid: number) =>
  modbus(tid, [
    { name: "Function code", u8: 0x83, value: "0x83 (3 + 0x80: exception)", note: "The top bit is set: the PLC is saying it could not do function 3." },
    { name: "Exception code", u8: 2, value: "2 (Illegal Data Address)", note: "The requested register range doesn't exist on this PLC." },
  ], `Response: Trans ${tid}; Unit: ${UNIT}, Func: 131: Read Holding Registers. Exception: Illegal data address`);

// ---------------------------------------------------------------- TCP conversation helper (LAN)

interface End { id: string; layers: () => LayerSpec[]; port: number; base: number; win: number }

function conversation(a: End, b: End) {
  const next = { a: 0, b: 0 };
  const send = (fromA: boolean, flags: string, app: LayerSpec[], opts?: TcpOpt[]) => {
    const me = fromA ? a : b, them = fromA ? b : a;
    const seq = fromA ? next.a : next.b;
    const ack = fromA ? next.b : next.a;
    const len = app.length ? build(...app).bytes.length : 0;
    const packet = build(
      ...me.layers(),
      tcp({ sport: me.port, dport: them.port, seq, ...(flags.includes("A") ? { ack } : {}), flags, win: me.win, opts, seqBase: me.base, ackBase: them.base }),
      ...app
    );
    const adv = len + (/[SF]/.test(flags) ? 1 : 0);
    if (fromA) next.a += adv; else next.b += adv;
    return packet;
  };
  const msg = (fromA: boolean) => (color: Color, label: string, lines: string[], time: number, info: string, app: LayerSpec[], extra: Partial<PacketEvent> = {}, flags = "PA"): PacketEvent =>
    pkt(fromA ? a.id : b.id, fromA ? b.id : a.id, color, label, lines, { time: r(time), info, packet: send(fromA, flags, app), ...extra });
  return {
    a: msg(true),
    b: msg(false),
    syn: (t: number, extra: Partial<PacketEvent> = {}): PacketEvent =>
      pkt(a.id, b.id, "red", "SYN", [`to port ${b.port}`], { time: r(t), info: `${a.port} → ${b.port} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: send(true, "S", [], [{ mss: 1460 }]), ...extra }),
    handshake: (t: number, rtt: number, color: Color = "green"): PacketEvent[] => [
      pkt(a.id, b.id, color, "SYN", [`to port ${b.port}`], {
        time: r(t), info: `${a.port} → ${b.port} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`,
        packet: send(true, "S", [], [{ mss: 1460 }]),
      }),
      pkt(b.id, a.id, color, "SYN-ACK", ["port open"], {
        time: r(t + rtt), info: `${b.port} → ${a.port} [SYN, ACK] Seq=0 Ack=1 Win=2048 Len=0 MSS=1460`,
        packet: send(false, "SA", [], [{ mss: 1460 }]),
      }),
      pkt(a.id, b.id, color, "ACK", ["connected"], {
        time: r(t + rtt + 0.0001), info: `${a.port} → ${b.port} [ACK] Seq=1 Ack=1 Win=64240 Len=0`,
        packet: send(true, "A", []),
      }),
    ],
  };
}

const hmiLayers = () => [eth({ src: HMI_MAC, dst: PLC_MAC }), ipv4({ src: HMI, dst: PLC, ttl: 128 })];
const plcLayers = (to = HMI, mac = HMI_MAC) => [eth({ src: PLC_MAC, dst: mac }), ipv4({ src: PLC, dst: to, ttl: 64 })];

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "hmi", kind: "desktop", label: "SCADA / HMI", sub: HMI, x: 10, y: 60 },
  { id: "switch", kind: "switch", label: "Plant switch", x: 40, y: 60 },
  { id: "plc", kind: "plc", label: "Tank PLC", sub: PLC, x: 70, y: 60 },
  { id: "pump", kind: "iot", label: "Pump + level sensor", sub: "wired I/O", x: 91, y: 30 },
];
const links: [string, string][] = [["hmi", "switch"], ["switch", "plc"], ["plc", "pump"]];

// ---------------------------------------------------------------- scenario 1

const M = conversation({ id: "hmi", layers: hmiLayers, port: 50210, base: 0x00a1b2c3, win: 64240 }, { id: "plc", layers: () => plcLayers(), port: 502, base: 0x4000e000, win: 2048 });

const REGS: [number, string][] = [
  [LEVEL_CM, `Tank level: ${LEVEL_CM} cm`],
  [LEVEL_PCT, `Tank level: ${LEVEL_PCT / 10}% (tenths of a percent)`],
  [HIGH_ALARM, `High-level alarm setpoint: ${HIGH_ALARM} cm`],
];

const normalSteps = [
  {
    title: "Connect to port 502",
    desc: "The HMI opens a TCP connection to the PLC",
    detail: "A water plant's SCADA screen (the HMI) shows a tank's level and lets the operator run a pump. The tank is controlled by a PLC, a rugged industrial computer wired to the sensor and pump. The HMI opens a TCP connection to the PLC on port 502, the Modbus/TCP port.",
    facts: [["PLC", `${PLC} port 502`], ["Roles", "HMI = client, PLC = server"], ["Network", "Plant LAN, < 1 ms"]] as [string, string][],
    events: M.handshake(0, 0.0006),
  },
  {
    title: "Read Holding Registers",
    desc: "Function code 3, three registers from 40001",
    detail: "Modbus thinks in 16-bit registers. The HMI asks for 3 holding registers starting at address 0 (which the manuals call 40001). In front of the request is the 7-byte MBAP header: transaction ID 1, protocol 0, length 6 (unit ID + 5 PDU bytes) and unit ID 1.",
    facts: [["Function", "3 (Read Holding Registers)"], ["Start, count", "address 0, 3 registers"], ["MBAP length", "6 = 1 unit + 5 PDU bytes"]] as [string, string][],
    quiz: {
      q: "The PDU is function code (1) + start address (2) + quantity (2). What goes in the MBAP Length field?",
      options: ["5", "6", "7", "12"],
      answer: 1,
      why: "Length counts every byte after it: the 1-byte unit ID plus the 5-byte PDU = 6.",
    },
    events: [M.a("amber", "READ", ["fc 3, 40001–40003"], 0.001, "Query: Trans 1; Unit: 1, Func: 3: Read Holding Registers", [readReq(1, 0, 3)])],
  },
  {
    title: "Registers come back",
    desc: "Byte count, then 16-bit values",
    detail: `The PLC answers with the same transaction ID, function 3, a byte count of 6 and three big-endian values: 0x02E6 = ${LEVEL_CM} cm, 0x026A = ${LEVEL_PCT} (61.8%) and the alarm setpoint ${HIGH_ALARM}. Modbus doesn't say what a number means. Only the PLC's register map, a document, tells you register 40002 is tenths of a percent.`,
    facts: [["40001", `0x02E6 = ${LEVEL_CM} cm`], ["40002", `0x026A = ${LEVEL_PCT} → 61.8%`], ["40003", `0x044C = ${HIGH_ALARM} cm alarm`]] as [string, string][],
    quiz: {
      q: "A register holds the bytes 02 E6. What number is that?",
      options: ["230", "742", "58882", "2.230"],
      answer: 1,
      why: "Modbus is big-endian: 0x02 × 256 + 0xE6 = 512 + 230 = 742.",
    },
    events: [M.b("violet", "REGISTERS", [`${LEVEL_CM}, ${LEVEL_PCT}, ${HIGH_ALARM}`], 0.0016, "Response: Trans 1; Unit: 1, Func: 3: Read Holding Registers", [readResp(1, REGS)])],
  },
  {
    title: "Write Single Coil",
    desc: "Function 5, value 0xFF00: start the pump",
    detail: "The operator clicks Start Pump. A coil is a single on/off output. The HMI sends function 5 to coil address 0 with the value 0xFF00, which means ON (0x0000 means OFF; any other value is illegal). The PLC switches its output and echoes the request back as confirmation.",
    facts: [["Function", "5 (Write Single Coil)"], ["Coil", "address 0 (00001: pump run)"], ["Value", "0xFF00 = ON, 0x0000 = OFF"]] as [string, string][],
    quiz: {
      q: "What does a successful Write Single Coil response look like?",
      options: ["An empty packet", "An exact echo of the request", "The new value of every coil", "A register list"],
      answer: 1,
      why: "For function 5 the PLC repeats the address and value it wrote. That echo is the confirmation.",
    },
    events: [
      M.a("amber", "WRITE", ["fc 5, coil 0", "0xFF00 = ON"], 2.401, "Query: Trans 2; Unit: 1, Func: 5: Write Single Coil", [writeCoil(2, true, false)]),
      M.b("green", "ECHO", ["coil 0 = ON"], 2.4016, "Response: Trans 2; Unit: 1, Func: 5: Write Single Coil", [writeCoil(2, true, true)]),
      note("pump", "PUMP RUNNING", "green"),
    ],
  },
  {
    title: "Keep polling",
    desc: "The HMI reads again every second",
    detail: "Modbus has no push: the PLC never speaks unless asked. So the HMI polls, reading the same registers every second with a new transaction ID. The level has risen to 745 cm. This steady request-response rhythm is what normal Modbus traffic looks like, and makes odd writes easy to spot.",
    facts: [["Transaction", "3"], ["Level now", "745 cm, 62.1%"], ["Pattern", "Poll every 1 s, no push"]] as [string, string][],
    events: [
      M.a("amber", "READ", ["fc 3, 40001–40003"], 3.001, "Query: Trans 3; Unit: 1, Func: 3: Read Holding Registers", [readReq(3, 0, 3)]),
      M.b("violet", "REGISTERS", ["745, 621, 1100"], 3.0016, "Response: Trans 3; Unit: 1, Func: 3: Read Holding Registers", [readResp(3, [[745, "Tank level: 745 cm"], [621, "Tank level: 62.1%"], [HIGH_ALARM, "High-level alarm setpoint"]])]),
    ],
  },
];

// ---------------------------------------------------------------- scenario 2: exception

const X = conversation({ id: "hmi", layers: hmiLayers, port: 50211, base: 0x0c0c0c0c, win: 64240 }, { id: "plc", layers: () => plcLayers(), port: 502, base: 0x40aa0000, win: 2048 });

const exceptionSteps = [
  {
    title: "Ask for a missing register",
    desc: "A wrong register map in the HMI",
    detail: "An engineer adds a new screen but copies the address from the wrong PLC manual: register 40257 (address 256). This PLC only has 64 holding registers. The request itself is perfectly well formed.",
    facts: [["Function", "3"], ["Start address", "256 (register 40257)"], ["PLC has", "Registers 40001–40064 only"]] as [string, string][],
    events: [
      ...X.handshake(0, 0.0006),
      X.a("amber", "READ", ["fc 3, 40257", "2 registers"], 0.001, "Query: Trans 1; Unit: 1, Func: 3: Read Holding Registers", [readReq(1, 256, 2)]),
    ],
  },
  {
    title: "Exception response",
    desc: "Function code 0x83, exception code 2",
    detail: "The PLC answers with the function code plus 0x80: 3 becomes 0x83. That top bit means \"this is an error\". The single byte after it is the exception code: 2, Illegal Data Address. The HMI shows a red question mark on the new screen instead of a value.",
    facts: [["Function", "0x83 = 0x03 | 0x80"], ["Exception", "2: Illegal Data Address"], ["MBAP length", "3"]] as [string, string][],
    quiz: {
      q: "A Write Single Coil (function 5) fails. Which function code comes back?",
      options: ["0x05", "0x85", "0x50", "0xFF"],
      answer: 1,
      why: "Exceptions set the top bit: 0x05 | 0x80 = 0x85.",
    },
    events: [
      X.b("red", "EXCEPTION", ["fc 0x83", "illegal address"], 0.0016, "Response: Trans 1; Unit: 1, Func: 131: Read Holding Registers. Exception: Illegal data address", [exception(1)]),
      note("hmi", "TAG ERROR: ILLEGAL ADDRESS", "red"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 3: unauthenticated write

const attackDevices: Device[] = [
  ...devices,
  { id: "fw", kind: "firewall", label: "Industrial firewall", sub: "IT ↔ OT", x: 40, y: 22 },
  { id: "attacker", kind: "attacker", label: "Compromised office PC", sub: EVIL, x: 10, y: 22 },
];
const attackLinks: [string, string][] = [...links, ["attacker", "fw"], ["fw", "switch"]];

const evilLayers = () => [eth({ src: FW_MAC, dst: PLC_MAC }), ipv4({ src: EVIL, dst: PLC, ttl: 127 })];
const A = conversation({ id: "attacker", layers: evilLayers, port: 51502, base: 0x66600000, win: 64240 }, { id: "plc", layers: () => plcLayers(EVIL, FW_MAC), port: 502, base: 0x40bb0000, win: 2048 });
const A2 = conversation({ id: "attacker", layers: evilLayers, port: 51503, base: 0x66700000, win: 64240 }, { id: "plc", layers: () => plcLayers(EVIL, FW_MAC), port: 502, base: 0x40cc0000, win: 2048 });
const SEC = conversation(
  { id: "hmi", layers: () => [eth({ src: HMI_MAC, dst: PLC_MAC }), ipv4({ src: HMI, dst: PLC, ttl: 128 })], port: 50300, base: 0x12340000, win: 64240 },
  { id: "plc", layers: () => plcLayers(), port: 802, base: 0x56780000, win: 2048 }
);

const attackSteps = [
  {
    title: "Anyone can connect",
    desc: "The firewall allows any office PC to reach 502",
    detail: "An office PC is infected with malware. The firewall between the office (IT) network and the plant (OT) network has an old \"allow any\" rule, so the malware reaches the PLC on port 502. Modbus has no login, no password and no encryption. The PLC accepts the connection like any other.",
    facts: [["Source", `${EVIL} (office network)`], ["Firewall rule", "allow any → 502 (too wide)"], ["Modbus auth", "None"]] as [string, string][],
    events: [...A.handshake(0, 0.0008, "red")],
  },
  {
    title: "Coil written, no questions",
    desc: "The tank is already high; the pump starts anyway",
    detail: "The malware sends exactly the same Write Single Coil the HMI uses: coil 0, 0xFF00. The PLC can't tell who sent it and simply obeys. If the PLC logic has no independent high-level interlock, the tank could overflow. Nothing in the packet is unusual; only its source is.",
    facts: [["Packet", "fc 5, coil 0, 0xFF00"], ["PLC checks", "Nothing about the sender"], ["Risk", "Overflow, damage, safety"]] as [string, string][],
    quiz: {
      q: "How does a standard Modbus/TCP PLC decide whether to accept a write?",
      options: ["It checks a password in the MBAP header", "It checks the sender's certificate", "It doesn't: any well-formed request is executed", "It asks the HMI first"],
      answer: 2,
      why: "Classic Modbus has no authentication at all. Protection has to come from the network around it, or from Modbus Security.",
    },
    events: [
      A.a("red", "WRITE", ["fc 5, coil 0", "0xFF00 = ON"], 0.002, "Query: Trans 7; Unit: 1, Func: 5: Write Single Coil", [writeCoil(7, true, false)]),
      A.b("red", "ECHO", ["done"], 0.0026, "Response: Trans 7; Unit: 1, Func: 5: Write Single Coil", [writeCoil(7, true, true)]),
      note("pump", "PUMP STARTED BY MALWARE", "red"),
    ],
  },
  {
    title: "Defence: segment and filter",
    desc: "Only the HMI may talk to port 502",
    detail: "The plant fixes the firewall: only the HMI's address may reach the PLC on 502, and the office network is a separate zone (the IEC 62443 zones-and-conduits idea). The malware's next SYN is dropped at the firewall and never reaches the PLC. Many sites also add a Modbus-aware firewall that blocks write function codes from anything but the HMI.",
    facts: [["Rule", `allow ${HMI} → ${PLC}:502 only`], ["Office PCs", "No route to OT"], ["Extra", "Deep packet inspection: block fc 5/6/15/16"]] as [string, string][],
    events: [
      A2.syn(10, { lost: true }),
      note("fw", "DROPPED: NOT ALLOWED TO OT", "green"),
    ],
  },
  {
    title: "Modbus Security on 802",
    desc: "TLS with client certificates",
    detail: "Newer PLCs support Modbus/TCP Security: the same Modbus messages inside mutual TLS on port 802. Both sides present X.509 certificates, and the HMI's certificate carries a role such as \"Operator\" that the PLC checks before allowing a write. After the TLS handshake (not shown), the 12-byte write travels as a 29-byte encrypted record.",
    facts: [["Port", "802"], ["Security", "TLS 1.2+ with client certificates"], ["Authorisation", "Role in the certificate"]] as [string, string][],
    quiz: {
      q: "What does Modbus Security on port 802 add that plain Modbus on 502 lacks?",
      options: ["Faster polling", "Authentication, encryption and role-based permissions", "More registers", "UDP support"],
      answer: 1,
      why: "TLS gives encryption and proves who each side is; the role in the certificate decides what that client may do.",
    },
    events: [
      ...SEC.handshake(11, 0.0006, "teal"),
      SEC.a("teal", "TLS", ["fc 5 inside", "(encrypted)"], 11.03, "Application Data", [tls({ records: [{ type: "appdata", encrypted: 29, what: "Modbus/TCP: MBAP + Write Single Coil (12 bytes)" }] })]),
      SEC.b("teal", "TLS", ["echo inside", "(encrypted)"], 11.0306, "Application Data", [tls({ records: [{ type: "appdata", encrypted: 29, what: "Modbus/TCP: Write Single Coil response" }] })]),
    ],
  },
];

export default defineLesson({
  id: "modbus",
  name: "Modbus/TCP",
  full: "Modbus over TCP/IP",
  group: "iot",
  layer: 7,
  difficulty: 2,
  tagline: "The simple, trusting language of industrial control.",
  description:
    "Modbus lets a control computer read numbers from and switch outputs on a PLC: registers hold 16-bit values, coils are on/off switches. Modbus/TCP wraps each request in a 7-byte MBAP header and sends it to port 502. It has no authentication, so the network around it must protect it.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP 502 (802 with TLS)"],
    ["Defined in", "Modbus Application Protocol v1.1b3"],
    ["Header", "MBAP, 7 bytes"],
    ["Data model", "Coils, inputs, holding/input registers"],
    ["Security", "None built in; Modbus Security adds TLS"],
  ],
  ports: "502 Modbus/TCP, 802 Modbus/TCP Security",
  rfc: "Modbus.org specifications (not an RFC)",
  keywords: ["scada", "plc", "ics", "ot", "industrial", "mbap", "holding register", "coil", "function code", "exception", "502", "802", "hmi"],
  related: ["tcp", "mqtt", "coap", "tls"],
  devices,
  links,
  legend: [
    ["green", "Handshake and confirmations"],
    ["amber", "Requests from the HMI"],
    ["violet", "Values from the PLC"],
    ["teal", "Modbus Security (TLS)"],
    ["red", "Exceptions and attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Read the tank level and start the pump",
      summary: "The HMI polls three holding registers, then writes a coil to start the pump.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "Pump running",
        text: "The HMI read the tank level as raw 16-bit registers, switched the pump on with function 5 and 0xFF00, and kept polling. Every message was a tiny MBAP header plus a few bytes of PDU.",
        facts: [["Read", "fc 3 → 3 registers"], ["Write", "fc 5, coil 0 = 0xFF00"], ["Biggest packet", "Under 80 bytes"], ["Model", "Client polls, PLC answers"]],
      },
    },
    {
      id: "exception",
      name: "Exception: illegal data address",
      summary: "A request for registers the PLC doesn't have returns function 0x83, code 2.",
      kind: "failure",
      steps: exceptionSteps,
      outro: {
        title: "Exception handled",
        text: "Modbus errors come back as the function code with its top bit set, plus a one-byte exception code. Code 2 means the address range isn't on this device.",
        facts: [["Function", "0x83"], ["Code", "2 Illegal Data Address"], ["Others", "1 bad function, 3 bad value, 4 device failure"]],
      },
    },
    {
      id: "unauth-write",
      name: "Unauthenticated write from the office network",
      summary: "Malware starts the pump because Modbus has no login; segmentation and Modbus Security stop it.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: attackSteps,
      outro: {
        title: "Protect the network, not just the PLC",
        text: "Plain Modbus trusts every packet, so any device that can reach port 502 can control the plant. Separate IT and OT networks, allow only the HMI through, inspect function codes, and move to Modbus Security with certificates where devices support it.",
        facts: [["Attack", "Unauthenticated Write Single Coil"], ["Defence 1", "Segmentation + strict firewall rules"], ["Defence 2", "Modbus/TCP Security on port 802"], ["Standard", "IEC 62443"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Function codes",
      items: [["1 / 2", "Read coils / discrete inputs"], ["3 / 4", "Read holding / input registers"], ["5 / 6", "Write single coil / register"], ["15 / 16", "Write multiple coils / registers"], ["fc | 0x80", "Exception response"]],
    },
    {
      title: "MBAP header (7 bytes)",
      items: [["Transaction ID", "2 bytes, echoed in the reply"], ["Protocol ID", "2 bytes, always 0"], ["Length", "2 bytes: unit ID + PDU"], ["Unit ID", "1 byte, device behind a gateway"]],
    },
    {
      title: "Exception codes",
      items: [["1", "Illegal function"], ["2", "Illegal data address"], ["3", "Illegal data value"], ["4", "Server device failure"], ["6", "Server busy"]],
    },
  ],
});
