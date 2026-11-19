import { Color, defineLesson, Device, note, pkt, PacketEvent } from "@/lib/lesson";
import { Bytes, text } from "@/lib/bytes";
import { build, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, tcp, TcpOpt } from "@/lib/proto";
import { ADDR, down, up } from "./_common";

// ---------------------------------------------------------------- addresses

const BROKER = "203.0.113.60";
const BROKER_HOST = "mqtt.example.com";
const SENSOR = "192.168.1.40";
const SENSOR_MAC = "24:0a:c4:5e:77:10";
const EVIL = "198.51.100.99";
const GW_MAC = "00:00:5e:00:01:01";
const BROKER_MAC = "00:16:3e:60:10:01";
const r = (n: number) => Number(n.toFixed(4));

// ---------------------------------------------------------------- MQTT encoding

/** Remaining Length: 7 bits per byte, top bit = "more bytes follow" */
const varint = (n: number): Bytes => {
  const out: Bytes = [];
  do { let b = n % 128; n = Math.floor(n / 128); if (n > 0) b |= 0x80; out.push(b); } while (n > 0);
  return out;
};
const sizeOf = (fs: FieldSpec[]) => (fs.length ? build(proto({ id: "x", name: "x", fields: fs })).bytes.length : 0);
const mstr = (name: string, s: string, note?: string): FieldSpec => ({ name, value: JSON.stringify(s), note, fields: [{ name: "Length", u16: text(s).length }, { name: "Text", text: s }] });

const TYPES: Record<number, string> = { 1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 8: "SUBSCRIBE", 9: "SUBACK", 12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT" };

const mqtt = (type: number, flags: number, varHeader: FieldSpec[], payload: FieldSpec[], summary: string, flagNote?: string): LayerSpec => {
  const rl = sizeOf(varHeader) + sizeOf(payload);
  const b1 = (type << 4) | flags;
  const fixed: FieldSpec = {
    name: "Fixed header", value: `${TYPES[type]}, remaining length ${rl}`,
    fields: [
      { name: "Type and flags", u8: b1, value: `0x${b1.toString(16).padStart(2, "0")} (${TYPES[type]}${flags ? `, flags 0x${flags.toString(16)}` : ""})`, note: flagNote ?? "High 4 bits: packet type. Low 4 bits: flags (used by PUBLISH; fixed values for the others)." },
      { name: "Remaining length", bytes: varint(rl), value: String(rl), note: rl > 127 ? "Above 127, so it takes more than one byte: 7 bits per byte, the top bit says another byte follows." : "Bytes that follow. Under 128 fits in one byte." },
    ],
  };
  const fields: FieldSpec[] = [fixed];
  if (varHeader.length) fields.push({ name: "Variable header", fields: varHeader });
  if (payload.length) fields.push({ name: "Payload", fields: payload });
  return proto({ id: "mqtt", name: "MQ Telemetry Transport", summary, fields });
};

const connect = (o: { clientId: string; clean: boolean; keepAlive: number; user?: string; pass?: string; will?: { topic: string; msg: string; qos: number; retain: boolean } }) => {
  const flags = (o.user ? 0x80 : 0) | (o.pass ? 0x40 : 0) | (o.will?.retain ? 0x20 : 0) | ((o.will?.qos ?? 0) << 3) | (o.will ? 0x04 : 0) | (o.clean ? 0x02 : 0);
  const names = [o.user && "username", o.pass && "password", o.will?.retain && "will retain", o.will && `will QoS ${o.will.qos}`, o.will && "will", o.clean && "clean session"].filter(Boolean).join(", ");
  return mqtt(1, 0, [
    mstr("Protocol name", "MQTT"),
    { name: "Protocol level", u8: 4, value: "4 (MQTT 3.1.1)", note: "5 would mean MQTT 5.0." },
    { name: "Connect flags", u8: flags, value: `0x${flags.toString(16).padStart(2, "0")} (${names || "none"})`, note: "Bits: 7 username, 6 password, 5 will retain, 4–3 will QoS, 2 will flag, 1 clean session." },
    { name: "Keep alive", u16: o.keepAlive, value: `${o.keepAlive} s`, note: "Longest silence allowed. The client must send something (at least PINGREQ) within this time." },
  ], [
    mstr("Client ID", o.clientId, "Unique per client. The broker keeps sessions under this name."),
    ...(o.will ? [mstr("Will topic", o.will.topic, "Where the broker publishes the will if this client vanishes."), mstr("Will message", o.will.msg)] : []),
    ...(o.user ? [mstr("Username", o.user)] : []),
    ...(o.pass ? [mstr("Password", o.pass, "Plain text on port 1883! Use TLS (8883) in real deployments.")] : []),
  ], `Connect Command (client ${o.clientId})`);
};
const CONNACK_RC = ["Connection Accepted", "Unacceptable protocol version", "Identifier rejected", "Server unavailable", "Bad user name or password", "Not authorized"];
const connack = (sessionPresent: boolean, rc = 0) =>
  mqtt(2, 0, [
    { name: "Acknowledge flags", u8: sessionPresent ? 1 : 0, value: sessionPresent ? "1 (session present)" : "0", note: "Session present = 1: the broker still has this client's subscriptions and queued messages." },
    { name: "Return code", u8: rc, value: `${rc} (${CONNACK_RC[rc]})` },
  ], [], `Connect Ack (${CONNACK_RC[rc]})`);
const subscribe = (id: number, filters: [string, number][]) =>
  mqtt(8, 2, [{ name: "Packet identifier", u16: id }], filters.flatMap(([f, q]) => [mstr("Topic filter", f, f.includes("+") ? "+ matches exactly one level: home/kitchen/temp, home/livingroom/temp…" : f === "#" ? "# matches every topic." : undefined), { name: "Requested QoS", u8: q }]), `Subscribe Request (id=${id}) ${filters.map((f) => f[0]).join(", ")}`, "SUBSCRIBE must have flags 0010.");
const suback = (id: number, codes: number[]) =>
  mqtt(9, 0, [{ name: "Packet identifier", u16: id }], codes.map((c) => ({ name: "Return code", u8: c, value: c === 0x80 ? "0x80 (failure)" : `QoS ${c} granted` })), `Subscribe Ack (id=${id})`);
const publish = (o: { topic: string; msg: string; qos: number; retain?: boolean; dup?: boolean; id?: number }) => {
  const flags = (o.dup ? 8 : 0) | (o.qos << 1) | (o.retain ? 1 : 0);
  return mqtt(3, flags, [mstr("Topic", o.topic), ...(o.qos > 0 ? [{ name: "Packet identifier", u16: o.id ?? 1 }] : [])], [{ name: "Message", text: o.msg, value: JSON.stringify(o.msg), note: "MQTT doesn't care what's in here: text, JSON or binary." }],
    `Publish Message${o.qos ? ` (id=${o.id})` : ""} [${o.topic}]`, `PUBLISH flags: DUP ${o.dup ? 1 : 0}, QoS ${o.qos}, RETAIN ${o.retain ? 1 : 0}.`);
};
const puback = (id: number) => mqtt(4, 0, [{ name: "Packet identifier", u16: id }], [], `Publish Ack (id=${id})`);
const pingreq = () => mqtt(12, 0, [], [], "Ping Request");
const pingresp = () => mqtt(13, 0, [], [], "Ping Response");

// ---------------------------------------------------------------- TCP conversation helper

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
    /** pretend the handshake already happened (connection opened earlier) */
    established() { next.a = 1; next.b = 1; return this; },
    syn: (t: number, extra: Partial<PacketEvent> = {}): PacketEvent => {
      const p = pkt(a.id, b.id, "slate", "SYN", [`to port ${b.port}`], { time: r(t), info: `${a.port} → ${b.port} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: build(...a.layers(), tcp({ sport: a.port, dport: b.port, seq: 0, flags: "S", opts: [{ mss: 1460 }], seqBase: a.base })), ...extra });
      return p;
    },
    handshake: (t: number, rtt: number): PacketEvent[] => [
      pkt(a.id, b.id, "green", "SYN", [`to port ${b.port}`], {
        time: r(t), info: `${a.port} → ${b.port} [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
        packet: send(true, "S", [], [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }]),
      }),
      pkt(b.id, a.id, "green", "SYN-ACK", ["port open"], {
        time: r(t + rtt), info: `${b.port} → ${a.port} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128`,
        packet: send(false, "SA", [], [{ mss: 1460 }, "sackOk", "nop", { ws: 7 }]),
      }),
      pkt(a.id, b.id, "green", "ACK", ["connected"], {
        time: r(t + rtt + 0.0005), info: `${a.port} → ${b.port} [ACK] Seq=1 Ack=1 Win=502 Len=0`,
        packet: send(true, "A", []),
      }),
    ],
  };
}

const sensorUp = () => [eth({ src: SENSOR_MAC, dst: ADDR.routerMac }), ipv4({ src: SENSOR, dst: BROKER, ttl: 64 })];
const sensorDown = () => [eth({ src: ADDR.routerMac, dst: SENSOR_MAC }), ipv4({ src: BROKER, dst: SENSOR, ttl: 54 })];

const sensorConv = (port: number, bases: [number, number]) =>
  conversation({ id: "sensor", layers: sensorUp, port, base: bases[0], win: 5744 }, { id: "broker", layers: sensorDown, port: 1883, base: bases[1], win: 509 });
const dashConv = (port: number, bases: [number, number]) =>
  conversation({ id: "client", layers: () => up(BROKER), port, base: bases[0], win: 502 }, { id: "broker", layers: () => down(BROKER), port: 1883, base: bases[1], win: 509 });

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "sensor", kind: "iot", label: "Temp sensor", sub: SENSOR, x: 9, y: 30 },
  { id: "client", kind: "laptop", label: "Dashboard", sub: ADDR.laptop, x: 9, y: 76 },
  { id: "router", kind: "router", label: "Home router", sub: ADDR.router, x: 30, y: 54 },
  { id: "internet", kind: "cloud", label: "Internet", x: 56, y: 34 },
  { id: "broker", kind: "broker", label: "MQTT broker", sub: `${BROKER_HOST} ${BROKER}`, x: 86, y: 56 },
];
const links: [string, string][] = [["sensor", "router"], ["client", "router"], ["router", "internet"], ["internet", "broker"]];

// ---------------------------------------------------------------- scenario 1

const SEN = sensorConv(49152, [0x00e5f001, 0x7a3b0000]);
const DASH = dashConv(53012, [0x4ad10000, 0x19c20000]);
const WILL = { topic: "home/livingroom/status", msg: "offline", qos: 1, retain: true };
const FILTERS: [string, number][] = [["home/+/temp", 1], ["home/+/status", 1]];

const normalSteps = [
  {
    title: "Sensor sends CONNECT",
    desc: "Client ID, keep alive, login and a last will",
    detail: "A small temperature sensor connects to the broker on port 1883. Its CONNECT says: protocol MQTT level 4 (3.1.1), keep alive 60 s, client ID livingroom-sensor, a username and password, and a last will: if I disappear, publish \"offline\" to home/livingroom/status. The broker answers CONNACK with return code 0.",
    facts: [["Connect flags", "0xEE: user, pass, will retain, will QoS 1, will, clean"], ["Keep alive", "60 s"], ["CONNACK", "0 = accepted"]] as [string, string][],
    quiz: {
      q: "The first byte of CONNECT is 0x10. What do its two halves mean?",
      options: ["Version 1, length 0", "Packet type 1 (CONNECT), flags 0", "QoS 1, no retain", "16 bytes follow"],
      answer: 1,
      why: "The high 4 bits are the packet type (1 = CONNECT). The low 4 bits are flags, which CONNECT doesn't use.",
    },
    events: [
      ...SEN.handshake(0, 0.03),
      SEN.a("amber", "CONNECT", ["livingroom-sensor", "will: offline"], 0.031, "Connect Command", [connect({ clientId: "livingroom-sensor", clean: true, keepAlive: 60, user: "sensor1", pass: "s3cret-iot", will: WILL })]),
      SEN.b("green", "CONNACK", ["accepted"], 0.062, "Connect Ack", [connack(false)]),
    ],
  },
  {
    title: "Dashboard subscribes",
    desc: "SUBSCRIBE home/+/temp and home/+/status",
    detail: "Danish's dashboard connects too, then subscribes with topic filters. The + wildcard matches exactly one level, so home/+/temp catches the temperature of every room. Both are asked at QoS 1. SUBACK grants QoS 1 for each filter, in the same order.",
    facts: [["Filters", "home/+/temp, home/+/status"], ["+", "One level; # = all remaining levels"], ["Granted", "QoS 1, QoS 1"]] as [string, string][],
    quiz: {
      q: "Which topic does home/+/temp NOT match?",
      options: ["home/kitchen/temp", "home/livingroom/temp", "home/floor1/kitchen/temp", "home/garage/temp"],
      answer: 2,
      why: "+ stands for exactly one level. home/floor1/kitchen/temp has two levels in between; home/# would match it.",
    },
    events: [
      ...DASH.handshake(0.2, 0.03),
      DASH.a("amber", "CONNECT", ["dashboard-danish"], 0.231, "Connect Command", [connect({ clientId: "dashboard-danish", clean: true, keepAlive: 60, user: "danish", pass: "dash-pass-7" })]),
      DASH.b("green", "CONNACK", ["accepted"], 0.262, "Connect Ack", [connack(false)]),
      DASH.a("amber", "SUBSCRIBE", ["home/+/temp", "home/+/status"], 0.263, "Subscribe Request (id=1)", [subscribe(1, FILTERS)]),
      DASH.b("green", "SUBACK", ["QoS 1, QoS 1"], 0.294, "Subscribe Ack (id=1)", [suback(1, [1, 1])]),
    ],
  },
  {
    title: "Retained message",
    desc: "The last known value arrives at once",
    detail: "The kitchen sensor published 21.5 earlier with the RETAIN flag, so the broker kept it as the topic's last known value. A new subscriber gets it immediately instead of waiting for the next reading. The RETAIN bit is set in this PUBLISH so the dashboard knows it's a stored value, not a fresh one.",
    facts: [["Topic", "home/kitchen/temp"], ["Value", "21.5"], ["First byte", "0x33: PUBLISH, QoS 1, RETAIN"]] as [string, string][],
    events: [
      DASH.b("violet", "PUBLISH", ["kitchen 21.5", "RETAIN"], 0.295, "Publish Message (id=1) [home/kitchen/temp]", [publish({ topic: "home/kitchen/temp", msg: "21.5", qos: 1, retain: true, id: 1 })]),
      DASH.a("green", "PUBACK", ["id 1"], 0.326, "Publish Ack (id=1)", [puback(1)]),
    ],
  },
  {
    title: "PUBLISH with QoS 1",
    desc: "Sensor → broker → dashboard, each hop acknowledged",
    detail: "The living-room sensor publishes 23.4 at QoS 1 with packet ID 1. QoS 1 means \"at least once\": the broker stores it and answers PUBACK. Then the broker forwards it to every matching subscriber, here the dashboard, with its own packet ID, and waits for the dashboard's PUBACK. Each hop is acknowledged separately.",
    facts: [["QoS 0", "At most once, no ack"], ["QoS 1", "At least once: PUBLISH → PUBACK"], ["QoS 2", "Exactly once: 4-packet exchange"]] as [string, string][],
    quiz: {
      q: "The sensor's PUBLISH reached the broker, but the PUBACK was lost. What does the sensor do?",
      options: ["Nothing, it's delivered", "Resends the PUBLISH with the DUP flag", "Sends DISCONNECT", "Switches to QoS 0"],
      answer: 1,
      why: "Without a PUBACK the sender can't know, so it resends with DUP=1. That's why QoS 1 can deliver duplicates.",
    },
    events: [
      SEN.a("amber", "PUBLISH", ["livingroom 23.4", "QoS 1, id 1"], 5.0, "Publish Message (id=1) [home/livingroom/temp]", [publish({ topic: "home/livingroom/temp", msg: "23.4", qos: 1, id: 1 })]),
      SEN.b("green", "PUBACK", ["id 1"], 5.031, "Publish Ack (id=1)", [puback(1)]),
      DASH.b("violet", "PUBLISH", ["livingroom 23.4", "QoS 1, id 2"], 5.032, "Publish Message (id=2) [home/livingroom/temp]", [publish({ topic: "home/livingroom/temp", msg: "23.4", qos: 1, id: 2 })], { parallel: true }),
      DASH.a("green", "PUBACK", ["id 2"], 5.063, "Publish Ack (id=2)", [puback(2)]),
    ],
  },
  {
    title: "PINGREQ / PINGRESP",
    desc: "Keeping a quiet connection alive",
    detail: "The sensor only reports when the temperature changes. After 60 seconds with nothing to send, it sends PINGREQ, just 2 bytes (0xC0 0x00), and the broker replies PINGRESP (0xD0 0x00). This proves both ends and the path between them are still alive, and keeps the home router's NAT entry from expiring.",
    facts: [["PINGREQ", "0xC0 0x00"], ["PINGRESP", "0xD0 0x00"], ["Broker timeout", "1.5 × keep alive = 90 s"]] as [string, string][],
    events: [
      SEN.a("slate", "PINGREQ", ["still here"], 65.0, "Ping Request", [pingreq()]),
      SEN.b("slate", "PINGRESP", [], 65.031, "Ping Response", [pingresp()]),
    ],
  },
  {
    title: "Last will",
    desc: "The sensor vanishes; the broker speaks for it",
    detail: "The sensor's battery dies. It never sends DISCONNECT, so the broker waits. After 90 s (1.5 × keep alive) with no packet, it gives up on the connection and publishes the sensor's will, \"offline\" on home/livingroom/status, retained. The dashboard shows the sensor as offline. A clean DISCONNECT would have discarded the will.",
    facts: [["Trigger", "No packet for 90 s"], ["Will", "home/livingroom/status = offline"], ["Not sent if", "Client sends DISCONNECT"]] as [string, string][],
    quiz: {
      q: "When does the broker publish a client's last will?",
      options: ["On every DISCONNECT", "When the connection is lost without a DISCONNECT", "Every keep-alive period", "When the client subscribes"],
      answer: 1,
      why: "The will is for unexpected loss: timeouts, broken connections. A polite DISCONNECT cancels it.",
    },
    events: [
      note("sensor", "BATTERY DEAD", "red"),
      note("broker", "NO PACKET FOR 90 s", "amber"),
      DASH.b("violet", "PUBLISH", ["livingroom/status", "offline (will)"], 155.04, "Publish Message (id=3) [home/livingroom/status]", [publish({ topic: WILL.topic, msg: WILL.msg, qos: 1, id: 3 })]),
      DASH.a("green", "PUBACK", ["id 3"], 155.071, "Publish Ack (id=3)", [puback(3)]),
      note("client", "LIVING ROOM SENSOR OFFLINE", "red"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 2: broker unreachable, persistent session

const P = dashConv(53020, [0x2d000000, 0x6c000000]).established();
const S2 = sensorConv(49160, [0x01020304, 0x05060708]).established();
const P2 = dashConv(53021, [0x2e000000, 0x6d000000]);

const reconnectSteps = [
  {
    title: "Pings go unanswered",
    desc: "The path to the broker breaks",
    detail: "The dashboard (client ID dashboard-danish) uses a persistent session: it connected with Clean Session = 0 and subscribed at QoS 1. Then Danish's internet connection drops. Its PINGREQ gets no PINGRESP, so after a timeout the client treats the connection as dead.",
    facts: [["Session", "Clean Session = 0 (persistent)"], ["Symptom", "No PINGRESP"], ["Client action", "Drop the connection, reconnect"]] as [string, string][],
    events: [
      P.a("slate", "PINGREQ", ["no answer"], 0, "Ping Request", [pingreq()], { lost: true }),
      note("router", "INTERNET DOWN", "red"),
    ],
  },
  {
    title: "Broker queues messages",
    desc: "The session lives on at the broker",
    detail: "Meanwhile the sensor keeps publishing. Because the dashboard's session is persistent and its subscription is QoS 1, the broker stores each matching message for it instead of throwing it away.",
    facts: [["Queued for", "dashboard-danish"], ["Why", "Persistent session + QoS 1 subscription"], ["QoS 0 messages", "Usually not queued"]] as [string, string][],
    events: [
      S2.a("amber", "PUBLISH", ["23.9, id 7"], 20, "Publish Message (id=7) [home/livingroom/temp]", [publish({ topic: "home/livingroom/temp", msg: "23.9", qos: 1, id: 7 })]),
      S2.b("green", "PUBACK", ["id 7"], 20.031, "Publish Ack (id=7)", [puback(7)]),
      S2.a("amber", "PUBLISH", ["24.3, id 8"], 50, "Publish Message (id=8) [home/livingroom/temp]", [publish({ topic: "home/livingroom/temp", msg: "24.3", qos: 1, id: 8 })]),
      S2.b("green", "PUBACK", ["id 8"], 50.031, "Publish Ack (id=8)", [puback(8)]),
      note("broker", "2 MESSAGES QUEUED", "amber"),
    ],
  },
  {
    title: "Retry with backoff",
    desc: "SYNs fail while the line is down",
    detail: "The client library retries the connection, waiting longer each time (2 s, 4 s, 8 s…) so thousands of devices don't hammer a broker that's coming back. These SYNs go nowhere until the internet returns.",
    facts: [["Retry gaps", "2 s, 4 s, 8 s… (capped)"], ["Why backoff", "Avoid a reconnect storm"], ["Plus", "Random jitter"]] as [string, string][],
    events: [
      P2.syn(62, { lost: true }),
      P2.syn(66, { lost: true }),
    ],
  },
  {
    title: "Session present",
    desc: "CONNECT with Clean Session 0",
    detail: "The line is back. The client reconnects with the same client ID and Clean Session = 0. CONNACK comes back with Session Present = 1: the broker still has the subscriptions and the queued messages, so the client doesn't even need to subscribe again.",
    facts: [["CONNECT flags", "Clean Session = 0"], ["CONNACK", "Session Present = 1, code 0"], ["Re-subscribe?", "Not needed"]] as [string, string][],
    quiz: {
      q: "If the client had reconnected with Clean Session = 1, what would happen to the 2 queued messages?",
      options: ["Delivered anyway", "Thrown away along with the old session", "Sent twice", "Kept until the next reconnect"],
      answer: 1,
      why: "Clean Session = 1 tells the broker to discard any old session state, including queued messages and subscriptions.",
    },
    events: [
      ...P2.handshake(74, 0.03),
      P2.a("amber", "CONNECT", ["same client ID", "clean = 0"], 74.031, "Connect Command", [connect({ clientId: "dashboard-danish", clean: false, keepAlive: 60, user: "danish", pass: "dash-pass-7" })]),
      P2.b("green", "CONNACK", ["session present"], 74.062, "Connect Ack (session present)", [connack(true)]),
    ],
  },
  {
    title: "Queued messages delivered",
    desc: "Both readings arrive, then PUBACKs",
    detail: "The broker immediately sends the two stored PUBLISH packets in order, and the client acknowledges each. Danish's graph fills the gap without losing a reading.",
    facts: [["Delivered", "23.9, then 24.3"], ["Order", "Kept"], ["Each", "PUBACK by packet ID"]] as [string, string][],
    events: [
      P2.b("violet", "PUBLISH", ["23.9, id 4"], 74.063, "Publish Message (id=4) [home/livingroom/temp]", [publish({ topic: "home/livingroom/temp", msg: "23.9", qos: 1, id: 4 })]),
      P2.b("violet", "PUBLISH", ["24.3, id 5"], 74.063, "Publish Message (id=5) [home/livingroom/temp]", [publish({ topic: "home/livingroom/temp", msg: "24.3", qos: 1, id: 5 })], { parallel: true }),
      P2.a("green", "PUBACK", ["id 4"], 74.094, "Publish Ack (id=4)", [puback(4)]),
      P2.a("green", "PUBACK", ["id 5"], 74.094, "Publish Ack (id=5)", [puback(5)], { parallel: true }),
      note("client", "NO READINGS LOST", "green"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 3: anonymous open broker

const attackDevices: Device[] = [
  ...devices,
  { id: "attacker", kind: "attacker", label: "Internet scanner", sub: EVIL, x: 60, y: 82 },
];
const attackLinks: [string, string][] = [...links, ["attacker", "internet"]];
const evilConv = (port: number, bases: [number, number]) =>
  conversation(
    { id: "attacker", layers: () => [eth({ src: GW_MAC, dst: BROKER_MAC }), ipv4({ src: EVIL, dst: BROKER, ttl: 50 })], port, base: bases[0], win: 502 },
    { id: "broker", layers: () => [eth({ src: BROKER_MAC, dst: GW_MAC }), ipv4({ src: BROKER, dst: EVIL, ttl: 64 })], port: 1883, base: bases[1], win: 509 }
  );
const EV = evilConv(40001, [0x0bad0000, 0x0cab0000]);
const EV2 = evilConv(40002, [0x0bae0000, 0x0cac0000]);

const attackSteps = [
  {
    title: "Anonymous CONNECT accepted",
    desc: "No username, no password, code 0",
    detail: "Search engines for internet devices list tens of thousands of brokers on port 1883. A scanner connects to this one with no username or password. The broker was installed with its default settings, which allow anonymous clients, so it answers CONNACK 0: accepted.",
    facts: [["Username", "None"], ["CONNACK", "0 (accepted)"], ["Cause", "allow_anonymous true"]] as [string, string][],
    events: [
      ...EV.handshake(0, 0.04),
      EV.a("red", "CONNECT", ["no login"], 0.041, "Connect Command", [connect({ clientId: "scan-7781", clean: true, keepAlive: 60 })]),
      EV.b("red", "CONNACK", ["accepted!"], 0.082, "Connect Ack", [connack(false)]),
    ],
  },
  {
    title: "SUBSCRIBE #",
    desc: "Everything, including retained secrets",
    detail: "The scanner subscribes to #, every topic. Retained messages flood in at once: room temperatures, but also home/frontdoor/lock = unlocked, which tells a burglar something useful. If the broker allowed it, the scanner could also publish commands to devices.",
    facts: [["Filter", "#"], ["Leaked", "Sensor data, lock state"], ["Worse", "Could publish commands too"]] as [string, string][],
    quiz: {
      q: "Which setting would have stopped this attacker at CONNECT?",
      options: ["Higher QoS", "Requiring a username and password (and ACLs per topic)", "A longer keep alive", "Retained messages off"],
      answer: 1,
      why: "Turn off anonymous access, require credentials over TLS, and use ACLs so each client sees only its own topics.",
    },
    events: [
      EV.a("red", "SUBSCRIBE", ["#"], 0.083, "Subscribe Request (id=1) #", [subscribe(1, [["#", 0]])]),
      EV.b("red", "SUBACK", ["QoS 0"], 0.124, "Subscribe Ack (id=1)", [suback(1, [0])]),
      EV.b("red", "PUBLISH", ["frontdoor/lock", "unlocked"], 0.125, "Publish Message [home/frontdoor/lock]", [publish({ topic: "home/frontdoor/lock", msg: "unlocked", qos: 0, retain: true })], { parallel: true }),
      note("attacker", "READING THE WHOLE HOUSE", "red"),
    ],
  },
  {
    title: "Defence: require login",
    desc: "CONNACK 5: not authorized",
    detail: "Danish fixes the broker: anonymous access off, a password for every client, per-topic ACLs, and TLS on port 8883 so passwords aren't sent in clear. The same anonymous CONNECT now gets CONNACK return code 5, Not authorized, and the broker closes the connection.",
    facts: [["CONNACK", "5 (Not authorized)"], ["Port", "8883 with TLS"], ["ACLs", "Each client only its own topics"]] as [string, string][],
    events: [
      ...EV2.handshake(10, 0.04),
      EV2.a("red", "CONNECT", ["no login"], 10.041, "Connect Command", [connect({ clientId: "scan-7781", clean: true, keepAlive: 60 })]),
      EV2.b("green", "CONNACK", ["5: not authorized"], 10.082, "Connect Ack (Not authorized)", [connack(false, 5)]),
      note("broker", "ANONYMOUS REJECTED", "green"),
    ],
  },
];

export default defineLesson({
  id: "mqtt",
  name: "MQTT",
  full: "MQTT (Message Queuing Telemetry Transport)",
  group: "iot",
  layer: 7,
  difficulty: 2,
  tagline: "Tiny publish/subscribe messages for millions of sensors.",
  description:
    "MQTT connects devices through a central broker. Sensors publish messages to topics like home/kitchen/temp, and anything subscribed to a matching topic gets a copy. Headers can be as small as 2 bytes, and features like QoS, retained messages and last wills make it fit flaky networks.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP 1883, 8883 (TLS)"],
    ["Defined in", "OASIS MQTT 3.1.1 (2014), 5.0 (2019)"],
    ["Pattern", "Publish/subscribe via a broker"],
    ["Smallest packet", "2 bytes (PINGREQ)"],
    ["Delivery", "QoS 0, 1, 2"],
  ],
  ports: "1883 MQTT, 8883 MQTT over TLS",
  rfc: "OASIS MQTT 3.1.1 / 5.0",
  keywords: ["iot", "publish", "subscribe", "broker", "topic", "wildcard", "qos", "retained", "last will", "keep alive", "mosquitto", "1883", "8883"],
  related: ["coap", "tcp", "tls", "websocket", "modbus"],
  devices,
  links,
  legend: [
    ["green", "Handshake and acknowledgements"],
    ["amber", "Packets from clients"],
    ["violet", "Messages from the broker"],
    ["slate", "Keep-alive and retries"],
    ["red", "Failures and attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Sensor, broker and dashboard",
      summary: "CONNECT with a will, SUBSCRIBE with wildcards, a retained value, QoS 1 publishing, pings, and the will firing.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "Publish, subscribe, survive",
        text: "The sensor and dashboard never talked to each other directly. The broker matched topics, kept the last value for newcomers, acknowledged every QoS 1 hop, and spoke the sensor's last will when it disappeared.",
        facts: [["Packet types used", "CONNECT, CONNACK, SUBSCRIBE, SUBACK, PUBLISH, PUBACK, PINGREQ, PINGRESP"], ["Smallest", "2 bytes"], ["Will fired after", "90 s silence"]],
      },
    },
    {
      id: "reconnect",
      name: "Broker unreachable: persistent session",
      summary: "The dashboard loses its connection, reconnects with Clean Session 0 and receives the messages queued for it.",
      kind: "failure",
      steps: reconnectSteps,
      outro: {
        title: "Nothing lost",
        text: "Because the session was persistent and the subscription used QoS 1, the broker held messages while the client was away. On reconnect, Session Present = 1 told the client its subscriptions were still in place.",
        facts: [["CONNECT", "Clean Session = 0"], ["CONNACK", "Session Present = 1"], ["Queued", "2 QoS 1 messages"], ["MQTT 5 name", "Clean Start + Session Expiry"]],
      },
    },
    {
      id: "open-broker",
      name: "Anonymous open broker",
      summary: "A scanner reads every topic of a broker left on defaults; requiring login stops it.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: attackSteps,
      outro: {
        title: "Lock the broker",
        text: "An MQTT broker with anonymous access hands every message, and often control, to anyone on the internet. Require credentials over TLS, apply per-topic ACLs, and don't expose the broker publicly if you don't have to.",
        facts: [["Attack", "Anonymous CONNECT + SUBSCRIBE #"], ["Defence", "Auth, TLS 8883, ACLs, firewall"], ["Rejected with", "CONNACK 5"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Packet types (first byte)",
      items: [["0x10", "CONNECT"], ["0x20", "CONNACK"], ["0x3X", "PUBLISH (X = DUP, QoS, RETAIN)"], ["0x40", "PUBACK"], ["0x82", "SUBSCRIBE"], ["0x90", "SUBACK"], ["0xC0 / 0xD0", "PINGREQ / PINGRESP"], ["0xE0", "DISCONNECT"]],
    },
    {
      title: "Ideas",
      items: [["+", "One topic level"], ["#", "All remaining levels"], ["Retained", "Broker keeps the last message per topic"], ["Last will", "Published if the client vanishes"], ["Clean session 0", "Broker keeps subscriptions + queue"], ["Remaining length", "1–4 bytes, 7 bits each"]],
    },
    {
      title: "MQTT 5 adds",
      items: [["Reason codes", "On every ack"], ["Properties", "Message expiry, content type, user properties"], ["Session expiry", "Replaces clean session"], ["Shared subscriptions", "$share/group/topic"]],
    },
  ],
});
