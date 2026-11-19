import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, FieldSpec, proto } from "@/lib/packet";
import { ip4, text, u32 } from "@/lib/bytes";
import { udp } from "@/lib/proto";
import { ADDR, down, homeToServer, up } from "./_common";

// ------------------------------------------------------------------ time helpers
// Times in this file are "seconds after 2026-11-19 10:00:00 UTC". NTP counts
// whole seconds since 1 January 1900 (32 bits) plus a 32-bit fraction of a second.

const NTP_EPOCH_OFFSET = 2208988800; // seconds from 1900-01-01 to 1970-01-01
const BASE_UNIX = Date.UTC(2026, 10, 19, 10, 0, 0) / 1000;
const TWO32 = 4294967296;

function split(t: number): [number, number] {
  let s = Math.floor(t);
  let f = Math.round((t - s) * TWO32);
  if (f >= TWO32) { f -= TWO32; s += 1; }
  return [BASE_UNIX + NTP_EPOCH_OFFSET + s, f];
}

function clock(t: number): string {
  const [s, f] = split(t);
  const d = new Date((s - NTP_EPOCH_OFFSET) * 1000);
  const us = Math.min(999999, Math.round((f / TWO32) * 1e6));
  return `${d.toISOString().slice(11, 19)}.${String(us).padStart(6, "0")}`;
}

const ms = (x: number, d = 3) => `${x >= 0 ? "+" : "−"}${Math.abs(x * 1000).toFixed(d)} ms`;
const msAbs = (x: number, d = 3) => `${(x * 1000).toFixed(d)} ms`;
const t3 = (n: number) => Number(n.toFixed(6));

function tsField(name: string, t: number | null, note: string): FieldSpec {
  if (t === null) return { name, zero: 8, value: "0 (not set)", note };
  const [s, f] = split(t);
  return {
    name,
    bytes: [...u32(s), ...u32(f)],
    value: `${clock(t)} UTC`,
    note: `${note} Stored as ${s} whole seconds since 1 Jan 1900 and a fraction of ${f} / 2³².`,
  };
}

const MODE_NAME: Record<number, string> = { 3: "client", 4: "server" };

function ntp(o: {
  li: number; mode: 3 | 4; stratum: number; poll: number; precision: number; rootDelay: number; rootDisp: number;
  refId: FieldSpec; ref: number | null; org: number | null; rec: number | null; xmt: number;
}) {
  const b0 = (o.li << 6) | (4 << 3) | o.mode;
  return proto({
    id: "ntp",
    name: "NTP",
    osi: 7,
    summary: `Network Time Protocol (NTP Version 4, ${MODE_NAME[o.mode]})`,
    fields: [
      {
        name: "Flags (LI, VN, Mode)",
        u8: b0,
        value: `0x${b0.toString(16)}: LI ${o.li}, version 4, mode ${o.mode} (${MODE_NAME[o.mode]})`,
        note: o.li === 3
          ? "Leap indicator 3 means “my own clock is not synchronised yet”. Version 4. Mode 3 is a client request."
          : `Leap indicator 0: no leap second coming. Version 4. Mode ${o.mode} is a ${MODE_NAME[o.mode]} packet.`,
      },
      { name: "Stratum", u8: o.stratum, value: o.stratum === 0 ? "0 (unspecified)" : o.stratum === 1 ? "1 (primary: has its own reference clock)" : `${o.stratum} (synced to a stratum ${o.stratum - 1} server)`, note: "How many steps this clock is from a reference clock such as GPS or an atomic clock." },
      { name: "Poll interval", u8: o.poll, value: `${o.poll} (2^${o.poll} = ${2 ** o.poll} s)`, note: "How often this side plans to ask, as a power of two seconds." },
      { name: "Precision", u8: o.precision & 0xff, value: `${o.precision} (about ${(2 ** o.precision * 1e6).toFixed(2)} µs)`, note: "A signed power of two: how finely this machine can read its own clock." },
      { name: "Root delay", u32: Math.round(o.rootDelay * 65536), value: `${(o.rootDelay * 1000).toFixed(3)} ms`, note: "Total round-trip time back to the reference clock, as 16.16 fixed-point seconds." },
      { name: "Root dispersion", u32: Math.round(o.rootDisp * 65536), value: `${(o.rootDisp * 1000).toFixed(3)} ms`, note: "How much error may have built up back to the reference clock (16.16 fixed point)." },
      o.refId,
      tsField("Reference timestamp", o.ref, "When this clock was last set or corrected."),
      tsField("Origin timestamp", o.org, o.mode === 4 ? "T1 copied from the request, so the client can match the reply and spot forgeries." : "Zero in a first request."),
      tsField("Receive timestamp", o.rec, o.mode === 4 ? "T2: when the request arrived at the server." : "Zero in a request."),
      tsField("Transmit timestamp", o.xmt, o.mode === 4 ? "T3: when the server sent this reply." : "T1: when the client sent this request, read from its own clock."),
    ],
  });
}

const zeroRef: FieldSpec = { name: "Reference ID", zero: 4, value: "(none)", note: "Empty: this client has no time source yet." };
const gpsRef: FieldSpec = { name: "Reference ID", bytes: [...text("GPS"), 0], value: "GPS", note: "For stratum 1, four ASCII letters naming the reference clock." };
const ipRef = (ip: string): FieldSpec => ({ name: "Reference ID", bytes: ip4(ip), value: ip, note: "For stratum 2 and up, the IPv4 address of the server it syncs to." });

interface Ex { t1: number; t2: number; t3: number; t4: number; offset: number; delay: number; rtt: number }

/** One request/reply. sendAt is true time; clientErr/serverErr are how far each clock is ahead of true time. */
function exchange(sendAt: number, clientErr: number, serverErr: number, upD: number, proc: number, downD: number): Ex {
  const t1 = sendAt + clientErr;
  const t2 = sendAt + upD + serverErr;
  const t3_ = t2 + proc;
  const t4 = sendAt + upD + proc + downD + clientErr;
  return { t1, t2, t3: t3_, t4, offset: (t2 - t1 + (t3_ - t4)) / 2, delay: t4 - t1 - (t3_ - t2), rtt: upD + proc + downD };
}

const PORT = 123;

function request(server: string, ex: Ex, o: { li: number; stratum: number; refId: FieldSpec; ref: number | null; rootDelay?: number; rootDisp?: number }) {
  return build(...up(server, { id: 0x4d21 }), udp({ sport: PORT, dport: PORT }), ntp({
    li: o.li, mode: 3, stratum: o.stratum, poll: 6, precision: -23, rootDelay: o.rootDelay ?? 0, rootDisp: o.rootDisp ?? 0,
    refId: o.refId, ref: o.ref, org: null, rec: null, xmt: ex.t1,
  }));
}

function reply(server: string, ex: Ex, o: { refAgo?: number; ttl?: number; refId?: FieldSpec; stratum?: number; serverErr?: number } = {}) {
  return build(...down(server, { ttl: o.ttl ?? 55, id: 0x0000 }), udp({ sport: PORT, dport: PORT }), ntp({
    li: 0, mode: 4, stratum: o.stratum ?? 1, poll: 6, precision: -20, rootDelay: 0, rootDisp: 0.000351,
    refId: o.refId ?? gpsRef, ref: ex.t2 - (o.refAgo ?? 14.6), org: ex.t1, rec: ex.t2, xmt: ex.t3,
  }));
}

// ------------------------------------------------------------------ normal scenario numbers
const SRV = "203.0.113.123";
const E1 = -0.137452; // laptop clock is 137.452 ms behind
const ex1 = exchange(0, E1, 0, 0.01713, 0.000041, 0.01687);
const E2 = E1 + ex1.offset; // after stepping the clock
const ex2 = exchange(64, E2, 0, 0.01702, 0.000038, 0.01698);

// far server, very uneven path
const FAR = "198.51.100.123";
const exFar = exchange(0, 0, 0, 0.12, 0.00004, 0.04);

// four servers, one broken
const POOL = [
  { id: "s1", ip: "203.0.113.123", label: "Server A", err: 0, up: 0.012, down: 0.0118, proc: 0.00003 },
  { id: "s2", ip: "198.51.100.123", label: "Server B", err: 0.0006, up: 0.021, down: 0.0205, proc: 0.00004 },
  { id: "s3", ip: "192.0.2.123", label: "Server C", err: -0.0004, up: 0.034, down: 0.0338, proc: 0.00005 },
  { id: "s4", ip: "203.0.113.200", label: "Server D", err: 37.2, up: 0.018, down: 0.0183, proc: 0.00004 },
];
const CERR = 0.0021; // laptop is 2.1 ms ahead
const poolEx = POOL.map((s, i) => ({ s, i, ex: exchange(i * 0.0001, CERR, s.err, s.up, s.proc, s.down) }));
const poolReplies = [...poolEx].sort((a, b) => a.i * 0.0001 + a.ex.rtt - (b.i * 0.0001 + b.ex.rtt));
const good = poolEx.filter((p) => p.s.id !== "s4");
const combined = good.reduce((n, p) => n + p.ex.offset / p.ex.delay, 0) / good.reduce((n, p) => n + 1 / p.ex.delay, 0);

const base = homeToServer({ kind: "server", label: "NTP server", sub: SRV });

const poolDevices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: ADDR.laptop, x: 9, y: 50 },
  { id: "router", kind: "router", label: "Home router", sub: ADDR.router, x: 30, y: 50 },
  { id: "internet", kind: "cloud", label: "Internet", x: 55, y: 50 },
  ...POOL.map((s, i) => ({ id: s.id, kind: "server" as const, label: s.label, sub: s.ip, x: 86, y: 15 + i * (70 / 3) })),
];
const poolLinks: [string, string][] = [["client", "router"], ["router", "internet"], ...POOL.map((s) => ["internet", s.id] as [string, string])];

const exchangeFacts = (ex: Ex): [string, string][] => [
  ["Offset θ", `((T2−T1) + (T3−T4)) / 2 = ${ms(ex.offset)}`],
  ["Delay δ", `(T4−T1) − (T3−T2) = ${msAbs(ex.delay)}`],
  ["Error bound", `at most δ/2 = ${msAbs(ex.delay / 2)}`],
];

export default defineLesson({
  id: "ntp",
  name: "NTP",
  full: "Network Time Protocol",
  group: "naming",
  layer: 7,
  difficulty: 2,
  tagline: "Four timestamps keep every clock on the internet in step.",
  description:
    "NTP sets your computer’s clock from a time server across the network. One small UDP exchange carries four timestamps, and from them the client works out both how wrong its clock is and how long the trip took. Talking to several servers lets it ignore one that tells the wrong time.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "UDP port 123"],
    ["Packet", "48 bytes (no extensions)"],
    ["Timestamps", "64 bits: seconds since 1900 + fraction"],
    ["Accuracy", "About 1–10 ms over the internet"],
    ["Defined in", "RFC 5905 (NTPv4)"],
  ],
  ports: "UDP 123",
  rfc: "RFC 5905",
  keywords: ["time", "clock", "sync", "stratum", "offset", "delay", "timestamp", "chrony", "ntpd", "falseticker", "pool"],
  related: ["udp", "dns", "dnssec"],
  ...base,
  legend: [
    ["blue", "Time requests from the laptop"],
    ["violet", "Time replies from servers"],
    ["green", "Clock corrected"],
    ["red", "Wrong time"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Setting a clock that runs slow",
      summary: "The laptop’s clock is 137 ms behind. One NTP exchange measures that, and the clock is fixed.",
      kind: "normal",
      steps: [
        {
          title: "Ask for the time",
          desc: "A 48-byte client request, mode 3",
          detail: `The laptop sends a 48-byte NTP packet to UDP port 123. It writes only one timestamp: T1, the moment it sent the request according to its own clock (${clock(ex1.t1)}). Leap indicator 3 says its clock is not synchronised yet.`,
          facts: [["T1 (laptop clock)", clock(ex1.t1)], ["Mode", "3 (client)"], ["Size", "48 bytes of NTP in 8 bytes of UDP"]],
          quiz: {
            q: "Which of the four timestamp fields does the laptop fill in on its request?",
            options: ["All four", "Only the transmit timestamp (T1)", "Only the reference timestamp", "None: the server fills them all"],
            answer: 1,
            why: "The client knows only when it sent the packet. The others stay zero until the server answers.",
          },
          events: [
            pkt("client", "server", "blue", "NTP REQ", ["mode 3", `T1 ${clock(ex1.t1).slice(3)}`], {
              time: 0, info: "NTP Version 4, client",
              packet: request(SRV, ex1, { li: 3, stratum: 0, refId: zeroRef, ref: null }),
            }),
          ],
        },
        {
          title: "Server stamps the reply",
          desc: "Receive time T2, transmit time T3",
          detail: `The stratum 1 server reads its GPS-disciplined clock twice: T2 when the request arrives and T3 just before the reply leaves, ${Math.round((ex1.t3 - ex1.t2) * 1e6)} µs later. It copies the laptop’s T1 into the origin field. When the reply lands, the laptop notes T4 on its own clock.`,
          facts: [["T2 / T3 (server)", `${clock(ex1.t2)} / ${clock(ex1.t3)}`], ["T4 (laptop clock)", clock(ex1.t4)], ["Stratum", "1, reference GPS"]],
          quiz: {
            q: "The laptop gets a reply whose origin timestamp is not the T1 it sent. What should it do?",
            options: ["Use it anyway", "Drop it: it doesn’t answer my request", "Add it to the offset", "Ask the server to resend T1"],
            answer: 1,
            why: "The origin field must echo the client’s transmit time. A mismatch means a stale, duplicated or forged reply.",
          },
          events: [
            pkt("server", "client", "violet", "NTP REPLY", ["mode 4, stratum 1", "T1 T2 T3"], {
              time: t3(ex1.rtt), info: "NTP Version 4, server",
              packet: reply(SRV, ex1),
            }),
          ],
        },
        {
          title: "Work out offset and delay",
          desc: "Two formulas, four timestamps",
          detail: `Delay is the total trip time minus the server’s holding time: (T4−T1) − (T3−T2) = ${msAbs(ex1.delay)}. Offset assumes the trip each way took the same time: ((T2−T1) + (T3−T4)) / 2 = ${ms(ex1.offset)}. So the laptop is about ${msAbs(ex1.offset, 1)} behind. The true error was ${msAbs(-E1)}; the tiny difference comes from the path being ${msAbs(0.01713 - 0.01687)} slower one way.`,
          facts: exchangeFacts(ex1),
          quiz: {
            q: "T2−T1 is +154.6 ms and T3−T4 is +120.6 ms. What is the offset?",
            options: ["+17.0 ms", "+137.6 ms", "+275.2 ms", "−34.0 ms"],
            answer: 1,
            why: "Offset is the average of the two: (154.6 + 120.6) / 2 = 137.6 ms. Positive means the server is ahead, so the laptop must move forward.",
          },
          events: [note("client", `OFFSET ${ms(ex1.offset, 1)}`, "blue"), note("client", `DELAY ${msAbs(ex1.delay, 1)}`, "blue")],
        },
        {
          title: "Step, then fine-tune",
          desc: "Big errors jump, small ones slew",
          detail: `The offset is over 128 ms, so the NTP daemon steps the clock forward in one jump. Smaller errors are slewed instead: the clock runs slightly fast or slow (at most 0.5 ms per second) so time never goes backwards. 64 seconds later the next poll shows an offset of only ${ms(ex2.offset)}.`,
          facts: [["Step threshold", "128 ms (ntpd)"], ["Next poll", "64 s later (poll 6)"], ["New offset", ms(ex2.offset)]],
          quiz: {
            q: "Why do NTP clients prefer to slew small errors instead of jumping?",
            options: ["Jumping is not allowed by UDP", "So time never runs backwards for programs on the machine", "Slewing uses less bandwidth", "The server forbids it"],
            answer: 1,
            why: "Logs, databases and timers can break if the clock suddenly goes back. Slewing speeds or slows the clock a little until it catches up.",
          },
          events: [
            note("client", "CLOCK STEPPED", "green"),
            pkt("client", "server", "blue", "NTP REQ", ["poll 64 s", "stratum 2 now"], {
              time: 64, info: "NTP Version 4, client",
              packet: request(SRV, ex2, { li: 0, stratum: 2, refId: ipRef(SRV), ref: ex1.t4 + ex1.offset, rootDelay: ex1.delay, rootDisp: 0.0005 }),
            }),
            pkt("server", "client", "violet", "NTP REPLY", ["mode 4", "offset ≈ 0"], {
              time: t3(64 + ex2.rtt), info: "NTP Version 4, server",
              packet: reply(SRV, ex2, { refAgo: 15.2 }),
            }),
            note("client", "IN SYNC", "green"),
          ],
        },
      ],
      outro: {
        title: "Clock in step",
        text: "One request and one reply gave the laptop four timestamps. From them it measured a 34 ms round trip and a 137.6 ms error, stepped its clock, and now polls every 64 seconds to stay within a fraction of a millisecond.",
        facts: [["Packets", "4"], ["Error found", ms(ex1.offset)], ["Round trip", msAbs(ex1.delay)], ["Left after sync", ms(ex2.offset)]],
      },
    },
    {
      id: "asymmetric",
      name: "A far server with a lopsided path",
      summary: "The trip there takes 120 ms but the trip back only 40 ms, and NTP cannot tell.",
      kind: "failure",
      devices: homeToServer({ kind: "server", label: "Far NTP server", sub: FAR }).devices,
      steps: [
        {
          title: "Slow there, fast back",
          desc: "Uneven routes are common",
          detail: "The laptop’s clock is perfectly right this time. It asks a server on another continent. The request takes a congested 120 ms route, but the reply comes back on a quicker 40 ms route. Internet routes often differ in each direction.",
          facts: [["Path out", "120 ms"], ["Path back", "40 ms"], ["Laptop clock error", "0 (it is correct)"]],
          events: [
            pkt("client", "server", "blue", "NTP REQ", ["120 ms to get there"], {
              time: 0, info: "NTP Version 4, client",
              packet: request(FAR, exFar, { li: 0, stratum: 2, refId: ipRef(SRV), ref: -300 }),
            }),
            pkt("server", "client", "violet", "NTP REPLY", ["40 ms back"], {
              time: t3(exFar.rtt), info: "NTP Version 4, server",
              packet: reply(FAR, exFar, { ttl: 47 }),
            }),
          ],
        },
        {
          title: "The maths is fooled",
          desc: "Offset assumes equal halves",
          detail: `Delay comes out right at ${msAbs(exFar.delay, 0)}. But the offset formula assumes each half took 80 ms, so it reports ${ms(exFar.offset, 0)} even though the clock is perfect. The error is always half the difference between the two directions.`,
          facts: exchangeFacts(exFar),
          quiz: {
            q: "The path is 120 ms out and 40 ms back, and both clocks are correct. What offset does NTP compute?",
            options: ["0 ms", "+40 ms", "+80 ms", "−40 ms"],
            answer: 1,
            why: "Half the asymmetry: (120 − 40) / 2 = 40 ms. NTP cannot see which direction was slow, so it blames the clock.",
          },
          events: [note("client", `WRONG BY ${ms(exFar.offset, 0)}`, "red")],
        },
        {
          title: "Limit the damage",
          desc: "Prefer close, fast servers",
          detail: "NTP can’t remove asymmetry, but it knows the worst case: the error is at most half the round trip, here 80 ms. So clients prefer servers with a short delay, use several of them, and pick a server near them, for example from pool.ntp.org’s country zones.",
          facts: [["Worst-case error", "δ / 2 = 80 ms"], ["Fix", "Nearby servers, short delay"], ["Better still", "PTP with hardware stamps on a LAN"]],
          quiz: {
            q: "Two servers both say +5 ms. One has a 10 ms delay, the other 200 ms. Which should the client trust more?",
            options: ["The 200 ms one: it is further away", "The 10 ms one: its error can be at most 5 ms", "They are equal", "Neither"],
            answer: 1,
            why: "The possible error is up to half the delay. A short round trip leaves very little room for asymmetry.",
          },
          events: [note("client", "ERROR ≤ δ/2", "amber")],
        },
      ],
      outro: {
        title: "Asymmetry is NTP’s blind spot",
        text: "NTP measures the total round trip exactly but must guess how it splits. On a lopsided path that guess becomes a clock error of half the difference. Short delays and several nearby servers keep it small.",
        facts: [["Reported offset", ms(exFar.offset, 0)], ["Real error", "0 ms"], ["Bound", "± delay / 2"]],
      },
    },
    {
      id: "falseticker",
      name: "Four servers, one liar",
      summary: "One server’s GPS has failed and it is 37 seconds ahead. The other three outvote it.",
      kind: "failure",
      devices: poolDevices,
      links: poolLinks,
      steps: [
        {
          title: "Ask four servers",
          desc: "One request to each",
          detail: "A well-configured client never trusts one clock. The laptop polls four servers from its configuration, each with its own request and its own T1.",
          facts: [["Servers", "4"], ["Laptop clock", `${ms(CERR, 1)} ahead (unknown to it)`], ["Rule", "Use at least 4 for safety"]],
          events: poolEx.map((p) =>
            pkt("client", p.s.id, "blue", "NTP REQ", [p.s.label], {
              time: t3(p.i * 0.0001), parallel: p.i > 0, info: "NTP Version 4, client",
              packet: request(p.s.ip, p.ex, { li: 0, stratum: 2, refId: ipRef(SRV), ref: -64 }),
            })
          ),
        },
        {
          title: "Four answers",
          desc: "Three agree, one is way off",
          detail: `Each reply gives an offset and a delay. A says ${ms(poolEx[0].ex.offset, 1)}, B ${ms(poolEx[1].ex.offset, 1)}, C ${ms(poolEx[2].ex.offset, 1)}. Server D says +${poolEx[3].ex.offset.toFixed(3)} s, about 37 seconds. Its packet looks perfectly normal; only the time inside is wrong.`,
          facts: [["A, B, C", "within about 1 ms of each other"], ["D", `+${poolEx[3].ex.offset.toFixed(3)} s`], ["D’s packet", "Valid format, wrong time"]],
          events: poolReplies.map((p, k) =>
            pkt(p.s.id, "client", p.s.id === "s4" ? "red" : "violet", "NTP REPLY", [p.s.label, p.s.id === "s4" ? "+37.2 s!" : ms(p.ex.offset, 1)], {
              time: t3(p.i * 0.0001 + p.ex.rtt), parallel: k > 0, info: "NTP Version 4, server",
              packet: reply(p.s.ip, p.ex, { ttl: 55 - p.i }),
            })
          ),
        },
        {
          title: "Spot the falseticker",
          desc: "Find where most clocks overlap",
          detail: "Each server gives a range: its offset plus or minus half its delay. The selection algorithm (based on Marzullo’s algorithm) looks for the time range that most servers agree on. A, B and C overlap; D’s range is nowhere near them, so it is marked a falseticker and ignored. The others are truechimers.",
          facts: [["A", `${ms(poolEx[0].ex.offset, 1)} ± ${msAbs(poolEx[0].ex.delay / 2, 1)}`], ["B / C", `${ms(poolEx[1].ex.offset, 1)} / ${ms(poolEx[2].ex.offset, 1)}`], ["D", "+37 s: rejected"]],
          quiz: {
            q: "If the laptop had used only two servers, A and D, what could it decide?",
            options: ["Trust A", "Trust D", "Nothing safely: it can’t tell which one is wrong", "Average them to +18.6 s"],
            answer: 2,
            why: "With two clocks that disagree there is no majority. That’s why the usual advice is four or more servers.",
          },
          events: [note("s4", "FALSETICKER", "red"), note("client", "3 TRUECHIMERS", "green")],
        },
        {
          title: "Combine the good ones",
          desc: "Weighted by quality",
          detail: `The surviving offsets are combined, giving more weight to servers with smaller delay and jitter. The result is ${ms(combined, 2)}, so the laptop slews its clock back by about ${msAbs(-combined, 1)}. Server D keeps being polled but stays ignored until it agrees with the others again.`,
          facts: [["Combined offset", ms(combined, 2)], ["Action", "Slew (well under 128 ms)"], ["D’s effect", "None"]],
          quiz: {
            q: "The combined offset is about −1.9 ms. What does the laptop do?",
            options: ["Step the clock back 1.9 ms at once", "Slew: run the clock slightly slow until it is right", "Nothing, it is under 1 s", "Ask D again"],
            answer: 1,
            why: "Under the 128 ms step threshold, NTP slews so time never jumps backwards.",
          },
          events: [note("client", `SLEW ${ms(combined, 1)}`, "green")],
        },
      ],
      outro: {
        title: "Majority wins",
        text: "A broken server can send perfectly formed packets with the wrong time. By polling several servers and keeping only the ones whose ranges overlap, NTP throws out the falseticker and keeps the clock right.",
        facts: [["Servers asked", "4"], ["Rejected", "1 (D, +37 s)"], ["Result", ms(combined, 2)], ["Advice", "4+ independent servers"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Modes",
      items: [["1 / 2", "Symmetric active / passive (peers)"], ["3", "Client"], ["4", "Server"], ["5", "Broadcast"], ["6", "Control (ntpq)"]],
    },
    {
      title: "Formulas",
      items: [["T1, T4", "Send and receive, client clock"], ["T2, T3", "Receive and send, server clock"], ["Offset", "((T2−T1) + (T3−T4)) / 2"], ["Delay", "(T4−T1) − (T3−T2)"]],
    },
    {
      title: "Numbers to know",
      items: [["Port", "UDP 123"], ["Packet", "48 bytes"], ["Epoch", "1 Jan 1900; era 0 ends Feb 2036"], ["Stratum", "1 = reference clock, 16 = unsynchronised"], ["Step threshold", "128 ms; max slew 500 ppm"]],
    },
  ],
});

