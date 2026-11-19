import { defineLesson, note, pkt, Step } from "@/lib/lesson";
import { build, field, FieldSpec, proto } from "@/lib/packet";
import { eth, ipv4, udp } from "@/lib/proto";
import { ADDR } from "./_common";

// ---------------------------------------------------------------- helpers
// 802.1X (EAPOL), EAP (RFC 3748) and RADIUS (RFC 2865, 2869, 3579, 2548, 2868)

const AP_MAC = "a4:5e:60:11:22:33"; // AP's BSSID on the Wi-Fi side, also its wired MAC
const RAD_MAC = "00:50:56:9a:10:20";
const AP_IP = "192.0.2.2";
const RAD_IP = "192.0.2.20";
const NAS_PORT = 50214; // the AP's source port towards RADIUS
const OUTER_ID = "anonymous@example.com";
const INNER_ID = "danish@example.com";

const blen = (fs: FieldSpec[]) => fs.map(field).flatMap((f) => f.bytes).length;

// --- EAPOL (802.1X-2004)
const EAPOL_T: Record<number, string> = { 0: "EAP-Packet", 1: "EAPOL-Start", 3: "EAPOL-Key" };
const eapol = (type: number, body: FieldSpec[], summary: string) =>
  proto({
    id: "eapol",
    name: "802.1X Authentication",
    osi: 2,
    ethertype: 0x888e,
    summary,
    fields: [
      { name: "Version", u8: 2, value: "2 (802.1X-2004)" },
      { name: "Type", u8: type, value: `${type} (${EAPOL_T[type]})` },
      { name: "Length", u16: blen(body), note: "Length of the body after this 4-byte header." },
      ...body,
    ],
  });

// --- EAP packet as one field
const EAP_CODE: Record<number, string> = { 1: "Request", 2: "Response", 3: "Success", 4: "Failure" };
const EAP_TYPE: Record<number, string> = { 1: "Identity", 25: "PEAP", 13: "EAP-TLS" };
const eap = (code: number, id: number, type?: number, data: FieldSpec[] = []): FieldSpec => {
  const rest: FieldSpec[] = type !== undefined ? [{ name: "Type", u8: type, value: `${type} (${EAP_TYPE[type]})` }, ...data] : [];
  const len = 4 + blen(rest);
  return {
    name: "Extensible Authentication Protocol",
    value: `${EAP_CODE[code]}${type !== undefined ? `, ${EAP_TYPE[type]}` : ""}`,
    fields: [
      { name: "Code", u8: code, value: `${code} (${EAP_CODE[code]})` },
      { name: "Id", u8: id, note: "Matches a Response to its Request." },
      { name: "Length", u16: len },
      ...rest,
    ],
  };
};

const peap = (flags: number, flagText: string, tlsLen: number | undefined, dataLen: number, seed: number, what: string): FieldSpec[] => [
  { name: "Flags", u8: flags, value: `0x${flags.toString(16).padStart(2, "0")} (${flagText})`, note: "L = total length included, M = more fragments follow, S = start. The low bits are the PEAP version." },
  ...(tlsLen !== undefined ? [{ name: "TLS message length", u32: tlsLen, note: "Total size of the TLS data across all fragments." } as FieldSpec] : []),
  ...(dataLen ? [{ name: "TLS data", random: dataLen, seed, opaque: true, value: `${dataLen} bytes`, note: what } as FieldSpec] : []),
];

// --- RADIUS
const RAD_CODE: Record<number, string> = { 1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject", 11: "Access-Challenge" };
const attr = (type: number, name: string, data: FieldSpec[], value?: string, note?: string): FieldSpec => ({
  name: `AVP: ${name} (${type})`,
  value: value ?? `${2 + blen(data)} bytes`,
  note,
  fields: [
    { name: "Type", u8: type, value: `${type} (${name})` },
    { name: "Length", u8: 2 + blen(data) },
    ...data,
  ],
});
const strAttr = (type: number, name: string, s: string, note?: string) => attr(type, name, [{ name: "Value", text: s }], s, note);
const msgAuth = (seed: number) =>
  attr(80, "Message-Authenticator", [{ name: "HMAC-MD5", random: 16, seed, opaque: true, value: "16 bytes" }], "HMAC-MD5 over the packet", "Keyed with the shared secret. Required whenever EAP-Message is present; stops forged packets.");
const state = (seed: number) => attr(24, "State", [{ name: "Value", random: 16, seed, value: "16 bytes" }], undefined, "A cookie from the server. The AP copies it into the next request so the server knows which conversation this is.");

/** EAP-Message attributes: an EAP packet longer than 253 bytes is split across several. */
const eapMsg = (e: FieldSpec): FieldSpec[] => {
  const bytes = field(e).bytes;
  if (bytes.length <= 253) return [attr(79, "EAP-Message", [e], e.value as string, "The EAP packet from the laptop, carried unchanged.")];
  const out: FieldSpec[] = [];
  const n = Math.ceil(bytes.length / 253);
  for (let i = 0; i < n; i++) {
    const chunk = bytes.slice(i * 253, (i + 1) * 253);
    out.push(attr(79, "EAP-Message", [{ name: i === 0 ? "EAP packet (start)" : "EAP packet (continued)", bytes: chunk, value: `${chunk.length} bytes`, opaque: i > 0 }], `part ${i + 1} of ${n}`, i === 0 ? "One attribute holds at most 253 bytes, so a big EAP packet is split. The server glues the parts back together." : undefined));
  }
  return out;
};

const radius = (code: number, id: number, attrs: FieldSpec[], seed: number) => {
  const len = 20 + blen(attrs);
  return proto({
    id: "radius",
    name: "RADIUS",
    summary: `RADIUS ${RAD_CODE[code]} id=${id}`,
    fields: [
      { name: "Code", u8: code, value: `${code} (${RAD_CODE[code]})` },
      { name: "Identifier", u8: id, note: "Matches a reply to its request." },
      { name: "Length", u16: len, value: `${len} bytes` },
      { name: "Authenticator", random: 16, seed, value: "16 bytes", note: code === 1 ? "Request Authenticator: 16 random bytes, also used to hide some attributes." : "Response Authenticator: MD5 over the reply, the request’s authenticator and the shared secret." },
      ...attrs,
    ],
  });
};

// --- frames
const toAp = (layer: ReturnType<typeof eapol>) => build(eth({ src: ADDR.laptopMac, dst: AP_MAC, type: 0x888e }), layer);
const toLaptop = (layer: ReturnType<typeof eapol>) => build(eth({ src: AP_MAC, dst: ADDR.laptopMac, type: 0x888e }), layer);
const toRad = (r: ReturnType<typeof radius>, id = 0x3e10) => build(eth({ src: AP_MAC, dst: RAD_MAC }), ipv4({ src: AP_IP, dst: RAD_IP, id }), udp({ sport: NAS_PORT, dport: 1812 }), r);
const fromRad = (r: ReturnType<typeof radius>, id = 0x8a01) => build(eth({ src: RAD_MAC, dst: AP_MAC }), ipv4({ src: RAD_IP, dst: AP_IP, id }), udp({ sport: 1812, dport: NAS_PORT }), r);

const nasAttrs = (): FieldSpec[] => [
  attr(4, "NAS-IP-Address", [{ name: "Address", bytes: [192, 0, 2, 2], value: AP_IP }], AP_IP, "Which access point is asking."),
  attr(61, "NAS-Port-Type", [{ name: "Value", u32: 19, value: "19 (Wireless - IEEE 802.11)" }], "Wireless 802.11"),
  strAttr(31, "Calling-Station-Id", "3C-22-FB-7A-91-0E", "The laptop’s MAC address."),
  strAttr(30, "Called-Station-Id", "A4-5E-60-11-22-33:CorpWiFi", "The AP’s MAC and the network name (SSID)."),
  attr(12, "Framed-MTU", [{ name: "Value", u32: 1400 }], "1400", "Keep EAP pieces smaller than this."),
];

// --- EAPOL-Key (4-way handshake, RSN descriptor)
const RSN_IE = "30140100000fac040100000fac040100000fac010000"; // RSN: CCMP-128 group+pairwise, 802.1X AKM
const eapolKey = (o: { info: number; infoText: string; replay: number; nonce?: number; mic?: number; data?: FieldSpec }) => {
  const data: FieldSpec[] = o.data ? [o.data] : [];
  return eapol(3, [
    { name: "Descriptor type", u8: 2, value: "2 (RSN / WPA2)" },
    { name: "Key information", u16: o.info, value: `0x${o.info.toString(16).padStart(4, "0")} (${o.infoText})` },
    { name: "Key length", u16: 16, value: "16 (CCMP)" },
    { name: "Replay counter", u64: o.replay, note: "Goes up with each message from the AP; old copies are ignored." },
    o.nonce !== undefined ? { name: "Key nonce", random: 32, seed: o.nonce, value: "32 random bytes" } : { name: "Key nonce", zero: 32, value: "zero" },
    { name: "Key IV", zero: 16, value: "zero" },
    { name: "Key RSC", zero: 8, value: "0" },
    { name: "Key ID", zero: 8, value: "0" },
    o.mic !== undefined ? { name: "Key MIC", random: 16, seed: o.mic, opaque: true, value: "16 bytes", note: "Proves the sender knows the PMK, which came from RADIUS." } : { name: "Key MIC", zero: 16, value: "none yet" },
    { name: "Key data length", u16: blen(data) },
    ...data,
  ], `EAPOL-Key (${o.infoText})`);
};

const devices = [
  { id: "client", kind: "laptop" as const, label: "Laptop", sub: "supplicant", x: 9, y: 62 },
  { id: "ap", kind: "ap" as const, label: "Access point", sub: `${AP_IP} (NAS)`, x: 36, y: 62 },
  { id: "radius", kind: "auth" as const, label: "RADIUS server", sub: RAD_IP, x: 66, y: 40 },
  { id: "dir", kind: "db" as const, label: "Directory", sub: "user accounts", x: 90, y: 22 },
  { id: "staff", kind: "server" as const, label: "Staff VLAN 20", sub: "10.20.0.0/16", x: 88, y: 76 },
];
const links: [string, string][] = [["client", "ap"], ["ap", "radius"], ["radius", "dir"], ["ap", "staff"]];

// --- shared first part (identity + PEAP start + TLS tunnel), used by both scenarios
const identitySteps = (base: number): Step[] => [
  {
    title: "Hello, who are you?",
    desc: "EAPOL-Start and EAP-Request/Identity",
    detail:
      "The laptop has joined the Wi-Fi network CorpWiFi, but the access point lets only 802.1X frames through until it says yes. The laptop sends EAPOL-Start, and the AP replies with an EAP Request for an identity. On a wired switch port the same frames go to the group address 01:80:c2:00:00:03 instead of the AP’s MAC.",
    facts: [["EtherType", "0x888E (EAPOL)"], ["Port state", "Blocked, except EAPOL"], ["Roles", "Supplicant, authenticator, server"]],
    events: [
      pkt("client", "ap", "blue", "START", ["EAPOL-Start"], {
        time: base, info: "Start",
        packet: toAp(eapol(1, [], "EAPOL-Start")),
      }),
      pkt("ap", "client", "blue", "IDENTITY?", ["EAP-Request/Identity"], {
        time: base + 0.001, info: "Request, Identity",
        packet: toLaptop(eapol(0, [eap(1, 1, 1)], "EAP Request, Identity")),
      }),
    ],
  },
  {
    title: "Identity, relayed",
    desc: "Outer identity goes into an Access-Request",
    detail: `The laptop answers with "${OUTER_ID}". With PEAP the real user name stays hidden until the encrypted tunnel exists; only the realm is needed here so the right server is chosen. The AP does not understand EAP: it copies the packet into a RADIUS Access-Request on UDP 1812, adds details about itself, and signs it with the shared secret.`,
    facts: [["Outer identity", OUTER_ID], ["RADIUS port", "UDP 1812"], ["Identifier", "0x41"]],
    quiz: {
      q: "Why does the laptop send “anonymous@…” instead of its real user name?",
      options: ["The AP rejects real names", "The real name is sent later inside the encrypted PEAP tunnel", "RADIUS has no field for names", "It is a typo in the config"],
      answer: 1,
      why: "The outer identity crosses the network in the clear. The realm after @ is enough for routing; the real identity travels inside TLS.",
    },
    events: [
      pkt("client", "ap", "amber", "IDENTITY", [OUTER_ID], {
        time: base + 0.002, info: `Response, Identity`,
        packet: toAp(eapol(0, [eap(2, 1, 1, [{ name: "Identity", text: OUTER_ID }])], "EAP Response, Identity")),
      }),
      pkt("ap", "radius", "amber", "ACC-REQ", ["Access-Request id=0x41", "EAP inside"], {
        time: base + 0.003, info: "Access-Request id=65",
        packet: toRad(radius(1, 0x41, [
          strAttr(1, "User-Name", OUTER_ID, "Copied from the EAP identity."),
          ...nasAttrs(),
          ...eapMsg(eap(2, 1, 1, [{ name: "Identity", text: OUTER_ID }])),
          msgAuth(601),
        ], 602)),
      }),
    ],
  },
  {
    title: "Let’s use PEAP",
    desc: "Access-Challenge with EAP-Request/PEAP Start",
    detail:
      "The RADIUS server picks the method. It answers with an Access-Challenge holding an EAP Request of type 25 (PEAP) with the Start flag, plus a State cookie. The AP unpacks the EAP and sends it to the laptop over EAPOL.",
    facts: [["RADIUS code", "11 (Access-Challenge)"], ["EAP type", "25 (PEAP)"], ["Flags", "Start, version 1"]],
    events: [
      pkt("radius", "ap", "teal", "CHALLENGE", ["Access-Challenge", "PEAP start"], {
        time: base + 0.006, info: "Access-Challenge id=65",
        packet: fromRad(radius(11, 0x41, [
          ...eapMsg(eap(1, 2, 25, peap(0x21, "Start, PEAP v1", undefined, 0, 0, ""))),
          msgAuth(611), state(612),
        ], 613)),
      }),
      pkt("ap", "client", "teal", "PEAP", ["EAP-Request/PEAP", "start TLS"], {
        time: base + 0.007, info: "Request, Protected EAP (EAP-PEAP)",
        packet: toLaptop(eapol(0, [eap(1, 2, 25, peap(0x21, "Start, PEAP v1", undefined, 0, 0, ""))], "EAP Request, PEAP")),
      }),
    ],
  },
  {
    title: "Build the TLS tunnel",
    desc: "Several challenge rounds carry a TLS handshake",
    detail:
      "Now a whole TLS handshake travels inside EAP, which travels inside RADIUS. The laptop’s ClientHello goes up; the server’s certificate is too big for one packet, so it comes back in fragments over several Access-Challenge rounds. The laptop must check that certificate against the company CA, or an evil twin access point could steal passwords.",
    facts: [["Rounds", "About 4 to 6 challenges"], ["Fragment", "Up to 1400 bytes (Framed-MTU)"], ["Check", "Server cert vs company CA"]],
    quiz: {
      q: "The laptop skips checking the RADIUS server’s certificate. What can an attacker with a fake AP do?",
      options: ["Nothing, PEAP is always safe", "Pose as the server and capture the inner login exchange", "Only slow the network down", "Read other users’ VLAN traffic"],
      answer: 1,
      why: "Without certificate checks the laptop will build a tunnel to anyone, so a fake AP can collect the MSCHAPv2 exchange and try to crack it.",
    },
    events: [
      pkt("ap", "radius", "amber", "ACC-REQ", ["id=0x42", "TLS ClientHello"], {
        time: base + 0.012, info: "Access-Request id=66",
        packet: toRad(radius(1, 0x42, [
          strAttr(1, "User-Name", OUTER_ID),
          ...nasAttrs(),
          ...eapMsg(eap(2, 2, 25, peap(0x01, "PEAP v1", undefined, 212, 621, "TLS ClientHello: versions, cipher suites, random, key share."))),
          state(612), msgAuth(622),
        ], 623), 0x3e11),
      }),
      pkt("radius", "ap", "teal", "CHALLENGE", ["id=0x42", "cert, part 1"], {
        time: base + 0.016, info: "Access-Challenge id=66",
        packet: fromRad(radius(11, 0x42, [
          ...eapMsg(eap(1, 3, 25, peap(0xc1, "Length, More fragments, PEAP v1", 3418, 984, 631, "TLS ServerHello, Certificate (first part)…"))),
          msgAuth(632), state(633),
        ], 634), 0x8a02),
      }),
      note("ap", "MORE ROUNDS…", "blue"),
    ],
  },
];

export default defineLesson({
  id: "radius",
  name: "802.1X + RADIUS",
  full: "IEEE 802.1X port authentication with RADIUS",
  group: "security",
  layer: 7,
  difficulty: 3,
  tagline: "Enterprise Wi-Fi: log in with your own account, not a shared key.",
  description:
    "With 802.1X, the access point or switch keeps a port closed until a central RADIUS server says yes. The laptop speaks EAP to the access point, which relays it inside RADIUS. On success RADIUS hands back keys for Wi-Fi encryption and the VLAN this user belongs to.",
  facts: [
    ["Layer", "Data Link (EAPOL) + Application (RADIUS)"],
    ["Transport", "EAPOL on Ethernet, RADIUS on UDP 1812"],
    ["Methods", "PEAP, EAP-TLS, EAP-TTLS"],
    ["RADIUS header", "20 bytes + attributes"],
    ["Attributes", "Type, length, value"],
    ["Defined in", "IEEE 802.1X, RFC 2865, RFC 3579"],
  ],
  ports: "UDP 1812 (authentication), UDP 1813 (accounting); EtherType 0x888E",
  rfc: "RFC 2865",
  keywords: ["eap", "eapol", "peap", "eap-tls", "wpa2 enterprise", "wpa3 enterprise", "nac", "access-accept", "access-reject", "vlan", "mppe", "4-way handshake"],
  related: ["tls", "kerberos", "ldap", "wifi"],
  devices,
  links,
  legend: [
    ["blue", "EAPOL control"],
    ["amber", "Requests from the laptop / AP"],
    ["teal", "Challenges and keys"],
    ["green", "Accepted"],
    ["red", "Rejected"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Joining enterprise Wi-Fi with PEAP",
      summary: "The laptop proves who it is through the access point to a RADIUS server and lands on VLAN 20.",
      kind: "normal",
      steps: [
        ...identitySteps(0),
        {
          title: "Access-Accept",
          desc: "Password checked, keys and VLAN handed over",
          detail: `Inside the tunnel the laptop sends "${INNER_ID}" and an MSCHAPv2 proof of its password; the server checks it with the directory. It then sends Access-Accept with EAP-Success, the real user name, two MS-MPPE keys (hidden using the shared secret) and three tunnel attributes that put this user on VLAN 20.`,
          facts: [["RADIUS code", "2 (Access-Accept)"], ["Keys", "MS-MPPE-Recv-Key, MS-MPPE-Send-Key"], ["VLAN", "Tunnel-Private-Group-ID = 20"]],
          quiz: {
            q: "What does the AP do with the MS-MPPE keys?",
            options: ["Send them to the laptop in the clear", "Use them as the PMK for the Wi-Fi 4-way handshake", "Store them in the directory", "Nothing, they are for logging"],
            answer: 1,
            why: "The laptop derived the same key from the TLS tunnel. Both sides now share a PMK without it ever crossing the air.",
          },
          events: [
            note("dir", "PASSWORD OK", "green"),
            pkt("radius", "ap", "green", "ACCEPT", ["Access-Accept", "VLAN 20 + keys"], {
              time: 0.061, info: "Access-Accept id=72",
              packet: fromRad(radius(2, 0x48, [
                strAttr(1, "User-Name", INNER_ID, "The real identity, learned inside the tunnel."),
                attr(64, "Tunnel-Type", [{ name: "Tag", u8: 0 }, { name: "Value", u24: 13, value: "13 (VLAN)" }], "VLAN"),
                attr(65, "Tunnel-Medium-Type", [{ name: "Tag", u8: 0 }, { name: "Value", u24: 6, value: "6 (IEEE-802)" }], "IEEE-802"),
                strAttr(81, "Tunnel-Private-Group-ID", "20", "The VLAN number, written as text."),
                attr(26, "Vendor-Specific", [
                  { name: "Vendor ID", u32: 311, value: "311 (Microsoft)" },
                  { name: "Vendor type", u8: 17, value: "17 (MS-MPPE-Recv-Key)" },
                  { name: "Vendor length", u8: 52 },
                  { name: "Salt", u16: 0x8d3c, value: "0x8d3c" },
                  { name: "Encrypted key", random: 48, seed: 641, opaque: true, value: "48 bytes", note: "32-byte key plus padding, hidden with MD5 of the shared secret and salt." },
                ], "MS-MPPE-Recv-Key"),
                attr(26, "Vendor-Specific", [
                  { name: "Vendor ID", u32: 311, value: "311 (Microsoft)" },
                  { name: "Vendor type", u8: 16, value: "16 (MS-MPPE-Send-Key)" },
                  { name: "Vendor length", u8: 52 },
                  { name: "Salt", u16: 0x9f12, value: "0x9f12" },
                  { name: "Encrypted key", random: 48, seed: 642, opaque: true, value: "48 bytes" },
                ], "MS-MPPE-Send-Key"),
                ...eapMsg(eap(3, 9)),
                msgAuth(643),
              ], 644), 0x8a07),
            }),
            pkt("ap", "client", "green", "SUCCESS", ["EAP-Success"], {
              time: 0.062, info: "Success",
              packet: toLaptop(eapol(0, [eap(3, 9)], "EAP Success")),
            }),
          ],
        },
        {
          title: "4-way handshake",
          desc: "EAPOL-Key messages turn the PMK into Wi-Fi keys",
          detail:
            "The AP and laptop now share the PMK. They swap nonces (ANonce and SNonce) in four EAPOL-Key messages, each proving it knows the PMK with a MIC. Message 3 carries the group key encrypted. After message 4 the port opens and traffic flows on VLAN 20.",
          facts: [["Messages", "4 EAPOL-Key frames"], ["Result", "Pairwise key (PTK) + group key (GTK)"], ["Cipher", "CCMP (AES)"]],
          events: [
            pkt("ap", "client", "teal", "KEY 1/4", ["ANonce"], {
              time: 0.063, info: "Key (Message 1 of 4)",
              packet: toLaptop(eapolKey({ info: 0x008a, infoText: "Message 1: Pairwise, ACK", replay: 1, nonce: 651 })),
            }),
            pkt("client", "ap", "teal", "KEY 2/4", ["SNonce + MIC"], {
              time: 0.065, info: "Key (Message 2 of 4)",
              packet: toAp(eapolKey({ info: 0x010a, infoText: "Message 2: Pairwise, MIC", replay: 1, nonce: 652, mic: 653, data: { name: "RSN information element", bytes: RSN_IE, value: "CCMP, 802.1X AKM", note: "What security the laptop is using, so a downgrade can be spotted." } })),
            }),
            pkt("ap", "client", "teal", "KEY 3/4", ["GTK (encrypted) + MIC"], {
              time: 0.066, info: "Key (Message 3 of 4)",
              packet: toLaptop(eapolKey({ info: 0x13ca, infoText: "Message 3: Pairwise, Install, ACK, MIC, Secure, Encrypted", replay: 2, nonce: 651, mic: 654, data: { name: "Encrypted key data", random: 56, seed: 655, opaque: true, value: "56 bytes", note: "RSN element and the group key (GTK), wrapped with AES." } })),
            }),
            pkt("client", "ap", "teal", "KEY 4/4", ["MIC", "done"], {
              time: 0.067, info: "Key (Message 4 of 4)",
              packet: toAp(eapolKey({ info: 0x030a, infoText: "Message 4: Pairwise, MIC, Secure", replay: 2, mic: 656 })),
            }),
            note("client", "ON VLAN 20", "green"),
          ],
        },
      ],
      outro: {
        title: "Connected as danish",
        text: "The access point never saw the password. It relayed EAP to RADIUS, which checked the user inside a TLS tunnel, then sent back Wi-Fi keys and a VLAN. Each user gets their own keys, and disabling one account locks out only that person.",
        facts: [["RADIUS round trips", "About 8"], ["Time", "About 70 ms on a LAN"], ["VLAN", "20 (staff)"], ["Shared Wi-Fi password", "None"]],
      },
    },
    {
      id: "reject",
      name: "Wrong password: Access-Reject",
      summary: "Same start, but the inner MSCHAPv2 proof doesn’t match and RADIUS says no.",
      kind: "failure",
      steps: [
        ...identitySteps(0),
        {
          title: "Wrong password",
          desc: "Access-Reject with EAP-Failure",
          detail:
            "Inside the tunnel the laptop sends an MSCHAPv2 answer made from a mistyped password. The directory says it doesn’t match, so the RADIUS server sends Access-Reject with an EAP-Failure. The AP passes the failure on and keeps the port closed.",
          facts: [["RADIUS code", "3 (Access-Reject)"], ["EAP code", "4 (Failure)"], ["Port", "Stays blocked"]],
          quiz: {
            q: "After the reject, what traffic can the laptop send through this AP?",
            options: ["Anything, the port is open", "Only EAPOL frames, to try again", "Only DNS", "Traffic on the guest VLAN by default"],
            answer: 1,
            why: "An unauthorised 802.1X port only passes EAPOL. Some networks are set to move failed clients to a guest VLAN, but that is extra configuration.",
          },
          events: [
            note("dir", "BAD PASSWORD", "red"),
            pkt("radius", "ap", "red", "REJECT", ["Access-Reject", "EAP-Failure"], {
              time: 0.058, info: "Access-Reject id=71",
              packet: fromRad(radius(3, 0x47, [
                ...eapMsg(eap(4, 8)),
                strAttr(18, "Reply-Message", "Authentication failed", "Free text for logs."),
                msgAuth(661),
              ], 662), 0x8a06),
            }),
            pkt("ap", "client", "red", "FAILURE", ["EAP-Failure"], {
              time: 0.059, info: "Failure",
              packet: toLaptop(eapol(0, [eap(4, 8)], "EAP Failure")),
            }),
            note("client", "ACCESS DENIED", "red"),
          ],
        },
      ],
      outro: {
        title: "Kept out",
        text: "A wrong password ends in Access-Reject and EAP-Failure. No keys are given, so the laptop cannot even start the 4-way handshake. The RADIUS server logs the failure, which helps spot guessing attacks.",
        facts: [["Packets", "Same as success until the end"], ["Result", "Access-Reject (3)"], ["Keys issued", "None"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "RADIUS codes",
      items: [["1 Access-Request", "AP asks"], ["2 Access-Accept", "Let them in"], ["3 Access-Reject", "Keep them out"], ["11 Access-Challenge", "Need more (next EAP round)"], ["4 / 5", "Accounting Request / Response (port 1813)"]],
    },
    {
      title: "Key attributes",
      items: [["1 User-Name", "Who"], ["4 NAS-IP-Address", "Which AP or switch"], ["24 State", "Conversation cookie"], ["79 EAP-Message", "EAP packet, split at 253 bytes"], ["80 Message-Authenticator", "HMAC-MD5 integrity"], ["64/65/81", "Tunnel type, medium, VLAN ID"], ["26 / 311 / 16,17", "Microsoft MPPE send/receive keys"]],
    },
    {
      title: "EAP / EAPOL",
      items: [["EtherType 0x888E", "EAPOL"], ["EAPOL types", "0 EAP, 1 Start, 3 Key"], ["EAP codes", "1 Request, 2 Response, 3 Success, 4 Failure"], ["EAP types", "1 Identity, 13 EAP-TLS, 25 PEAP"]],
    },
  ],
});
