import { defineLesson, note, pkt, Device } from "@/lib/lesson";
import { build, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, icmp, ipv4, udp } from "@/lib/proto";
import { u32le, u16, rand } from "@/lib/bytes";
import { ADDR, down, homeToServer, up } from "./_common";

const GW = ADDR.server2; // WireGuard gateway, public address
const CP = 48122; // laptop's WireGuard listen port
const WG = 51820;
const T_LAPTOP = "10.8.0.2"; // laptop's address inside the tunnel
const NAS = "10.20.0.5"; // office file server behind the gateway
const GW_LAN_MAC = "00:16:3e:5a:01:99";
const NAS_MAC = "00:11:32:4e:7b:05";
const BOT_MAC = "00:1b:21:aa:00:01";

const I_CLIENT = 0x6b2f91a4; // sender index chosen by the laptop
const I_SERVER = 0x0c7d3e55; // sender index chosen by the gateway

const idx = (name: string, v: number, note: string): FieldSpec => ({ name, bytes: u32le(v), value: `0x${v.toString(16).padStart(8, "0")}`, note });
const counter = (n: number): FieldSpec => ({ name: "Counter", bytes: [...u32le(n), 0, 0, 0, 0], value: String(n), note: "8-byte little-endian packet number. It is the nonce for the cipher and lets the receiver reject replayed packets." });
const header = (type: number, name: string): FieldSpec[] => [
  { name: "Type", u8: type, value: `${type} (${name})` },
  { name: "Reserved", zero: 3, note: "Three zero bytes, so the whole header lines up on 4 bytes." },
];

/** Type 1, 148 bytes */
function wgInit(sender: number, seed: number, mac2?: boolean): LayerSpec {
  return proto({
    id: "wg", name: "WireGuard", osi: 3, summary: `WireGuard Protocol, Handshake Initiation, sender=0x${sender.toString(16)}`,
    fields: [
      ...header(1, "Handshake Initiation"),
      idx("Sender index", sender, "A random number the laptop picks for this session. The other side puts it in every reply so the laptop knows which session a packet belongs to."),
      { name: "Unencrypted ephemeral", random: 32, seed, value: "32 bytes (Curve25519)", note: "A fresh public key made for this handshake only." },
      { name: "Encrypted static", random: 48, seed: seed + 1, opaque: true, value: "32 + 16 bytes", note: "The laptop's long-term public key (32 bytes), encrypted, plus a 16-byte tag. Observers can't see who is connecting." },
      { name: "Encrypted timestamp", random: 28, seed: seed + 2, opaque: true, value: "12 + 16 bytes", note: "A TAI64N timestamp (12 bytes) plus a tag. The server rejects any timestamp not newer than the last one, so a recorded initiation can't be replayed." },
      { name: "MAC1", random: 16, seed: seed + 3, note: "A keyed hash using the server's public key. Anyone who doesn't know that key can't make a valid MAC1, and the server silently ignores them." },
      mac2
        ? { name: "MAC2", random: 16, seed: seed + 4, note: "A keyed hash using the cookie the server sent earlier. It proves the sender really receives packets at this IP and port." }
        : { name: "MAC2", zero: 16, value: "all zeros", note: "Zero: no cookie yet. Only needed when the server is under load." },
    ],
  });
}

/** Type 2, 92 bytes */
function wgResp(seed: number, sender = I_SERVER, receiver = I_CLIENT): LayerSpec {
  return proto({
    id: "wg", name: "WireGuard", osi: 3, summary: `WireGuard Protocol, Handshake Response, sender=0x${sender.toString(16)}, receiver=0x${receiver.toString(16)}`,
    fields: [
      ...header(2, "Handshake Response"),
      idx("Sender index", sender, "The gateway's own number for this session."),
      idx("Receiver index", receiver, "Echoes the laptop's sender index."),
      { name: "Unencrypted ephemeral", random: 32, seed, value: "32 bytes (Curve25519)", note: "The gateway's fresh public key for this handshake." },
      { name: "Encrypted nothing", random: 16, seed: seed + 1, opaque: true, value: "0 + 16 bytes", note: "An empty message encrypted with the new keys: only the 16-byte tag. It proves the gateway computed the same keys." },
      { name: "MAC1", random: 16, seed: seed + 2, note: "Keyed with the laptop's public key." },
      { name: "MAC2", zero: 16, value: "all zeros" },
    ],
  });
}

/** Type 3, 64 bytes */
function wgCookie(seed: number): LayerSpec {
  return proto({
    id: "wg", name: "WireGuard", osi: 3, summary: `WireGuard Protocol, Cookie Reply, receiver=0x${I_CLIENT.toString(16)}`,
    fields: [
      ...header(3, "Cookie Reply"),
      idx("Receiver index", I_CLIENT, "The sender index from the initiation this answers."),
      { name: "Nonce", random: 24, seed, note: "24 random bytes for XChaCha20-Poly1305." },
      { name: "Encrypted cookie", random: 32, seed: seed + 1, opaque: true, value: "16 + 16 bytes", note: "A 16-byte cookie, a MAC of the laptop's IP and port under a secret that changes every 2 minutes, plus a tag." },
    ],
  });
}

/** Type 4: 16-byte header + encrypted inner packet (padded to 16) + 16-byte tag */
function wgData(receiver: number, n: number, inner: number, what: string, seed: number): LayerSpec {
  const padded = Math.ceil(inner / 16) * 16;
  const fields: FieldSpec[] = [
    ...header(4, "Transport Data"),
    idx("Receiver index", receiver, "Tells the other side which session keys to use."),
    counter(n),
  ];
  if (padded) fields.push({ name: "Encrypted packet", random: padded, seed, opaque: true, value: `${padded} bytes`, note: `Decrypted: ${what} (${inner} bytes, padded to a multiple of 16).` });
  fields.push({ name: "Poly1305 tag", random: 16, seed: seed + 1, opaque: true, note: "16-byte authentication tag. A changed or forged packet fails this check and is dropped." });
  return proto({
    id: "wg", name: "WireGuard", osi: 3,
    summary: padded ? `WireGuard Protocol, Transport Data, receiver=0x${receiver.toString(16)}, counter=${n}, datalen=${padded}` : `WireGuard Protocol, Keepalive, receiver=0x${receiver.toString(16)}, counter=${n}`,
    fields,
  });
}

// on the laptop's interface
const toGw = (...l: LayerSpec[]) => build(...up(GW), udp({ sport: CP, dport: WG }), ...l);
const fromGw = (...l: LayerSpec[]) => build(...down(GW), udp({ sport: WG, dport: CP }), ...l);

// on the office LAN, after decryption
const PING_DATA = rand(56, 0x77);
const lanPing = (reply: boolean) =>
  reply
    ? build(eth({ src: NAS_MAC, dst: GW_LAN_MAC }), ipv4({ src: NAS, dst: T_LAPTOP, ttl: 64, id: 0x5a21 }), icmp({ type: 0, name: "Echo (ping) reply", rest: [...u16(0x0b1d), ...u16(1)], data: PING_DATA }))
    : build(eth({ src: GW_LAN_MAC, dst: NAS_MAC }), ipv4({ src: T_LAPTOP, dst: NAS, ttl: 63, id: 0x91e4 }), icmp({ type: 8, name: "Echo (ping) request", rest: [...u16(0x0b1d), ...u16(1)], data: PING_DATA }));

const base = homeToServer({ kind: "vpn", label: "WireGuard gateway", sub: GW, x: 72, y: 62 });
const devices: Device[] = [
  { ...base.devices[0], sub: `${ADDR.laptop} · wg ${T_LAPTOP}` },
  { ...base.devices[1], x: 28 },
  { ...base.devices[2], x: 50, y: 36 },
  base.devices[3],
  { id: "nas", kind: "nas", label: "Office NAS", sub: NAS, x: 90, y: 26 },
];
const links: [string, string][] = [...base.links, ["server", "nas"]];

// flood scenario: captured on the gateway
const floodInit = (src: string, sport: number, sender: number, seed: number) =>
  build(eth({ src: BOT_MAC, dst: ADDR.serverMac }), ipv4({ src, dst: GW, ttl: 238, id: sport & 0xffff }), udp({ sport, dport: WG }), wgInit(sender, seed));
const attackDevices: Device[] = [...devices, { id: "attacker", kind: "attacker", label: "Botnet", sub: "forged sources", x: 36, y: 18 }];
const attackLinks: [string, string][] = [...links, ["attacker", "internet"]];

export default defineLesson({
  id: "wireguard",
  name: "WireGuard",
  full: "WireGuard VPN",
  group: "vpn",
  layer: 3,
  difficulty: 2,
  tagline: "A tiny, fast VPN: one round trip and you're in.",
  description:
    "WireGuard is a modern VPN that puts whole IP packets inside encrypted UDP datagrams. Each side is known by a Curve25519 public key, the handshake takes a single round trip, and there are only four message types. It stays silent to anyone who doesn't know the server's public key.",
  facts: [
    ["Layer", "Network (Layer 3) tunnel"],
    ["Transport", "UDP, default port 51820"],
    ["Handshake", "Noise IK, 1 round trip"],
    ["Crypto", "Curve25519, ChaCha20-Poly1305, BLAKE2s"],
    ["Overhead", "32 bytes + outer IP/UDP"],
    ["Defined in", "WireGuard whitepaper (2017)"],
  ],
  ports: "UDP 51820",
  rfc: "WireGuard whitepaper (Donenfeld)",
  keywords: ["vpn", "tunnel", "noise", "curve25519", "chacha20", "poly1305", "wg-quick", "keepalive", "cookie", "allowedips", "peer"],
  related: ["ipsec", "udp", "ip", "ssh"],
  devices,
  links,
  legend: [
    ["teal", "Handshake (keys)"],
    ["amber", "Laptop's tunnelled data"],
    ["violet", "Gateway's tunnelled data"],
    ["blue", "Plain traffic inside the office"],
    ["slate", "Keepalive"],
    ["red", "Flood and cookies"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Reach the office NAS through the tunnel",
      summary: "The laptop handshakes with the office gateway, pings the NAS through the tunnel, and keeps the tunnel alive.",
      kind: "normal",
      steps: [
        {
          title: "Handshake Initiation",
          desc: "Type 1, exactly 148 bytes",
          detail:
            "The laptop wants to send a packet to 10.20.0.5, which its AllowedIPs say belongs to the office peer. No session exists yet, so it first sends a Handshake Initiation. It carries a fresh ephemeral key, the laptop's identity (encrypted) and an encrypted timestamp, all protected with the gateway's known public key.",
          facts: [["Message", "Type 1, 148 bytes"], ["To", `${GW}:${WG} (UDP)`], ["Identity", "Laptop's static key, encrypted"]],
          quiz: {
            q: "Someone without the gateway's public key sends a random initiation. What does the gateway reply?",
            options: ["An error message", "A cookie reply", "Nothing at all", "A handshake response"],
            answer: 2,
            why: "MAC1 is keyed with the gateway's public key. If it is wrong, WireGuard drops the packet silently, so port scans see nothing.",
          },
          events: [
            pkt("client", "server", "teal", "INIT", ["type 1, 148 B", "ephemeral key"], { time: 0, info: `Handshake Initiation, sender=0x${I_CLIENT.toString(16)}`, packet: toGw(wgInit(I_CLIENT, 0x1101)) }),
          ],
        },
        {
          title: "Handshake Response",
          desc: "Type 2, 92 bytes: keys agreed",
          detail:
            "The gateway checks MAC1, decrypts the laptop's static key and finds it in its peer list, and checks that the timestamp is newer than the last one. It answers with its own ephemeral key and an empty encrypted message. Both sides now mix four Diffie-Hellman results into a pair of session keys, one per direction.",
          facts: [["Message", "Type 2, 92 bytes"], ["Round trips", "1 for the whole handshake"], ["Keys", "One for each direction"]],
          events: [
            pkt("server", "client", "teal", "RESPONSE", ["type 2, 92 B"], { time: 0.031, info: `Handshake Response, sender=0x${I_SERVER.toString(16)}, receiver=0x${I_CLIENT.toString(16)}`, packet: fromGw(wgResp(0x1201)) }),
            note("client", "SESSION KEYS READY", "green"),
          ],
        },
        {
          title: "Ping through the tunnel",
          desc: "Type 4 carries the real IP packet",
          detail:
            "The laptop takes its ping to 10.20.0.5 (84 bytes), pads it to 96, encrypts it with ChaCha20-Poly1305 and wraps it in a Transport Data message. The gateway checks the tag, decrypts, checks the inner source is allowed for this peer, and sends the plain ping onto the office LAN. The NAS never knows a tunnel was involved.",
          facts: [["Inner packet", `${T_LAPTOP} → ${NAS}, ICMP echo`], ["Outer packet", `${ADDR.laptop}:${CP} → ${GW}:${WG}`], ["Overhead", "16 header + 16 tag (+ padding)"]],
          quiz: {
            q: "The inner packet is 84 bytes. How big is the WireGuard message carrying it?",
            options: ["84 bytes", "100 bytes", "128 bytes", "148 bytes"],
            answer: 2,
            why: "16-byte header, the packet padded to 96 bytes, and a 16-byte tag: 16 + 96 + 16 = 128.",
          },
          events: [
            pkt("client", "server", "amber", "DATA", ["type 4, counter 0", "encrypted ping"], { time: 0.0312, info: `Transport Data, receiver=0x${I_SERVER.toString(16)}, counter=0, datalen=96`, packet: toGw(wgData(I_SERVER, 0, 84, `IPv4 ${T_LAPTOP} → ${NAS}, ICMP echo request id 0x0b1d seq 1`, 0x1301)) }),
            pkt("server", "nas", "blue", "PING", [`${T_LAPTOP} → ${NAS}`], { time: 0.0466, info: `Echo (ping) request id=0x0b1d, seq=1/256, ttl=63`, packet: lanPing(false) }),
            pkt("nas", "server", "blue", "PONG", [`${NAS} → ${T_LAPTOP}`], { time: 0.0468, info: `Echo (ping) reply id=0x0b1d, seq=1/256, ttl=64`, packet: lanPing(true) }),
            pkt("server", "client", "violet", "DATA", ["type 4, counter 0", "encrypted reply"], { time: 0.0623, info: `Transport Data, receiver=0x${I_CLIENT.toString(16)}, counter=0, datalen=96`, packet: fromGw(wgData(I_CLIENT, 0, 84, `IPv4 ${NAS} → ${T_LAPTOP}, ICMP echo reply id 0x0b1d seq 1`, 0x1401)) }),
          ],
        },
        {
          title: "Keepalive",
          desc: "A 32-byte empty packet every 25 s",
          detail:
            "With PersistentKeepalive = 25, the laptop sends an empty Transport Data message whenever the tunnel has been quiet for 25 seconds. It has no inner packet, just the header and tag. This keeps the home router's NAT mapping open so the gateway can still reach the laptop.",
          facts: [["Size", "32 bytes (16 header + 16 tag)"], ["Counter", "Keeps counting up"], ["Why", "Keep NAT mappings alive"]],
          quiz: {
            q: "Why does the laptop need keepalives but the gateway usually doesn't?",
            options: ["The gateway has no keys", "The laptop sits behind NAT, which forgets idle mappings", "Keepalives speed up encryption", "The gateway uses TCP"],
            answer: 1,
            why: "Home routers drop idle UDP mappings after a minute or two. Without keepalives, the gateway's packets would hit a closed door.",
          },
          events: [
            pkt("client", "server", "slate", "KEEPALIVE", ["type 4, no payload"], { time: 25.062, info: `Keep-Alive, receiver=0x${I_SERVER.toString(16)}, counter=1`, packet: toGw(wgData(I_SERVER, 1, 0, "", 0x1501)) }),
          ],
        },
        {
          title: "Fresh keys every 2 minutes",
          desc: "A new handshake, no interruption",
          detail:
            "Session keys are replaced after 120 seconds (or 2^60 messages). The laptop simply sends a new Handshake Initiation while the old keys keep working, so traffic never stops. Old keys are thrown away, which means a key stolen later can't decrypt earlier traffic (forward secrecy).",
          facts: [["Rekey after", "120 s"], ["Keys rejected after", "180 s"], ["Property", "Forward secrecy"]],
          events: [
            pkt("client", "server", "teal", "INIT", ["type 1, new keys"], { time: 120.031, info: `Handshake Initiation, sender=0x${(I_CLIENT + 1).toString(16)}`, packet: toGw(wgInit(I_CLIENT + 1, 0x1601)) }),
            pkt("server", "client", "teal", "RESPONSE", ["type 2"], { time: 120.062, info: `Handshake Response, sender=0x${(I_SERVER + 1).toString(16)}, receiver=0x${(I_CLIENT + 1).toString(16)}`, packet: fromGw(wgResp(0x1701, I_SERVER + 1, I_CLIENT + 1)) }),
          ],
        },
      ],
      outro: {
        title: "A tunnel in one round trip",
        text: "WireGuard needed just two handshake messages before real packets flowed. Every IP packet then travelled inside a small UDP datagram with a 16-byte header and a 16-byte tag, and keepalives held the NAT door open.",
        facts: [["Message types", "1 Init, 2 Response, 3 Cookie, 4 Data"], ["Sizes", "148, 92, 64, 32+ bytes"], ["Port", "UDP 51820"], ["Rekey", "Every 2 minutes"]],
      },
    },
    {
      id: "cookie",
      name: "Under load: the cookie reply",
      summary: "A flood of initiations makes the gateway ask for proof of address before doing expensive crypto.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "A flood of initiations",
          desc: "Each one costs the gateway real CPU",
          detail:
            "An attacker who knows the gateway's public key sends thousands of Handshake Initiations from forged addresses. Their MAC1 is valid, so the gateway would have to do expensive Curve25519 maths for each one. This capture is taken on the gateway.",
          facts: [["Source IPs", "Forged"], ["Each costs", "Several Curve25519 operations"], ["Goal", "Exhaust the gateway's CPU"]],
          events: [
            pkt("attacker", "server", "red", "INIT", ["from 198.18.3.9 (fake)"], { time: 0, info: "Handshake Initiation, sender=0x11110001", packet: floodInit("198.18.3.9", 40111, 0x11110001, 0x2101) }),
            pkt("attacker", "server", "red", "INIT", ["from 198.18.44.2 (fake)"], { time: 0.0001, parallel: true, info: "Handshake Initiation, sender=0x11110002", packet: floodInit("198.18.44.2", 40112, 0x11110002, 0x2111) }),
            pkt("attacker", "server", "red", "INIT", ["from 198.18.120.7 (fake)"], { time: 0.0002, parallel: true, info: "Handshake Initiation, sender=0x11110003", packet: floodInit("198.18.120.7", 40113, 0x11110003, 0x2121) }),
            note("server", "UNDER LOAD", "red"),
          ],
        },
        {
          title: "Cookie instead of a response",
          desc: "Type 3, 64 bytes: prove your address",
          detail:
            "Under load, the gateway won't do the expensive work for an initiation with an empty MAC2. It sends a cheap Cookie Reply instead. The cookie is a MAC of the sender's IP and port under a secret that changes every two minutes, so the gateway stores nothing. Forged senders never receive their cookies.",
          facts: [["Message", "Type 3, 64 bytes"], ["Encrypted with", "XChaCha20-Poly1305"], ["Gateway stores", "Nothing per sender"]],
          quiz: {
            q: "Why can't the attacker with forged source addresses use the cookie?",
            options: ["The cookie is too long", "The cookie goes to the forged address, not to the attacker", "Cookies expire in 1 ms", "The attacker lacks a VPN client"],
            answer: 1,
            why: "The reply is sent to the address in the packet. If that address is fake, the attacker never sees the cookie and can't make a valid MAC2.",
          },
          events: [
            pkt("client", "server", "teal", "INIT", ["type 1, MAC2 = 0"], { time: 0.01, info: `Handshake Initiation, sender=0x${I_CLIENT.toString(16)}`, packet: toGw(wgInit(I_CLIENT, 0x2201)) }),
            pkt("server", "client", "red", "COOKIE", ["type 3, 64 B", "come back with this"], { time: 0.041, info: `Cookie Reply, receiver=0x${I_CLIENT.toString(16)}`, packet: fromGw(wgCookie(0x2301)) }),
          ],
        },
        {
          title: "Retry with MAC2",
          desc: "Proof of address, then a normal handshake",
          detail:
            "The laptop decrypts the cookie and waits for its retry timer (5 seconds). Its next initiation carries MAC2 made with the cookie. The gateway checks MAC2 cheaply, sees the laptop really lives at that address, and does the full handshake. Forged floods are dropped before any expensive work.",
          facts: [["Retry after", "5 s (REKEY_TIMEOUT)"], ["MAC2", "Keyed with the cookie"], ["Result", "Handshake succeeds"]],
          events: [
            pkt("client", "server", "teal", "INIT", ["type 1, MAC2 set"], { time: 5.041, info: `Handshake Initiation, sender=0x${(I_CLIENT + 1).toString(16)}`, packet: toGw(wgInit(I_CLIENT + 1, 0x2401, true)) }),
            pkt("server", "client", "teal", "RESPONSE", ["type 2"], { time: 5.072, info: `Handshake Response, sender=0x${I_SERVER.toString(16)}, receiver=0x${(I_CLIENT + 1).toString(16)}`, packet: fromGw(wgResp(0x2501, I_SERVER, I_CLIENT + 1)) }),
            note("client", "TUNNEL UP", "green"),
          ],
        },
      ],
      outro: {
        title: "Real users got through",
        text: "WireGuard's cookie reply works like TCP's SYN cookies: under load, the gateway asks for cheap proof that the sender owns its address before spending CPU. Forged floods never get a cookie, so they're dropped early.",
        facts: [["Defence", "Cookie Reply + MAC2"], ["Cost to gateway", "One cheap MAC per packet"], ["Without load", "MAC2 is ignored"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Message types",
      items: [["1 Handshake Initiation", "148 bytes"], ["2 Handshake Response", "92 bytes"], ["3 Cookie Reply", "64 bytes"], ["4 Transport Data", "32 bytes + padded payload"]],
    },
    {
      title: "Building blocks",
      items: [["Curve25519", "Key agreement"], ["ChaCha20-Poly1305", "Encryption + 16-byte tag"], ["BLAKE2s", "Hashing and MACs"], ["Noise IK", "The handshake pattern"]],
    },
    {
      title: "Config and timers",
      items: [["ListenPort", "51820 by default"], ["AllowedIPs", "Which inner addresses belong to a peer"], ["PersistentKeepalive", "Often 25 s behind NAT"], ["Rekey", "120 s; reject after 180 s"]],
    },
  ],
});
