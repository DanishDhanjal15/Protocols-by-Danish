import { defineLesson, note, pkt, Device } from "@/lib/lesson";
import { build, field, FieldSpec, LayerSpec, proto, textLayer } from "@/lib/packet";
import { eth, ipv4, tcp } from "@/lib/proto";
import { text } from "@/lib/bytes";
import { ADDR, down, homeToServer, up } from "./_common";

const S = ADDR.server2; // the SSH server
const BOT = "198.18.77.14"; // a scanning bot (benchmark range, not a real host)
const t = (n: number) => Number(n.toFixed(4));

// ---------------------------------------------------------------- SSH wire helpers

const fbytes = (specs: FieldSpec[]) => specs.map(field).flatMap((f) => f.bytes);

/** SSH "string": uint32 length + bytes */
const sstr = (name: string, s: string, note?: string): FieldSpec => ({
  name, value: JSON.stringify(s), note,
  fields: [{ name: "Length", u32: text(s).length }, { name: "Value", text: s }],
});
/** SSH "string" holding binary data */
const sblob = (name: string, inner: FieldSpec[], note?: string): FieldSpec => {
  const n = fbytes(inner).length;
  return { name, value: `${n} bytes`, note, fields: [{ name: "Length", u32: n }, ...inner] };
};

const KEY_C = 0x5100; // seeds so each key stays the same everywhere
const hostKeyBlob = (seed: number, note: string) =>
  sblob("Host key (K_S)", [sstr("Key type", "ssh-ed25519"), sblob("Public key", [{ name: "Ed25519 key", random: 32, seed }])], note);
const sigBlob = (name: string, seed: number, note: string) =>
  sblob(name, [sstr("Signature type", "ssh-ed25519"), sblob("Signature", [{ name: "Ed25519 signature", random: 64, seed, opaque: true }])], note);

/** Unencrypted SSH binary packet (RFC 4253 §6): length, padding length, payload, random padding. */
function sshPacket(code: number, msg: string, payload: FieldSpec[], seed = code): LayerSpec {
  const body = 1 + fbytes(payload).length;
  let pad = 8 - ((4 + 1 + body) % 8);
  if (pad < 4) pad += 8;
  const plen = 1 + body + pad;
  return proto({
    id: "ssh", name: "SSH", osi: 7, summary: `SSH Protocol, ${msg}`,
    fields: [
      { name: "Packet length", u32: plen, value: `${plen} bytes`, note: "Everything after this field: padding length, payload and padding. No MAC yet, because no keys exist." },
      { name: "Padding length", u8: pad, note: "Random bytes are added so the packet is a multiple of 8 bytes and its exact size is harder to guess." },
      { name: "Message code", u8: code, value: `${code} (${msg})` },
      ...payload,
      { name: "Random padding", random: pad, seed: seed + 900, note: `${pad} random bytes. At least 4 are always added.` },
    ],
  });
}

/** Encrypted SSH packet with chacha20-poly1305@openssh.com: even the length is encrypted. */
function sshEnc(n: number, what: string, inside: string, seed: number): LayerSpec {
  return proto({
    id: "ssh", name: "SSH", osi: 7, summary: `SSH Protocol, Encrypted packet (len=${n})`,
    fields: [
      { name: "Encrypted packet length", random: 4, seed, opaque: true, note: "With chacha20-poly1305 the length is encrypted too, with its own key, so an observer can't even see where packets end." },
      { name: `Encrypted packet: ${what}`, random: n, seed: seed + 1, opaque: true, value: `${n} bytes`, note: `Decrypted, this holds: ${inside}` },
      { name: "MAC (Poly1305 tag)", random: 16, seed: seed + 2, opaque: true, note: "16-byte tag. If one bit is changed on the way, the check fails and the connection is dropped." },
    ],
  });
}

// ---------------------------------------------------------------- KEXINIT

const nameList = (name: string, s: string, note?: string) => sstr(name, s, note);
const CLIENT_KEX = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com";
const SERVER_KEX = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,diffie-hellman-group14-sha256,kex-strict-s-v00@openssh.com";
const CIPHERS = "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes256-ctr";
const MACS = "umac-64-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com";

const kexinit = (kex: string, hostkeys: string, seed: number, comp = "none,zlib@openssh.com") =>
  sshPacket(20, "Key Exchange Init", [
    { name: "Cookie", random: 16, seed, note: "16 random bytes so every key exchange is unique." },
    nameList("kex_algorithms", kex, "Ways to agree a shared secret, best first."),
    nameList("server_host_key_algorithms", hostkeys, "Key types the server may prove its identity with."),
    nameList("encryption_algorithms_client_to_server", CIPHERS),
    nameList("encryption_algorithms_server_to_client", CIPHERS),
    nameList("mac_algorithms_client_to_server", MACS, "Only used by ciphers that don't carry their own tag."),
    nameList("mac_algorithms_server_to_client", MACS),
    nameList("compression_algorithms_client_to_server", comp),
    nameList("compression_algorithms_server_to_client", comp),
    nameList("languages_client_to_server", ""),
    nameList("languages_server_to_client", ""),
    { name: "first_kex_packet_follows", u8: 0, value: "false" },
    { name: "Reserved", u32: 0 },
  ], seed);

const clientKexinit = () => kexinit(CLIENT_KEX, "ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256", 0x2001);
const serverKexinit = () => kexinit(SERVER_KEX, "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519", 0x2002, "none,zlib@openssh.com");

const ecdhInit = (seed: number) =>
  sshPacket(30, "Elliptic Curve Diffie-Hellman Key Exchange Init", [
    sblob("Client ephemeral public key (Q_C)", [{ name: "Curve25519 point", random: 32, seed }], "A brand-new X25519 public key, used for this connection only."),
  ]);
const ecdhReply = (hostSeed: number, seed: number) =>
  sshPacket(31, "Elliptic Curve Diffie-Hellman Key Exchange Reply", [
    hostKeyBlob(hostSeed, "The server's long-term Ed25519 public key. The client compares its fingerprint with ~/.ssh/known_hosts."),
    sblob("Server ephemeral public key (Q_S)", [{ name: "Curve25519 point", random: 32, seed }], "The server's one-time X25519 key."),
    sigBlob("Signature over exchange hash (H)", seed + 1, "The server signs a hash of everything so far with its host key. Only the real owner of the private key can make this."),
  ]);
const newkeys = () => sshPacket(21, "New Keys", []);

// ---------------------------------------------------------------- TCP conversation helper

function conv(o: { sport: number; cl: () => LayerSpec[]; sl: () => LayerSpec[]; cBase: number; sBase: number }) {
  let c = 1, s = 1;
  const len = (specs: LayerSpec[]) => (specs.length ? build(...specs).bytes.length : 0);
  return {
    syn: () => build(...o.cl(), tcp({ sport: o.sport, dport: 22, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", { ts: [1201, 0] }, "nop", { ws: 7 }], seqBase: o.cBase })),
    synack: () => build(...o.sl(), tcp({ sport: 22, dport: o.sport, seq: 0, ack: 1, flags: "SA", win: 65160, opts: [{ mss: 1460 }, "sackOk", { ts: [88001, 1201] }, "nop", { ws: 7 }], seqBase: o.sBase, ackBase: o.cBase })),
    c: (specs: LayerSpec[], flags = "PA") => {
      const p = build(...o.cl(), tcp({ sport: o.sport, dport: 22, seq: c, ack: s, flags, win: 502, seqBase: o.cBase, ackBase: o.sBase }), ...specs);
      c += len(specs) + (flags.includes("F") ? 1 : 0);
      return p;
    },
    s: (specs: LayerSpec[], flags = "PA") => {
      const p = build(...o.sl(), tcp({ sport: 22, dport: o.sport, seq: s, ack: c, flags, win: 509, seqBase: o.sBase, ackBase: o.cBase }), ...specs);
      s += len(specs) + (flags.includes("F") ? 1 : 0);
      return p;
    },
  };
}

const banner = (line: string, who: string) =>
  textLayer({ id: "ssh", name: "SSH", lines: [line], summary: `SSH Protocol, ${who}: ${line}`, notes: { 0: "The identification string: protocol 2.0, then the software name. It ends with CR LF and is sent in clear." } });

const CLIENT_BANNER = "SSH-2.0-OpenSSH_9.6";
const SERVER_BANNER = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13";
const FP_REAL = "SHA256:k3Vq9pXo2mT8yL1cRw0eHf6uJbN4sAa7dZiGQ5vE2Yc";
const FP_FAKE = "SHA256:Zx81Lq0WmPa6rT3uYc9VbK2nHf5sDe7gJiO4lQwE1Ra";

// ---------------------------------------------------------------- normal session

const SP = 50412;
const n = conv({ sport: SP, cl: () => up(S), sl: () => down(S), cBase: 0x3c11a000, sBase: 0x8e20f400 });
const HOST_SEED = 0x4401;

const normalEvents = {
  connect: [
    pkt("client", "server", "green", "SYN", ["port 22"], { time: 0, info: `${SP} → 22 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: n.syn() }),
    pkt("server", "client", "green", "SYN-ACK", [], { time: 0.03, info: `22 → ${SP} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460`, packet: n.synack() }),
    pkt("client", "server", "green", "ACK", [], { time: 0.0302, info: `${SP} → 22 [ACK] Seq=1 Ack=1 Win=502 Len=0`, packet: n.c([], "A") }),
    pkt("client", "server", "amber", "BANNER", [CLIENT_BANNER], { time: 0.0303, info: `Client: Protocol (${CLIENT_BANNER})`, packet: n.c([banner(CLIENT_BANNER, "Client")]) }),
    pkt("server", "client", "violet", "BANNER", ["SSH-2.0-OpenSSH_9.6p1"], { time: 0.061, info: `Server: Protocol (${SERVER_BANNER})`, packet: n.s([banner(SERVER_BANNER, "Server")]) }),
  ],
  kexinit: [
    pkt("client", "server", "blue", "KEXINIT", ["my algorithm lists"], { time: 0.0615, info: "Client: Key Exchange Init", packet: n.c([clientKexinit()]) }),
    pkt("server", "client", "blue", "KEXINIT", ["my algorithm lists"], { time: 0.0625, parallel: true, info: "Server: Key Exchange Init", packet: n.s([serverKexinit()]) }),
  ],
  ecdh: [
    pkt("client", "server", "teal", "ECDH INIT", ["X25519 public key"], { time: 0.063, info: "Client: Elliptic Curve Diffie-Hellman Key Exchange Init", packet: n.c([ecdhInit(0x3001)]) }),
    pkt("server", "client", "teal", "ECDH REPLY", ["host key + signature", "+ NEWKEYS"], { time: 0.095, info: "Server: Elliptic Curve Diffie-Hellman Key Exchange Reply, New Keys", packet: n.s([ecdhReply(HOST_SEED, 0x3002), newkeys()]) }),
  ],
  newkeys: [
    pkt("client", "server", "teal", "NEWKEYS", ["switching to new keys"], { time: 0.0965, info: "Client: New Keys", packet: n.c([newkeys()]) }),
    note("client", `HOST KEY OK: ${FP_REAL.slice(0, 16)}…`, "green"),
  ],
  auth: [
    pkt("client", "server", "amber", "ENCRYPTED", ["SERVICE_REQUEST", "ssh-userauth"], { time: 0.097, info: "Client: Encrypted packet (len=24)", packet: n.c([sshEnc(24, "SSH_MSG_SERVICE_REQUEST", "message 5, service \"ssh-userauth\".", 0x6001)]) }),
    pkt("server", "client", "violet", "ENCRYPTED", ["EXT_INFO + ACCEPT"], { time: 0.128, info: "Server: Encrypted packet (len=264)", packet: n.s([sshEnc(208, "SSH_MSG_EXT_INFO", "message 7, server-sig-algs and other extensions the server supports.", 0x6011), sshEnc(24, "SSH_MSG_SERVICE_ACCEPT", "message 6, \"ssh-userauth\": go ahead and log in.", 0x6021)]) }),
    pkt("client", "server", "amber", "ENCRYPTED", ["USERAUTH_REQUEST", "may I use this key?"], { time: 0.1285, info: "Client: Encrypted packet (len=120)", packet: n.c([sshEnc(120, "SSH_MSG_USERAUTH_REQUEST (query)", "message 50, user \"danish\", service \"ssh-connection\", method \"publickey\", has-signature false, the Ed25519 public key.", 0x6031)]) }),
    pkt("server", "client", "violet", "ENCRYPTED", ["USERAUTH_PK_OK"], { time: 0.159, info: "Server: Encrypted packet (len=80)", packet: n.s([sshEnc(80, "SSH_MSG_USERAUTH_PK_OK", "message 60: that key is in danish's authorized_keys, prove you own it.", 0x6041)]) }),
    pkt("client", "server", "amber", "ENCRYPTED", ["USERAUTH_REQUEST", "signed proof"], { time: 0.161, info: "Client: Encrypted packet (len=208)", packet: n.c([sshEnc(208, "SSH_MSG_USERAUTH_REQUEST (signed)", "message 50, same fields, has-signature true, plus an Ed25519 signature over the session ID and the request.", 0x6051)]) }),
    pkt("server", "client", "green", "ENCRYPTED", ["USERAUTH_SUCCESS"], { time: 0.192, info: "Server: Encrypted packet (len=8)", packet: n.s([sshEnc(8, "SSH_MSG_USERAUTH_SUCCESS", "message 52: you are logged in.", 0x6061)]) }),
    note("server", "LOGGED IN AS danish", "green"),
  ],
  channel: [
    pkt("client", "server", "amber", "ENCRYPTED", ["CHANNEL_OPEN session"], { time: 0.193, info: "Client: Encrypted packet (len=32)", packet: n.c([sshEnc(32, "SSH_MSG_CHANNEL_OPEN", "message 90, type \"session\", sender channel 0, window 2 MB, max packet 32 KB.", 0x6071)]) }),
    pkt("server", "client", "violet", "ENCRYPTED", ["OPEN_CONFIRMATION"], { time: 0.224, info: "Server: Encrypted packet (len=24)", packet: n.s([sshEnc(24, "SSH_MSG_CHANNEL_OPEN_CONFIRMATION", "message 91, recipient channel 0, sender channel 0, window and max packet size.", 0x6081)]) }),
    pkt("client", "server", "amber", "ENCRYPTED", ["CHANNEL_REQUEST", "exec \"uptime\""], { time: 0.2245, info: "Client: Encrypted packet (len=32)", packet: n.c([sshEnc(32, "SSH_MSG_CHANNEL_REQUEST", "message 98, channel 0, request \"exec\", want-reply true, command \"uptime\".", 0x6091)]) }),
  ],
  output: [
    pkt("server", "client", "violet", "ENCRYPTED", ["SUCCESS + DATA", "load average: 0.08"], { time: 0.262, info: "Server: Encrypted packet (len=120)", packet: n.s([sshEnc(16, "SSH_MSG_CHANNEL_SUCCESS", "message 99: the command started.", 0x6101), sshEnc(88, "SSH_MSG_CHANNEL_DATA", "message 94, channel 0, \" 10:42:01 up 12 days,  3:04,  1 user,  load average: 0.08, 0.05, 0.01\".", 0x6111)]) }),
    pkt("server", "client", "slate", "ENCRYPTED", ["EXIT_STATUS 0", "EOF, CLOSE"], { time: 0.263, info: "Server: Encrypted packet (len=104)", packet: n.s([sshEnc(40, "SSH_MSG_CHANNEL_REQUEST exit-status", "message 98, \"exit-status\", value 0: the command succeeded.", 0x6121), sshEnc(16, "SSH_MSG_CHANNEL_EOF", "message 96: no more output.", 0x6131), sshEnc(16, "SSH_MSG_CHANNEL_CLOSE", "message 97: channel 0 is closed.", 0x6141)]) }),
    pkt("client", "server", "slate", "ENCRYPTED", ["CHANNEL_CLOSE", "+ DISCONNECT"], { time: 0.2635, info: "Client: Encrypted packet (len=96)", packet: n.c([sshEnc(16, "SSH_MSG_CHANNEL_CLOSE", "message 97: closed on this side too.", 0x6151), sshEnc(40, "SSH_MSG_DISCONNECT", "message 1, reason 11 \"disconnected by user\".", 0x6161)]) }),
    pkt("client", "server", "slate", "FIN", [], { time: 0.264, info: `${SP} → 22 [FIN, ACK]`, packet: n.c([], "FA") }),
  ],
};

// ---------------------------------------------------------------- MITM scenario (host key changed)

const MP = 50998;
const m = conv({ sport: MP, cl: () => up(S), sl: () => down(S), cBase: 0x71d0e000, sBase: 0x22aa1000 });
const mitmDevices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: "café Wi-Fi", x: 9, y: 62 },
  { id: "attacker", kind: "attacker", label: "Attacker", sub: "same Wi-Fi", x: 24, y: 24 },
  { id: "router", kind: "ap", label: "Café Wi-Fi", sub: ADDR.router, x: 38, y: 62 },
  { id: "internet", kind: "cloud", label: "Internet", x: 62, y: 40 },
  { id: "server", kind: "server", label: "SSH server", sub: S, x: 87, y: 62 },
];
const mitmLinks: [string, string][] = [["client", "attacker"], ["attacker", "router"], ["router", "internet"], ["internet", "server"]];

// ---------------------------------------------------------------- brute force scenario (captured on the server)

const BP = 41822;
const botL = () => [eth({ src: "00:1b:21:aa:00:01", dst: ADDR.serverMac }), ipv4({ src: BOT, dst: S, ttl: 47, id: 0x2a10 })];
const srvL = () => [eth({ src: ADDR.serverMac, dst: "00:1b:21:aa:00:01" }), ipv4({ src: S, dst: BOT, ttl: 64, id: 0x51c0 })];
const b = conv({ sport: BP, cl: botL, sl: srvL, cBase: 0x0b0b0000, sBase: 0x5e5e0000 });
const BOT_BANNER = "SSH-2.0-libssh_0.9.6";

const base = homeToServer({ kind: "server", label: "SSH server", sub: S });
const bfDevices: Device[] = [...base.devices, { id: "attacker", kind: "attacker", label: "Scanning bot", sub: BOT, x: 40, y: 18 }];
const bfLinks: [string, string][] = [...base.links, ["attacker", "internet"]];

export default defineLesson({
  id: "ssh",
  name: "SSH",
  full: "Secure Shell",
  group: "security",
  layer: 7,
  difficulty: 2,
  tagline: "Log in to a remote machine without anyone listening in.",
  description:
    "SSH gives you an encrypted command line on a far-away computer. The two sides agree on fresh keys with Diffie-Hellman, the server proves who it is with its host key, and you prove who you are with a key pair instead of a password. Everything after that, including your password if you use one, travels encrypted.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP port 22"],
    ["Key exchange", "curve25519-sha256 (ECDH)"],
    ["Server proof", "Host key + known_hosts"],
    ["Packet", "length, padding length, payload, padding, MAC"],
    ["Defined in", "RFC 4251–4254"],
  ],
  ports: "TCP 22",
  rfc: "RFC 4253",
  keywords: ["openssh", "shell", "host key", "known_hosts", "kexinit", "curve25519", "ed25519", "public key", "authorized_keys", "fail2ban", "scp", "sftp", "port forwarding"],
  related: ["tcp", "tls", "wireguard"],
  ...base,
  legend: [
    ["green", "TCP setup and success"],
    ["blue", "Algorithm negotiation"],
    ["teal", "Key exchange"],
    ["amber", "Client messages"],
    ["violet", "Server messages"],
    ["red", "Attacks and warnings"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "ssh danish@server uptime",
      summary: "The laptop connects, agrees on keys, logs in with an Ed25519 key and runs one command.",
      kind: "normal",
      steps: [
        {
          title: "Connect and say hello",
          desc: "TCP to port 22, then version banners",
          detail:
            "After the TCP handshake, each side sends one plain text line naming the protocol version and its software. \"SSH-2.0\" means the modern protocol; SSH-1 is long dead and insecure. This is the only part of SSH that is readable text.",
          facts: [["Server", `${S}, TCP 22`], ["Client says", CLIENT_BANNER], ["Server says", "SSH-2.0-OpenSSH_9.6p1 Ubuntu"]],
          quiz: {
            q: "The banner travels before any keys exist. What can an observer learn from it?",
            options: ["Nothing, it is encrypted", "The software and version on each side", "The user name", "The password"],
            answer: 1,
            why: "Banners are clear text, so anyone on the path sees the SSH software and version. That is why scanners collect them.",
          },
          events: normalEvents.connect,
        },
        {
          title: "Swap algorithm lists",
          desc: "KEXINIT: here is what I support",
          detail:
            "Both sides send a KEXINIT packet at the same time. It lists, in order of preference, the key exchange methods, host key types, ciphers, MACs and compression they support. For each list, the first entry in the client's list that the server also has wins.",
          facts: [["Message code", "20 (KEXINIT)"], ["Chosen kex", "curve25519-sha256"], ["Chosen cipher", "chacha20-poly1305@openssh.com"]],
          quiz: {
            q: "Client prefers ssh-ed25519 first; the server lists rsa-sha2-512 first but also has ssh-ed25519. Which host key type is used?",
            options: ["rsa-sha2-512", "ssh-ed25519", "Both", "They fail to agree"],
            answer: 1,
            why: "SSH walks the client's list in order and takes the first one the server supports. The server's order does not matter.",
          },
          events: normalEvents.kexinit,
        },
        {
          title: "Elliptic curve key exchange",
          desc: "ECDH with curve25519, signed by the host key",
          detail:
            "The client sends a fresh X25519 public key. The server answers with its own fresh key, its long-term host key, and a signature over a hash of the whole conversation so far. Both sides now compute the same shared secret, which nobody watching can work out. The client checks the host key fingerprint against ~/.ssh/known_hosts.",
          facts: [["Message codes", "30 INIT, 31 REPLY"], ["Ephemeral keys", "32 bytes each (X25519)"], ["Host key", `Ed25519, ${FP_REAL.slice(0, 18)}…`]],
          quiz: {
            q: "Why does the server sign the exchange hash with its host key?",
            options: ["To compress the data", "To prove it is the real server, not someone in the middle", "To pick the cipher", "To encrypt the password"],
            answer: 1,
            why: "Only the holder of the host private key can make that signature. A man in the middle could do its own key exchange but could not sign as the real server.",
          },
          events: normalEvents.ecdh,
        },
        {
          title: "Switch on encryption",
          desc: "NEWKEYS: from now on, everything is encrypted",
          detail:
            "Each side sends NEWKEYS, a packet with no payload. Every packet after it is encrypted with keys derived from the shared secret, and a fresh set of keys is used in each direction. Look at the next packets: even the length field is now scrambled.",
          facts: [["Message code", "21 (NEWKEYS)"], ["Keys", "Separate for each direction"], ["Strict kex", "kex-strict (Terrapin fix)"]],
          events: normalEvents.newkeys,
        },
        {
          title: "Log in with a key",
          desc: "Public key authentication, fully encrypted",
          detail:
            "The client asks for the ssh-userauth service, then asks whether its public key is allowed for user danish. The server finds it in authorized_keys and says PK_OK. The client then signs the session ID with its private key. The private key never leaves the laptop, and there is no password to steal.",
          facts: [["User", "danish"], ["Method", "publickey (Ed25519)"], ["Server checks", "~/.ssh/authorized_keys"]],
          quiz: {
            q: "What does the client send to prove it owns the key?",
            options: ["The private key itself", "A signature made with the private key", "A password", "The host key"],
            answer: 1,
            why: "A signature proves ownership without revealing the private key. The server checks it with the public key it already has.",
          },
          events: normalEvents.auth,
        },
        {
          title: "Open a channel, run a command",
          desc: "CHANNEL_OPEN session, then exec",
          detail:
            "One SSH connection can carry many channels: shells, commands, file transfers and port forwards. The client opens a session channel and asks it to run \"uptime\". Each channel has its own flow control window so one busy channel can't block the others.",
          facts: [["Channel type", "session"], ["Request", "exec \"uptime\""], ["Window", "2 MB, max packet 32 KB"]],
          events: normalEvents.channel,
        },
        {
          title: "Output and goodbye",
          desc: "CHANNEL_DATA, exit status, close",
          detail:
            "The server sends the command's output in a CHANNEL_DATA message, then the exit status 0, EOF and CLOSE. The client closes its side, sends DISCONNECT and ends the TCP connection. Several SSH packets often share one TCP segment, as you can see in the capture.",
          facts: [["Output", "one line from uptime"], ["Exit status", "0 (success)"], ["Total time", "about 0.26 s"]],
          quiz: {
            q: "An observer counts the encrypted packets. What can they still learn?",
            options: ["The command typed", "Rough sizes and timing of the traffic", "The output", "The private key"],
            answer: 1,
            why: "Contents and even lengths are encrypted, but the number, size and timing of TCP segments are still visible. Random padding blurs sizes a little.",
          },
          events: normalEvents.output,
        },
      ],
      outro: {
        title: "Logged in, command run, all encrypted",
        text: "SSH agreed on algorithms, used X25519 to make a shared secret, proved the server's identity with a signed host key, and logged the user in with a key pair. Only the version banners and the key exchange were visible; everything else was ciphertext.",
        facts: [["Round trips", "about 7"], ["Clear text", "banners, KEXINIT, ECDH"], ["Auth", "Ed25519 key, no password"], ["Cipher", "chacha20-poly1305"]],
      },
    },
    {
      id: "host-key-changed",
      name: "Host key changed: someone in the middle?",
      summary: "On café Wi-Fi an attacker intercepts the connection, and OpenSSH refuses because the host key doesn't match known_hosts.",
      kind: "attack",
      devices: mitmDevices,
      links: mitmLinks,
      steps: [
        {
          title: "Intercepted on café Wi-Fi",
          desc: "The attacker answers in the server's name",
          detail:
            "The attacker on the same Wi-Fi has poisoned the laptop's ARP cache, so traffic for the router goes to the attacker first. When the laptop connects to port 22, the attacker's own SSH server answers, pretending to be the real one. From the laptop's side the packets look completely normal.",
          facts: [["Trick", "ARP spoofing on shared Wi-Fi"], ["Laptop thinks it talks to", S], ["Really talks to", "Attacker"]],
          events: [
            pkt("client", "attacker", "green", "SYN", ["port 22"], { time: 0, info: `${MP} → 22 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: m.syn() }),
            pkt("attacker", "client", "red", "SYN-ACK", ["from the attacker"], { time: 0.004, info: `22 → ${MP} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460`, packet: m.synack() }),
            pkt("client", "attacker", "green", "ACK", [], { time: 0.0042, info: `${MP} → 22 [ACK] Seq=1 Ack=1 Win=502 Len=0`, packet: m.c([], "A") }),
            pkt("client", "attacker", "amber", "BANNER", [CLIENT_BANNER], { time: 0.0043, info: `Client: Protocol (${CLIENT_BANNER})`, packet: m.c([banner(CLIENT_BANNER, "Client")]) }),
            pkt("attacker", "client", "red", "BANNER", ["copied banner"], { time: 0.009, info: `Server: Protocol (${SERVER_BANNER})`, packet: m.s([banner(SERVER_BANNER, "Server")]) }),
            note("attacker", "PRETENDING TO BE THE SERVER", "red"),
          ],
        },
        {
          title: "A different host key",
          desc: "The attacker can't sign with the real key",
          detail:
            "Key exchange runs as usual, but the attacker does not have the real server's private host key. To make a valid signature it must send its own host key instead. The fingerprint is now different from the one saved in known_hosts the first time the laptop connected.",
          facts: [["Saved fingerprint", `${FP_REAL.slice(0, 18)}…`], ["Received", `${FP_FAKE.slice(0, 18)}…`], ["Signature", "Valid, but for the wrong key"]],
          quiz: {
            q: "Why can't the attacker just send the real server's host key?",
            options: ["It is too long", "It can't make a matching signature without the real private key", "The client never checks it", "Host keys are encrypted"],
            answer: 1,
            why: "The public host key is easy to copy, but the signature over the exchange hash needs the private key, which stays on the real server.",
          },
          events: [
            pkt("client", "attacker", "blue", "KEXINIT", [], { time: 0.0095, info: "Client: Key Exchange Init", packet: m.c([clientKexinit()]) }),
            pkt("attacker", "client", "blue", "KEXINIT", [], { time: 0.0097, parallel: true, info: "Server: Key Exchange Init", packet: m.s([serverKexinit()]) }),
            pkt("client", "attacker", "teal", "ECDH INIT", [], { time: 0.01, info: "Client: Elliptic Curve Diffie-Hellman Key Exchange Init", packet: m.c([ecdhInit(0x3101)]) }),
            pkt("attacker", "client", "red", "ECDH REPLY", ["attacker's host key!"], { time: 0.014, info: "Server: Elliptic Curve Diffie-Hellman Key Exchange Reply, New Keys", packet: m.s([ecdhReply(0x9901, 0x3102), newkeys()]) }),
          ],
        },
        {
          title: "OpenSSH refuses",
          desc: "REMOTE HOST IDENTIFICATION HAS CHANGED!",
          detail:
            "OpenSSH compares the fingerprint, sees a mismatch, prints a large warning (\"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\") and stops with \"Host key verification failed\". It never sends NEWKEYS or any login data. If the server really was reinstalled, the admin should confirm the new fingerprint through another channel before you remove the old line with ssh-keygen -R.",
          facts: [["Result", "Host key verification failed"], ["Login data sent", "None"], ["Safe fix", "Check the new fingerprint out of band"]],
          quiz: {
            q: "The warning appears. What is the right thing to do?",
            options: ["Delete known_hosts and connect anyway", "Stop, and confirm the new fingerprint with the server's admin", "Use a password instead of a key", "Turn off StrictHostKeyChecking"],
            answer: 1,
            why: "Blindly accepting the new key hands your session to whoever is in the middle. Only accept it once someone you trust confirms the new fingerprint.",
          },
          events: [
            note("client", "REMOTE HOST IDENTIFICATION HAS CHANGED!", "red"),
            pkt("client", "attacker", "slate", "FIN", ["connection aborted"], { time: 0.015, info: `${MP} → 22 [FIN, ACK]`, packet: m.c([], "FA") }),
          ],
        },
      ],
      outro: {
        title: "The host key stopped the attack",
        text: "SSH trusts a server by remembering its host key the first time (trust on first use). A man in the middle can copy the banner and do its own key exchange, but it can't sign with the real host key, so the fingerprint changes and OpenSSH refuses to continue.",
        facts: [["Defence", "known_hosts fingerprint check"], ["Stronger", "SSHFP DNS records or SSH certificates"], ["Never", "Ignore the warning blindly"]],
      },
    },
    {
      id: "brute-force",
      name: "Password guessing bot vs key-only login",
      summary: "A bot tries root passwords; the server only accepts keys, and fail2ban blocks the bot's address.",
      kind: "attack",
      devices: bfDevices,
      links: bfLinks,
      steps: [
        {
          title: "A bot comes knocking",
          desc: "Internet scanners try port 22 all day",
          detail:
            "Any server with port 22 open sees thousands of login attempts a day from bots. This one connects and sends a libssh banner. The capture is now taken on the server, so the bot's address is the source.",
          facts: [["Bot", BOT], ["Banner", BOT_BANNER], ["Typical rate", "Thousands of tries per day"]],
          events: [
            pkt("attacker", "server", "red", "SYN", ["port 22"], { time: 0, info: `${BP} → 22 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: b.syn() }),
            pkt("server", "attacker", "green", "SYN-ACK", [], { time: 0.0001, info: `22 → ${BP} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460`, packet: b.synack() }),
            pkt("attacker", "server", "red", "ACK", [], { time: 0.08, info: `${BP} → 22 [ACK] Seq=1 Ack=1 Win=502 Len=0`, packet: b.c([], "A") }),
            pkt("attacker", "server", "red", "BANNER", [BOT_BANNER], { time: 0.0801, info: `Client: Protocol (${BOT_BANNER})`, packet: b.c([banner(BOT_BANNER, "Client")]) }),
            pkt("server", "attacker", "violet", "BANNER", ["OpenSSH_9.6p1"], { time: 0.0802, info: `Server: Protocol (${SERVER_BANNER})`, packet: b.s([banner(SERVER_BANNER, "Server")]) }),
          ],
        },
        {
          title: "Try a password",
          desc: "root / admin123, sent encrypted",
          detail:
            "After key exchange (not shown) the bot sends a USERAUTH_REQUEST for user root with method \"password\". It is encrypted, but the server decrypts it. This server has PasswordAuthentication no and PermitRootLogin no, so it answers USERAUTH_FAILURE and lists the only method it accepts: publickey.",
          facts: [["Tried", "root / admin123"], ["Server config", "PasswordAuthentication no"], ["Reply", "USERAUTH_FAILURE: publickey"]],
          quiz: {
            q: "With passwords turned off, how many guesses would the bot need to get in?",
            options: ["About a million", "It depends on the password", "Guessing can't work; it needs the private key", "Five"],
            answer: 2,
            why: "With key-only login there is no password to guess. The bot would have to steal a private key from someone's computer.",
          },
          events: [
            pkt("attacker", "server", "red", "ENCRYPTED", ["USERAUTH_REQUEST", "root / admin123"], { time: 0.4, info: "Client: Encrypted packet (len=72)", packet: b.c([sshEnc(72, "SSH_MSG_USERAUTH_REQUEST (password)", "message 50, user \"root\", service \"ssh-connection\", method \"password\", password \"admin123\".", 0x7001)]) }),
            pkt("server", "attacker", "violet", "ENCRYPTED", ["USERAUTH_FAILURE", "publickey only"], { time: 0.4012, info: "Server: Encrypted packet (len=32)", packet: b.s([sshEnc(32, "SSH_MSG_USERAUTH_FAILURE", "message 51, methods that can continue: \"publickey\", partial success false.", 0x7011)]) }),
            note("server", "PASSWORDS DISABLED", "green"),
          ],
        },
        {
          title: "fail2ban steps in",
          desc: "Too many failures, the address is banned",
          detail:
            "fail2ban reads sshd's log. After 5 failures from the same address within 10 minutes it adds a firewall rule that drops that address for an hour. The bot's next SYN never gets an answer. This keeps logs quiet and saves CPU, while key-only login is what actually keeps the door shut.",
          facts: [["Rule", "maxretry 5, findtime 10m, bantime 1h"], ["Action", "Firewall drop for " + BOT], ["Bot sees", "Timeouts"]],
          events: [
            note("server", "FAIL2BAN: BANNED " + BOT, "red"),
            pkt("attacker", "server", "red", "SYN", ["dropped by firewall"], { time: 31, lost: true, info: `41830 → 22 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`, packet: build(...botL(), tcp({ sport: 41830, dport: 22, seq: 0, flags: "S", opts: [{ mss: 1460 }], seqBase: 0x0c0c0000 })) }),
          ],
        },
      ],
      outro: {
        title: "The bot got nowhere",
        text: "Password guessing only works when passwords are allowed. Key-only login removes the target entirely, and fail2ban or rate limits stop the noise. Moving SSH behind a VPN or allowing only known addresses shrinks the exposure further.",
        facts: [["Main defence", "PasswordAuthentication no"], ["Also", "PermitRootLogin no"], ["Noise control", "fail2ban, rate limits"], ["Best", "Only reachable over VPN"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Message codes",
      items: [["1", "DISCONNECT"], ["5 / 6", "SERVICE_REQUEST / ACCEPT"], ["20", "KEXINIT"], ["21", "NEWKEYS"], ["30 / 31", "KEX_ECDH_INIT / REPLY"], ["50 / 51 / 52", "USERAUTH_REQUEST / FAILURE / SUCCESS"], ["90 / 91", "CHANNEL_OPEN / CONFIRMATION"], ["94", "CHANNEL_DATA"], ["98", "CHANNEL_REQUEST"]],
    },
    {
      title: "Binary packet",
      items: [["packet_length", "4 bytes"], ["padding_length", "1 byte"], ["payload", "message code + fields"], ["random padding", "4–255 bytes, total a multiple of 8 (or block size)"], ["MAC / tag", "after NEWKEYS, e.g. 16-byte Poly1305"]],
    },
    {
      title: "Files and settings",
      items: [["~/.ssh/known_hosts", "Remembered server host keys"], ["~/.ssh/authorized_keys", "Public keys allowed to log in"], ["PasswordAuthentication no", "Keys only"], ["ssh-keygen -R host", "Forget an old host key"]],
    },
  ],
});
