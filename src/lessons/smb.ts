import { Color, defineLesson, Device, note, pkt, PacketEvent } from "@/lib/lesson";
import { Bytes, u16le, u32le, utf16le } from "@/lib/bytes";
import { build, FieldSpec, LayerSpec, proto } from "@/lib/packet";
import { eth, ipv4, tcp, TcpOpt } from "@/lib/proto";
import { ADDR } from "./_common";

// ---------------------------------------------------------------- addresses

const FS = "192.168.1.20";
const FS_MAC = "00:15:5d:21:7c:04";
const OLD = "192.168.1.30";
const OLD_MAC = "00:0c:29:4e:11:9a";
const WORM = "192.168.1.66";
const WORM_MAC = "08:00:27:66:66:01";
const SHARE = "\\\\fileserver\\share";
const FILE = "reports\\q3-notes.txt";
const FILE_SIZE = 1180;
const SESSION = BigInt("0x0000100000000049");
const r = (n: number) => Number(n.toFixed(5));

// ---------------------------------------------------------------- little-endian field helpers (SMB is little-endian)

const u64le = (n: bigint): Bytes => Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * i)) & BigInt("0xff")));
const L16 = (name: string, n: number, value?: string, note?: string): FieldSpec => ({ name, bytes: u16le(n), value: value ?? String(n), note });
const L32 = (name: string, n: number, value?: string, note?: string): FieldSpec => ({ name, bytes: u32le(n >>> 0), value: value ?? String(n >>> 0), note });
const L64 = (name: string, n: bigint, value?: string, note?: string): FieldSpec => ({ name, bytes: u64le(n), value: value ?? String(n), note });
const U8 = (name: string, n: number, value?: string, note?: string): FieldSpec => ({ name, u8: n, value, note });
const hx = (n: number, w = 8) => `0x${(n >>> 0).toString(16).padStart(w, "0")}`;
/** FILETIME: 100-ns ticks since 1601 for 19 Nov 2026 10:15 UTC */
const FILETIME = BigInt("134395569000000000");
const sizeOf = (fs: FieldSpec[]) => build(proto({ id: "x", name: "x", fields: fs })).bytes.length;

// ---------------------------------------------------------------- SMB2 header and transport

const CMD: Record<number, string> = { 0: "NEGOTIATE", 1: "SESSION_SETUP", 3: "TREE_CONNECT", 5: "CREATE", 6: "CLOSE", 8: "READ" };
const STATUS: Record<number, string> = { 0: "STATUS_SUCCESS", 0xc0000016: "STATUS_MORE_PROCESSING_REQUIRED" };

interface Hdr { cmd: number; resp?: boolean; status?: number; mid: number; credits: number; tree?: number; session?: bigint; signed?: boolean }

const smb2Header = (h: Hdr): FieldSpec[] => {
  const flags = (h.resp ? 0x1 : 0) | (h.signed ? 0x8 : 0);
  const st = h.status ?? 0;
  return [
    { name: "ProtocolId", bytes: "fe534d42", value: "0xFE 'SMB'", note: "0xFE then the letters SMB marks an SMB2/3 message. SMB1 used 0xFF." },
    L16("StructureSize", 64, "64", "The SMB2 header is always 64 bytes."),
    L16("CreditCharge", 1, "1", "How many credits this message costs. Credits are how the server limits outstanding requests."),
    L32(h.resp ? "Status" : "ChannelSequence / Reserved", st, h.resp ? `${hx(st)} (${STATUS[st] ?? "?"})` : "0", h.resp ? "An NT status code. 0 means success." : undefined),
    L16("Command", h.cmd, `${h.cmd} (${CMD[h.cmd]})`),
    L16(h.resp ? "CreditResponse" : "CreditRequest", h.credits, String(h.credits), h.resp ? "Credits the server grants: how many more requests the client may have in flight." : "Credits the client asks for."),
    L32("Flags", flags, `${hx(flags)}${h.resp ? " (response" : " (request"}${h.signed ? ", signed)" : ")"}`, h.signed ? "Bit 0x08: this message carries a signature." : undefined),
    L32("NextCommand", 0, "0", "Offset of a chained (compound) command; 0 = none."),
    L64("MessageId", BigInt(h.mid), String(h.mid), "Counts up by one for each request; the reply repeats it."),
    L32("Reserved (ProcessId)", 0xfeff, "0x0000feff"),
    L32("TreeId", h.tree ?? 0, String(h.tree ?? 0), "Which connected share this is about. 0 before TREE_CONNECT."),
    L64("SessionId", h.session ?? BigInt("0"), h.session ? `0x${h.session.toString(16).padStart(16, "0")}` : "0", "Which logged-in session. 0 before SESSION_SETUP."),
    h.signed
      ? { name: "Signature", random: 16, value: "16 bytes (AES-128-GMAC)", note: "A keyed checksum over the whole message. Any change on the wire breaks it." }
      : { name: "Signature", zero: 16, value: "zeros (not signed)" },
  ];
};

/** NetBIOS Session Service header + SMB2 header + body */
const smb2 = (h: Hdr, bodyName: string, body: FieldSpec[]): LayerSpec[] => {
  const hdr = smb2Header(h);
  const total = sizeOf(hdr) + sizeOf(body);
  return [
    proto({ id: "nbss", name: "NetBIOS Session Service", osi: 5, summary: `NetBIOS Session Service, Length: ${total}`, fields: [
      { name: "Message type", u8: 0, value: "0x00 (Session message)" },
      { name: "Length", u24: total, value: String(total), note: "Length of the SMB message that follows (24 bits)." },
    ] }),
    proto({ id: "smb2", name: "SMB2 Header", summary: `SMB2 Header: ${CMD[h.cmd]} ${h.resp ? "Response" : "Request"}, MessageId ${h.mid}`, fields: hdr }),
    proto({ id: "smb2-body", name: bodyName, fields: body }),
  ];
};

// ---------------------------------------------------------------- the messages

const DIALECTS: [number, string][] = [[0x0202, "SMB 2.0.2"], [0x0210, "SMB 2.1"], [0x0300, "SMB 3.0"], [0x0302, "SMB 3.0.2"], [0x0311, "SMB 3.1.1"]];

const preauthCtx = (pad: boolean): FieldSpec => ({
  name: "Context: PREAUTH_INTEGRITY_CAPABILITIES", value: "SHA-512",
  note: "Both sides hash every message of the setup, so a tampered NEGOTIATE breaks the keys later.",
  fields: [
    L16("ContextType", 1, "0x0001 (PREAUTH_INTEGRITY)"), L16("DataLength", 38), L32("Reserved", 0),
    L16("HashAlgorithmCount", 1), L16("SaltLength", 32), L16("HashAlgorithm", 1, "0x0001 (SHA-512)"),
    { name: "Salt", random: 32 },
    ...(pad ? [{ name: "Padding", zero: 2 }] : []),
  ],
});
const encCtx = (ciphers: [number, string][]): FieldSpec => ({
  name: "Context: ENCRYPTION_CAPABILITIES", value: ciphers.map((c) => c[1]).join(", "),
  fields: [
    L16("ContextType", 2, "0x0002 (ENCRYPTION)"), L16("DataLength", 2 + 2 * ciphers.length), L32("Reserved", 0),
    L16("CipherCount", ciphers.length), ...ciphers.map(([c, n]) => L16("Cipher", c, `${hx(c, 4)} (${n})`)),
  ],
});

const negotiateReq = (): FieldSpec[] => [
  L16("StructureSize", 36), L16("DialectCount", DIALECTS.length),
  L16("SecurityMode", 1, "0x0001 (signing enabled)"), L16("Reserved", 0),
  L32("Capabilities", 0x7f, "0x0000007f (DFS, leasing, large MTU, multichannel, persistent handles, dir leasing, encryption)"),
  { name: "ClientGuid", random: 16 },
  L32("NegotiateContextOffset", 112, "112", "Counted from the start of the SMB2 header."), L16("NegotiateContextCount", 2), L16("Reserved2", 0),
  { name: "Dialects", value: "2.0.2, 2.1, 3.0, 3.0.2, 3.1.1", note: "Every version the client can speak. The server picks one.", fields: DIALECTS.map(([d, n]) => L16("Dialect", d, `${hx(d, 4)} (${n})`)) },
  { name: "Padding", zero: 2, value: "2 bytes", note: "Contexts start on an 8-byte boundary." },
  preauthCtx(true),
  encCtx([[0x0002, "AES-128-GCM"], [0x0001, "AES-128-CCM"]]),
];

const NEG_BLOB = 74;
const negotiateResp = (): FieldSpec[] => [
  L16("StructureSize", 65), L16("SecurityMode", 1, "0x0001 (signing enabled)"),
  L16("DialectRevision", 0x0311, "0x0311 (SMB 3.1.1)", "The server's choice: the newest dialect both sides know."),
  L16("NegotiateContextCount", 2), { name: "ServerGuid", random: 16 },
  L32("Capabilities", 0x6f, "0x0000006f"),
  L32("MaxTransactSize", 8388608), L32("MaxReadSize", 8388608), L32("MaxWriteSize", 8388608),
  L64("SystemTime", FILETIME, "Nov 19, 2026 10:15:00 UTC"), L64("ServerStartTime", BigInt("0")),
  L16("SecurityBufferOffset", 128), L16("SecurityBufferLength", NEG_BLOB),
  L32("NegotiateContextOffset", 208),
  { name: "Security blob (SPNEGO)", random: NEG_BLOB, opaque: true, value: `${NEG_BLOB} bytes`, note: "GSS-API/SPNEGO hint listing the login methods the server accepts (Kerberos, NTLMSSP). Not decoded here." },
  { name: "Padding", zero: 6 },
  preauthCtx(true),
  encCtx([[0x0002, "AES-128-GCM"]]),
];

const sessionSetupReq = (blob: number, what: string): FieldSpec[] => [
  L16("StructureSize", 25), U8("Flags", 0), U8("SecurityMode", 1, "0x01 (signing enabled)"),
  L32("Capabilities", 1, "0x00000001 (DFS)"), L32("Channel", 0),
  L16("SecurityBufferOffset", 88), L16("SecurityBufferLength", blob), L64("PreviousSessionId", BigInt("0")),
  { name: `Security blob (${what})`, random: blob, opaque: true, value: `${blob} bytes`, note: "NTLMSSP inside SPNEGO. Summarised in the step text, not decoded here." },
];
const sessionSetupResp = (blob: number, what: string, flags = 0): FieldSpec[] => [
  L16("StructureSize", 9), L16("SessionFlags", flags, flags === 4 ? "0x0004 (ENCRYPT_DATA)" : "0"),
  L16("SecurityBufferOffset", 72), L16("SecurityBufferLength", blob),
  { name: `Security blob (${what})`, random: blob, opaque: true, value: `${blob} bytes` },
];

const sharePath = utf16le(SHARE);
const treeReq = (): FieldSpec[] => [
  L16("StructureSize", 9), L16("Flags", 0), L16("PathOffset", 72), L16("PathLength", sharePath.length),
  { name: "Path (UTF-16LE)", bytes: sharePath, value: SHARE, note: "Server and share name, two bytes per character." },
];
const treeResp = (encrypt = false): FieldSpec[] => [
  L16("StructureSize", 16), U8("ShareType", 1, "0x01 (DISK)"), U8("Reserved", 0),
  L32("ShareFlags", encrypt ? 0x8000 : 0, encrypt ? "0x00008000 (ENCRYPT_DATA)" : "0x00000000"),
  L32("Capabilities", 0), L32("MaximalAccess", 0x001f01ff, "0x001f01ff (full control)"),
];

const fileName = utf16le(FILE);
const FILE_ID: FieldSpec = { name: "FileId", value: "Persistent 0x…0019, Volatile 0x…a311", fields: [L64("Persistent", BigInt("0x19"), "0x0000000000000019"), L64("Volatile", BigInt("0x10000000a311"), "0x000010000000a311")] };
const createReq = (): FieldSpec[] => [
  L16("StructureSize", 57), U8("SecurityFlags", 0), U8("RequestedOplockLevel", 0, "0 (none)"),
  L32("ImpersonationLevel", 2, "2 (Impersonation)"), L64("SmbCreateFlags", BigInt("0")), L64("Reserved", BigInt("0")),
  L32("DesiredAccess", 0x00120089, "0x00120089 (read data, read attributes, read EA, read control, synchronize)"),
  L32("FileAttributes", 0), L32("ShareAccess", 1, "0x00000001 (others may read)"),
  L32("CreateDisposition", 1, "1 (FILE_OPEN: only if it exists)"), L32("CreateOptions", 0x40, "0x00000040 (NON_DIRECTORY_FILE)"),
  L16("NameOffset", 120), L16("NameLength", fileName.length), L32("CreateContextsOffset", 0), L32("CreateContextsLength", 0),
  { name: "Name (UTF-16LE)", bytes: fileName, value: FILE, note: "Relative to the share, no leading backslash." },
];
const createResp = (): FieldSpec[] => [
  L16("StructureSize", 89), U8("OplockLevel", 0), U8("Flags", 0), L32("CreateAction", 1, "1 (FILE_OPENED)"),
  L64("CreationTime", FILETIME - BigInt("6048000000000"), "Nov 12, 2026"), L64("LastAccessTime", FILETIME, "Nov 19, 2026"),
  L64("LastWriteTime", FILETIME - BigInt("864000000000"), "Nov 18, 2026"), L64("ChangeTime", FILETIME - BigInt("864000000000"), "Nov 18, 2026"),
  L64("AllocationSize", BigInt("4096")), L64("EndofFile", BigInt(FILE_SIZE), `${FILE_SIZE} bytes`, "The file size."),
  L32("FileAttributes", 0x20, "0x00000020 (ARCHIVE)"), L32("Reserved2", 0), FILE_ID,
  L32("CreateContextsOffset", 0), L32("CreateContextsLength", 0),
];
const readReq = (): FieldSpec[] => [
  L16("StructureSize", 49), U8("Padding", 0x50, "0x50", "Where the server should put data in its reply (offset 80)."), U8("Flags", 0),
  L32("Length", FILE_SIZE, `${FILE_SIZE} bytes`), L64("Offset", BigInt("0"), "0", "Start reading at the beginning."), FILE_ID,
  L32("MinimumCount", 0), L32("Channel", 0), L32("RemainingBytes", 0), L16("ReadChannelInfoOffset", 0), L16("ReadChannelInfoLength", 0), U8("Buffer", 0),
];
const readResp = (): FieldSpec[] => [
  L16("StructureSize", 17), U8("DataOffset", 0x50, "80"), U8("Reserved", 0),
  L32("DataLength", FILE_SIZE), L32("DataRemaining", 0), L32("Flags", 0),
  { name: "File data", random: FILE_SIZE, opaque: true, value: `${FILE_SIZE} bytes`, note: "The file contents. Readable by anyone on the wire unless SMB encryption is on." },
];
const closeReq = (): FieldSpec[] => [L16("StructureSize", 24), L16("Flags", 0), L32("Reserved", 0), FILE_ID];
const closeResp = (): FieldSpec[] => [
  L16("StructureSize", 60), L16("Flags", 0), L32("Reserved", 0),
  L64("CreationTime", BigInt("0")), L64("LastAccessTime", BigInt("0")), L64("LastWriteTime", BigInt("0")), L64("ChangeTime", BigInt("0")),
  L64("AllocationSize", BigInt("0")), L64("EndofFile", BigInt("0")), L32("FileAttributes", 0),
];

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
    handshake: (t: number, rtt: number): PacketEvent[] => [
      pkt(a.id, b.id, "green", "SYN", [`to port ${b.port}`], {
        time: r(t), info: `${a.port} → ${b.port} [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM`,
        packet: send(true, "S", [], [{ mss: 1460 }, "nop", { ws: 8 }, "nop", "nop", "sackOk"]),
      }),
      pkt(b.id, a.id, "green", "SYN-ACK", ["port open"], {
        time: r(t + rtt), info: `${b.port} → ${a.port} [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1460 WS=256 SACK_PERM`,
        packet: send(false, "SA", [], [{ mss: 1460 }, "nop", { ws: 8 }, "nop", "nop", "sackOk"]),
      }),
      pkt(a.id, b.id, "green", "ACK", ["connected"], {
        time: r(t + rtt + 0.0001), info: `${a.port} → ${b.port} [ACK] Seq=1 Ack=1 Win=1026 Len=0`,
        packet: send(true, "A", []),
      }),
    ],
    rst: (fromA: boolean, color: Color, label: string, lines: string[], time: number, info: string): PacketEvent =>
      pkt(fromA ? a.id : b.id, fromA ? b.id : a.id, color, label, lines, { time: r(time), info, packet: send(fromA, "RA", []) }),
  };
}

const lanConv = (sport: number, bases: [number, number]) =>
  conversation(
    { id: "client", layers: () => [eth({ src: ADDR.laptopMac, dst: FS_MAC }), ipv4({ src: ADDR.laptop, dst: FS, ttl: 128 })], port: sport, base: bases[0], win: 1026 },
    { id: "server", layers: () => [eth({ src: FS_MAC, dst: ADDR.laptopMac }), ipv4({ src: FS, dst: ADDR.laptop, ttl: 128 })], port: 445, base: bases[1], win: 1026 }
  );

// ---------------------------------------------------------------- devices

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop (Windows)", sub: ADDR.laptop, x: 10, y: 62 },
  { id: "switch", kind: "switch", label: "Office switch", x: 42, y: 62 },
  { id: "server", kind: "nas", label: "fileserver", sub: FS, x: 82, y: 62 },
  { id: "dc", kind: "auth", label: "Domain controller", sub: "192.168.1.5", x: 62, y: 20 },
];
const links: [string, string][] = [["client", "switch"], ["switch", "server"], ["switch", "dc"]];

// ---------------------------------------------------------------- scenario 1

const C = lanConv(50544, [0x1e2d3c4b, 0x5a697887]);

const sessionSteps = (X: ReturnType<typeof lanConv>, t0: number, encrypt: boolean) => [
  X.a("amber", "SESSION", ["NTLMSSP_NEGOTIATE"], t0, "Session Setup Request, NTLMSSP_NEGOTIATE", smb2({ cmd: 1, mid: 1, credits: 33 }, "SESSION_SETUP Request", sessionSetupReq(74, "SPNEGO: NTLMSSP_NEGOTIATE"))),
  X.b("violet", "CHALLENGE", ["MORE_PROCESSING"], t0 + 0.0004, "Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE", smb2({ cmd: 1, resp: true, status: 0xc0000016, mid: 1, credits: 1, session: SESSION }, "SESSION_SETUP Response", sessionSetupResp(239, "SPNEGO: NTLMSSP_CHALLENGE"))),
  X.a("amber", "AUTH", ["NTLMSSP_AUTH", "danish"], t0 + 0.0006, "Session Setup Request, NTLMSSP_AUTH, User: OFFICE\\danish", smb2({ cmd: 1, mid: 2, credits: 33, session: SESSION }, "SESSION_SETUP Request", sessionSetupReq(526, "SPNEGO: NTLMSSP_AUTH"))),
  X.b("green", "SUCCESS", ["logged in", encrypt ? "encrypt data" : "signed"], t0 + 0.0031, "Session Setup Response", smb2({ cmd: 1, resp: true, status: 0, mid: 2, credits: 32, session: SESSION, signed: true }, "SESSION_SETUP Response", sessionSetupResp(9, "SPNEGO: accept-completed", encrypt ? 4 : 0))),
];

const normalSteps = [
  {
    title: "TCP to port 445",
    desc: "SMB runs straight over TCP",
    detail: "Danish opens \\\\fileserver\\share in File Explorer. Windows connects to TCP port 445. Every SMB message is then prefixed with a 4-byte NetBIOS Session Service header: one type byte (0) and a 24-bit length, so the receiver knows where each message ends in the TCP stream.",
    facts: [["Port", "TCP 445 (direct hosting)"], ["Framing", "4-byte NBSS header: type + 24-bit length"], ["Network", "Office LAN, < 1 ms"]] as [string, string][],
    events: C.handshake(0, 0.0003),
  },
  {
    title: "NEGOTIATE",
    desc: "Pick a dialect: 2.0.2 … 3.1.1",
    detail: "The client lists every SMB2/3 dialect it speaks, from 0x0202 to 0x0311, plus negotiate contexts for 3.1.1: a SHA-512 pre-authentication hash with a random salt, and the ciphers it supports. The server picks the newest common dialect, 3.1.1, and AES-128-GCM. Note the 64-byte SMB2 header starting with 0xFE 'SMB'.",
    facts: [["Offered", "0x0202, 0x0210, 0x0300, 0x0302, 0x0311"], ["Chosen", "0x0311 (SMB 3.1.1)"], ["Header", "64 bytes, starts 0xFE 'SMB'"]] as [string, string][],
    quiz: {
      q: "The client offers 2.0.2, 2.1, 3.0, 3.0.2 and 3.1.1. The server supports up to 3.1.1. Which does it choose?",
      options: ["2.0.2, the safest", "3.1.1, the highest both support", "3.0, a middle ground", "All of them"],
      answer: 1,
      why: "The server picks the highest dialect both sides know. 3.1.1 adds pre-auth integrity and AES-GCM.",
    },
    events: [
      C.a("amber", "NEGOTIATE", ["dialects 2.0.2…3.1.1"], 0.0005, "Negotiate Protocol Request", smb2({ cmd: 0, mid: 0, credits: 31 }, "NEGOTIATE Request", negotiateReq())),
      C.b("violet", "NEGOTIATE", ["3.1.1 + AES-GCM"], 0.0009, "Negotiate Protocol Response", smb2({ cmd: 0, resp: true, mid: 0, credits: 1 }, "NEGOTIATE Response", negotiateResp())),
    ],
  },
  {
    title: "SESSION_SETUP",
    desc: "Log in with NTLM (two round trips)",
    detail: "The laptop isn't using Kerberos here, so it falls back to NTLM, carried inside SPNEGO blobs. Round 1: the client says NEGOTIATE, the server answers with a random CHALLENGE and status MORE_PROCESSING_REQUIRED. Round 2: the client proves it knows the password by answering the challenge (the password itself is never sent). The server checks with the domain controller and returns SUCCESS, now signed.",
    facts: [["Round 1", "NEGOTIATE → CHALLENGE (0xC0000016)"], ["Round 2", "AUTHENTICATE → STATUS_SUCCESS"], ["Password", "Never sent; a challenge response is"]] as [string, string][],
    quiz: {
      q: "Why does the first SESSION_SETUP reply carry an error status?",
      options: ["The password was wrong", "MORE_PROCESSING_REQUIRED just means another round is needed", "The dialect is unsupported", "The share doesn't exist"],
      answer: 1,
      why: "0xC0000016 isn't a failure. It tells the client the login has more steps; here the NTLM challenge.",
    },
    events: [...sessionSteps(C, 0.001, false), note("server", "SESSION KEYS DERIVED", "green")],
  },
  {
    title: "TREE_CONNECT",
    desc: `Connect to ${SHARE}`,
    detail: `Now the client attaches to the share. The path ${SHARE} is sent in UTF-16LE, two bytes per character. The server replies with ShareType DISK and assigns TreeId 1, which every later request about this share carries. From now on every message is signed.`,
    facts: [["Path", SHARE], ["TreeId", "1"], ["Signing", "On: Flags 0x08 + 16-byte signature"]] as [string, string][],
    events: [
      C.a("amber", "TREE", [SHARE], 0.0045, `Tree Connect Request Tree: ${SHARE}`, smb2({ cmd: 3, mid: 3, credits: 64, session: SESSION, signed: true }, "TREE_CONNECT Request", treeReq())),
      C.b("violet", "TREE OK", ["TreeId 1", "DISK"], 0.0049, "Tree Connect Response", smb2({ cmd: 3, resp: true, mid: 3, credits: 64, tree: 1, session: SESSION, signed: true }, "TREE_CONNECT Response", treeResp())),
    ],
  },
  {
    title: "CREATE (open the file)",
    desc: "CREATE also means open",
    detail: `To read a file, SMB uses CREATE with disposition FILE_OPEN, meaning "open only if it already exists". The client asks for read access to ${FILE}. The server answers with the file's times, its size (${FILE_SIZE} bytes) and a 16-byte FileId that names this open handle.`,
    facts: [["Name", FILE], ["Disposition", "FILE_OPEN (1)"], ["Result", `FILE_OPENED, ${FILE_SIZE} bytes, FileId`]] as [string, string][],
    quiz: {
      q: "Which SMB2 command opens an existing file for reading?",
      options: ["OPEN", "READ", "CREATE with FILE_OPEN", "TREE_CONNECT"],
      answer: 2,
      why: "SMB2 has no separate OPEN. CREATE does both, and CreateDisposition decides whether to open, create or overwrite.",
    },
    events: [
      C.a("amber", "CREATE", [FILE.split("\\")[1]], 0.0052, `Create Request File: ${FILE}`, smb2({ cmd: 5, mid: 4, credits: 64, tree: 1, session: SESSION, signed: true }, "CREATE Request", createReq())),
      C.b("violet", "CREATE OK", ["FileId", `${FILE_SIZE} bytes`], 0.0057, `Create Response File: ${FILE}`, smb2({ cmd: 5, resp: true, mid: 4, credits: 64, tree: 1, session: SESSION, signed: true }, "CREATE Response", createResp())),
    ],
  },
  {
    title: "READ and CLOSE",
    desc: "Read the bytes, release the handle",
    detail: `READ asks for ${FILE_SIZE} bytes from offset 0 using the FileId. The response puts the data at offset 80 from the header start. Then CLOSE releases the handle. The file contents travel signed but not encrypted: signing stops tampering, but someone capturing the LAN could still read them.`,
    facts: [["READ", `${FILE_SIZE} bytes at offset 0`], ["DataOffset", "80 (64 header + 16 body)"], ["CLOSE", "Frees the FileId"]] as [string, string][],
    quiz: {
      q: "Signing is on, encryption is off. What can someone capturing the LAN do?",
      options: ["Nothing at all", "Read the file contents, but not change them unnoticed", "Change the file without detection", "Read the password"],
      answer: 1,
      why: "Signing protects integrity, not privacy. To hide the contents you need SMB 3 encryption.",
    },
    events: [
      C.a("amber", "READ", [`${FILE_SIZE} bytes @ 0`], 0.006, `Read Request Len:${FILE_SIZE} Off:0 File: ${FILE}`, smb2({ cmd: 8, mid: 5, credits: 64, tree: 1, session: SESSION, signed: true }, "READ Request", readReq())),
      C.b("violet", "DATA", [`${FILE_SIZE} bytes`], 0.0066, `Read Response`, smb2({ cmd: 8, resp: true, mid: 5, credits: 64, tree: 1, session: SESSION, signed: true }, "READ Response", readResp())),
      C.a("slate", "CLOSE", ["FileId"], 0.007, `Close Request File: ${FILE}`, smb2({ cmd: 6, mid: 6, credits: 64, tree: 1, session: SESSION, signed: true }, "CLOSE Request", closeReq())),
      C.b("slate", "CLOSED", [], 0.0073, "Close Response", smb2({ cmd: 6, resp: true, mid: 6, credits: 64, tree: 1, session: SESSION, signed: true }, "CLOSE Response", closeResp())),
      note("client", "FILE OPENED IN NOTEPAD", "green"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 2: encryption on SMB 3.1.1

const E = lanConv(50560, [0x0abcdef0, 0x76543210]);

/** SMB2 TRANSFORM_HEADER (52 bytes) + ciphertext of the original message */
const encrypted = (inner: LayerSpec[], label: string): LayerSpec[] => {
  const innerLen = build(...inner.slice(1)).bytes.length; // the SMB2 message without its NBSS header
  const fields: FieldSpec[] = [
    { name: "ProtocolId", bytes: "fd534d42", value: "0xFD 'SMB'", note: "0xFD marks an encrypted SMB3 message." },
    { name: "Signature", random: 16, value: "16 bytes (AES-GCM tag)", note: "The authentication tag: proves nothing was changed." },
    { name: "Nonce", fields: [{ name: "AES-GCM nonce", random: 12 }, { name: "Unused", zero: 4 }], value: "12-byte nonce + 4 zero bytes" },
    L32("OriginalMessageSize", innerLen, String(innerLen), "Size of the hidden SMB2 message."),
    L16("Reserved", 0), L16("Flags", 1, "0x0001 (Encrypted)"),
    L64("SessionId", SESSION, `0x${SESSION.toString(16).padStart(16, "0")}`, "Tells the receiver which session key to decrypt with."),
  ];
  const transform = proto({ id: "smb2-transform", name: "SMB2 Transform Header", summary: `SMB2 Transform Header (encrypted ${label})`, fields: [...fields, { name: `Encrypted SMB2 message (${label})`, random: innerLen, opaque: true, value: `${innerLen} bytes` }] });
  const total = build(transform).bytes.length;
  return [
    proto({ id: "nbss", name: "NetBIOS Session Service", osi: 5, summary: `NetBIOS Session Service, Length: ${total}`, fields: [{ name: "Message type", u8: 0, value: "0x00 (Session message)" }, { name: "Length", u24: total }] }),
    transform,
  ];
};

const encryptSteps = [
  {
    title: "Negotiate and log in",
    desc: "Same start, but the server wants encryption",
    detail: "This time the admin has switched on encryption for the share (or the whole server). NEGOTIATE settles on SMB 3.1.1 with AES-128-GCM, exactly as before. The final SESSION_SETUP response sets SessionFlags ENCRYPT_DATA: from here on, every message must be encrypted.",
    facts: [["Dialect", "3.1.1"], ["Cipher", "AES-128-GCM"], ["SessionFlags", "0x0004 ENCRYPT_DATA"]] as [string, string][],
    events: [
      ...E.handshake(0, 0.0003),
      E.a("amber", "NEGOTIATE", ["2.0.2…3.1.1"], 0.0005, "Negotiate Protocol Request", smb2({ cmd: 0, mid: 0, credits: 31 }, "NEGOTIATE Request", negotiateReq())),
      E.b("violet", "NEGOTIATE", ["3.1.1 + AES-GCM"], 0.0009, "Negotiate Protocol Response", smb2({ cmd: 0, resp: true, mid: 0, credits: 1 }, "NEGOTIATE Response", negotiateResp())),
      ...sessionSteps(E, 0.001, true),
    ],
  },
  {
    title: "Everything inside 0xFD 'SMB'",
    desc: "The TRANSFORM_HEADER hides the real command",
    detail: "Now TREE_CONNECT, CREATE and READ are each wrapped in a 52-byte TRANSFORM_HEADER that starts with 0xFD 'SMB'. It carries a nonce, the GCM tag and the SessionId; the original 64-byte header and body are ciphertext. A capture can't even tell which command is inside, only its size.",
    facts: [["Header", "0xFD 'SMB', 52 bytes"], ["Hidden", "Command, path, file names, data"], ["Visible", "SessionId, sizes"]] as [string, string][],
    quiz: {
      q: "Looking at an encrypted SMB3 packet, what can an observer still learn?",
      options: ["The file name", "The share path", "The SessionId and the message size", "The file contents"],
      answer: 2,
      why: "The transform header itself is clear: SessionId, nonce, size. Everything about the actual request is encrypted.",
    },
    events: [
      E.a("teal", "ENCRYPTED", ["(TREE_CONNECT)"], 0.0045, "Encrypted SMB3", encrypted(smb2({ cmd: 3, mid: 3, credits: 64, session: SESSION }, "TREE_CONNECT Request", treeReq()), "TREE_CONNECT")),
      E.b("teal", "ENCRYPTED", ["(TREE_CONNECT ok)"], 0.0049, "Encrypted SMB3", encrypted(smb2({ cmd: 3, resp: true, mid: 3, credits: 64, tree: 1, session: SESSION }, "TREE_CONNECT Response", treeResp(true)), "TREE_CONNECT")),
      E.a("teal", "ENCRYPTED", ["(CREATE)"], 0.0052, "Encrypted SMB3", encrypted(smb2({ cmd: 5, mid: 4, credits: 64, tree: 1, session: SESSION }, "CREATE Request", createReq()), "CREATE")),
      E.b("teal", "ENCRYPTED", ["(CREATE ok)"], 0.0057, "Encrypted SMB3", encrypted(smb2({ cmd: 5, resp: true, mid: 4, credits: 64, tree: 1, session: SESSION }, "CREATE Response", createResp()), "CREATE")),
    ],
  },
  {
    title: "The file, encrypted",
    desc: "READ data is ciphertext on the wire",
    detail: "The READ response carries the same 1180 bytes, but now as ciphertext with a GCM tag. Any change breaks the tag, so encryption gives both privacy and integrity, and SMB doesn't need a separate signature. Cost: a little CPU, which modern AES instructions make tiny.",
    facts: [["Privacy", "Yes"], ["Integrity", "Yes (GCM tag)"], ["Turn on", "Set-SmbServerConfiguration -EncryptData $true"]] as [string, string][],
    events: [
      E.a("teal", "ENCRYPTED", ["(READ)"], 0.006, "Encrypted SMB3", encrypted(smb2({ cmd: 8, mid: 5, credits: 64, tree: 1, session: SESSION }, "READ Request", readReq()), "READ")),
      E.b("teal", "ENCRYPTED", ["(file data)"], 0.0066, "Encrypted SMB3", encrypted(smb2({ cmd: 8, resp: true, mid: 5, credits: 64, tree: 1, session: SESSION }, "READ Response", readResp()), "READ")),
      note("switch", "CAPTURE SHOWS ONLY CIPHERTEXT", "green"),
    ],
  },
];

// ---------------------------------------------------------------- scenario 3: SMBv1 worm, and why SMBv1 is off

const attackDevices: Device[] = [
  { id: "worm", kind: "attacker", label: "Infected PC", sub: WORM, x: 12, y: 22 },
  { id: "switch", kind: "switch", label: "Office switch", x: 42, y: 55 },
  { id: "old", kind: "server", label: "Old server (SMBv1 on)", sub: OLD, x: 84, y: 24 },
  { id: "server", kind: "nas", label: "fileserver (SMBv1 off)", sub: FS, x: 84, y: 76 },
  { id: "client", kind: "laptop", label: "Laptop", sub: ADDR.laptop, x: 12, y: 78 },
];
const attackLinks: [string, string][] = [["worm", "switch"], ["switch", "old"], ["switch", "server"], ["client", "switch"]];

const wormConv = (id: string, ip: string, mac: string, sport: number, bases: [number, number]) =>
  conversation(
    { id: "worm", layers: () => [eth({ src: WORM_MAC, dst: mac }), ipv4({ src: WORM, dst: ip, ttl: 128 })], port: sport, base: bases[0], win: 1026 },
    { id, layers: () => [eth({ src: mac, dst: WORM_MAC }), ipv4({ src: ip, dst: WORM, ttl: 128 })], port: 445, base: bases[1], win: 1026 }
  );
const W1 = wormConv("old", OLD, OLD_MAC, 49301, [0x11112222, 0x33334444]);
const W2 = wormConv("server", FS, FS_MAC, 49302, [0x55556666, 0x77778888]);

const DIALECT_V1 = "NT LM 0.12";
const smb1Negotiate = (): LayerSpec[] => {
  const dialectBytes: FieldSpec = { name: "Dialect", fields: [{ name: "Buffer format", u8: 2, value: "0x02 (dialect)" }, { name: "Name", text: DIALECT_V1 + "\0", value: DIALECT_V1 }], value: DIALECT_V1 };
  const fields: FieldSpec[] = [
    { name: "Protocol", bytes: "ff534d42", value: "0xFF 'SMB'", note: "0xFF marks SMB1, the 1990s version." },
    U8("Command", 0x72, "0x72 (Negotiate Protocol)"),
    L32("Status", 0), U8("Flags", 0x18, "0x18"), L16("Flags2", 0xc853, "0xc853"),
    L16("PID High", 0), { name: "Security features", zero: 8 }, L16("Reserved", 0),
    L16("TID", 0xffff, "65535"), L16("PID Low", 0xfeff), L16("UID", 0), L16("MID", 0),
    U8("Word count", 0), L16("Byte count", 12), dialectBytes,
  ];
  const total = sizeOf(fields);
  return [
    proto({ id: "nbss", name: "NetBIOS Session Service", osi: 5, summary: `NetBIOS Session Service, Length: ${total}`, fields: [{ name: "Message type", u8: 0, value: "0x00 (Session message)" }, { name: "Length", u24: total }] }),
    proto({ id: "smb", name: "SMB (version 1)", summary: `SMB (Server Message Block Protocol v1): Negotiate Protocol Request, dialect "${DIALECT_V1}"`, fields }),
  ];
};

const attackSteps = [
  {
    title: "A worm scans port 445",
    desc: "Looking for machines that still speak SMBv1",
    detail: "A PC on the office network is infected with a worm of the WannaCry/NotPetya family. It connects to every address on port 445 and offers only the old SMB1 dialect \"NT LM 0.12\". Machines that accept SMB1 and lack the 2017 MS17-010 patch can be taken over remotely without any password. We only show the harmless first message here.",
    facts: [["Target", "TCP 445 across the LAN"], ["Offers", `SMB1 dialect "${DIALECT_V1}" only`], ["Known flaw", "MS17-010 (EternalBlue), patched 2017"]] as [string, string][],
    events: [
      ...W1.handshake(0, 0.0003),
      W1.a("red", "SMB1 NEG", [DIALECT_V1], 0.0005, `Negotiate Protocol Request (SMB1, "${DIALECT_V1}")`, smb1Negotiate()),
    ],
  },
  {
    title: "The old server answers",
    desc: "SMBv1 still on: the worm has a way in",
    detail: "The old server still has SMBv1 enabled, so it answers the negotiation and the worm continues to its exploit stage. Worms like this spread from machine to machine in minutes across flat networks, encrypting files as they go. The fix is not clever detection, it's removing the target: patch, and turn SMBv1 off.",
    facts: [["Old server", "SMBv1 enabled, unpatched"], ["Risk", "Remote code execution, no login"], ["Spread", "Minutes, across a flat LAN"]] as [string, string][],
    quiz: {
      q: "What is the most effective defence against this kind of SMBv1 worm?",
      options: ["A longer password", "Disable SMBv1, apply MS17-010, and block 445 between network segments", "Use FTP instead", "Change the share name"],
      answer: 1,
      why: "The flaw needs no password at all. Removing SMBv1, patching and limiting who can reach 445 removes the path.",
    },
    events: [
      W1.b("red", "SMB1 OK", ["NT LM 0.12 accepted"], 0.0009, "Negotiate Protocol Response (SMB1)", [
        proto({ id: "nbss", name: "NetBIOS Session Service", osi: 5, fields: [{ name: "Message type", u8: 0, value: "0x00" }, { name: "Length", u24: 35 }] }),
        proto({ id: "smb", name: "SMB (version 1)", summary: "SMB v1: Negotiate Protocol Response (header only shown)", fields: [{ name: "Protocol", bytes: "ff534d42", value: "0xFF 'SMB'" }, U8("Command", 0x72, "0x72 (Negotiate Protocol)"), L32("Status", 0, "STATUS_SUCCESS"), U8("Flags", 0x98), L16("Flags2", 0xc853), { name: "Rest of header", zero: 20 }, U8("Word count", 0), L16("Byte count", 0)] }),
      ]),
      note("old", "VULNERABLE: SMBv1 ON", "red"),
    ],
  },
  {
    title: "SMBv1 off: connection reset",
    desc: "The modern server refuses outright",
    detail: "The worm tries the file server too. SMBv1 is disabled there (the default since Windows 10 1709 and Server 2019), so there is no common dialect. The server simply resets the TCP connection. There's nothing to exploit. Danish's laptop keeps using SMB 3.1.1 as normal.",
    facts: [["Server", "SMBv1 disabled"], ["Answer", "TCP RST"], ["Check", "Get-SmbServerConfiguration | Select EnableSMB1Protocol"]] as [string, string][],
    events: [
      ...W2.handshake(0.01, 0.0003),
      W2.a("red", "SMB1 NEG", [DIALECT_V1], 0.0105, `Negotiate Protocol Request (SMB1, "${DIALECT_V1}")`, smb1Negotiate()),
      W2.rst(false, "green", "RST", ["no SMB1 here"], 0.0107, `445 → 49302 [RST, ACK]`),
      note("server", "SMBv1 DISABLED: NOTHING TO ATTACK", "green"),
    ],
  },
];

export default defineLesson({
  id: "smb",
  name: "SMB",
  full: "Server Message Block 2/3",
  group: "mail-files",
  layer: 7,
  difficulty: 3,
  tagline: "How Windows opens files on a shared drive.",
  description:
    "SMB is the protocol behind Windows file shares and most NAS boxes. After choosing a dialect and logging in, the client connects to a share, opens files with CREATE, reads them and closes them, all over one TCP connection on port 445. SMB 3 adds signing and encryption; the old SMBv1 should be switched off.",
  facts: [
    ["Layer", "Application (Layer 7)"],
    ["Transport", "TCP 445 (NetBIOS framing header)"],
    ["Defined in", "Microsoft [MS-SMB2]"],
    ["Header", "64 bytes, 0xFE 'SMB', little-endian"],
    ["Dialects", "2.0.2, 2.1, 3.0, 3.0.2, 3.1.1"],
    ["Security", "Signing, AES encryption (3.x)"],
  ],
  ports: "445 (direct), 139 (old NetBIOS)",
  rfc: "MS-SMB2 (Microsoft open specification)",
  keywords: ["windows share", "file share", "cifs", "samba", "smb2", "smb3", "ntlm", "tree connect", "smbv1", "eternalblue", "wannacry", "signing", "encryption", "445", "nas"],
  related: ["tcp", "ftp", "kerberos", "ldap"],
  devices,
  links,
  legend: [
    ["green", "Handshake and success"],
    ["amber", "Requests from the laptop"],
    ["violet", "Server responses"],
    ["teal", "Encrypted SMB3"],
    ["red", "Attack traffic"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Open a file on \\\\fileserver\\share",
      summary: "NEGOTIATE, NTLM login, TREE_CONNECT, CREATE, READ and CLOSE over port 445.",
      kind: "normal",
      steps: normalSteps,
      outro: {
        title: "File read",
        text: "Seven SMB exchanges took under 8 milliseconds on the LAN: pick a dialect, log in, attach to the share, open, read and close the file. Every message after login was signed, so nobody could change it on the way.",
        facts: [["Dialect", "SMB 3.1.1"], ["Login", "NTLM in 2 round trips"], ["Handles", "TreeId 1, one FileId"], ["Total time", "7.3 ms"]],
      },
    },
    {
      id: "encrypted",
      name: "SMB 3.1.1 with encryption on",
      summary: "The server requires encryption, so every message after login is wrapped in an AES-GCM transform header.",
      kind: "failure",
      steps: encryptSteps,
      outro: {
        title: "Private and tamper-proof",
        text: "With encryption required, the same requests were wrapped in 0xFD 'SMB' transform headers. A capture shows only session IDs and sizes, not the share, the file name or its contents.",
        facts: [["Signing", "Integrity only"], ["Encryption", "Integrity + privacy"], ["Cipher", "AES-128-GCM"]],
      },
    },
    {
      id: "smbv1",
      name: "SMBv1 worm: why SMBv1 is disabled",
      summary: "A worm probes port 445 with SMB1. The old server answers; the modern one resets the connection.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: attackSteps,
      outro: {
        title: "Remove the old door",
        text: "SMBv1 is decades old and was the entry point for the 2017 WannaCry and NotPetya outbreaks. The defence is simple: patch, disable SMBv1 everywhere, require SMB signing or encryption, and never expose port 445 to the internet.",
        facts: [["Disable", "SMBv1 on every machine"], ["Patch", "MS17-010 and later"], ["Firewall", "Block 445 at the internet edge and between segments"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Commands",
      items: [["NEGOTIATE", "Pick dialect and capabilities"], ["SESSION_SETUP", "Log in (Kerberos or NTLM)"], ["TREE_CONNECT", "Attach to \\\\server\\share"], ["CREATE", "Open or create a file"], ["READ / WRITE", "Move bytes"], ["CLOSE", "Release the FileId"], ["LOGOFF", "End the session"]],
    },
    {
      title: "Magic numbers",
      items: [["0xFF 'SMB'", "SMB1 (disable it)"], ["0xFE 'SMB'", "SMB2/3 header, 64 bytes"], ["0xFD 'SMB'", "SMB3 encrypted (transform header)"], ["0xC0000016", "MORE_PROCESSING_REQUIRED"], ["0x0311", "Dialect SMB 3.1.1"]],
    },
    {
      title: "Ports",
      items: [["445", "SMB over TCP"], ["139", "SMB over NetBIOS (legacy)"]],
    },
  ],
});
