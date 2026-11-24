// Low-level byte helpers used by the packet builders.

export type Bytes = number[];

export const u8 = (n: number): Bytes => [n & 0xff];
export const u16 = (n: number): Bytes => [(n >>> 8) & 0xff, n & 0xff];
export const u24 = (n: number): Bytes => [(n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
export const u32 = (n: number): Bytes => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
export const u64 = (n: number | bigint): Bytes => {
  let b = BigInt(n);
  const out: number[] = [];
  for (let i = 0; i < 8; i++) {
    out.unshift(Number(b & BigInt(0xff)));
    b >>= BigInt(8);
  }
  return out;
};
export const u16le = (n: number): Bytes => [n & 0xff, (n >>> 8) & 0xff];
export const u32le = (n: number): Bytes => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];

/** "de ad be ef" / "deadbeef" / "de:ad:be:ef" -> bytes */
export const hex = (s: string): Bytes => {
  const clean = s.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2) throw new Error(`hex(): odd length "${s}"`);
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 2) out.push(parseInt(clean.slice(i, i + 2), 16));
  return out;
};

export const text = (s: string): Bytes => Array.from(new TextEncoder().encode(s));
export const utf16le = (s: string): Bytes => {
  const out: number[] = [];
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    out.push(c & 0xff, c >>> 8);
  }
  return out;
};

export const zeros = (n: number): Bytes => new Array(n).fill(0);

/** Deterministic pseudo-random bytes so every page load shows the same "random" values. */
export const rand = (n: number, seed = 1): Bytes => {
  let x = (seed * 2654435761) >>> 0 || 0x9e3779b9;
  const out: number[] = [];
  for (let i = 0; i < n; i++) {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    out.push(x & 0xff);
  }
  return out;
};

export const ip4 = (s: string): Bytes => {
  const parts = s.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) throw new Error(`bad IPv4 ${s}`);
  return parts;
};

export const ip6 = (s: string): Bytes => {
  const [head, tail] = s.split("::");
  const h = head ? head.split(":") : [];
  const t = tail !== undefined ? (tail ? tail.split(":") : []) : [];
  if (tail === undefined && h.length !== 8) throw new Error(`bad IPv6 ${s}`);
  const fill = 8 - h.length - t.length;
  const groups = [...h, ...new Array(Math.max(0, fill)).fill("0"), ...t];
  return groups.flatMap((g) => u16(parseInt(g, 16)));
};

export const mac = (s: string): Bytes => hex(s);

export const toHex = (b: Bytes, sep = " "): string => b.map((x) => x.toString(16).padStart(2, "0")).join(sep);
export const fmtMac = (b: Bytes) => toHex(b, ":");
export const fmtIp4 = (b: Bytes) => b.join(".");
export const fmtIp6 = (b: Bytes): string => {
  const g: string[] = [];
  for (let i = 0; i < 16; i += 2) g.push(((b[i] << 8) | b[i + 1]).toString(16));
  // compress the longest run of zero groups
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (g[i] === "0") {
      let j = i;
      while (j < 8 && g[j] === "0") j++;
      if (j - i > bestLen) { best = i; bestLen = j - i; }
      i = j;
    } else i++;
  }
  if (bestLen > 1) {
    const left = g.slice(0, best).join(":");
    const right = g.slice(best + bestLen).join(":");
    return `${left}::${right}`;
  }
  return g.join(":");
};

/** RFC 1071 internet checksum */
export const inetChecksum = (data: Bytes): number => {
  let sum = 0;
  for (let i = 0; i < data.length; i += 2) {
    sum += (data[i] << 8) + (i + 1 < data.length ? data[i + 1] : 0);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  }
  return ~sum & 0xffff;
};

/** CRC-32 (IEEE), used for STUN fingerprints, Ethernet FCS examples etc. */
let crcTable: number[] | null = null;
export const crc32 = (data: Bytes): number => {
  if (!crcTable) {
    crcTable = [];
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable.push(c >>> 0);
    }
  }
  let crc = 0xffffffff;
  for (const b of data) crc = crcTable[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
};

/** CRC-16/MODBUS */
export const crc16modbus = (data: Bytes): number => {
  let crc = 0xffff;
  for (const b of data) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = crc & 1 ? (crc >>> 1) ^ 0xa001 : crc >>> 1;
  }
  return crc;
};

export const fmtBytes = (n: number): string =>
  n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
