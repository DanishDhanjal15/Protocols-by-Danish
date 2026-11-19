// The packet model: a packet is a stack of layers, each layer a list of fields,
// each field owning real bytes. The inspector and the hex view read this, and
// the .pcap exporter writes the concatenated bytes.

import { Bytes, hex as hexBytes, rand, text, u16, u24, u32, u64, u8, zeros, toHex } from "./bytes";

export type Osi = 1 | 2 | 3 | 4 | 5 | 6 | 7;

export interface Field {
  name: string;
  value: string;
  note?: string;
  bytes: Bytes;
  children?: Field[];
  /** bytes the lesson cannot show in clear: encrypted, random or file contents */
  opaque?: boolean;
}

export interface Layer {
  id: string;
  name: string;
  osi: Osi;
  summary: string;
  fields: Field[];
  /** fields that sit after the payload (Ethernet padding, FCS, MIC...) */
  trailer?: Field[];
}

export interface BuiltPacket {
  layers: Layer[];
  bytes: Bytes;
}

export interface Ctx {
  ipSrc?: Bytes;
  ipDst?: Bytes;
  ipVersion?: 4 | 6;
  /** spec that wraps the current one (outer) and the one inside it */
  outer?: LayerSpec;
  inner?: LayerSpec;
}

export interface LayerSpec {
  kind: string;
  /** EtherType this layer has when carried directly in Ethernet */
  ethertype?: number;
  /** IP protocol number this layer has when carried in IP */
  ipProto?: number;
  meta?: (ctx: Ctx) => void;
  build: (payload: Bytes, ctx: Ctx) => Layer;
}

/** Field description used by lesson authors. Exactly one byte source should be given. */
export interface FieldSpec {
  name: string;
  bytes?: Bytes | string; // raw bytes or hex string
  u8?: number;
  u16?: number;
  u24?: number;
  u32?: number;
  u64?: number | bigint;
  text?: string;
  random?: number; // n deterministic "random" bytes
  zero?: number; // n zero bytes
  value?: string; // display value (defaults to a sensible rendering)
  note?: string;
  opaque?: boolean;
  seed?: number;
  fields?: FieldSpec[]; // sub-fields: bytes are the concatenation
}

let seedCounter = 7;

export function field(spec: FieldSpec): Field {
  if (spec.fields) {
    const children = spec.fields.map(field);
    const bytes = children.flatMap((c) => c.bytes);
    return {
      name: spec.name,
      value: spec.value ?? `${bytes.length} bytes`,
      note: spec.note,
      bytes,
      children,
      opaque: spec.opaque,
    };
  }
  let bytes: Bytes;
  let value: string | undefined = spec.value;
  if (spec.bytes !== undefined) {
    bytes = typeof spec.bytes === "string" ? hexBytes(spec.bytes) : spec.bytes;
    value ??= bytes.length <= 8 ? `0x${toHex(bytes, "")}` : `${bytes.length} bytes`;
  } else if (spec.u8 !== undefined) {
    bytes = u8(spec.u8);
    value ??= String(spec.u8);
  } else if (spec.u16 !== undefined) {
    bytes = u16(spec.u16);
    value ??= String(spec.u16);
  } else if (spec.u24 !== undefined) {
    bytes = u24(spec.u24);
    value ??= String(spec.u24);
  } else if (spec.u32 !== undefined) {
    bytes = u32(spec.u32);
    value ??= String(spec.u32 >>> 0);
  } else if (spec.u64 !== undefined) {
    bytes = u64(spec.u64);
    value ??= String(spec.u64);
  } else if (spec.text !== undefined) {
    bytes = text(spec.text);
    value ??= JSON.stringify(spec.text);
  } else if (spec.random !== undefined) {
    bytes = rand(spec.random, spec.seed ?? seedCounter++);
    value ??= `${spec.random} bytes`;
  } else if (spec.zero !== undefined) {
    bytes = zeros(spec.zero);
    value ??= spec.zero <= 8 ? "0" : `${spec.zero} zero bytes`;
  } else {
    bytes = [];
    value ??= "";
  }
  return { name: spec.name, value: value ?? "", note: spec.note, bytes, opaque: spec.opaque };
}

export const layerBytes = (l: Layer): Bytes => l.fields.flatMap((f) => f.bytes);
export const trailerBytes = (l: Layer): Bytes => (l.trailer ?? []).flatMap((f) => f.bytes);

/** Build a packet from outermost to innermost layer spec: build(eth(...), ipv4(...), tcp(...), http(...)) */
export function build(...specs: LayerSpec[]): BuiltPacket {
  // Each layer sees the addresses of the nearest IP header outside it, so the
  // outer UDP of a tunnel (VXLAN, GTP-U, WireGuard) checksums against the outer IPs.
  const ctxs: Ctx[] = [];
  const running: Ctx = {};
  specs.forEach((s) => {
    ctxs.push({ ...running });
    s.meta?.(running);
  });
  const layers: Layer[] = new Array(specs.length);
  let payload: Bytes = [];
  for (let i = specs.length - 1; i >= 0; i--) {
    const local: Ctx = { ...ctxs[i], outer: specs[i - 1], inner: specs[i + 1] };
    const layer = specs[i].build(payload, local);
    layers[i] = layer;
    payload = [...layerBytes(layer), ...payload, ...trailerBytes(layer)];
  }
  return { layers, bytes: payload };
}

/** Generic layer for any protocol: you list the fields and their bytes. */
export function proto(opts: {
  id: string;
  name: string;
  osi?: Osi;
  summary?: string;
  fields: FieldSpec[];
  trailer?: FieldSpec[];
  ethertype?: number;
  ipProto?: number;
}): LayerSpec {
  return {
    kind: opts.id,
    ethertype: opts.ethertype,
    ipProto: opts.ipProto,
    build: () => ({
      id: opts.id,
      name: opts.name,
      osi: opts.osi ?? 7,
      summary: opts.summary ?? opts.name,
      fields: opts.fields.map(field),
      trailer: opts.trailer?.map(field),
    }),
  };
}

/** Text protocols (HTTP/1.1, SMTP, FTP, SIP, RTSP...): one field per line, CRLF endings. */
export function textLayer(opts: {
  id: string;
  name: string;
  osi?: Osi;
  lines: string[];
  /** add a blank line after the headers (HTTP style) */
  blankLine?: boolean;
  body?: { text?: string; opaque?: number; what?: string; note?: string };
  notes?: Record<number, string>;
  summary?: string;
}): LayerSpec {
  return {
    kind: opts.id,
    build: () => {
      const fields: Field[] = opts.lines.map((line, i) =>
        field({ name: i === 0 ? "First line" : lineName(line), text: line + "\r\n", value: line, note: opts.notes?.[i] })
      );
      if (opts.blankLine) fields.push(field({ name: "End of headers", text: "\r\n", value: "\\r\\n", note: "An empty line: the headers are over." }));
      if (opts.body?.text !== undefined)
        fields.push(field({ name: opts.body.what ?? "Body", text: opts.body.text, value: `${text(opts.body.text).length} bytes`, note: opts.body.note }));
      if (opts.body?.opaque)
        fields.push(field({ name: opts.body.what ?? "Body", random: opts.body.opaque, opaque: true, value: `${opts.body.opaque} bytes`, note: opts.body.note }));
      return {
        id: opts.id,
        name: opts.name,
        osi: opts.osi ?? 7,
        summary: opts.summary ?? `${opts.name}: ${opts.lines[0]}`,
        fields,
      };
    },
  };
}

const lineName = (line: string) => {
  const m = /^([A-Za-z0-9-]+):/.exec(line);
  return m ? m[1] : line.length ? "Line" : "Blank line";
};

/** Opaque payload: encrypted or binary content the lesson does not decode. */
export function opaque(name: string, length: number, what?: string, osi: Osi = 7): LayerSpec {
  return proto({
    id: "data",
    name,
    osi,
    fields: [{ name: what ?? name, random: length, opaque: true, note: "Bytes the lesson doesn't decode: encrypted, random, or file contents." }],
  });
}

/** Flatten a packet's fields with byte offsets for the hex view. */
export interface FlatField {
  key: string;
  layer: number;
  depth: number;
  field: Field;
  start: number;
  end: number;
}

export function flatten(p: BuiltPacket): FlatField[] {
  const out: FlatField[] = [];
  let offset = 0;
  const trailers: { layer: number; fields: Field[] }[] = [];
  const walk = (f: Field, layer: number, depth: number, key: string, start: number) => {
    out.push({ key, layer, depth, field: f, start, end: start + f.bytes.length });
    if (f.children) {
      let o = start;
      f.children.forEach((c, i) => {
        walk(c, layer, depth + 1, `${key}.${i}`, o);
        o += c.bytes.length;
      });
    }
  };
  p.layers.forEach((l, li) => {
    l.fields.forEach((f, fi) => {
      walk(f, li, 0, `${li}.${fi}`, offset);
      offset += f.bytes.length;
    });
    if (l.trailer?.length) trailers.unshift({ layer: li, fields: l.trailer });
  });
  for (const t of trailers) {
    t.fields.forEach((f, fi) => {
      walk(f, t.layer, 0, `${t.layer}.t${fi}`, offset);
      offset += f.bytes.length;
    });
  }
  return out;
}

/** Byte range of a whole layer (header + its trailer is ignored for simplicity). */
export function layerRange(p: BuiltPacket, layerIdx: number): [number, number] {
  let start = 0;
  for (let i = 0; i < layerIdx; i++) start += layerBytes(p.layers[i]).length;
  return [start, start + layerBytes(p.layers[layerIdx]).length];
}
