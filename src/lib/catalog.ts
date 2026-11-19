import { GROUPS, GroupId, Lesson } from "./lesson";
import { BuiltPacket, Field, Layer } from "./packet";

export interface LessonMeta {
  id: string;
  name: string;
  full: string;
  group: GroupId;
  layer: number;
  tagline: string;
  difficulty: number;
  ports?: string;
  rfc?: string;
  keywords: string[];
  scenarios: { id: string; name: string; kind: string; steps: string[] }[];
  packets: number;
}

/** Preferred reading order inside each group. Unknown ids go to the end. */
const ORDER = [
  "journey",
  "ip", "tcp", "udp", "icmp", "ipv6", "nat", "quic",
  "ethernet", "arp", "dhcp", "vlan", "stp", "wifi", "wpa3", "pppoe", "igmp", "ble", "cellular",
  "bgp", "ospf", "mpls", "vxlan", "cdn",
  "http", "https", "http2", "websocket", "grpc", "proxy", "socks", "reverse", "portal",
  "dns", "doh", "dnssec", "ntp",
  "webrtc", "sip", "rtsp", "rtmp",
  "smtp", "pop3", "imap", "emailauth", "ftp", "smb",
  "tls", "ssh", "mtls", "oauth", "kerberos", "ldap", "radius",
  "wireguard", "ipsec",
  "modbus", "mqtt", "coap", "snmp", "syslog",
  "upi",
];

export function toMeta(l: Lesson): LessonMeta {
  return {
    id: l.id,
    name: l.name,
    full: l.full,
    group: l.group,
    layer: l.layer,
    tagline: l.tagline,
    difficulty: l.difficulty ?? 2,
    ports: l.ports,
    rfc: l.rfc,
    keywords: l.keywords ?? [],
    scenarios: l.scenarios.map((s) => ({ id: s.id, name: s.name, kind: s.kind ?? "normal", steps: s.steps.map((st) => st.title) })),
    packets: l.scenarios.reduce((n, s) => n + s.steps.reduce((m, st) => m + st.events.filter((e) => e.type === "packet").length, 0), 0),
  };
}

export function sortCatalog(list: LessonMeta[]): LessonMeta[] {
  const g = (id: GroupId) => GROUPS.findIndex((x) => x.id === id);
  const o = (id: string) => {
    const i = ORDER.indexOf(id);
    return i < 0 ? 999 : i;
  };
  return [...list].sort((a, b) => g(a.group) - g(b.group) || o(a.id) - o(b.id) || a.name.localeCompare(b.name));
}

// ---- compacting lessons for the client: drop duplicated bytes, rebuild them on arrival

type CField = Omit<Field, "bytes" | "children"> & { bytes?: number[]; children?: CField[] };

const compactField = (f: Field): CField =>
  f.children ? { ...f, bytes: undefined, children: f.children.map(compactField) } : f;

const expandField = (f: CField): Field => {
  if (f.children) {
    const children = f.children.map(expandField);
    return { ...f, children, bytes: children.flatMap((c) => c.bytes) };
  }
  return { ...f, bytes: f.bytes ?? [] } as Field;
};

export function compactLesson(l: Lesson): Lesson {
  return {
    ...l,
    scenarios: l.scenarios.map((s) => ({
      ...s,
      steps: s.steps.map((st) => ({
        ...st,
        events: st.events.map((e) =>
          e.type === "packet"
            ? {
                ...e,
                packet: {
                  bytes: [],
                  layers: e.packet.layers.map((ly) => ({
                    ...ly,
                    fields: ly.fields.map(compactField) as unknown as Field[],
                    trailer: ly.trailer?.map(compactField) as unknown as Field[] | undefined,
                  })),
                },
              }
            : e
        ),
      })),
    })),
  };
}

export function expandPacket(p: BuiltPacket): BuiltPacket {
  if (p.bytes.length) return p;
  const layers: Layer[] = p.layers.map((ly) => ({
    ...ly,
    fields: (ly.fields as unknown as CField[]).map(expandField),
    trailer: ly.trailer ? (ly.trailer as unknown as CField[]).map(expandField) : undefined,
  }));
  const head = layers.flatMap((ly) => ly.fields.flatMap((f) => f.bytes));
  const tail = [...layers].reverse().flatMap((ly) => (ly.trailer ?? []).flatMap((f) => f.bytes));
  return { layers, bytes: [...head, ...tail] };
}

export function expandLesson(l: Lesson): Lesson {
  return {
    ...l,
    scenarios: l.scenarios.map((s) => ({
      ...s,
      steps: s.steps.map((st) => ({
        ...st,
        events: st.events.map((e) => (e.type === "packet" ? { ...e, packet: expandPacket(e.packet) } : e)),
      })),
    })),
  };
}
