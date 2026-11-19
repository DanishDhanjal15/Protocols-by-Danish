// Lesson schema. Every protocol lesson is plain data in this shape; the player,
// the network view, the sequence view, the capture table and the inspector all
// read from it.

import { BuiltPacket, Osi } from "./packet";

export type Color = "green" | "amber" | "violet" | "slate" | "teal" | "blue" | "red" | "pink";

export type DeviceKind =
  | "laptop" | "phone" | "desktop" | "router" | "switch" | "ap" | "cloud" | "server" | "dns" | "web" | "mail" | "db"
  | "camera" | "tv" | "firewall" | "proxy" | "vpn" | "plc" | "isp" | "cdn" | "auth" | "printer" | "tower" | "bank"
  | "attacker" | "nas" | "iot" | "satellite" | "phonepbx" | "broker";

export interface Device {
  id: string;
  kind: DeviceKind;
  label: string;
  /** small line under the label, usually an IP address */
  sub?: string;
  /** position on the stage in percent (0–100) of width and height */
  x: number;
  y: number;
}

export interface PacketEvent {
  type: "packet";
  from: string;
  to: string;
  /** devices to pass through; if left out, the shortest path over `links` is used */
  via?: string[];
  color: Color;
  /** short label shown on the flying packet, e.g. "SYN" */
  label: string;
  /** one or two short lines shown under the label */
  lines?: string[];
  /** dropped on the way: animates halfway and shows a cross */
  lost?: boolean;
  /** start together with the previous packet instead of after it */
  parallel?: boolean;
  /** seconds since the start of the lesson (capture timestamp) */
  time: number;
  /** capture-table summary, Wireshark style */
  info: string;
  packet: BuiltPacket;
  /** overrides for the capture row (derived from the packet otherwise) */
  proto?: string;
  src?: string;
  dst?: string;
}

export interface NoteEvent {
  type: "note";
  at: string;
  text: string;
  tone?: "green" | "amber" | "red" | "blue";
}

export type LessonEvent = PacketEvent | NoteEvent;

export interface Quiz {
  q: string;
  options: string[];
  answer: number;
  why: string;
}

export interface Step {
  title: string;
  /** one-line subtitle */
  desc: string;
  /** 2–4 sentence plain-English explanation */
  detail: string;
  facts: [string, string][];
  events: LessonEvent[];
  /** asked in Predict mode before the step plays */
  quiz?: Quiz;
}

export interface Scenario {
  id: string;
  name: string;
  summary: string;
  kind?: "normal" | "failure" | "attack";
  /** replace the lesson's devices/links for this scenario (e.g. add an attacker) */
  devices?: Device[];
  links?: [string, string][];
  steps: Step[];
  outro: { title: string; text: string; facts: [string, string][] };
}

export type GroupId =
  | "journey" | "foundations" | "lan" | "routing" | "web" | "naming" | "realtime" | "mail-files" | "security" | "vpn" | "iot" | "india";

export interface CheatSection {
  title: string;
  items: [string, string][];
}

export interface Lesson {
  id: string;
  name: string;
  full: string;
  group: GroupId;
  layer: Osi;
  /** one-line hook shown on cards */
  tagline: string;
  description: string;
  facts: [string, string][];
  ports?: string;
  rfc?: string;
  devices: Device[];
  links: [string, string][];
  legend: [Color, string][];
  scenarios: Scenario[];
  cheatsheet?: CheatSection[];
  related?: string[];
  keywords?: string[];
  /** pcap link type: 1 Ethernet (default), 105 802.11, 101 raw IP */
  linktype?: number;
  difficulty?: 1 | 2 | 3;
}

export const GROUPS: { id: GroupId; name: string; blurb: string }[] = [
  { id: "foundations", name: "Internet foundations", blurb: "IP, TCP, UDP, QUIC and friends: how data crosses the internet." },
  { id: "lan", name: "Local networks", blurb: "Ethernet, ARP, VLANs, DHCP, Wi‑Fi: the first hop." },
  { id: "routing", name: "Routing and the backbone", blurb: "How networks find paths to each other." },
  { id: "web", name: "The web", blurb: "HTTP in all its versions, proxies and real-time web." },
  { id: "naming", name: "Names and time", blurb: "DNS, its secure variants, and clock sync." },
  { id: "realtime", name: "Voice and video", blurb: "Calls, cameras and live streams." },
  { id: "mail-files", name: "Email and files", blurb: "Sending mail, reading mail, sharing files." },
  { id: "security", name: "Security and identity", blurb: "Encryption, login and trust." },
  { id: "vpn", name: "Tunnels and VPNs", blurb: "Private paths over the public internet." },
  { id: "iot", name: "IoT and operations", blurb: "Industrial control, sensors and monitoring." },
  { id: "india", name: "Made for India", blurb: "Everyday Indian systems, explained packet by packet." },
  { id: "journey", name: "Put it all together", blurb: "The capstone: type a web address and watch DHCP, ARP, DNS, TCP, TLS and HTTP work together." },
];

export const OSI_NAMES: Record<number, string> = {
  1: "Physical", 2: "Data Link", 3: "Network", 4: "Transport", 5: "Session", 6: "Presentation", 7: "Application",
};

/** Small helper so lesson files read cleanly. */
export function pkt(
  from: string,
  to: string,
  color: Color,
  label: string,
  lines: string[],
  rest: Omit<PacketEvent, "type" | "from" | "to" | "color" | "label" | "lines">
): PacketEvent {
  return { type: "packet", from, to, color, label, lines, ...rest };
}

export function note(at: string, text: string, tone: NoteEvent["tone"] = "amber"): NoteEvent {
  return { type: "note", at, text, tone };
}

export const defineLesson = (l: Lesson): Lesson => l;
