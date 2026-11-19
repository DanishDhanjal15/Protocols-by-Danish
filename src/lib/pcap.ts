// Writes a classic libpcap file (microsecond timestamps) from lesson packets.
import { expandPacket } from "./catalog";
import type { PacketEvent } from "./lesson";

export function toPcap(events: PacketEvent[], linktype = 1, epoch = Date.UTC(2026, 0, 15, 9, 30, 0) / 1000): Uint8Array {
  const parts: number[] = [];
  const u32 = (n: number) => parts.push(n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255);
  const u16 = (n: number) => parts.push(n & 255, (n >>> 8) & 255);
  // global header, little endian
  u32(0xa1b2c3d4);
  u16(2);
  u16(4);
  u32(0);
  u32(0);
  u32(65535);
  u32(linktype);
  for (const ev of events) {
    const bytes = expandPacket(ev.packet).bytes;
    const t = epoch + ev.time;
    const sec = Math.floor(t);
    const usec = Math.round((t - sec) * 1e6);
    u32(sec);
    u32(usec);
    u32(bytes.length);
    u32(bytes.length);
    parts.push(...bytes);
  }
  return new Uint8Array(parts);
}

export function downloadPcap(name: string, events: PacketEvent[], linktype?: number) {
  const data = toPcap(events, linktype);
  const blob = new Blob([data as BlobPart], { type: "application/vnd.tcpdump.pcap" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${name}.pcap`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
