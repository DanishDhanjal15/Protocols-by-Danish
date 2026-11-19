// Validate lessons: npx tsx scripts/validate.ts [id ...]   (no ids = all files in src/lessons)
import { readdirSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type { Lesson } from "../src/lib/lesson.ts";
import { inetChecksum } from "../src/lib/bytes.ts";
import { flatten, layerBytes } from "../src/lib/packet.ts";

const dir = path.join(process.cwd(), "src", "lessons");
const ids = process.argv.slice(2).length
  ? process.argv.slice(2)
  : readdirSync(dir).filter((f) => f.endsWith(".ts") && !f.startsWith("_") && f !== "index.ts").map((f) => f.replace(/\.ts$/, ""));

let errors = 0;
const err = (id: string, msg: string) => { errors++; console.log(`  ✗ [${id}] ${msg}`); };

for (const id of ids) {
  let lesson: Lesson;
  try {
    const mod = await import(pathToFileURL(path.join(dir, `${id}.ts`)).href);
    lesson = mod.default?.default ?? mod.default;
  } catch (e) {
    err(id, `failed to load: ${(e as Error).stack?.split("\n").slice(0, 4).join(" | ")}`);
    continue;
  }
  if (!lesson || lesson.id !== id) { err(id, `default export id "${lesson?.id}" must equal file name`); continue; }
  let packets = 0;
  for (const sc of lesson.scenarios) {
    const devs = new Set((sc.devices ?? lesson.devices).map((d) => d.id));
    for (const [a, b] of sc.links ?? lesson.links) if (!devs.has(a) || !devs.has(b)) err(id, `${sc.id}: link ${a}-${b} uses unknown device`);
    for (const d of sc.devices ?? lesson.devices) if (d.x < 0 || d.x > 100 || d.y < 0 || d.y > 100) err(id, `device ${d.id} position out of 0–100`);
    if (!sc.steps.length) err(id, `${sc.id}: no steps`);
    let lastT = -1;
    sc.steps.forEach((st, si) => {
      if (st.quiz && (st.quiz.answer < 0 || st.quiz.answer >= st.quiz.options.length)) err(id, `${sc.id} step ${si + 1}: quiz answer index out of range`);
      for (const ev of st.events) {
        if (ev.type === "note") { if (!devs.has(ev.at)) err(id, `${sc.id} step ${si + 1}: note at unknown device ${ev.at}`); continue; }
        packets++;
        for (const d of [ev.from, ev.to, ...(ev.via ?? [])]) if (!devs.has(d)) err(id, `${sc.id} step ${si + 1}: packet "${ev.label}" uses unknown device ${d}`);
        if (ev.from === ev.to) err(id, `${sc.id} step ${si + 1}: packet "${ev.label}" from === to`);
        if (typeof ev.time !== "number" || isNaN(ev.time)) err(id, `${sc.id} step ${si + 1}: packet "${ev.label}" has no time`);
        if (ev.time < lastT - 1e-9) err(id, `${sc.id} step ${si + 1}: packet "${ev.label}" time ${ev.time} goes backwards (prev ${lastT})`);
        lastT = Math.max(lastT, ev.time);
        const p = ev.packet;
        if (!p?.layers?.length) { err(id, `${sc.id} step ${si + 1}: packet "${ev.label}" not built`); continue; }
        const total = p.layers.reduce((n, l) => n + layerBytes(l).length + (l.trailer ?? []).reduce((m, f) => m + f.bytes.length, 0), 0);
        if (total !== p.bytes.length) err(id, `${sc.id} step ${si + 1}: byte count mismatch`);
        if (p.bytes.some((b) => !Number.isInteger(b) || b < 0 || b > 255)) err(id, `${sc.id} step ${si + 1}: packet "${ev.label}" has invalid byte values`);
        const fl = flatten(p);
        if (fl.length && fl[fl.length - 1].end > p.bytes.length) err(id, `${sc.id} step ${si + 1}: field offsets overflow`);
        // verify IPv4 header checksums
        let off = 0;
        let ipHdr: number[] | null = null;
        for (const l of p.layers) {
          const lb = layerBytes(l);
          if (l.id === "ipv4") { if (inetChecksum(lb) !== 0) err(id, `${sc.id} step ${si + 1}: bad IPv4 checksum in "${ev.label}"`); ipHdr = lb; }
          if ((l.id === "tcp" || l.id === "udp") && ipHdr) {
            const totalLen = (ipHdr[2] << 8) | ipHdr[3];
            const seg = p.bytes.slice(off, off + totalLen - (ipHdr[0] & 0x0f) * 4);
            const proto = l.id === "tcp" ? 6 : 17;
            const pseudo = [...ipHdr.slice(12, 20), 0, proto, (seg.length >> 8) & 255, seg.length & 255];
            const zeroCs = l.id === "udp" && seg[6] === 0 && seg[7] === 0;
            if (!zeroCs && inetChecksum([...pseudo, ...seg]) !== 0) err(id, `${sc.id} step ${si + 1}: bad ${l.id.toUpperCase()} checksum in "${ev.label}"`);
            ipHdr = null;
          }
          off += lb.length;
        }
      }
    });
  }
  console.log(`${errors ? "…" : "✓"} ${id}: ${lesson.scenarios.length} scenario(s), ${packets} packets`);
}
console.log(errors ? `\n${errors} problem(s)` : "\nAll good");
process.exit(errors ? 1 : 0);
