// npx tsx scripts/text.mts extract <id>   → prints the English text JSON of a lesson
// npx tsx scripts/text.mts check [ids…]   → checks src/lessons/hinglish/<id>.json and src/lessons/tryit/<id>.json
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { extractText } from "../src/lib/text.ts";
import type { Lesson } from "../src/lib/lesson.ts";

const dir = path.join(process.cwd(), "src", "lessons");
const [cmd, ...rest] = process.argv.slice(2);

async function load(id: string): Promise<Lesson> {
  const mod = await import(pathToFileURL(path.join(dir, `${id}.ts`)).href);
  return mod.default?.default ?? mod.default;
}

if (cmd === "extract") {
  for (const id of rest) console.log(JSON.stringify(extractText(await load(id)), null, 2));
  process.exit(0);
}

if (cmd !== "check") {
  console.log("usage: text.mts extract <id> | check [ids…]");
  process.exit(1);
}

const ids = rest.length
  ? rest
  : readdirSync(path.join(dir, "hinglish")).filter((f) => f.endsWith(".json")).map((f) => f.replace(/\.json$/, ""));
let errors = 0;
const bad = (id: string, m: string) => { errors++; console.log(`  ✗ [${id}] ${m}`); };

// compare shapes: every string in en must have a non-empty string at the same place
function same(id: string, where: string, en: unknown, tr: unknown) {
  if (typeof en === "string") {
    if (typeof tr !== "string" || !tr.trim()) bad(id, `${where}: missing text`);
    return;
  }
  if (Array.isArray(en)) {
    if (!Array.isArray(tr)) return bad(id, `${where}: should be an array`);
    if (tr.length !== en.length) bad(id, `${where}: has ${tr.length} items, English has ${en.length}`);
    en.forEach((v, i) => same(id, `${where}[${i}]`, v, tr[i]));
    return;
  }
  if (en && typeof en === "object") {
    if (!tr || typeof tr !== "object") return bad(id, `${where}: should be an object`);
    for (const k of Object.keys(en)) same(id, `${where}.${k}`, (en as Record<string, unknown>)[k], (tr as Record<string, unknown>)[k]);
    for (const k of Object.keys(tr)) if (!(k in (en as object))) bad(id, `${where}: unknown key "${k}"`);
  }
}

for (const id of ids) {
  const before = errors;
  let lesson: Lesson;
  try { lesson = await load(id); } catch (e) { bad(id, `lesson failed to load: ${(e as Error).message}`); continue; }
  const en = extractText(lesson);
  const hp = path.join(dir, "hinglish", `${id}.json`);
  if (!existsSync(hp)) bad(id, "no hinglish file");
  else {
    try { same(id, "hinglish", JSON.parse(JSON.stringify(en)), JSON.parse(readFileSync(hp, "utf8"))); }
    catch (e) { bad(id, `hinglish JSON invalid: ${(e as Error).message}`); }
  }
  const tp = path.join(dir, "tryit", `${id}.json`);
  if (!existsSync(tp)) bad(id, "no tryit file");
  else {
    try {
      const t = JSON.parse(readFileSync(tp, "utf8"));
      if (!Array.isArray(t.commands) || !t.commands.length) bad(id, "tryit: commands must be a non-empty array");
      else t.commands.forEach((c: Record<string, unknown>, i: number) => {
        for (const k of ["title", "why", "expect"]) {
          const v = c[k] as Record<string, string> | undefined;
          if (!v?.en?.trim() || !v?.hinglish?.trim()) bad(id, `tryit.commands[${i}].${k}: needs en and hinglish`);
        }
        if (!c.windows && !c.unix && !c.wireshark) bad(id, `tryit.commands[${i}]: needs windows, unix or wireshark`);
        const steps = lesson.scenarios[0].steps.length;
        if (c.step !== undefined && (typeof c.step !== "number" || c.step < 1 || c.step > steps)) bad(id, `tryit.commands[${i}].step must be 1–${steps}`);
      });
    } catch (e) { bad(id, `tryit JSON invalid: ${(e as Error).message}`); }
  }
  console.log(`${errors === before ? "✓" : "✗"} ${id}`);
}
console.log(errors ? `\n${errors} problem(s)` : "\nAll good");
process.exit(errors ? 1 : 0);
