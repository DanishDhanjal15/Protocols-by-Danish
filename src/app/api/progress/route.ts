// Save the signed-in user's progress. The upload is merged with what is already stored,
// so an old tab or device can never wipe progress made elsewhere.
import { authEnabled } from "@/lib/auth/cookie";
import { currentUser, mergeAndSaveProgress } from "@/lib/auth/server";
import type { Progress } from "@/lib/progress";

const MAX_BYTES = 200_000;

export async function PUT(request: Request) {
  if (!authEnabled()) return Response.json({ ok: false, reason: "not-configured" }, { status: 503 });
  let user;
  try {
    user = await currentUser();
  } catch (e) {
    console.error("/api/progress database error", e);
    return Response.json({ ok: false, reason: "database" }, { status: 503 });
  }
  if (!user) return Response.json({ ok: false }, { status: 401 });
  if (Number(request.headers.get("content-length") ?? 0) > MAX_BYTES) return Response.json({ ok: false, reason: "too-large" }, { status: 413 });
  const text = await request.text();
  if (text.length > MAX_BYTES) return Response.json({ ok: false, reason: "too-large" }, { status: 413 });
  let data: { done?: unknown; quiz?: unknown; streak?: unknown };
  try {
    data = JSON.parse(text);
  } catch {
    return Response.json({ ok: false, reason: "bad-json" }, { status: 400 });
  }
  const incoming = clean(data);
  if (!incoming) return Response.json({ ok: false, reason: "bad-shape" }, { status: 400 });
  try {
    await mergeAndSaveProgress(user.id, incoming);
  } catch (e) {
    console.error("/api/progress save failed", e);
    return Response.json({ ok: false, reason: "database" }, { status: 503 });
  }
  return Response.json({ ok: true });
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** Keep only well-formed fields; null if the shape is wrong. */
function clean(d: unknown): Progress | null {
  if (!isObj(d) || !Array.isArray(d.done) || !isObj(d.quiz)) return null;
  const done = d.done.filter((x): x is string => typeof x === "string" && x.length <= 64).slice(0, 500);
  const quiz: Progress["quiz"] = {};
  for (const [k, v] of Object.entries(d.quiz)) {
    if (k.length <= 64 && isObj(v) && Number.isFinite(v.correct) && Number.isFinite(v.total)) quiz[k] = { correct: Number(v.correct), total: Number(v.total) };
  }
  const st = isObj(d.streak) && typeof d.streak.day === "string" && Number.isFinite(d.streak.count)
    ? { day: d.streak.day.slice(0, 10), count: Number(d.streak.count) } : { day: "", count: 0 };
  const last = isObj(d.last) && typeof d.last.id === "string" && Number.isFinite(d.last.step) && Number.isFinite(d.last.at)
    ? { id: d.last.id.slice(0, 64), step: Number(d.last.step), at: Number(d.last.at) } : undefined;
  return { done, quiz, streak: st, last };
}
