// Save the signed-in user's progress (the whole progress object, replaced).
import { authEnabled } from "@/lib/auth/cookie";
import { currentUser, saveProgress } from "@/lib/auth/server";

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
  const text = await request.text();
  if (text.length > 200_000) return Response.json({ ok: false, reason: "too-large" }, { status: 413 });
  let data: { done?: unknown; quiz?: unknown; streak?: unknown };
  try {
    data = JSON.parse(text);
  } catch {
    return Response.json({ ok: false, reason: "bad-json" }, { status: 400 });
  }
  if (!data || typeof data !== "object" || !Array.isArray(data.done) || typeof data.quiz !== "object") {
    return Response.json({ ok: false, reason: "bad-shape" }, { status: 400 });
  }
  try {
    await saveProgress(user.id, { done: data.done, quiz: data.quiz, streak: data.streak, last: (data as { last?: unknown }).last });
  } catch (e) {
    console.error("/api/progress save failed", e);
    return Response.json({ ok: false, reason: "database" }, { status: 503 });
  }
  return Response.json({ ok: true });
}
