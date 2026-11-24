// Who is signed in, plus their saved progress.
import { connection } from "next/server";
import { authEnabled } from "@/lib/auth/cookie";
import { currentUser, loadProgress } from "@/lib/auth/server";

export async function GET() {
  await connection(); // per-request: never cache who is signed in
  if (!authEnabled()) return Response.json({ enabled: false, user: null, progress: null });
  try {
    const user = await currentUser();
    if (!user) return Response.json({ enabled: true, user: null, progress: null }, { status: 401 });
    return Response.json({ enabled: true, user, progress: await loadProgress(user.id) }, { headers: { "Cache-Control": "no-store" } });
  } catch (e) {
    console.error("/api/me database error", e);
    return Response.json({ enabled: true, user: null, progress: null, error: "database" }, { status: 503 });
  }
}
