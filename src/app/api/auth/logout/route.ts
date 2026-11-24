import { authEnabled } from "@/lib/auth/cookie";
import { endSession } from "@/lib/auth/server";

export async function POST(request: Request) {
  // only our own pages may sign someone out (stops other sites from posting here)
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin && origin !== process.env.APP_URL?.replace(/\/$/, "")) {
    return new Response("Forbidden", { status: 403 });
  }
  if (authEnabled()) await endSession();
  return Response.redirect(new URL("/login", request.url), 303);
}
