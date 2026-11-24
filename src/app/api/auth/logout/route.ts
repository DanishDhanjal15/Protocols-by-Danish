import { authEnabled } from "@/lib/auth/cookie";
import { endSession } from "@/lib/auth/server";

export async function POST(request: Request) {
  if (authEnabled()) await endSession();
  return Response.redirect(new URL("/login", request.url), 303);
}
