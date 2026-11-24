// Login wall: every page needs a signed-in Google user, except /login itself.
// This is the optimistic check (cookie signature only). APIs check the session in Postgres.
// If Google sign-in isn't configured yet (env vars missing), the site stays open.
import { NextRequest, NextResponse } from "next/server";
import { authEnabled, SESSION_COOKIE, verifyCookie } from "@/lib/auth/cookie";

export async function proxy(req: NextRequest) {
  if (!authEnabled()) return NextResponse.next();
  const path = req.nextUrl.pathname;
  const signedIn = !!(await verifyCookie(req.cookies.get(SESSION_COOKIE)?.value));

  if (path === "/login") {
    return signedIn ? NextResponse.redirect(new URL("/", req.nextUrl)) : NextResponse.next();
  }
  if (!signedIn) {
    const to = new URL("/login", req.nextUrl);
    const next = path + req.nextUrl.search;
    if (next !== "/") to.searchParams.set("next", next);
    return NextResponse.redirect(to);
  }
  return NextResponse.next();
}

export const config = {
  // everything except API routes, Next.js assets and the icon
  matcher: ["/((?!api/|_next/static|_next/image|icon.svg|favicon.ico|robots.txt).*)"],
};
