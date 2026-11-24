// Step 1 of Google sign-in: send the browser to Google with state + PKCE.
import { generateCodeVerifier, generateState } from "arctic";
import { cookies } from "next/headers";
import { authEnabled } from "@/lib/auth/cookie";
import { googleClient, safeNext } from "@/lib/auth/google";

export async function GET(request: Request) {
  const url = new URL(request.url);
  if (!authEnabled()) return Response.redirect(new URL("/login?error=not-configured", url), 302);
  const state = generateState();
  const verifier = generateCodeVerifier();
  const authUrl = googleClient(request.url).createAuthorizationURL(state, verifier, ["openid", "email", "profile"]);
  authUrl.searchParams.set("prompt", "select_account");
  const jar = await cookies();
  const opts = { httpOnly: true, sameSite: "lax" as const, secure: url.protocol === "https:", path: "/", maxAge: 600 };
  jar.set("pbd_oauth_state", state, opts);
  jar.set("pbd_oauth_verifier", verifier, opts);
  jar.set("pbd_oauth_next", safeNext(url.searchParams.get("next")), opts);
  return Response.redirect(authUrl, 302);
}
