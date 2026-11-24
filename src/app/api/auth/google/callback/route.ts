// Step 2: Google sends the user back with a code. Exchange it, read the ID token,
// create or update the user, start a session, and go to the page they wanted.
import { decodeIdToken } from "arctic";
import { cookies } from "next/headers";
import { authEnabled } from "@/lib/auth/cookie";
import { googleClient, safeNext, secureCookies } from "@/lib/auth/google";
import { startSession, upsertGoogleUser } from "@/lib/auth/server";

interface GoogleClaims { sub: string; email?: string; email_verified?: boolean; name?: string; picture?: string }

export async function GET(request: Request) {
  const url = new URL(request.url);
  const fail = (reason: string) => Response.redirect(new URL(`/login?error=${reason}`, url), 302);
  if (!authEnabled()) return fail("not-configured");

  const jar = await cookies();
  const state = jar.get("pbd_oauth_state")?.value;
  const verifier = jar.get("pbd_oauth_verifier")?.value;
  const next = safeNext(jar.get("pbd_oauth_next")?.value);
  jar.delete("pbd_oauth_state");
  jar.delete("pbd_oauth_verifier");
  jar.delete("pbd_oauth_next");

  if (url.searchParams.get("error")) return fail("cancelled");
  const code = url.searchParams.get("code");
  if (!code || !state || !verifier || url.searchParams.get("state") !== state) return fail("state");

  let claims: GoogleClaims;
  try {
    const tokens = await googleClient(request.url).validateAuthorizationCode(code, verifier);
    // The ID token came straight from Google's token endpoint over TLS, so its claims can be read directly.
    claims = decodeIdToken(tokens.idToken()) as GoogleClaims;
  } catch (e) {
    console.error("Google token exchange failed", e);
    return fail("google");
  }
  if (!claims.email || claims.email_verified === false) return fail("email");

  try {
    const userId = await upsertGoogleUser({ sub: claims.sub, email: claims.email, name: claims.name, picture: claims.picture });
    await startSession(userId, secureCookies(request.url));
  } catch (e) {
    console.error("Database error during sign-in", e);
    return fail("database");
  }
  return Response.redirect(new URL(next, url), 302);
}
