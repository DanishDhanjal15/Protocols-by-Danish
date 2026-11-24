import "server-only";
import { Google } from "arctic";

/** Redirect URI = APP_URL (if set) or the request's own origin + the callback path. */
export function googleClient(requestUrl: string) {
  const origin = process.env.APP_URL?.replace(/\/$/, "") || new URL(requestUrl).origin;
  return new Google(process.env.GOOGLE_CLIENT_ID!, process.env.GOOGLE_CLIENT_SECRET!, `${origin}/api/auth/google/callback`);
}

/** Only same-site paths may be used as the after-login destination. */
export function safeNext(next: string | null | undefined) {
  return next && next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/api/") ? next : "/";
}
