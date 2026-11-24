// Signed session cookie: "<token>.<hmac>". The signature lets the proxy reject
// forged cookies without a database call; the server still checks the session in Postgres.
// Uses Web Crypto so it works in both the proxy and route handlers.

export const SESSION_COOKIE = "pbd_session";
export const SESSION_DAYS = 30;

const enc = new TextEncoder();

const b64url = (buf: ArrayBuffer | Uint8Array) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

async function hmac(value: string, secret: string) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, enc.encode(value)));
}

export const authSecret = () => process.env.AUTH_SECRET ?? "";

/** Is Google sign-in fully configured? Without it the site stays open (no login wall). */
export const authEnabled = () =>
  !!(process.env.AUTH_SECRET && process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.DATABASE_URL);

export async function signToken(token: string) {
  return `${token}.${await hmac(token, authSecret())}`;
}

/** Returns the raw token if the signature is valid, else null. */
export async function verifyCookie(value: string | undefined): Promise<string | null> {
  if (!value || !authSecret()) return null;
  const i = value.lastIndexOf(".");
  if (i <= 0) return null;
  const token = value.slice(0, i);
  const sig = value.slice(i + 1);
  const expected = await hmac(token, authSecret());
  if (sig.length !== expected.length) return null;
  let diff = 0;
  for (let k = 0; k < sig.length; k++) diff |= sig.charCodeAt(k) ^ expected.charCodeAt(k);
  return diff === 0 ? token : null;
}

export function randomToken(bytes = 32) {
  return b64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256(value: string) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(value));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
