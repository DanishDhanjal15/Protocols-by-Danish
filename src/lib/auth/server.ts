// Server-only: Postgres access, sessions and progress storage.
import "server-only";
import postgres from "postgres";
import { cookies } from "next/headers";
import { randomToken, SESSION_COOKIE, SESSION_DAYS, sha256, signToken, verifyCookie } from "./cookie";

declare global {
  // keep one pool across hot reloads in development
  var __pbdSql: ReturnType<typeof postgres> | undefined;
}

export function db() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not set");
  globalThis.__pbdSql ??= postgres(process.env.DATABASE_URL, { max: 5, idle_timeout: 20, prepare: false });
  return globalThis.__pbdSql;
}

export interface SessionUser {
  id: string;
  email: string;
  name: string | null;
  avatar_url: string | null;
}

export async function upsertGoogleUser(u: { sub: string; email: string; name?: string; picture?: string }): Promise<string> {
  const sql = db();
  const [row] = await sql<{ id: string }[]>`
    insert into users (google_sub, email, name, avatar_url)
    values (${u.sub}, ${u.email.toLowerCase()}, ${u.name ?? null}, ${u.picture ?? null})
    on conflict (google_sub) do update
      set email = excluded.email, name = excluded.name, avatar_url = excluded.avatar_url, last_login_at = now()
    returning id`;
  return row.id;
}

/** Creates a session row and sets the signed cookie. */
export async function startSession(userId: string, secure: boolean) {
  const token = randomToken();
  const expires = new Date(Date.now() + SESSION_DAYS * 86400_000);
  await db()`insert into sessions (id, user_id, expires_at) values (${await sha256(token)}, ${userId}, ${expires})`;
  (await cookies()).set(SESSION_COOKIE, await signToken(token), {
    httpOnly: true,
    sameSite: "lax",
    secure,
    path: "/",
    expires,
  });
}

/** The signed-in user, or null. Checks the cookie signature and the session row. */
export async function currentUser(): Promise<SessionUser | null> {
  const token = await verifyCookie((await cookies()).get(SESSION_COOKIE)?.value);
  if (!token) return null;
  const rows = await db()<SessionUser[]>`
    select u.id, u.email, u.name, u.avatar_url
    from sessions s join users u on u.id = s.user_id
    where s.id = ${await sha256(token)} and s.expires_at > now()`;
  return rows[0] ?? null;
}

export async function endSession() {
  const jar = await cookies();
  const token = await verifyCookie(jar.get(SESSION_COOKIE)?.value);
  if (token) await db()`delete from sessions where id = ${await sha256(token)}`;
  jar.delete(SESSION_COOKIE);
}

export async function loadProgress(userId: string): Promise<unknown | null> {
  const rows = await db()<{ data: unknown }[]>`select data from progress where user_id = ${userId}`;
  return rows[0]?.data ?? null;
}

export async function saveProgress(userId: string, data: unknown) {
  const json = db().json(data as Parameters<ReturnType<typeof postgres>["json"]>[0]);
  await db()`
    insert into progress (user_id, data, updated_at) values (${userId}, ${json}, now())
    on conflict (user_id) do update set data = excluded.data, updated_at = now()`;
}
