// Creates the tables in DATABASE_URL: npm run db:migrate
import { readFileSync } from "node:fs";
import path from "node:path";
import postgres from "postgres";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("Set DATABASE_URL first (in .env.local, or in the shell).");
  process.exit(1);
}
const sql = postgres(url, { max: 1 });
try {
  await sql.unsafe(readFileSync(path.join(process.cwd(), "db", "schema.sql"), "utf8"));
  const tables = await sql`select table_name from information_schema.tables where table_schema = 'public' order by 1`;
  console.log("Tables ready:", tables.map((t) => t.table_name).join(", "));
} catch (e) {
  console.error("Migration failed:", e.message);
  process.exitCode = 1;
} finally {
  await sql.end();
}
