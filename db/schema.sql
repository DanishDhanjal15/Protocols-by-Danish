-- Protocols by Danish: users sign in with Google only; progress is kept per user.
-- Safe to run more than once.

create table if not exists users (
  id            uuid primary key default gen_random_uuid(),
  google_sub    text unique not null,          -- Google's stable user id
  email         text unique not null,
  name          text,
  avatar_url    text,
  created_at    timestamptz not null default now(),
  last_login_at timestamptz not null default now()
);

create table if not exists sessions (
  id          text primary key,                -- sha-256 of the cookie token, never the token itself
  user_id     uuid not null references users(id) on delete cascade,
  expires_at  timestamptz not null,
  created_at  timestamptz not null default now()
);
create index if not exists sessions_user_idx on sessions(user_id);

create table if not exists progress (
  user_id     uuid primary key references users(id) on delete cascade,
  data        jsonb not null default '{}'::jsonb, -- lessons done, quiz scores, labs solved, streak
  updated_at  timestamptz not null default now()
);
