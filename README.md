# Protocols by Danish

See the internet work, packet by packet. Interactive, byte-accurate lessons on 60+ network
protocols with an animated network, a sequence diagram, a Wireshark-style capture table and a
byte-by-byte packet inspector.

## What's inside

- **Lessons** (`/learn`, `/learn/<id>`): each protocol plays real scenarios step by step. Every
  packet is built from real bytes with correct lengths and checksums.
- **What-if scenarios**: most lessons have a failure case (NXDOMAIN, expired certificate, wrong
  password…) and many have an attack with its defence (SYN flood, ARP spoofing, DNS poisoning…).
- **Predict mode**: quizzes before a step plays. **Read aloud** narration. Keyboard shortcuts (`?`).
- **Packet inspector**: layer tree, plain-English notes per field, hex view with highlighting,
  copy hex, and **.pcap export** that opens in Wireshark.
- **English / Hinglish**: every lesson (overview, steps, quizzes, cheat sheet) in both; switch in the player.
- **Layers view**: watch each packet get wrapped (encapsulation) and unwrapped, header by header.
- **Live tables**: ARP cache, DNS cache and a netstat-style connection table, rebuilt from the packets as they arrive.
- **Try it yourself**: real commands (Windows, Mac/Linux) and Wireshark filters for every lesson.
- **Troubleshooting labs** (`/labs`): a real symptom plus the packet capture; diagnose the fault, with hints.
- **Compare** (`/compare`): side-by-side facts plus a packet race on a shared clock.
- **Paths** (`/paths`), **Tools** (`/tools`): subnet calculator, port lookup, packet playground,
  live DNS lookup.
- Shareable links to any step (`/learn/tcp?s=syn-flood&step=2`), black-and-green terminal theme, English/Hindi UI,
  mobile layout, search (`Ctrl K`).

## Run it

```bash
npm install
npm run dev                  # http://localhost:3000
```

`npm run build` makes a production build; every lesson page is pre-rendered.

## Sign-in and saved progress

Users sign in with Google only (no passwords, no registration form). Their email, name, photo and
progress (lessons done, quiz scores, labs solved, streak) are stored in Postgres.

1. Copy `.env.example` to `.env.local` (or `.env`) and fill in `DATABASE_URL`, `GOOGLE_CLIENT_ID`,
   `GOOGLE_CLIENT_SECRET` and `AUTH_SECRET`.
2. Create the tables: `npm run db:migrate`
3. In Google Cloud Console, create an OAuth client (Web application) whose authorised redirect URIs
   include `http://localhost:3000/api/auth/google/callback` and
   `https://<your-domain>/api/auth/google/callback`. On a deployment, set `APP_URL` to that domain.

Never commit `.env` / `.env.local` (they are gitignored).

Until all four variables are set the site runs without the login wall. With them set, every page
except `/login` requires a signed-in user (`src/proxy.ts`).

## Adding a lesson

Read [AUTHORING.md](AUTHORING.md). In short: add `src/lessons/<id>.ts` exporting
`defineLesson({...})`, then check it:

```bash
npm run validate -- <id>     # device ids, timing, quiz answers, byte counts, IPv4/TCP/UDP checksums
npx tsc --noEmit -p .
```

Hinglish text and try-it commands live in `src/lessons/hinglish/<id>.json` and `src/lessons/tryit/<id>.json`;
see [TEXT-AUTHORING.md](TEXT-AUTHORING.md) and check them with `npx tsx scripts/text.mts check <id>`.

The registry (`src/lessons/index.ts`) is generated automatically before `dev` and `build`.

## Layout

| Path | What |
| --- | --- |
| `src/lib/bytes.ts`, `packet.ts`, `proto.ts` | Byte helpers, packet model, protocol builders |
| `src/lib/lesson.ts` | Lesson schema |
| `src/lessons/` | One file per protocol |
| `src/components/player/` | Player, stage (network + sequence), inspector, panels |
| `scripts/` | Registry generator and lesson validator |

## Contributing

Issues and pull requests are welcome. Before opening a PR, run:

```bash
npx tsc --noEmit
npm run lint
npm run validate            # all lessons
npm run build
```

## License

[MIT](LICENSE) © Danish Dhanjal. The social-links widget in the footer is adapted from
[Uiverse.io by Praashoo7](https://uiverse.io/Praashoo7/smooth-crab-52) (MIT).
