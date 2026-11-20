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
