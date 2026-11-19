# Writing a lesson for Protocols by Danish

Every protocol lesson is one TypeScript file in `src/lessons/<id>.ts` whose default export is
`defineLesson({...})`. The UI (network animation, sequence diagram, Wireshark-style capture table,
byte-by-byte packet inspector, quizzes, cheat sheet, .pcap export) is driven entirely by this data.

**Read these first:** `src/lib/lesson.ts` (schema), `src/lib/packet.ts` (packet model, `build`,
`proto`, `textLayer`, `opaque`, `FieldSpec`), `src/lib/proto.ts` (ready builders), `src/lib/bytes.ts`,
`src/lessons/_common.ts` (shared addresses, `homeToServer()`, `up()`, `down()`), and the reference lesson
`src/lessons/tcp.ts`. Copy its structure and quality bar.

## Rules

1. **Only create your own lesson files.** Do not edit anything in `src/lib/`, `_common.ts`, `tcp.ts`
   or other people's lessons. If you need a helper, define it inside your lesson file. If a builder is
   missing (e.g. 802.11, BGP, QUIC), use `proto({ id, name, osi, fields: [...] })` and list the real
   fields with real sizes and values.
2. **File name = lesson id** (lowercase, no spaces), and `id` in the object must match.
3. **Validate:** `npx tsx scripts/validate.mts <id> [<id>...]` must print `All good`. It checks device
   ids, timing order, quiz indexes, byte integrity, IPv4 + TCP/UDP checksums. Also run
   `npx tsc --noEmit -p .` and fix type errors in your files.
4. **Write all text yourself**, in plain, friendly English a first-year student understands. Short
   sentences. No em-dash asides, no hype. Use the protocol's real terms but explain them. Don't copy
   text from any website.
5. **Byte accuracy matters.** Field order, sizes and values must follow the real RFC/spec so an exported
   .pcap opens cleanly in Wireshark. Use documentation addresses (192.0.2.x, 198.51.100.x,
   203.0.113.x, 2001:db8::/32, example.com). For encrypted content use `opaque(...)`, `tls({records:[{type:"appdata", encrypted: n}]})`
   or a `FieldSpec` with `random: n, opaque: true`. Keep packets realistic in size but don't exceed
   ~1500 bytes; for bulk data show one or two representative segments.

## Shape of a good lesson

- `group`: one of `journey | foundations | lan | routing | web | naming | realtime | mail-files | security | vpn | iot | india`.
- `layer`: main OSI layer (1–7). `difficulty`: 1 beginner, 2 intermediate, 3 advanced.
- `tagline`: one line hook (≤ 70 chars). `description`: 2–3 sentences.
- `facts`: 5–6 `[label, value]` pairs (Layer, Transport/port, Defined in, Header size, …).
- `ports`, `rfc`, `keywords` (for search), `related` (other lesson ids).
- `devices`: 3–6 devices with `x`,`y` in percent of a wide stage (about 1000×460). Keep devices
  between x 6–94 and y 15–85, spread out, client on the left, servers on the right, cloud in the
  middle-top. Device kinds: laptop, phone, desktop, router, switch, ap, cloud, server, dns, web, mail,
  db, camera, tv, firewall, proxy, vpn, plc, isp, cdn, auth, printer, tower, bank, attacker, nas, iot,
  satellite, phonepbx, broker. `sub` is usually the IP address.
- `links`: pairs of device ids; packets follow the shortest path over links (or pass `via`).
- `legend`: 3–5 `[color, meaning]`. Colors: green (handshake/ack/success), amber (client data),
  violet (server data), teal (crypto/keys), blue (lookups/control), slate (closing/background),
  red (errors/attacks), pink (multicast/special).
- `scenarios`: **at least 2**. First is the normal flow (`kind: "normal"`, 4–8 steps). Add one or two
  what-if variants: a realistic failure (`kind: "failure"`: wrong password, NXDOMAIN, expired cert,
  timeout, 404…) and, where it makes sense, an attack with its defence (`kind: "attack"`). A scenario may
  override `devices`/`links` (e.g. to add an attacker).
- Each step: `title` (2–5 words), `desc` (one line), `detail` (2–4 sentences: what happens and why),
  `facts` (3 pairs), `events` (packets and notes). Put a `quiz` on at least half the steps:
  `{ q, options (3–4), answer (index), why }`. Quizzes should make the learner predict what comes next
  or reason about a field, not trivia.
- Packets: `pkt(from, to, color, LABEL, [line1, line2?], { time, info, packet: build(...layers) })`.
  `label` is short uppercase (≤ 12 chars). `info` is a Wireshark-style one-liner. `time` is seconds
  from the start of the scenario and must never go backwards. Typical internet RTT 30–40 ms, LAN
  < 1 ms. Use `parallel: true` to fire together with the previous packet, `lost: true` for drops.
  `note(deviceId, "SHORT CAPS TEXT", tone)` shows a callout.
- `outro`: title, 2–3 sentence recap, 3–4 facts.
- `cheatsheet`: 2–4 sections of `[term, meaning]` (message types, ports, codes, numbers to know).
- `linktype`: leave out for Ethernet. Use 105 for raw 802.11 frames, 101 for raw IP (no link header).

## Layer stacks

Typical internet packet captured on the laptop: `build(...up(server), tcp({...}), textLayer({...}))`
and replies `build(...down(server), ...)`. On a LAN use `eth({src,dst})` + `ipv4({...})` directly.
For UDP: `udp({ sport, dport })`. Protocols carried over TLS: show the TLS record with
`tls({ records: [{ type: "appdata", encrypted: n, what: "HTTP/2 frames" }] })`, and describe what's
inside in the step text.
