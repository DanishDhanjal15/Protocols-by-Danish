# Hinglish text and "Try it yourself" commands

For each lesson id you get, create **two files**. Do not edit any other file.

## 1. `src/lessons/hinglish/<id>.json`: the lesson text in Hinglish

1. Print the English text: `npx tsx scripts/text.mts extract <id>`
2. Write a JSON file with **exactly the same keys, the same array lengths and the same order**, with
   every English string replaced by its Hinglish version. Fact pairs `["Layer", "Transport (Layer 4)"]`
   translate both sides. Quiz `options` keep the same order (the answer index must stay correct).

**Hinglish style**: Hindi written in Roman (Latin) script, mixed naturally with English, the way a
good Indian teacher explains to college students. Friendly, simple, short sentences.

- Keep in English: protocol names, field names, packet labels, flags (SYN, ACK, FIN), numbers, IP and
  MAC addresses, ports, RFC numbers, commands, file names, and well-known technical words (packet,
  server, router, handshake, header, checksum, encrypted, certificate, key, port, request, response).
- Translate the explanation around them into Hindi (Roman script).
- Keep the meaning exact. Don't add or drop facts. Don't make it longer than the English.
- No Devanagari script, no emoji.

Example:
- English: "Before any data moves, both sides pick a starting sequence number and confirm the other's."
- Hinglish: "Data bhejne se pehle dono sides apna starting sequence number chunte hain aur ek doosre ka confirm karte hain."
- English fact: `["Takes", "1 round trip (34 ms)"]` → `["Time lagta hai", "1 round trip (34 ms)"]`

## 2. `src/lessons/tryit/<id>.json`: real commands students can run

```json
{
  "commands": [
    {
      "title": { "en": "Watch the handshake time", "hinglish": "Handshake ka time dekho" },
      "why": { "en": "…one or two sentences…", "hinglish": "…" },
      "windows": "Test-NetConnection example.com -Port 443",
      "unix": "nc -vz example.com 443",
      "expect": { "en": "What the output shows and how it maps to the lesson.", "hinglish": "…" },
      "step": 1
    },
    {
      "title": { "en": "Find the SYN packets in the capture", "hinglish": "Capture mein SYN packets dhoondo" },
      "why": { "en": "…", "hinglish": "…" },
      "wireshark": "tcp.flags.syn == 1",
      "expect": { "en": "…", "hinglish": "…" },
      "step": 1
    }
  ]
}
```

- **2 to 4 commands** per lesson. `step` (optional) = the 1-based step of the lesson's first scenario
  the command relates to.
- Give `windows` (cmd or PowerShell) and/or `unix` (macOS/Linux). Each must be a real, working command.
- Add a `wireshark` display filter entry for the lesson's own capture: every lesson has a
  "Download .pcap" button, so students can open it in Wireshark and apply the filter. For protocols a
  laptop can't reach directly (BGP, OSPF, MPLS, Modbus, cellular, STP…), use Wireshark filters plus any
  safe read-only lookups (e.g. `whois`, `dig`, `nslookup`, `curl -sI`).
- **Safe only**: read-only, no admin rights where possible, no changes to settings, no scanning or
  probing machines the student doesn't own. Use example.com, google.com, 1.1.1.1, 8.8.8.8 or the
  student's own machine/router as targets.
- `expect` must describe realistic output (it varies by machine; say so) and connect it to the lesson.

## Check your work

`npx tsx scripts/text.mts check <id> [<id>…]` must print `All good`. It checks that every English
string has a non-empty translation in the same place and that the try-it file is well formed.
