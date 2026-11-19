import { Device, defineLesson, note, pkt } from "@/lib/lesson";
import { build, FieldSpec, opaque } from "@/lib/packet";
import { rand, u16le } from "@/lib/bytes";
import {
  ANONCE_SEED, BCAST, BSSID, STA, SSID, assocReqBody, assocRespBody, authBody, beaconBody, ccmp, eapolKey, llc,
  m2KeyData, m3KeyData, rsnIE, wlan,
} from "./wifi";

const t = (n: number) => Number(n.toFixed(4));

// WPA3-only: AKM 8 (SAE), PMF required. Transition mode: AKM 2 + 8, PMF capable.
const RSN_SAE = rsnIE([8], 0x00c0);
const RSN_TRANS = rsnIE([2, 8], 0x0080);
const RSN_WPA2 = rsnIE([2], 0x0000);

const toAp = (sub: number, seq: number, flags = 0) => wlan({ type: 0, subtype: sub, a1: BSSID, a2: STA, a3: BSSID, seq, flags });
const toSta = (sub: number, seq: number, flags = 0) => wlan({ type: 0, subtype: sub, a1: STA, a2: BSSID, a3: BSSID, seq, flags });
const dataUp = (seq: number, flags = 0x01) => wlan({ type: 2, subtype: 0, a1: BSSID, a2: STA, a3: BSSID, seq, flags });
const dataDown = (seq: number, flags = 0x02) => wlan({ type: 2, subtype: 0, a1: STA, a2: BSSID, a3: BSSID, seq, flags });

/** SAE Commit body fields: finite cyclic group, scalar, element (RFC 7664 / 802.11 12.4) */
const commitFields = (seed: number): FieldSpec[] => [
  { name: "Group ID", bytes: u16le(19), value: "19 (NIST P-256)", note: "Which elliptic curve both sides use." },
  { name: "Scalar", bytes: rand(32, seed), value: "32 bytes", note: "A number made from this side's secret random values. On its own it reveals nothing about the password." },
  { name: "Element", bytes: rand(64, seed + 1), value: "64 bytes (x, y)", note: "A point on the curve, built from the password element (PWE) and a secret mask. Without the secret, it can't be turned back into the password." },
];
const confirmFields = (seed: number): FieldSpec[] => [
  { name: "Send-Confirm", bytes: u16le(1), value: "1", note: "Counts confirm messages sent, to spot replays." },
  { name: "Confirm", bytes: rand(32, seed), value: "32 bytes", note: "A hash over the shared secret and both commits. It proves this side ended up with the same key." },
];

const commit = (from: "client" | "ap", time: number, seq: number, seed: number, to = from === "client" ? "ap" : "client") =>
  pkt(from, to, "teal", "SAE COMMIT", ["scalar + element", "group 19"], {
    time, info: `Authentication, SN=${seq}, SAE, seq 1 (Commit), Group 19`,
    packet: build(from === "client" ? toAp(11, seq) : toSta(11, seq), authBody(3, 1, 0, commitFields(seed))),
  });
const confirm = (from: "client" | "ap", time: number, seq: number, seed: number) =>
  pkt(from, from === "client" ? "ap" : "client", "green", "SAE CONFIRM", ["proof of same key"], {
    time, info: `Authentication, SN=${seq}, SAE, seq 2 (Confirm)`,
    packet: build(from === "client" ? toAp(11, seq) : toSta(11, seq), authBody(3, 2, 0, confirmFields(seed))),
  });

const beaconPkt = (from: string, time: number, rsn: FieldSpec, seq: number, lines: string[], label = "BEACON") =>
  pkt(from, "client", "blue", label, lines, {
    time, info: `Beacon frame, SN=${seq}, FN=0, BI=100, SSID="${SSID}"`,
    packet: build(wlan({ type: 0, subtype: 8, a1: BCAST, a2: BSSID, a3: BSSID, seq }), beaconBody(rsn, BigInt(77000000000) + BigInt(Math.round(time * 1e6)))),
  });

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: STA, x: 12, y: 64 },
  { id: "ap", kind: "ap", label: "Wi-Fi router", sub: `"${SSID}" WPA3`, x: 55, y: 64 },
  { id: "internet", kind: "cloud", label: "Internet", x: 87, y: 36 },
];
const links: [string, string][] = [["client", "ap"], ["ap", "internet"]];

const twinDevices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: STA, x: 12, y: 64 },
  { id: "ap", kind: "ap", label: "Real router", sub: `"${SSID}" WPA2/WPA3`, x: 62, y: 72 },
  { id: "twin", kind: "attacker", label: "Evil twin", sub: `fake "${SSID}" WPA2`, x: 40, y: 22 },
  { id: "internet", kind: "cloud", label: "Internet", x: 88, y: 36 },
];
const twinLinks: [string, string][] = [["client", "ap"], ["client", "twin"], ["ap", "internet"]];

export default defineLesson({
  id: "wpa3",
  name: "WPA3 (SAE)",
  full: "Wi-Fi Protected Access 3, Simultaneous Authentication of Equals",
  group: "lan",
  layer: 2,
  difficulty: 3,
  tagline: "A Wi-Fi password exchange that can't be cracked from a recording.",
  description:
    "WPA3-Personal replaces WPA2's password step with SAE, a Dragonfly key exchange on an elliptic curve. Both sides prove they know the password in a way that gives a listener nothing to test guesses against, so a recorded join can't be cracked offline. After SAE, the familiar 4-way handshake installs the keys.",
  facts: [
    ["Layer", "Data link (Layer 2)"],
    ["Key exchange", "SAE (Dragonfly), then 4-way handshake"],
    ["Curve", "Group 19 (NIST P-256)"],
    ["AKM suite", "00-0f-ac:8 (SAE)"],
    ["PMF (802.11w)", "Required"],
    ["Defined in", "IEEE 802.11-2020, WPA3 spec"],
  ],
  ports: "None (link layer)",
  rfc: "IEEE 802.11-2020 §12.4, RFC 7664",
  keywords: ["wpa3", "sae", "dragonfly", "wifi", "802.11", "commit", "confirm", "pmf", "802.11w", "transition mode", "downgrade", "evil twin", "offline dictionary", "forward secrecy"],
  related: ["wifi", "tls", "ethernet"],
  linktype: 105,
  devices,
  links,
  legend: [
    ["blue", "Finding and joining (management)"],
    ["teal", "SAE and key handshake"],
    ["green", "Confirmed / accepted"],
    ["amber", "Encrypted data"],
    ["red", "Attack"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Joining a WPA3 network",
      summary: "SAE Commit and Confirm prove the password, then association and the 4-way handshake install keys.",
      kind: "normal",
      steps: [
        {
          title: "WPA3 beacon",
          desc: "The RSN element says SAE, PMF required",
          detail:
            "The router's beacon looks like a WPA2 one, but its RSN element lists AKM 8 (SAE) instead of AKM 2 (PSK) and sets “management frame protection required”. A laptop that doesn't support WPA3 won't even try to join.",
          facts: [["AKM", "8 (SAE)"], ["RSN capabilities", "0x00c0: PMF capable + required"], ["Cipher", "AES-CCMP"]],
          quiz: {
            q: "Which field changed compared to a WPA2 beacon?",
            options: ["The SSID", "The AKM suite in the RSN element", "The channel", "The beacon interval"],
            answer: 1,
            why: "The AKM (Authentication and Key Management) suite says how the password is used: 2 for WPA2 PSK, 8 for SAE.",
          },
          events: [beaconPkt("ap", 0, RSN_SAE, 801, [`SSID ${SSID}`, "SAE, PMF required"])],
        },
        {
          title: "SAE Commit",
          desc: "Both sides send a scalar and an element",
          detail:
            "Authentication frames now use algorithm 3 (SAE). Each side turns the password and both MAC addresses into a secret point on the curve (the password element), picks fresh random numbers, and sends a scalar and an element. The two commits can cross in the air: SAE is “simultaneous”, neither side is the leader.",
          facts: [["Algorithm", "3 (SAE)"], ["Transaction seq", "1 (Commit)"], ["Sizes", "Scalar 32 B, element 64 B"]],
          quiz: {
            q: "Does the Commit frame contain anything derived from the password that an eavesdropper could test guesses against?",
            options: ["Yes, a hash of the password", "No: the element is masked by a secret random number that never leaves the device", "Yes, the password in plain text", "Only the first letter"],
            answer: 1,
            why: "The element mixes the password point with a random secret. Without that secret, a guess can't be checked against it.",
          },
          events: [commit("client", 0.03, 210, 7301), commit("ap", 0.0306, 802, 7401)],
        },
        {
          title: "SAE Confirm",
          desc: "Prove you got the same key",
          detail:
            "From the other side's commit and its own secrets, each side computes the same shared secret, and from it the PMK. Each sends a Confirm hash to prove it. If the passwords differ, the hashes don't match and the join stops. Every join produces a new PMK, so a password leaked later can't decrypt old recordings (forward secrecy).",
          facts: [["Transaction seq", "2 (Confirm)"], ["Result", "Shared PMK, new each time"], ["Forward secrecy", "Yes"]],
          quiz: {
            q: "An attacker recorded this whole exchange. How many password guesses can they test offline?",
            options: ["As many as they like, like WPA2", "None: every guess needs a live exchange with the router", "Exactly one", "Only guesses shorter than 8 characters"],
            answer: 1,
            why: "To test a guess you need the secret random values from one side. The only way to try a password is to run SAE with the router, which can rate-limit you.",
          },
          events: [confirm("client", 0.0352, 211, 7501), confirm("ap", 0.0357, 803, 7601), note("client", "PMK AGREED", "green")],
        },
        {
          title: "Associate",
          desc: "Ask to join with SAE and PMF",
          detail: "With SAE done, the laptop sends an Association Request whose RSN element repeats the choice: AKM 8, CCMP, PMF required. The router accepts and assigns Association ID 1.",
          facts: [["AKM", "SAE"], ["PMF", "Required"], ["Association ID", "1"]],
          events: [
            pkt("client", "ap", "blue", "ASSOC REQ", [`SSID ${SSID}`, "SAE + PMF"], {
              time: 0.037, info: `Association Request, SN=212, SSID="${SSID}"`,
              packet: build(toAp(0, 212), assocReqBody(RSN_SAE)),
            }),
            pkt("ap", "client", "green", "ASSOC RESP", ["success", "AID 1"], {
              time: 0.0376, info: "Association Response, SN=804, Status=Successful, AID=1",
              packet: build(toSta(1, 804), assocRespBody(1)),
            }),
          ],
        },
        {
          title: "4-way handshake",
          desc: "Same four EAPOL messages, keyed from the SAE PMK",
          detail:
            "The 4-way handshake runs just like WPA2, but its PMK came from SAE, not straight from the password. So the MIC in message 2 is no use to a password guesser. Key descriptor version 0 means the SAE AKM picks the algorithms (AES-CMAC for the MIC).",
          facts: [["PMK from", "SAE (not the password)"], ["Key descriptor version", "0 (AKM-defined)"], ["Delivers", "PTK + GTK + IGTK"]],
          events: [
            pkt("ap", "client", "teal", "EAPOL 1/4", ["ANonce"], {
              time: 0.039, info: "Key (Message 1 of 4)", packet: build(dataDown(805), llc(), eapolKey({ msg: 1, replay: 1, ver: 0 })),
            }),
            pkt("client", "ap", "teal", "EAPOL 2/4", ["SNonce + MIC"], {
              time: 0.0402, info: "Key (Message 2 of 4)", packet: build(dataUp(213), llc(), eapolKey({ msg: 2, replay: 1, ver: 0, keyData: m2KeyData(8, 0x00c0) })),
            }),
            pkt("ap", "client", "teal", "EAPOL 3/4", ["install, GTK"], {
              time: 0.0414, info: "Key (Message 3 of 4)", packet: build(dataDown(806), llc(), eapolKey({ msg: 3, replay: 2, ver: 0, keyData: m3KeyData() })),
            }),
            pkt("client", "ap", "teal", "EAPOL 4/4", ["done"], {
              time: 0.0421, info: "Key (Message 4 of 4)", packet: build(dataUp(214), llc(), eapolKey({ msg: 4, replay: 2, ver: 0 })),
            }),
            note("client", "CONNECTED (WPA3)", "green"),
          ],
        },
        {
          title: "Encrypted data",
          desc: "CCMP for data, and management frames are protected too",
          detail: "Data frames look the same as with WPA2: a CCMP header, encrypted contents and a MIC. The difference is that deauthentication and other action frames are also protected (PMF is mandatory), so forged kick-offs no longer work.",
          facts: [["Data", "AES-CCMP"], ["Management frames", "Protected (802.11w)"], ["Forged deauth", "Ignored"]],
          events: [
            pkt("client", "ap", "amber", "DATA", ["encrypted", "PN 1"], {
              time: 0.15, info: "Data, SN=215, FN=0, Flags=.p.....T (Protected)",
              packet: build(dataUp(215, 0x41), ccmp(1), opaque("Encrypted data", 92, "LLC + IPv4 + TCP + TLS, all encrypted")),
            }),
          ],
        },
      ],
      outro: {
        title: "Joined with WPA3",
        text: "SAE let both sides prove the password with a fresh elliptic-curve exchange that a listener can't use to test guesses. The 4-way handshake then installed keys from the SAE PMK, and PMF protects management frames too.",
        facts: [["Offline cracking", "Not possible from a capture"], ["Forward secrecy", "Yes"], ["Extra frames vs WPA2", "4 (two commits, two confirms)"]],
      },
    },
    {
      id: "downgrade",
      name: "Transition-mode downgrade",
      summary: "An evil twin offers WPA2 only, hoping a transition-mode laptop falls back and leaks a crackable handshake.",
      kind: "attack",
      devices: twinDevices,
      links: twinLinks,
      steps: [
        {
          title: "Transition mode",
          desc: "The real router offers both WPA2 and WPA3",
          detail:
            "So that older phones can still join, many routers run WPA3 “transition mode”: one SSID that accepts both PSK (WPA2) and SAE (WPA3), with PMF optional. The same password works for both.",
          facts: [["AKMs", "2 (PSK) + 8 (SAE)"], ["PMF", "Capable, not required"], ["Weak spot", "WPA2 is still allowed"]],
          events: [beaconPkt("ap", 0, RSN_TRANS, 900, [`SSID ${SSID}`, "PSK + SAE"])],
        },
        {
          title: "An evil twin appears",
          desc: "Same name, WPA2 only, louder signal",
          detail:
            "The attacker starts a fake access point with the same SSID and BSSID that only offers WPA2-PSK. Being closer, its signal is stronger. A laptop that has saved HomeNet as “WPA2 or WPA3” sees nothing wrong.",
          facts: [["Fake SSID", SSID], ["Offers", "AKM 2 only, no PMF"], ["Goal", "Get a WPA2 handshake"]],
          quiz: {
            q: "What does the attacker hope to get by offering only WPA2?",
            options: ["The password in plain text", "A WPA2 message 2 with a MIC, which can be cracked offline", "The SAE element", "The GTK"],
            answer: 1,
            why: "The attacker doesn't know the password, so the join will fail at message 3. But message 2's MIC is enough to test guesses offline.",
          },
          events: [beaconPkt("twin", 0.05, RSN_WPA2, 3001, [`SSID ${SSID}`, "WPA2 only"], "FAKE BEACON")],
        },
        {
          title: "The laptop falls back",
          desc: "Open auth, association, messages 1 and 2",
          detail:
            "The laptop joins the twin with WPA2. The twin sends message 1 with its own ANonce; the laptop answers with SNonce and a MIC computed from the real password. The twin can't send a valid message 3, so the join fails, but it now has everything needed for offline guessing.",
          facts: [["Laptop used", "WPA2-PSK"], ["Captured", "ANonce, SNonce, MIC"], ["Join result", "Fails, but too late"]],
          events: [
            pkt("client", "twin", "blue", "AUTH", ["Open System"], { time: 0.2, info: "Authentication, SN=230, Open System, seq 1", packet: build(toAp(11, 230), authBody(0, 1)) }),
            pkt("twin", "client", "green", "AUTH", ["success"], { time: t(0.2004), info: "Authentication, SN=3002, Open System, seq 2, Successful", packet: build(toSta(11, 3002), authBody(0, 2)) }),
            pkt("client", "twin", "blue", "ASSOC REQ", ["WPA2-PSK"], { time: t(0.2011), info: `Association Request, SN=231, SSID="${SSID}"`, packet: build(toAp(0, 231), assocReqBody(RSN_WPA2)) }),
            pkt("twin", "client", "green", "ASSOC RESP", ["AID 1"], { time: t(0.2017), info: "Association Response, SN=3003, Status=Successful, AID=1", packet: build(toSta(1, 3003), assocRespBody(1)) }),
            pkt("twin", "client", "red", "EAPOL 1/4", ["attacker's ANonce"], { time: t(0.203), info: "Key (Message 1 of 4)", packet: build(dataDown(3004), llc(), eapolKey({ msg: 1, replay: 1, nonceSeed: ANONCE_SEED + 9 })) }),
            pkt("client", "twin", "teal", "EAPOL 2/4", ["SNonce + MIC"], { time: t(0.2042), info: "Key (Message 2 of 4)", packet: build(dataUp(232), llc(), eapolKey({ msg: 2, replay: 1, keyData: m2KeyData(2) })) }),
            note("twin", "MIC CAPTURED: CRACK OFFLINE", "red"),
          ],
        },
        {
          title: "Defence: WPA3 only",
          desc: "SAE-only network, or Transition Disable",
          detail:
            "If the router is set to WPA3-only (SAE, PMF required), the laptop's saved profile never accepts WPA2 for HomeNet, so the twin's offer is ignored. Newer routers in transition mode can also send a Transition Disable flag inside message 3 once a device has joined with SAE; the laptop remembers it and refuses WPA2 for that network from then on.",
          facts: [["Router setting", "WPA3-Personal only, PMF required"], ["Client memory", "Transition Disable indication"], ["Twin gets", "Nothing"]],
          quiz: {
            q: "With a WPA3-only profile, what does the laptop do with the twin's WPA2-only beacon?",
            options: ["Joins with WPA2 anyway", "Treats it as the wrong security type and keeps using SAE with the real router", "Sends the password to check", "Disconnects from all Wi-Fi"],
            answer: 1,
            why: "The profile allows only AKM 8. A network offering only AKM 2 doesn't match, so the laptop never sends a WPA2 message 2.",
          },
          events: [
            beaconPkt("twin", 1, RSN_WPA2, 3010, ["WPA2 only"], "FAKE BEACON"),
            note("client", "WPA2 OFFER REFUSED", "green"),
            commit("client", 1.05, 240, 7701, "ap"),
            commit("ap", 1.0507, 910, 7801),
          ],
        },
      ],
      outro: {
        title: "Downgrade blocked",
        text: "WPA3 transition mode keeps WPA2 alive for old devices, and an evil twin can use that to collect a crackable handshake. Running WPA3-only with PMF required, or honouring Transition Disable, closes the door.",
        facts: [["Attack", "Evil twin + downgrade to WPA2"], ["Defence", "SAE-only, PMF required"], ["Also", "Transition Disable (WPA3 v3)"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "SAE messages",
      items: [["Commit (seq 1)", "Group, scalar, element"], ["Confirm (seq 2)", "Send-confirm, confirm hash"], ["Auth algorithm", "3 = SAE (0 = Open System)"], ["Anti-clogging token", "Router asks for it when flooded"]],
    },
    {
      title: "WPA2 vs WPA3-Personal",
      items: [["Password step", "PSK vs SAE"], ["Offline cracking", "Possible vs not possible"], ["Forward secrecy", "No vs yes"], ["PMF", "Optional vs required"]],
    },
    {
      title: "Numbers to know",
      items: [["AKM 2 / 8", "PSK / SAE"], ["Group 19", "NIST P-256"], ["RSN caps 0x00c0", "PMF required"], ["Status 126", "SAE hash-to-element variant"]],
    },
  ],
});
