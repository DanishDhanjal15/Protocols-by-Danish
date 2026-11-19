import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build, textLayer } from "@/lib/packet";
import { arp, BROADCAST_MAC, eth, icmp, ipv4, tcp } from "@/lib/proto";
import { ADDR } from "./_common";

const LAPTOP = ADDR.laptop;
const ROUTER = ADDR.router;
const PRINTER = "192.168.1.50";
const EVIL = "192.168.1.66";
const LMAC = ADDR.laptopMac;
const RMAC = ADDR.routerMac;
const PMAC = "00:80:77:3b:c2:19";
const XMAC = "02:42:de:ad:be:ef";

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: LAPTOP, x: 10, y: 62 },
  { id: "switch", kind: "switch", label: "Switch", x: 42, y: 62 },
  { id: "router", kind: "router", label: "Home router", sub: ROUTER, x: 86, y: 62 },
  { id: "printer", kind: "printer", label: "Printer", sub: PRINTER, x: 42, y: 20 },
];
const links: [string, string][] = [["client", "switch"], ["switch", "router"], ["switch", "printer"]];

const attackDevices: Device[] = [
  ...devices,
  { id: "attacker", kind: "attacker", label: "Attacker", sub: EVIL, x: 70, y: 22 },
];
const attackLinks: [string, string][] = [...links, ["switch", "attacker"]];

const echo = (type: 0 | 8, seq: number) =>
  icmp({ type, name: type === 8 ? "Echo (ping) request" : "Echo (ping) reply", restFields: [{ name: "Identifier", u16: 0x0b5e }, { name: "Sequence number", u16: seq }], data: Array.from({ length: 56 }, (_, i) => (i < 16 ? 0 : i)) });

const who = (time: number, to: string, parallel = false) =>
  pkt("client", to, "blue", "ARP REQ", [`who has ${ROUTER}?`, "broadcast"], {
    time, parallel, info: `Who has ${ROUTER}? Tell ${LAPTOP}`,
    packet: build(eth({ src: LMAC, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: LMAC, senderIp: LAPTOP, targetIp: ROUTER })),
  });

/** forged ARP reply from the attacker: "<ip> is at <attacker MAC>" */
const forged = (to: "client" | "router", time: number, lost = false) =>
  pkt("attacker", to, "red", "FAKE ARP", [`${to === "client" ? ROUTER : LAPTOP} is at`, "attacker MAC"], {
    time, lost,
    info: `${to === "client" ? ROUTER : LAPTOP} is at ${XMAC}${lost ? " (dropped by DAI)" : ""}`,
    packet: build(
      eth({ src: XMAC, dst: to === "client" ? LMAC : RMAC }),
      arp({ op: 2, senderMac: XMAC, senderIp: to === "client" ? ROUTER : LAPTOP, targetMac: to === "client" ? LMAC : RMAC, targetIp: to === "client" ? LAPTOP : ROUTER })
    ),
  });

const HTTP = ["POST /login HTTP/1.1", "Host: example.com", "Content-Type: application/x-www-form-urlencoded", "Content-Length: 29"];
const login = (srcMac: string, dstMac: string, ttl: number) =>
  build(
    eth({ src: srcMac, dst: dstMac }),
    ipv4({ src: LAPTOP, dst: ADDR.web, ttl, id: 0x4411 }),
    tcp({ sport: 51234, dport: 80, seq: 1, ack: 1, flags: "PA", win: 502, seqBase: 0x10203040, ackBase: 0x55aa0000 }),
    textLayer({ id: "http", name: "HTTP", lines: HTTP, blankLine: true, body: { text: "user=danish&pass=hunter2-demo", what: "Form data", note: "Plain HTTP: anyone in the middle can read this." } })
  );

export default defineLesson({
  id: "arp",
  name: "ARP",
  full: "Address Resolution Protocol",
  group: "lan",
  layer: 2,
  difficulty: 1,
  tagline: "Turning an IP address into a MAC address on the local network.",
  description:
    "IP addresses say where a packet should go, but Ethernet can only deliver to MAC addresses. ARP bridges the gap: a device shouts “who has this IP?” to everyone on the LAN, the owner answers with its MAC, and the answer is cached. ARP trusts every answer, which is exactly what attackers abuse.",
  facts: [
    ["Layer", "Between 2 and 3 (link layer)"],
    ["EtherType", "0x0806"],
    ["Message size", "28 bytes (padded to 60 on Ethernet)"],
    ["Request", "Broadcast to ff:ff:ff:ff:ff:ff"],
    ["Reply", "Unicast to the asker"],
    ["Defined in", "RFC 826"],
  ],
  ports: "None: runs straight on Ethernet",
  rfc: "RFC 826",
  keywords: ["arp", "mac address", "arp cache", "arp table", "gratuitous arp", "arp spoofing", "arp poisoning", "man in the middle", "dynamic arp inspection", "dai"],
  related: ["ethernet", "ip", "ipv6", "dhcp", "vlan"],
  devices,
  links,
  legend: [
    ["blue", "ARP requests (broadcast)"],
    ["green", "ARP replies"],
    ["amber", "Normal traffic"],
    ["red", "Forged ARP and attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Finding the router’s MAC",
      summary: "The laptop asks who has 192.168.1.1, the router answers, and the result is cached.",
      kind: "normal",
      steps: [
        {
          title: "Who has 192.168.1.1?",
          desc: "An ARP request to everyone",
          detail:
            "The laptop wants to send a packet through its gateway, 192.168.1.1, but doesn’t know its MAC address. It broadcasts an ARP request to ff:ff:ff:ff:ff:ff. The switch copies it to every port, so the printer gets it too. The target MAC field is all zeros because that’s the unknown.",
          facts: [["Opcode", "1 (request)"], ["Ethernet to", "ff:ff:ff:ff:ff:ff"], ["Target MAC", "00:00:00:00:00:00 (unknown)"]],
          quiz: {
            q: "Who receives this request?",
            options: ["Only the router", "Every device on the LAN", "Only the switch", "Every device on the internet"],
            answer: 1,
            why: "A broadcast goes to every device in the same Layer 2 network. Routers don’t forward it, so it never leaves the LAN.",
          },
          events: [who(0, "router"), who(0, "printer", true)],
        },
        {
          title: "I am, here’s my MAC",
          desc: "The router answers directly",
          detail:
            "The printer sees the request is not for its IP and ignores it. The router recognises its own address and sends an ARP reply straight to the laptop’s MAC: 192.168.1.1 is at b0:be:76:12:4c:01.",
          facts: [["Opcode", "2 (reply)"], ["Ethernet to", `${LMAC} (unicast)`], ["Answer", `${ROUTER} is at ${RMAC}`]],
          events: [
            note("printer", "NOT MY IP: IGNORE", "blue"),
            pkt("router", "client", "green", "ARP REPLY", [`${ROUTER} is at`, RMAC], {
              time: 0.0004, info: `${ROUTER} is at ${RMAC}`,
              packet: build(eth({ src: RMAC, dst: LMAC }), arp({ op: 2, senderMac: RMAC, senderIp: ROUTER, targetMac: LMAC, targetIp: LAPTOP })),
            }),
          ],
        },
        {
          title: "Cache it and send",
          desc: "No more questions for a while",
          detail:
            "The laptop stores 192.168.1.1 → b0:be:76:12:4c:01 in its ARP cache (see it with “arp -a” or “ip neigh”). The ping that was waiting now goes out at once. The router also learned the laptop’s MAC from the request itself, so it can answer without asking.",
          facts: [["Cache entry", `${ROUTER} → ${RMAC}`], ["Router learned", `${LAPTOP} → ${LMAC}`], ["Extra ARP needed", "None"]],
          quiz: {
            q: "Does the router need to send its own ARP request before replying to the ping?",
            options: ["Yes, always", "No, it learned the laptop’s MAC from the request", "Only if the ping is large", "It asks the switch instead"],
            answer: 1,
            why: "Every ARP request contains the sender’s IP and MAC. The target stores that pair, saving a second round of questions.",
          },
          events: [
            pkt("client", "router", "amber", "PING", ["to router’s MAC"], {
              time: 0.0006, info: "Echo (ping) request id=0x0b5e, seq=1/256, ttl=64",
              packet: build(eth({ src: LMAC, dst: RMAC }), ipv4({ src: LAPTOP, dst: ROUTER, ttl: 64, id: 0x2201 }), echo(8, 1)),
            }),
            pkt("router", "client", "green", "PONG", ["no ARP needed"], {
              time: 0.0009, info: "Echo (ping) reply id=0x0b5e, seq=1/256, ttl=64",
              packet: build(eth({ src: RMAC, dst: LMAC }), ipv4({ src: ROUTER, dst: LAPTOP, ttl: 64, id: 0x8a01, df: false }), echo(0, 1)),
            }),
          ],
        },
        {
          title: "Re-checking an old entry",
          desc: "A unicast ARP request",
          detail:
            "Cache entries don’t last forever, because devices can change. After about 30 seconds without confirmation Linux marks the entry stale. Next time it is used, the laptop checks it with an ARP request sent straight to the cached MAC instead of broadcasting.",
          facts: [["Sent to", `${RMAC} (not broadcast)`], ["Why", "Confirm the entry still works"], ["Cache life", "Seconds to minutes, OS dependent"]],
          events: [
            pkt("client", "router", "blue", "ARP REQ", ["still you?", "unicast"], {
              time: 35.2, info: `Who has ${ROUTER}? Tell ${LAPTOP}`,
              packet: build(eth({ src: LMAC, dst: RMAC }), arp({ op: 1, senderMac: LMAC, senderIp: LAPTOP, targetIp: ROUTER })),
            }),
            pkt("router", "client", "green", "ARP REPLY", ["yes, still me"], {
              time: 35.2004, info: `${ROUTER} is at ${RMAC}`,
              packet: build(eth({ src: RMAC, dst: LMAC }), arp({ op: 2, senderMac: RMAC, senderIp: ROUTER, targetMac: LMAC, targetIp: LAPTOP })),
            }),
          ],
        },
        {
          title: "Gratuitous ARP",
          desc: "Announcing yourself without being asked",
          detail:
            "When the printer reboots it broadcasts an ARP for its own address. Nobody asked; the point is to refresh everyone’s cache and to check that no one else uses 192.168.1.50. Devices that already know the printer update their entry. Keep this in mind: anyone can send an unasked ARP.",
          facts: [["Sender IP = Target IP", PRINTER], ["Sent to", "Broadcast"], ["Used for", "Updates, duplicate check, failover"]],
          quiz: {
            q: "A device receives an ARP reply it never asked for. What does a typical OS do?",
            options: ["Drops it, it wasn’t requested", "Updates its cache if it already has that IP", "Reports an attack", "Forwards it to the router"],
            answer: 1,
            why: "ARP has no authentication and no request tracking, so hosts accept unasked answers for addresses they know. That is the weakness ARP spoofing uses.",
          },
          events: [
            pkt("printer", "client", "pink", "GARP", [`${PRINTER} is at`, PMAC], {
              time: 60.0, info: `ARP Announcement for ${PRINTER}`,
              packet: build(eth({ src: PMAC, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: PMAC, senderIp: PRINTER, targetIp: PRINTER })),
            }),
            pkt("printer", "router", "pink", "GARP", [`${PRINTER} is at`, PMAC], {
              time: 60.0, parallel: true, info: `ARP Announcement for ${PRINTER}`,
              packet: build(eth({ src: PMAC, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: PMAC, senderIp: PRINTER, targetIp: PRINTER })),
            }),
          ],
        },
      ],
      outro: {
        title: "IP to MAC, solved",
        text: "One broadcast question and one direct answer gave the laptop the router’s MAC, and both sides cached the result. ARP is simple and fast, but it believes whatever it hears.",
        facts: [["Request", "Broadcast, opcode 1"], ["Reply", "Unicast, opcode 2"], ["See the cache", "arp -a / ip neigh"], ["Trust", "None checked"]],
      },
    },
    {
      id: "spoofing",
      name: "ARP spoofing and Dynamic ARP Inspection",
      summary: "An attacker on the LAN claims to be the router to sit in the middle; the switch learns to drop forged ARP.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "Lie to the laptop",
          desc: "“192.168.1.1 is at 02:42:de:ad:be:ef”",
          detail:
            "The attacker, plugged into the same switch, sends the laptop an ARP reply nobody asked for: the router’s IP is at the attacker’s MAC. The laptop overwrites its cache entry. Tools like arpspoof repeat this every couple of seconds so the lie sticks.",
          facts: [["Claim", `${ROUTER} is at ${XMAC}`], ["Asked for?", "No"], ["Repeated", "Every 2 s"]],
          events: [forged("client", 0), note("client", "CACHE POISONED", "red")],
        },
        {
          title: "Lie to the router",
          desc: "“192.168.1.10 is at 02:42:de:ad:be:ef”",
          detail:
            "It does the same to the router, claiming the laptop’s IP. Now each side believes the attacker’s MAC belongs to the other. Traffic in both directions will be framed to the attacker.",
          facts: [["Claim", `${LAPTOP} is at ${XMAC}`], ["Both sides fooled", "Yes"], ["Name", "ARP poisoning"]],
          quiz: {
            q: "The laptop now sends a packet to the internet. Which MAC is in the Ethernet destination?",
            options: ["The router’s real MAC", "The attacker’s MAC", "Broadcast", "The web server’s MAC"],
            answer: 1,
            why: "The laptop looks up its gateway in the poisoned cache and gets the attacker’s MAC. The IP header still says the web server.",
          },
          events: [forged("router", 0.001), note("router", "CACHE POISONED", "red")],
        },
        {
          title: "Man in the middle",
          desc: "Every frame passes through the attacker",
          detail:
            "The laptop posts a login form over plain HTTP. The frame goes to the attacker, who reads it and forwards it to the real router so nothing looks broken. The IP addresses never change; only the MAC addresses lie.",
          facts: [["Frame to", `${XMAC} (attacker)`], ["Forwarded to", `${RMAC} (router)`], ["Exposed", "Anything not encrypted"]],
          events: [
            pkt("client", "attacker", "amber", "HTTP", ["POST /login", "to attacker MAC"], {
              time: 2.0, info: "POST /login HTTP/1.1 (application/x-www-form-urlencoded)",
              packet: login(LMAC, XMAC, 64),
            }),
            note("attacker", "READS THE PASSWORD", "red"),
            pkt("attacker", "router", "red", "HTTP", ["passed on", "nobody notices"], {
              time: 2.0003, info: "POST /login HTTP/1.1 (application/x-www-form-urlencoded)",
              packet: login(XMAC, RMAC, 64),
            }),
          ],
        },
        {
          title: "Dynamic ARP Inspection",
          desc: "The switch checks every ARP",
          detail:
            "The network admin turns on DHCP snooping and Dynamic ARP Inspection on the switch. The switch already knows from DHCP which IP and MAC belong on which port. The attacker’s port is bound to 192.168.1.66, so an ARP claiming 192.168.1.1 from that port is dropped and logged.",
          facts: [["Checks", "Sender IP + MAC vs DHCP bindings"], ["Router port", "Trusted"], ["Result", "Forged ARP dropped"]],
          quiz: {
            q: "How does the switch know the ARP is forged?",
            options: ["It pings the router", "Its DHCP snooping table says that port has 192.168.1.66, not 192.168.1.1", "The packet is too small", "Forged ARPs have a special flag"],
            answer: 1,
            why: "DAI compares the sender IP and MAC in each ARP with the bindings DHCP snooping recorded per port. A mismatch means a lie.",
          },
          events: [forged("client", 10.0, true), note("switch", "DAI: INVALID ARP DROPPED", "green")],
        },
        {
          title: "Back to normal",
          desc: "Real ARP restores the cache",
          detail:
            "The laptop’s entry soon times out or is refreshed by the real router’s reply, and traffic flows straight to the router again. Small networks without smart switches can set a static ARP entry for the gateway instead. And HTTPS would have kept the password secret even in the middle.",
          facts: [["Static entry", "arp -s 192.168.1.1 b0:be:76:12:4c:01"], ["Also helps", "HTTPS, port security, 802.1X"], ["Attacker sees", "Nothing new"]],
          events: [
            pkt("router", "client", "green", "ARP REPLY", [`${ROUTER} is at`, RMAC], {
              time: 12.0, info: `${ROUTER} is at ${RMAC}`,
              packet: build(eth({ src: RMAC, dst: LMAC }), arp({ op: 2, senderMac: RMAC, senderIp: ROUTER, targetMac: LMAC, targetIp: LAPTOP })),
            }),
            pkt("client", "router", "amber", "PING", ["straight to router"], {
              time: 12.001, info: "Echo (ping) request id=0x0b5e, seq=2/512, ttl=64",
              packet: build(eth({ src: LMAC, dst: RMAC }), ipv4({ src: LAPTOP, dst: ROUTER, ttl: 64, id: 0x2202 }), echo(8, 2)),
            }),
          ],
        },
      ],
      outro: {
        title: "Lies stopped at the switch",
        text: "ARP spoofing works because ARP believes any answer, even unasked ones. Dynamic ARP Inspection checks every ARP against what DHCP handed out, and static entries or encryption take away what the attacker could gain.",
        facts: [["Attack", "ARP spoofing / poisoning"], ["Defence", "DHCP snooping + DAI"], ["Small networks", "Static gateway entry"], ["Always", "Use encryption (HTTPS)"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "ARP message",
      items: [["Opcode 1", "Request: who has this IP?"], ["Opcode 2", "Reply: this IP is at this MAC"], ["Sender MAC / IP", "Who is speaking"], ["Target MAC / IP", "Who is asked (MAC zero in requests)"]],
    },
    {
      title: "Commands",
      items: [["arp -a", "Show the cache (Windows, macOS)"], ["ip neigh", "Show the cache (Linux)"], ["arp -s IP MAC", "Add a static entry"], ["arping IP", "Send ARP requests by hand"]],
    },
    {
      title: "Defences",
      items: [["DHCP snooping", "Switch records IP↔MAC↔port"], ["DAI", "Drops ARP that doesn’t match"], ["Port security", "Limits MACs per port"], ["Encryption", "Makes a middleman useless"]],
    },
  ],
});
