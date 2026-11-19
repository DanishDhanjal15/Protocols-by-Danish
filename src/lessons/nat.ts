import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build } from "@/lib/packet";
import { eth, ipv4, tcp, TcpOpt } from "@/lib/proto";
import { ADDR } from "./_common";

const LAPTOP = ADDR.laptop;
const PHONE = ADDR.phone;
const NAS = "192.168.1.50";
const PUB = ADDR.routerWan; // 198.51.100.7
const S = ADDR.web;
const FRIEND = ADDR.server2;

const MAC = {
  laptop: ADDR.laptopMac,
  phone: ADDR.phoneMac,
  nas: "00:11:32:c4:5e:07",
  lan: ADDR.routerMac,
  wan: "b0:be:76:12:4c:02",
  isp: "00:25:90:aa:10:01",
};

const LP = 51234;
const MAP1 = 40001;
const MAP2 = 40002;
const FWD = 8443;

const synOpts: TcpOpt[] = [{ mss: 1460 }, "sackOk", { ts: [5512001, 0] }, "nop", { ws: 7 }];
const saOpts = (ecr: number): TcpOpt[] => [{ mss: 1460 }, "sackOk", { ts: [88120034, ecr] }, "nop", { ws: 7 }];

// inside = between a LAN device and the router; outside = between router and ISP
const inside = (srcMac: string, dstMac: string, src: string, dst: string, ttl: number, id: number) => [eth({ src: srcMac, dst: dstMac }), ipv4({ src, dst, ttl, id })];
const outside = (out: boolean, src: string, dst: string, ttl: number, id: number) => [eth(out ? { src: MAC.wan, dst: MAC.isp } : { src: MAC.isp, dst: MAC.wan }), ipv4({ src, dst, ttl, id })];

const devices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: LAPTOP, x: 9, y: 40 },
  { id: "phone", kind: "phone", label: "Phone", sub: PHONE, x: 9, y: 80 },
  { id: "router", kind: "router", label: "Home router (NAT)", sub: PUB, x: 36, y: 60 },
  { id: "internet", kind: "cloud", label: "Internet", x: 62, y: 32 },
  { id: "server", kind: "web", label: "Web server", sub: S, x: 89, y: 60 },
];
const links: [string, string][] = [["client", "router"], ["phone", "router"], ["router", "internet"], ["internet", "server"]];

const failDevices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: LAPTOP, x: 9, y: 40 },
  { id: "nas", kind: "nas", label: "NAS", sub: NAS, x: 9, y: 80 },
  { id: "router", kind: "router", label: "Home router (NAT)", sub: PUB, x: 36, y: 60 },
  { id: "internet", kind: "cloud", label: "Internet", x: 62, y: 32 },
  { id: "friend", kind: "desktop", label: "Friend’s PC", sub: FRIEND, x: 89, y: 60 },
];
const failLinks: [string, string][] = [["client", "router"], ["nas", "router"], ["router", "internet"], ["internet", "friend"]];

export default defineLesson({
  id: "nat",
  name: "NAT",
  full: "Network Address Translation (with port translation, PAT)",
  group: "routing",
  layer: 3,
  difficulty: 2,
  tagline: "Many devices, one public address: how your home router shares it.",
  description:
    "Your home devices use private addresses like 192.168.1.10 that mean nothing on the internet. The home router rewrites each outgoing packet to use its single public address and a port of its choosing, writes down the swap in a table, and reverses it for the replies. Packets nobody asked for have no table entry, so they are dropped.",
  facts: [
    ["Layer", "Network + transport (rewrites IP and ports)"],
    ["Where", "Home router, firewall, carrier (CGNAT)"],
    ["Private ranges", "10/8, 172.16/12, 192.168/16"],
    ["Key idea", "Translation table"],
    ["Inbound by default", "Dropped"],
    ["Defined in", "RFC 3022, RFC 4787"],
  ],
  ports: "Any: the router picks outside ports (here 40001, 40002)",
  rfc: "RFC 3022, RFC 4787",
  keywords: ["nat", "pat", "napt", "masquerade", "port forwarding", "private address", "public address", "cgnat", "translation table"],
  related: ["ip", "tcp", "udp", "ipv6"],
  devices,
  links,
  legend: [
    ["amber", "Inside, before translation"],
    ["teal", "Outside, after translation"],
    ["violet", "Replies"],
    ["red", "Dropped"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Two devices share one address",
      summary: "The laptop and the phone both reach the same server through one public IP; the router keeps them apart by port.",
      kind: "normal",
      steps: [
        {
          title: "Leaving the laptop",
          desc: "Private source: 192.168.1.10:51234",
          detail:
            "The laptop opens a connection to the web server. As it leaves the laptop, the packet has the laptop’s private address and its own temporary port, 51234. If it went onto the internet like this, the server could never answer: 192.168.1.10 exists in millions of homes.",
          facts: [["Source", `${LAPTOP}:${LP}`], ["Destination", `${S}:443`], ["Address type", "Private (RFC 1918)"]],
          events: [
            pkt("client", "router", "amber", "SYN", [`${LAPTOP}:${LP}`, "private"], {
              time: 0, info: `${LP} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(...inside(MAC.laptop, MAC.lan, LAPTOP, S, 64, 0x3a01), tcp({ sport: LP, dport: 443, seq: 0, flags: "S", opts: synOpts, seqBase: 0x7710aa00 })),
            }),
          ],
        },
        {
          title: "Translated",
          desc: "Becomes 198.51.100.7:40001",
          detail:
            "The router replaces the source address with its public one and the source port with a free port, 40001. It writes a line in its NAT table: 192.168.1.10:51234 ↔ 198.51.100.7:40001, to 203.0.113.10:443. Because the addresses and port changed, it also recomputes the IP and TCP checksums.",
          facts: [["New source", `${PUB}:${MAP1}`], ["Table entry", `${LAPTOP}:${LP} ↔ ${PUB}:${MAP1}`], ["Also changed", "TTL, IP + TCP checksums"]],
          quiz: {
            q: "Which fields did the router change?",
            options: ["Only the destination address", "Source address, source port, TTL and checksums", "Nothing, it just forwards", "The TCP sequence number"],
            answer: 1,
            why: "Port address translation rewrites the source address and port. The TTL drops by one as with any router, and both checksums must be fixed because they cover the changed fields.",
          },
          events: [
            pkt("router", "server", "teal", "SYN", [`${PUB}:${MAP1}`, "public"], {
              time: 0.0003, info: `${MAP1} → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(...outside(true, PUB, S, 63, 0x3a01), tcp({ sport: MAP1, dport: 443, seq: 0, flags: "S", opts: synOpts, seqBase: 0x7710aa00 })),
            }),
            note("router", `NEW: ${LP} → ${MAP1}`, "blue"),
          ],
        },
        {
          title: "The reply, translated back",
          desc: "To 198.51.100.7:40001, then to the laptop",
          detail:
            "The server only ever sees 198.51.100.7:40001, so that is where it replies. The router looks up port 40001 in its table, finds the laptop, and rewrites the destination back to 192.168.1.10:51234 before passing it inside.",
          facts: [["Arrives for", `${PUB}:${MAP1}`], ["Table says", `${LAPTOP}:${LP}`], ["Server knows the laptop?", "No, only the public address"]],
          quiz: {
            q: `The SYN-ACK arrives for ${PUB}:${MAP1}. Where does the router send it?`,
            options: ["To every device in the house", `${LAPTOP}:${LP}`, `${PHONE}:${LP}`, "It drops it"],
            answer: 1,
            why: "The table entry made in the last step maps outside port 40001 back to the laptop’s address and port.",
          },
          events: [
            pkt("server", "router", "violet", "SYN-ACK", [`to ${PUB}:${MAP1}`], {
              time: 0.0302, info: `443 → ${MAP1} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(...outside(false, S, PUB, 55, 0), tcp({ sport: 443, dport: MAP1, seq: 0, ack: 1, flags: "SA", win: 65160, opts: saOpts(5512001), seqBase: 0x2c4b9100, ackBase: 0x7710aa00 })),
            }),
            pkt("router", "client", "violet", "SYN-ACK", [`to ${LAPTOP}:${LP}`], {
              time: 0.0304, info: `443 → ${LP} [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM WS=128`,
              packet: build(...inside(MAC.lan, MAC.laptop, S, LAPTOP, 54, 0), tcp({ sport: 443, dport: LP, seq: 0, ack: 1, flags: "SA", win: 65160, opts: saOpts(5512001), seqBase: 0x2c4b9100, ackBase: 0x7710aa00 })),
            }),
          ],
        },
        {
          title: "The phone joins in",
          desc: "Same server, same inside port, different outside port",
          detail:
            "The phone happens to pick port 51234 too and connects to the same server. Using 40001 again would mix the two connections up, so the router picks 40002. That is the “port” part of PAT: one public address, told apart by port number.",
          facts: [["Phone", `${PHONE}:${LP}`], ["Becomes", `${PUB}:${MAP2}`], ["Up to", "About 64,000 flows per protocol and server"]],
          quiz: {
            q: `Why can’t the router reuse port ${MAP1} for the phone?`,
            options: ["Ports can’t be reused ever", "Replies to 40001 would be ambiguous: laptop or phone?", "The phone uses UDP", "The server would refuse it"],
            answer: 1,
            why: "Both connections go to the same server and port. Only the outside port tells their replies apart, so each needs its own.",
          },
          events: [
            pkt("phone", "router", "amber", "SYN", [`${PHONE}:${LP}`], {
              time: 1.2, info: `${LP} → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 SACK_PERM WS=64`,
              packet: build(...inside(MAC.phone, MAC.lan, PHONE, S, 64, 0x0e11), tcp({ sport: LP, dport: 443, seq: 0, flags: "S", win: 65535, opts: [{ mss: 1460 }, "sackOk", { ts: [301, 0] }, "nop", { ws: 6 }], seqBase: 0x9e000001 })),
            }),
            pkt("router", "server", "teal", "SYN", [`${PUB}:${MAP2}`], {
              time: 1.2003, info: `${MAP2} → 443 [SYN] Seq=0 Win=65535 Len=0 MSS=1460 SACK_PERM WS=64`,
              packet: build(...outside(true, PUB, S, 63, 0x0e11), tcp({ sport: MAP2, dport: 443, seq: 0, flags: "S", win: 65535, opts: [{ mss: 1460 }, "sackOk", { ts: [301, 0] }, "nop", { ws: 6 }], seqBase: 0x9e000001 })),
            }),
            note("router", `NEW: ${PHONE} → ${MAP2}`, "blue"),
          ],
        },
        {
          title: "Entries expire",
          desc: "FIN closes it, a timer cleans up",
          detail:
            "When the laptop closes its connection with FIN, the router translates it like any other packet and then shortens the entry’s life to a few seconds. Entries for idle connections expire on their own: minutes for UDP, hours for an open TCP connection. Then port 40001 is free again.",
          facts: [["After FIN", "Removed within seconds"], ["Idle UDP", "Typically 30–180 s"], ["Idle TCP", "Often 2 h or more"]],
          events: [
            pkt("client", "router", "slate", "FIN", [`${LAPTOP}:${LP}`], {
              time: 9.5, info: `${LP} → 443 [FIN, ACK] Seq=518 Ack=4890 Win=501 Len=0`,
              packet: build(...inside(MAC.laptop, MAC.lan, LAPTOP, S, 64, 0x3a40), tcp({ sport: LP, dport: 443, seq: 518, ack: 4890, flags: "FA", win: 501, seqBase: 0x7710aa00, ackBase: 0x2c4b9100 })),
            }),
            pkt("router", "server", "slate", "FIN", [`${PUB}:${MAP1}`], {
              time: 9.5003, info: `${MAP1} → 443 [FIN, ACK] Seq=518 Ack=4890 Win=501 Len=0`,
              packet: build(...outside(true, PUB, S, 63, 0x3a40), tcp({ sport: MAP1, dport: 443, seq: 518, ack: 4890, flags: "FA", win: 501, seqBase: 0x7710aa00, ackBase: 0x2c4b9100 })),
            }),
            note("router", `${MAP1}: CLOSING`, "amber"),
          ],
        },
      ],
      outro: {
        title: "One address, many devices",
        text: "The router swapped each private address and port for its public address and a unique port, remembered the swap, and reversed it for the replies. The server never saw a private address, and the laptop and phone never noticed the translation.",
        facts: [["Laptop", `${LAPTOP}:${LP} ↔ ${PUB}:${MAP1}`], ["Phone", `${PHONE}:${LP} ↔ ${PUB}:${MAP2}`], ["Public addresses used", "1"]],
      },
    },
    {
      id: "inbound",
      name: "Unsolicited inbound and port forwarding",
      summary: "A friend tries to reach the NAS from outside. With no table entry it is dropped, until a port forward is added.",
      kind: "failure",
      devices: failDevices,
      links: failLinks,
      steps: [
        {
          title: "A knock from outside",
          desc: "SYN to 198.51.100.7:8443",
          detail:
            "A friend wants to open the photo site on the home NAS. All they know is the public address, so they connect to 198.51.100.7 port 8443. The router has no table entry for port 8443: nobody inside ever started this conversation.",
          facts: [["From", `${FRIEND}:52011`], ["To", `${PUB}:${FWD}`], ["Table entry", "None"]],
          quiz: {
            q: "What does the router do with this SYN?",
            options: ["Sends it to every device inside", "Drops it: there is no mapping", "Sends it to the first device it finds", "Replies itself with a web page"],
            answer: 1,
            why: "NAT only knows where to send replies to connections that started inside. With no entry and no rule, the packet has nowhere to go.",
          },
          events: [
            pkt("friend", "router", "red", "SYN", [`to ${PUB}:${FWD}`, "no mapping"], {
              time: 0, lost: true, info: `52011 → ${FWD} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`,
              packet: build(...outside(false, FRIEND, PUB, 52, 0x6c01), tcp({ sport: 52011, dport: FWD, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", { ts: [7001, 0] }, "nop", { ws: 7 }], seqBase: 0x44110000 })),
            }),
            note("router", "NO MAPPING: DROPPED", "red"),
          ],
        },
        {
          title: "Add a port forward",
          desc: "8443 outside → 192.168.1.50:443 inside",
          detail:
            "In the router’s settings, the owner adds a port forwarding rule: anything arriving on TCP port 8443 goes to the NAS at 192.168.1.50, port 443. This is a permanent table entry that works in the other direction: from outside in.",
          facts: [["Rule", `TCP ${FWD} → ${NAS}:443`], ["Lasts", "Until removed"], ["Risk", "The NAS is now open to the whole internet"]],
          events: [note("router", `RULE: ${FWD} → ${NAS}:443`, "green")],
        },
        {
          title: "Forwarded inside",
          desc: "Destination rewritten to the NAS",
          detail:
            "The friend’s browser retries. This time the router matches the rule, rewrites the destination to 192.168.1.50:443, and records the connection in its table so replies can find their way back. The source stays the friend’s real address.",
          facts: [["Arrives for", `${PUB}:${FWD}`], ["Rewritten to", `${NAS}:443`], ["Source", `${FRIEND} (unchanged)`]],
          quiz: {
            q: "In port forwarding, which address is rewritten on the way in?",
            options: ["The source address", "The destination address and port", "Both addresses", "Neither"],
            answer: 1,
            why: "Inbound forwarding is destination NAT: the public destination becomes the inside device. Outgoing NAT rewrites the source instead.",
          },
          events: [
            pkt("friend", "router", "amber", "SYN", [`to ${PUB}:${FWD}`], {
              time: 3.0, info: `52011 → ${FWD} [SYN] Seq=0 Win=64240 Len=0 MSS=1460`,
              packet: build(...outside(false, FRIEND, PUB, 52, 0x6c02), tcp({ sport: 52011, dport: FWD, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", { ts: [10001, 0] }, "nop", { ws: 7 }], seqBase: 0x44110000 })),
            }),
            pkt("router", "nas", "teal", "SYN", [`to ${NAS}:443`], {
              time: 3.0003, info: `52011 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460`,
              packet: build(...inside(MAC.lan, MAC.nas, FRIEND, NAS, 51, 0x6c02), tcp({ sport: 52011, dport: 443, seq: 0, flags: "S", opts: [{ mss: 1460 }, "sackOk", { ts: [10001, 0] }, "nop", { ws: 7 }], seqBase: 0x44110000 })),
            }),
          ],
        },
        {
          title: "Reply goes back out",
          desc: "Source rewritten to 198.51.100.7:8443",
          detail:
            "The NAS answers from 192.168.1.50:443. The router reverses the swap so the friend sees the reply come from 198.51.100.7:8443, exactly where they knocked. The connection works.",
          facts: [["NAS sends from", `${NAS}:443`], ["Friend sees", `${PUB}:${FWD}`], ["Connection", "Established"]],
          events: [
            pkt("nas", "router", "violet", "SYN-ACK", [`from ${NAS}:443`], {
              time: 3.0005, info: `443 → 52011 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460`,
              packet: build(...inside(MAC.nas, MAC.lan, NAS, FRIEND, 64, 0), tcp({ sport: 443, dport: 52011, seq: 0, ack: 1, flags: "SA", win: 65160, opts: saOpts(10001), seqBase: 0x5ab00000, ackBase: 0x44110000 })),
            }),
            pkt("router", "friend", "violet", "SYN-ACK", [`from ${PUB}:${FWD}`], {
              time: 3.0008, info: `${FWD} → 52011 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460`,
              packet: build(...outside(true, PUB, FRIEND, 63, 0), tcp({ sport: FWD, dport: 52011, seq: 0, ack: 1, flags: "SA", win: 65160, opts: saOpts(10001), seqBase: 0x5ab00000, ackBase: 0x44110000 })),
            }),
            note("friend", "CONNECTED", "green"),
          ],
        },
      ],
      outro: {
        title: "Closed by default, open by rule",
        text: "NAT drops packets that don’t match a connection started inside, which works like a basic firewall. A port forward is a fixed rule that lets one outside port reach one inside device. Open only what you need, and keep that device updated.",
        facts: [["Without rule", "Dropped"], ["With rule", `${FWD} → ${NAS}:443`], ["Inbound NAT", "Rewrites destination"], ["Outbound NAT", "Rewrites source"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Kinds of NAT",
      items: [["SNAT / masquerade", "Rewrite source on the way out"], ["PAT / NAPT", "Many inside hosts share one IP by port"], ["DNAT / port forward", "Rewrite destination on the way in"], ["CGNAT", "Your ISP adds another NAT layer (100.64.0.0/10)"]],
    },
    {
      title: "NAT table columns",
      items: [["Inside", "Private IP:port"], ["Outside", "Public IP:port the router chose"], ["Remote", "Server IP:port"], ["Timer", "When the entry expires"]],
    },
    {
      title: "Good to know",
      items: [["Breaks", "Inbound connections, some VoIP and games"], ["Workarounds", "Port forwarding, UPnP, STUN/TURN"], ["IPv6", "Usually no NAT: every device has a public address"]],
    },
  ],
});
