import { defineLesson, Device, note, pkt } from "@/lib/lesson";
import { build } from "@/lib/packet";
import { arp, BROADCAST_MAC, dhcp, dhcpOpt, eth, ipv4, udp } from "@/lib/proto";
import { ADDR } from "./_common";

const L = ADDR.laptop;
const R = ADDR.router;
const LM = ADDR.laptopMac;
const RM = ADDR.routerMac;
const BC = "255.255.255.255";
const XID = 0x3903f326;
const XID2 = 0x5e1a77c4;
const ROGUE = "192.168.1.66";
const ROGUE_MAC = "00:0c:29:66:6e:01";
const APIPA = "169.254.37.112";

const LEASE = 86400;
const T1 = LEASE / 2;
const T2 = (LEASE * 7) / 8;

// broadcast from a client that has no address yet
const fromNowhere = (src = LM) => [eth({ src, dst: BROADCAST_MAC }), ipv4({ src: "0.0.0.0", dst: BC, ttl: 64, id: 0, df: false }), udp({ sport: 68, dport: 67 })];
// broadcast reply from a server
const bcastReply = (srcIp: string, srcMac: string) => [eth({ src: srcMac, dst: BROADCAST_MAC }), ipv4({ src: srcIp, dst: BC, ttl: 64, id: 0, df: false }), udp({ sport: 67, dport: 68 })];

const clientOpts = [dhcpOpt.clientId(LM), dhcpOpt.hostname("danish-laptop"), dhcpOpt.paramList(1, 3, 6, 15, 51, 58, 59)];

const discover = (xid: number, secs = 0) =>
  build(...fromNowhere(), dhcp({ op: 1, xid, chaddr: LM, broadcast: true, secs, options: [dhcpOpt.msgType(1), ...clientOpts] }));

const offerOpts = (server: string, gw: string, dnsIp: string) => [
  dhcpOpt.serverId(server),
  dhcpOpt.lease(LEASE),
  dhcpOpt.renewal(T1),
  dhcpOpt.rebind(T2),
  dhcpOpt.subnet("255.255.255.0"),
  dhcpOpt.router(gw),
  dhcpOpt.dns(dnsIp),
  dhcpOpt.domain("home.arpa"),
];

const realOffer = (type: 2 | 5, xid = XID) =>
  build(...bcastReply(R, RM), dhcp({ op: 2, xid, chaddr: LM, broadcast: true, yiaddr: L, options: [dhcpOpt.msgType(type), ...offerOpts(R, R, R)] }));

const rogueOffer = (type: 2 | 5) =>
  build(
    ...bcastReply(ROGUE, ROGUE_MAC),
    dhcp({
      op: 2, xid: XID, chaddr: LM, broadcast: true, yiaddr: "192.168.1.150",
      options: [
        dhcpOpt.msgType(type),
        dhcpOpt.serverId(ROGUE),
        dhcpOpt.lease(LEASE),
        dhcpOpt.subnet("255.255.255.0"),
        dhcpOpt.raw(3, "Router", [192, 168, 1, 66], ROGUE, "The attacker names itself as the default gateway."),
        dhcpOpt.raw(6, "DNS servers", [192, 168, 1, 66], ROGUE, "The attacker names itself as the DNS server too."),
      ],
    })
  );

const request = (server: string, ip: string, xid = XID) =>
  build(...fromNowhere(), dhcp({ op: 1, xid, chaddr: LM, broadcast: true, options: [dhcpOpt.msgType(3), dhcpOpt.requestedIp(ip), dhcpOpt.serverId(server), ...clientOpts] }));

const lanDevices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: "no address yet", x: 10, y: 62 },
  { id: "switch", kind: "switch", label: "Switch", x: 38, y: 62 },
  { id: "router", kind: "router", label: "Home router", sub: `${R} (DHCP server)`, x: 66, y: 62 },
  { id: "internet", kind: "cloud", label: "Internet", x: 89, y: 32 },
];
const lanLinks: [string, string][] = [["client", "switch"], ["switch", "router"], ["router", "internet"]];

const noServerDevices: Device[] = [
  { id: "client", kind: "laptop", label: "Laptop", sub: "no address yet", x: 12, y: 62 },
  { id: "switch", kind: "switch", label: "Switch", x: 45, y: 62 },
  { id: "router", kind: "router", label: "Router", sub: "DHCP service off", x: 80, y: 62 },
];

const attackDevices: Device[] = [
  ...lanDevices,
  { id: "attacker", kind: "attacker", label: "Rogue DHCP", sub: ROGUE, x: 38, y: 22 },
];
const attackLinks: [string, string][] = [...lanLinks, ["attacker", "switch"]];

export default defineLesson({
  id: "dhcp",
  name: "DHCP",
  full: "Dynamic Host Configuration Protocol",
  group: "lan",
  layer: 7,
  difficulty: 1,
  tagline: "How a device gets an IP address the moment it joins a network.",
  description:
    "A new device knows nothing about the network it just joined: not its own address, not the router, not the DNS server. DHCP fixes that in four messages (Discover, Offer, Request, Ack), and the device then rents its address for a set time and renews it before it runs out.",
  facts: [
    ["Layer", "Application (runs over UDP)"],
    ["Ports", "UDP 68 client, 67 server"],
    ["Messages", "DISCOVER, OFFER, REQUEST, ACK"],
    ["Address rented for", "The lease time"],
    ["Header", "236 bytes + options"],
    ["Defined in", "RFC 2131, options in RFC 2132"],
  ],
  ports: "UDP 67 (server), UDP 68 (client)",
  rfc: "RFC 2131",
  keywords: ["dora", "discover", "offer", "request", "ack", "lease", "apipa", "169.254", "rogue dhcp", "dhcp snooping", "renewal", "t1", "gateway"],
  related: ["arp", "ethernet", "ip", "dns", "journey"],
  devices: lanDevices,
  links: lanLinks,
  legend: [
    ["blue", "Client asking (broadcast)"],
    ["green", "Server answers"],
    ["slate", "Background: ARP checks"],
    ["red", "Problems and attacks"],
  ],
  scenarios: [
    {
      id: "normal",
      name: "Joining the network (DORA) and renewing",
      summary: "The laptop plugs in, gets 192.168.1.10 in four messages, and renews its lease halfway through.",
      kind: "normal",
      steps: [
        {
          title: "DISCOVER",
          desc: "“Is there a DHCP server out there?”",
          detail:
            "The laptop has no IP address and doesn’t know who the server is, so it shouts. It sends from 0.0.0.0 to 255.255.255.255, inside an Ethernet frame to ff:ff:ff:ff:ff:ff, so every device on the network hears it. It picks a random transaction ID so it can match the replies to this request.",
          facts: [["From", "0.0.0.0 : 68"], ["To", "255.255.255.255 : 67"], ["Ethernet to", "ff:ff:ff:ff:ff:ff (everyone)"]],
          quiz: {
            q: "Why does the laptop send from the address 0.0.0.0?",
            options: ["It hides its identity", "It has no IP address yet", "0.0.0.0 is the DHCP server", "Routers require it"],
            answer: 1,
            why: "0.0.0.0 means “this host, no address yet”. The MAC address inside the message tells the server who is asking.",
          },
          events: [
            pkt("client", "router", "blue", "DISCOVER", ["0.0.0.0 → broadcast", `xid 0x${XID.toString(16)}`], {
              time: 0, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: discover(XID),
            }),
          ],
        },
        {
          title: "OFFER",
          desc: "The server suggests an address",
          detail:
            "The home router runs a small DHCP server. It picks a free address from its pool, 192.168.1.10, and offers it along with the subnet mask, the gateway, a DNS server and the lease time. The laptop asked for a broadcast reply (it has no address to receive a unicast), so the offer is broadcast too.",
          facts: [["Offered", L], ["Gateway, DNS", `${R}, ${R}`], ["Lease", "86400 s (24 h)"]],
          quiz: {
            q: "The OFFER is sent to 255.255.255.255. Why not straight to 192.168.1.10?",
            options: ["The laptop doesn’t own that address yet and set the broadcast flag", "Routers never send unicast", "UDP can’t do unicast", "To save bandwidth"],
            answer: 0,
            why: "The address is only offered, not confirmed, and the laptop asked for broadcast replies because its IP stack is not configured yet.",
          },
          events: [
            pkt("router", "client", "green", "OFFER", [`how about ${L}?`, "lease 24 h"], {
              time: 0.002, info: `DHCP Offer - Transaction ID 0x${XID.toString(16)}`, packet: realOffer(2),
            }),
          ],
        },
        {
          title: "REQUEST",
          desc: "“Yes please, I’ll take that one”",
          detail:
            "The laptop accepts by broadcasting a REQUEST that names the address it wants (option 50) and the server it chose (option 54). It is still broadcast so that if several servers made offers, the others see they were not picked and put their addresses back in the pool.",
          facts: [["Requested IP", L], ["Chosen server", R], ["Still from", "0.0.0.0 (not confirmed yet)"]],
          quiz: {
            q: "Why is the REQUEST broadcast when the laptop already knows the server?",
            options: ["To tell any other servers their offers were declined", "Because UDP has no unicast", "To reach the internet", "It isn’t; it goes to 192.168.1.1"],
            answer: 0,
            why: "Every server hears the REQUEST and sees option 54. Only the named server answers; the rest free up their offered addresses.",
          },
          events: [
            pkt("client", "router", "blue", "REQUEST", [`I take ${L}`, `from ${R}`], {
              time: 1.004, info: `DHCP Request - Transaction ID 0x${XID.toString(16)}`, packet: request(R, L),
            }),
          ],
        },
        {
          title: "ACK",
          desc: "The lease is confirmed",
          detail:
            "The server writes the lease into its table and confirms with ACK. Only now does the laptop configure 192.168.1.10/24, set 192.168.1.1 as the default gateway and use it for DNS. Many systems then send a quick ARP check to make sure nobody else is already using the address.",
          facts: [["Address", `${L}/24`], ["Renew at (T1)", "43200 s (12 h)"], ["Rebind at (T2)", "75600 s (21 h)"]],
          events: [
            pkt("router", "client", "green", "ACK", [`${L} is yours`, "for 24 h"], {
              time: 1.006, info: `DHCP ACK - Transaction ID 0x${XID.toString(16)}`, packet: realOffer(5),
            }),
            pkt("client", "switch", "slate", "ARP", [`anyone using ${L}?`], {
              time: 1.01, info: `Who has ${L}? Tell 0.0.0.0 (ARP Probe)`,
              packet: build(eth({ src: LM, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: LM, senderIp: "0.0.0.0", targetIp: L })),
            }),
            note("client", `CONFIGURED: ${L}`, "green"),
          ],
        },
        {
          title: "Renew at T1",
          desc: "Halfway through the lease, ask to extend it",
          detail:
            "Twelve hours later (T1, half the lease) the laptop asks to keep its address. Now it has a working address and knows the server, so the REQUEST goes straight to 192.168.1.1 with its own address in the ciaddr field. The server answers with a fresh ACK and the 24-hour clock starts again. If the server stayed silent until T2, the laptop would broadcast to any server instead.",
          facts: [["When", "T1 = 43200 s"], ["Sent", `unicast ${L} → ${R}`], ["ciaddr", `${L} (filled in now)`]],
          quiz: {
            q: "Twelve hours later, how will the renewal REQUEST be addressed?",
            options: ["Broadcast from 0.0.0.0, like before", `Unicast from ${L} to ${R}`, "Multicast to all routers", "It isn’t sent; leases renew themselves"],
            answer: 1,
            why: "The laptop now has a valid address and knows the server, so it can simply talk to it directly.",
          },
          events: [
            pkt("client", "router", "blue", "REQUEST", ["renew please", "unicast"], {
              time: T1, info: `DHCP Request - Transaction ID 0x${XID2.toString(16)}`,
              packet: build(eth({ src: LM, dst: RM }), ipv4({ src: L, dst: R, ttl: 64, id: 0x4b21, df: false }), udp({ sport: 68, dport: 67 }), dhcp({ op: 1, xid: XID2, chaddr: LM, ciaddr: L, options: [dhcpOpt.msgType(3), ...clientOpts] })),
            }),
            pkt("router", "client", "green", "ACK", ["renewed", "24 h more"], {
              time: T1 + 0.002, info: `DHCP ACK - Transaction ID 0x${XID2.toString(16)}`,
              packet: build(eth({ src: RM, dst: LM }), ipv4({ src: R, dst: L, ttl: 64, id: 0, df: false }), udp({ sport: 67, dport: 68 }), dhcp({ op: 2, xid: XID2, chaddr: LM, ciaddr: L, yiaddr: L, options: [dhcpOpt.msgType(5), ...offerOpts(R, R, R)] })),
            }),
            note("client", "LEASE EXTENDED", "green"),
          ],
        },
      ],
      outro: {
        title: "Configured and renewed",
        text: "Four broadcasts and replies (Discover, Offer, Request, Ack) gave the laptop an address, a gateway and a DNS server. Halfway through the lease it renewed with two small unicast messages, so the address never ran out.",
        facts: [["Messages to join", "4 (DORA)"], ["Time to join", "About 1 s"], ["Renewal", "At T1, unicast"], ["Ports", "UDP 68 ↔ 67"]],
      },
    },
    {
      id: "no-server",
      name: "No DHCP server (APIPA 169.254.x.x)",
      summary: "Nobody answers the DISCOVER, so the laptop gives itself a link-local address that only works on the local wire.",
      kind: "failure",
      devices: noServerDevices,
      links: [["client", "switch"], ["switch", "router"]],
      steps: [
        {
          title: "DISCOVER, no answer",
          desc: "The shout goes unanswered",
          detail:
            "The router’s DHCP service has been switched off (or crashed). The DISCOVER reaches every device on the network, but nobody is listening on port 67, so nothing comes back.",
          facts: [["Sent", "DISCOVER (broadcast)"], ["Replies", "None"], ["Laptop waits", "About 4 s"]],
          events: [
            pkt("client", "router", "blue", "DISCOVER", ["anyone?"], { time: 0, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: discover(XID) }),
            note("router", "NOT LISTENING ON 67", "red"),
          ],
        },
        {
          title: "Try again, wait longer",
          desc: "Retries with growing gaps",
          detail:
            "DHCP runs over UDP, which has no delivery guarantee, so the client does its own retries. It waits about 4, then 8, then 16 seconds between attempts (plus a little randomness). The seconds-elapsed field grows each time so a server could see the client has been waiting.",
          facts: [["Retries at", "≈ 4 s, 12 s, 28 s"], ["Backoff", "Doubles each time"], ["secs field", "Counts up"]],
          quiz: {
            q: "Why does the waiting time double after each failed attempt?",
            options: ["To avoid flooding a busy network with broadcasts", "Because the lease doubles", "UDP requires it", "To let the switch learn the MAC"],
            answer: 0,
            why: "Backing off stops hundreds of devices from hammering the network with broadcasts when a server is slow or missing.",
          },
          events: [
            pkt("client", "router", "blue", "DISCOVER", ["retry 1"], { time: 4, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: discover(XID, 4) }),
            pkt("client", "router", "blue", "DISCOVER", ["retry 2"], { time: 12, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: discover(XID, 12) }),
            pkt("client", "router", "blue", "DISCOVER", ["retry 3"], { time: 28, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: discover(XID, 28) }),
          ],
        },
        {
          title: "Pick a 169.254 address",
          desc: "APIPA: choose one at random, check it first",
          detail:
            "After about a minute the laptop gives up and picks a random link-local address in 169.254.0.0/16 (Windows calls this APIPA). Before using it, it sends ARP probes from 0.0.0.0 asking whether anyone already has 169.254.37.112. Silence means the address is free.",
          facts: [["Range", "169.254.1.0 – 169.254.254.255"], ["Picked", APIPA], ["Defined in", "RFC 3927"]],
          quiz: {
            q: "What is the ARP probe’s sender IP while the laptop checks the address?",
            options: [APIPA, "0.0.0.0", "255.255.255.255", R],
            answer: 1,
            why: "The laptop must not claim the address until it knows it is free, so the probe’s sender IP is 0.0.0.0.",
          },
          events: [
            pkt("client", "switch", "slate", "ARP PROBE", [`anyone have ${APIPA}?`], {
              time: 60, info: `Who has ${APIPA}? Tell 0.0.0.0 (ARP Probe)`,
              packet: build(eth({ src: LM, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: LM, senderIp: "0.0.0.0", targetIp: APIPA })),
            }),
          ],
        },
        {
          title: "Announce and live with it",
          desc: "The address works on this wire only",
          detail:
            "Nobody answered, so the laptop announces the address with a gratuitous ARP and starts using it. It can talk to other devices on the same switch that also have 169.254 addresses, but there is no gateway and no DNS, so the internet is unreachable. Seeing a 169.254 address is the classic sign that DHCP failed.",
          facts: [["Address", `${APIPA}/16`], ["Gateway", "None"], ["Internet", "No access"]],
          events: [
            pkt("client", "switch", "slate", "ARP ANNOUNCE", [`${APIPA} is mine`], {
              time: 62, info: `ARP Announcement for ${APIPA}`,
              packet: build(eth({ src: LM, dst: BROADCAST_MAC }), arp({ op: 1, senderMac: LM, senderIp: APIPA, targetIp: APIPA })),
            }),
            note("client", "169.254.x.x: LOCAL ONLY", "red"),
          ],
        },
      ],
      outro: {
        title: "Self-assigned, but stuck",
        text: "With no DHCP server, the laptop fell back to a self-assigned 169.254 address. It keeps sending DISCOVERs in the background, and the moment a server answers it switches to a proper address.",
        facts: [["Symptom", "169.254.x.x address"], ["Cause", "No reply to DISCOVER"], ["Fix", "Check the DHCP server, cable or Wi-Fi"]],
      },
    },
    {
      id: "rogue",
      name: "Rogue DHCP server and DHCP snooping",
      summary: "An attacker answers faster than the real router and makes itself the gateway; DHCP snooping on the switch blocks it.",
      kind: "attack",
      devices: attackDevices,
      links: attackLinks,
      steps: [
        {
          title: "DISCOVER reaches everyone",
          desc: "Including the attacker",
          detail:
            "A broadcast goes to every port on the switch. An attacker who plugged a laptop (or a cheap router) into the network sees the DISCOVER just like the real server does. DHCP has no built-in way to prove which server is genuine.",
          facts: [["Heard by", "Router and attacker"], ["Authentication", "None in DHCP"], ["Attacker", ROGUE]],
          events: [
            pkt("client", "router", "blue", "DISCOVER", ["anyone?"], { time: 0, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: discover(XID) }),
            pkt("client", "attacker", "blue", "DISCOVER", ["heard by attacker"], { time: 0, parallel: true, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: discover(XID) }),
          ],
        },
        {
          title: "The rogue answers first",
          desc: "A fake offer with a fake gateway",
          detail:
            "The attacker’s server replies within a millisecond, before the real router. Its offer looks normal, but it lists the attacker’s own machine as both the default gateway and the DNS server. Clients usually take the first offer they get.",
          facts: [["Rogue gateway", ROGUE], ["Rogue DNS", ROGUE], ["Real offer", "Arrives 2 ms later"]],
          quiz: {
            q: "If the laptop accepts this offer, where will its traffic to the internet go first?",
            options: ["Straight to the real router", "To the attacker at 192.168.1.66", "Nowhere; it will fail", "To the switch only"],
            answer: 1,
            why: "The default gateway option tells the laptop where to send everything outside the local network. Here that is the attacker.",
          },
          events: [
            pkt("attacker", "client", "red", "OFFER", ["gateway = me", "DNS = me"], { time: 0.001, info: `DHCP Offer - Transaction ID 0x${XID.toString(16)}`, packet: rogueOffer(2) }),
            pkt("router", "client", "green", "OFFER", ["real offer", "too late"], { time: 0.002, info: `DHCP Offer - Transaction ID 0x${XID.toString(16)}`, packet: realOffer(2) }),
          ],
        },
        {
          title: "Laptop takes the bait",
          desc: "Traffic now flows through the attacker",
          detail:
            "The laptop requests the rogue offer and gets an ACK. From now on every packet bound for the internet goes to the attacker first, and every DNS lookup is answered by the attacker, who can send the victim to fake websites. This is a man-in-the-middle position.",
          facts: [["Chosen server", ROGUE], ["Risk", "Spying, fake DNS answers"], ["Victim notices", "Usually nothing"]],
          events: [
            pkt("client", "attacker", "blue", "REQUEST", ["I take your offer"], { time: 1.003, info: `DHCP Request - Transaction ID 0x${XID.toString(16)}`, packet: request(ROGUE, "192.168.1.150") }),
            pkt("attacker", "client", "red", "ACK", ["gateway = me"], { time: 1.004, info: `DHCP ACK - Transaction ID 0x${XID.toString(16)}`, packet: rogueOffer(5) }),
            note("attacker", "MAN IN THE MIDDLE", "red"),
          ],
        },
        {
          title: "Defence: DHCP snooping",
          desc: "The switch only trusts the router’s port",
          detail:
            "With DHCP snooping turned on, the switch marks the port to the real router as trusted and every other port as untrusted. Server messages (OFFER, ACK) arriving on an untrusted port are dropped, so the rogue offer never reaches the laptop. The switch also records which MAC got which IP, which later helps block ARP spoofing.",
          facts: [["Trusted port", "Uplink to the router"], ["Dropped", "OFFER/ACK from other ports"], ["Bonus", "Binding table for ARP inspection"]],
          quiz: {
            q: "A DHCP OFFER arrives on a switch port marked untrusted. What does snooping do?",
            options: ["Forwards it normally", "Drops it", "Changes the gateway field", "Sends it only to the router"],
            answer: 1,
            why: "Only trusted ports may carry server messages. Clients never need to send OFFER or ACK, so dropping them is safe.",
          },
          events: [
            pkt("client", "router", "blue", "DISCOVER", ["new attempt"], { time: 5, info: `DHCP Discover - Transaction ID 0x${XID.toString(16)}`, packet: discover(XID, 5) }),
            pkt("attacker", "client", "red", "OFFER", ["blocked at switch"], { time: 5.001, lost: true, info: `DHCP Offer - Transaction ID 0x${XID.toString(16)}`, packet: rogueOffer(2) }),
            note("switch", "SNOOPING: DROPPED", "green"),
            pkt("router", "client", "green", "OFFER", ["the real one"], { time: 5.002, info: `DHCP Offer - Transaction ID 0x${XID.toString(16)}`, packet: realOffer(2) }),
          ],
        },
      ],
      outro: {
        title: "Only the real server gets through",
        text: "DHCP trusts whoever answers first, which makes a rogue server an easy way to become everyone’s gateway. DHCP snooping on managed switches stops server messages from ports that should only have clients.",
        facts: [["Attack", "Rogue DHCP server"], ["Effect", "Attacker becomes gateway and DNS"], ["Defence", "DHCP snooping, trusted uplink ports"]],
      },
    },
  ],
  cheatsheet: [
    {
      title: "Message types (option 53)",
      items: [["1 DISCOVER", "Client looks for servers"], ["2 OFFER", "Server proposes an address"], ["3 REQUEST", "Client accepts or renews"], ["5 ACK", "Server confirms"], ["6 NAK", "Server refuses (wrong subnet, stale address)"], ["7 RELEASE", "Client gives the address back"]],
    },
    {
      title: "Common options",
      items: [["1", "Subnet mask"], ["3", "Router (default gateway)"], ["6", "DNS servers"], ["51", "Lease time"], ["54", "Server identifier"], ["58 / 59", "T1 renew, T2 rebind"]],
    },
    {
      title: "Numbers to know",
      items: [["Ports", "UDP 68 client, 67 server"], ["T1", "50% of the lease"], ["T2", "87.5% of the lease"], ["APIPA", "169.254.0.0/16"], ["Magic cookie", "0x63825363"]],
    },
  ],
});
