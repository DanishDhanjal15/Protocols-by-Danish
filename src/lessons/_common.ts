// Shared addresses and device layouts so every lesson tells the same story:
// Danish's laptop at home, a home router, the internet, and servers out there.
// All addresses are from documentation ranges (RFC 5737 / RFC 3849).

import { Device } from "@/lib/lesson";
import { eth, ipv4, ipv6 } from "@/lib/proto";

export const ADDR = {
  laptopMac: "3c:22:fb:7a:91:0e",
  routerMac: "b0:be:76:12:4c:01",
  phoneMac: "f4:5c:89:3a:20:7d",
  serverMac: "00:16:3e:5a:01:22",
  laptop: "192.168.1.10",
  phone: "192.168.1.23",
  router: "192.168.1.1",
  routerWan: "198.51.100.7",
  web: "203.0.113.10",
  dns: "192.0.2.53",
  mail: "203.0.113.25",
  server2: "203.0.113.40",
  laptop6: "2001:db8:1::10",
  router6: "fe80::1",
  web6: "2001:db8:ab::10",
  lan: "192.168.1.0/24",
} as const;

/** Standard four-device layout: laptop → router → internet → server */
export function homeToServer(server: Partial<Device> = {}): { devices: Device[]; links: [string, string][] } {
  return {
    devices: [
      { id: "client", kind: "laptop", label: "Laptop", sub: ADDR.laptop, x: 9, y: 62 },
      { id: "router", kind: "router", label: "Home router", sub: ADDR.router, x: 32, y: 62 },
      { id: "internet", kind: "cloud", label: "Internet", x: 58, y: 40 },
      { id: "server", kind: "web", label: "Web server", sub: ADDR.web, x: 87, y: 62, ...server },
    ],
    links: [
      ["client", "router"],
      ["router", "internet"],
      ["internet", "server"],
    ],
  };
}

/** Ethernet + IPv4 from the laptop (as captured on the laptop's own interface). */
export const up = (dst: string, o: { ttl?: number; id?: number } = {}) => [
  eth({ src: ADDR.laptopMac, dst: ADDR.routerMac }),
  ipv4({ src: ADDR.laptop, dst, ttl: o.ttl ?? 64, id: o.id }),
];

/** Ethernet + IPv4 towards the laptop. TTL is lower: routers on the way took some. */
export const down = (src: string, o: { ttl?: number; id?: number } = {}) => [
  eth({ src: ADDR.routerMac, dst: ADDR.laptopMac }),
  ipv4({ src, dst: ADDR.laptop, ttl: o.ttl ?? 54, id: o.id }),
];

export const up6 = (dst: string) => [eth({ src: ADDR.laptopMac, dst: ADDR.routerMac }), ipv6({ src: ADDR.laptop6, dst })];
export const down6 = (src: string) => [eth({ src: ADDR.routerMac, dst: ADDR.laptopMac }), ipv6({ src, dst: ADDR.laptop6, hop: 54 })];
