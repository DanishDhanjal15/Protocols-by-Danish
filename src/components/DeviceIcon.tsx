import type { DeviceKind } from "@/lib/lesson";

// Line icons drawn in a 32×32 box, stroked with currentColor.
export const GLYPHS: Record<string, React.ReactNode> = {
  laptop: (<><rect x="6" y="7" width="20" height="13" rx="2" /><path d="M3 24h26l-2 2H5z" /><path d="M12 11h8M12 14h5" /></>),
  desktop: (<><rect x="4" y="5" width="24" height="16" rx="2" /><path d="M12 27h8M16 21v6" /></>),
  phone: (<><rect x="10" y="3" width="12" height="26" rx="3" /><path d="M14 25h4" /></>),
  router: (<><rect x="4" y="15" width="24" height="9" rx="2.5" /><path d="M9 15l-2-7M23 15l2-7" /><circle cx="10" cy="19.5" r="1" /><circle cx="14" cy="19.5" r="1" /><path d="M19 19.5h5" /></>),
  switch: (<><rect x="3" y="11" width="26" height="10" rx="2" /><path d="M7 16h2M11 16h2M15 16h2M19 16h2M23 16h2" /></>),
  ap: (<><path d="M9 12a10 10 0 0 1 14 0M11.5 15a6 6 0 0 1 9 0" /><circle cx="16" cy="18" r="1.4" /><rect x="7" y="22" width="18" height="5" rx="2" /></>),
  cloud: (<><path d="M9 24a6 6 0 0 1-.6-12A8 8 0 0 1 24 11a6.5 6.5 0 0 1 0 13z" /><path d="M12 18h8M14 21h4" /></>),
  server: (<><rect x="7" y="4" width="18" height="7" rx="1.5" /><rect x="7" y="12.5" width="18" height="7" rx="1.5" /><rect x="7" y="21" width="18" height="7" rx="1.5" /><circle cx="11" cy="7.5" r=".9" /><circle cx="11" cy="16" r=".9" /><circle cx="11" cy="24.5" r=".9" /></>),
  web: (<><rect x="4" y="6" width="24" height="20" rx="2.5" /><path d="M4 11h24" /><circle cx="7.5" cy="8.5" r=".7" /><circle cx="10" cy="8.5" r=".7" /><path d="M9 16h14M9 20h9" /></>),
  dns: (<><circle cx="16" cy="16" r="11" /><path d="M5 16h22M16 5c4 4 4 18 0 22M16 5c-4 4-4 18 0 22" /></>),
  mail: (<><rect x="4" y="8" width="24" height="16" rx="2" /><path d="M4 9l12 9 12-9" /></>),
  db: (<><ellipse cx="16" cy="8" rx="10" ry="3.5" /><path d="M6 8v16c0 2 4.5 3.5 10 3.5S26 26 26 24V8M6 16c0 2 4.5 3.5 10 3.5S26 18 26 16" /></>),
  camera: (<><rect x="4" y="9" width="18" height="12" rx="2" /><path d="M22 13l6-3v10l-6-3" /><path d="M10 21v4h6" /><circle cx="11" cy="15" r="2.5" /></>),
  tv: (<><rect x="3" y="6" width="26" height="17" rx="2" /><path d="M11 27h10M13 2l3 4 3-4" /></>),
  firewall: (<><rect x="4" y="6" width="24" height="20" rx="1.5" /><path d="M4 12.5h24M4 19h24M12 6v6.5M20 12.5V19M12 19v7M20 6v6.5" /></>),
  proxy: (<><circle cx="16" cy="16" r="5" /><path d="M3 16h8M21 16h8M24 12l4 4-4 4" /></>),
  vpn: (<><rect x="8" y="14" width="16" height="12" rx="2" /><path d="M11 14v-3a5 5 0 0 1 10 0v3" /><circle cx="16" cy="20" r="1.6" /></>),
  plc: (<><rect x="5" y="6" width="22" height="20" rx="1.5" /><path d="M9 10h14M9 14h6" /><circle cx="10" cy="20.5" r="1.3" /><circle cx="15" cy="20.5" r="1.3" /><circle cx="20" cy="20.5" r="1.3" /></>),
  isp: (<><path d="M16 4v24M9 28h14M11 9l5-5 5 5" /><path d="M8 13a11 11 0 0 1 16 0M5 9.5a15 15 0 0 1 22 0" /></>),
  cdn: (<><circle cx="16" cy="16" r="4" /><circle cx="6" cy="8" r="2.5" /><circle cx="26" cy="8" r="2.5" /><circle cx="6" cy="24" r="2.5" /><circle cx="26" cy="24" r="2.5" /><path d="M8 9.5l5 4M24 9.5l-5 4M8 22.5l5-4M24 22.5l-5-4" /></>),
  auth: (<><circle cx="12" cy="14" r="5" /><path d="M16 17l10 7M22 21l2-2.5M25 23l1.5-2" /><circle cx="12" cy="14" r="1.5" /></>),
  printer: (<><path d="M9 11V4h14v7" /><rect x="4" y="11" width="24" height="11" rx="2" /><rect x="9" y="18" width="14" height="9" rx="1" /></>),
  tower: (<><path d="M16 12L11 28M16 12l5 16M12.5 22h7" /><circle cx="16" cy="10" r="2" /><path d="M10 5a8 8 0 0 0 0 10M22 5a8 8 0 0 1 0 10" /></>),
  bank: (<><path d="M4 12l12-7 12 7z" /><path d="M7 13v10M12 13v10M20 13v10M25 13v10M4 26h24" /></>),
  attacker: (<><path d="M7 14a9 9 0 0 1 18 0v6l-3 5h-12l-3-5z" /><circle cx="12" cy="16" r="2" /><circle cx="20" cy="16" r="2" /><path d="M14 22h4" /></>),
  nas: (<><rect x="7" y="4" width="18" height="24" rx="2" /><path d="M11 9h10M11 13h10M11 17h10" /><circle cx="16" cy="23" r="1.4" /></>),
  iot: (<><rect x="9" y="9" width="14" height="14" rx="2" /><path d="M13 4v5M19 4v5M13 23v5M19 23v5M4 13h5M4 19h5M23 13h5M23 19h5" /></>),
  satellite: (<><rect x="13" y="13" width="6" height="6" transform="rotate(45 16 16)" /><path d="M5 5l6 6M21 21l6 6M3 9l6-6M23 29l6-6" /></>),
  phonepbx: (<><path d="M8 5h5l2 6-3 2a14 14 0 0 0 7 7l2-3 6 2v5a2 2 0 0 1-2 2A20 20 0 0 1 6 7a2 2 0 0 1 2-2z" /></>),
  broker: (<><circle cx="16" cy="16" r="4" /><circle cx="16" cy="16" r="10" strokeDasharray="3 3" /><circle cx="26" cy="16" r="1.6" /><circle cx="6" cy="16" r="1.6" /><circle cx="16" cy="6" r="1.6" /></>),
};

export function DeviceGlyph({ kind, size = 32 }: { kind: DeviceKind | string; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {GLYPHS[kind] ?? GLYPHS.server}
    </svg>
  );
}

/** Same icon as an SVG <g> for use inside the stage SVG, centred on (0,0). */
export function DeviceGlyphG({ kind, size = 30 }: { kind: DeviceKind | string; size?: number }) {
  const s = size / 32;
  return (
    <g transform={`translate(${-size / 2} ${-size / 2}) scale(${s})`} fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
      {GLYPHS[kind] ?? GLYPHS.server}
    </g>
  );
}
