import type { Metadata, Viewport } from "next";
import { IBM_Plex_Mono, IBM_Plex_Sans } from "next/font/google";
import "./globals.css";
import { TopBar } from "@/components/TopBar";
import { Providers } from "@/components/Providers";
import { SiteFooter } from "@/components/SiteFooter";
import { getCatalog } from "@/lessons";

const inter = IBM_Plex_Sans({ variable: "--font-inter", subsets: ["latin"], weight: ["400", "500", "600", "700"] });
const display = IBM_Plex_Sans({ variable: "--font-display", subsets: ["latin"], weight: ["600", "700"] });
const mono = IBM_Plex_Mono({ variable: "--font-mono", subsets: ["latin"], weight: ["400", "500", "600"] });

export const metadata: Metadata = {
  metadataBase: new URL("https://protocols-by-danish.vercel.app"),
  title: { default: "Protocols by Danish · See the internet, packet by packet", template: "%s · Protocols by Danish" },
  description:
    "Interactive, byte-accurate lessons on 60+ network protocols: TCP, DNS, TLS, HTTP/2, QUIC, Wi‑Fi, BGP, UPI and more. Animated packets, Wireshark-style inspector, what-if scenarios and quizzes.",
  applicationName: "Protocols by Danish",
  authors: [{ name: "Danish" }],
  openGraph: { type: "website", siteName: "Protocols by Danish" },
};

export const viewport: Viewport = {
  themeColor: [
    { color: "#0f1114" },
  ],
  viewportFit: "cover",
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const catalog = await getCatalog();
  return (
    <html lang="en" className={`${inter.variable} ${display.variable} ${mono.variable}`} suppressHydrationWarning>
      <body className="min-h-dvh flex flex-col">
        <Providers catalog={catalog}>
          <TopBar />
          <div className="flex-1 flex flex-col min-h-0">{children}</div>
          <SiteFooter />
        </Providers>
      </body>
    </html>
  );
}
