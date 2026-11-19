import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono, Space_Grotesk } from "next/font/google";
import "./globals.css";
import { TopBar } from "@/components/TopBar";
import { Providers } from "@/components/Providers";
import { getCatalog } from "@/lessons";

const inter = Inter({ variable: "--font-inter", subsets: ["latin"] });
const display = Space_Grotesk({ variable: "--font-display", subsets: ["latin"], weight: ["500", "600", "700"] });
const mono = JetBrains_Mono({ variable: "--font-mono", subsets: ["latin"] });

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
    { color: "#0e1116" },
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
        </Providers>
      </body>
    </html>
  );
}
