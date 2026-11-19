import type { Metadata } from "next";
import { getCatalog } from "@/lessons";
import { Catalog } from "@/components/Catalog";

export const metadata: Metadata = {
  title: "Learning roadmap",
  description: "Every protocol lesson, grouped from internet foundations to VPNs, IoT and India's UPI.",
};

export default async function LearnPage() {
  const catalog = await getCatalog();
  return (
    <main className="max-w-[1280px] w-full mx-auto px-[max(16px,env(safe-area-inset-left,0px))] py-8">
      <div className="eyebrow">Roadmap · {catalog.length} lessons in 12 stages</div>
      <h1 className="text-[34px] font-bold mt-1">Your networking roadmap</h1>
      <p className="text-muted mt-2 max-w-2xl">Go stage by stage, from the first packet on your Wi‑Fi to VPNs and UPI. Each lesson plays a real scenario on an animated network, decodes every byte, and ends with a quiz.</p>
      <div className="mt-6"><Catalog /></div>
    </main>
  );
}
