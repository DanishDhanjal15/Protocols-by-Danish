import type { Metadata } from "next";
import { LabList } from "@/components/LabView";

export const metadata: Metadata = {
  title: "Troubleshooting labs",
  description: "Real-world network problems with the packet capture as evidence. Read the packets, find the fault, learn the fix.",
};

export default function LabsPage() {
  return (
    <main className="max-w-[1280px] w-full mx-auto px-[max(16px,env(safe-area-inset-left,0px))] py-8">
      <div className="eyebrow">Labs</div>
      <h1 className="text-[34px] font-bold mt-1">Troubleshooting labs</h1>
      <p className="text-muted mt-2 max-w-2xl">
        Each lab is a real problem someone reports: “no internet”, “connection refused”, “502”. You get the packet capture from
        that moment. Open the packets, read the fields like a network engineer, and diagnose the fault.
      </p>
      <div className="mt-6"><LabList /></div>
    </main>
  );
}
