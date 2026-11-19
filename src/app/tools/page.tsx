import type { Metadata } from "next";
import { ToolsView } from "./ToolsView";

export const metadata: Metadata = {
  title: "Networking tools",
  description: "Wireshark-style packet playground, nslookup-style live DNS lookup, subnet calculator and port finder.",
};

export default function ToolsPage() {
  return (
    <main className="max-w-[1280px] w-full mx-auto px-[max(16px,env(safe-area-inset-left,0px))] py-8">
      <div className="eyebrow">Tools</div>
      <h1 className="text-[34px] font-bold mt-1">Networking tools</h1>
      <p className="text-muted mt-2 max-w-2xl">
        Hands-on versions of the tools network engineers use every day: a Wireshark-style packet editor, an nslookup-style DNS lookup, a subnet calculator and a port finder.
      </p>
      <div className="mt-8">
        <ToolsView />
      </div>
    </main>
  );
}
