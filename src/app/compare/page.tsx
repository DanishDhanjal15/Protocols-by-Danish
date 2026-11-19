import type { Metadata } from "next";
import { getCatalog } from "@/lessons";
import { CompareView } from "./CompareView";

export const metadata: Metadata = {
  title: "Compare protocols",
  description: "Compare two protocols side by side: layer, ports, security, packet structure and use cases.",
};

export default async function ComparePage() {
  const catalog = await getCatalog();
  return (
    <main className="max-w-[1280px] w-full mx-auto px-[max(16px,env(safe-area-inset-left,0px))] py-8">
      <div className="eyebrow">Compare</div>
      <h1 className="text-[34px] font-bold mt-1">Compare two protocols</h1>
      <p className="text-muted mt-2 max-w-2xl">
        Pick any two protocols and see them side by side: layer, ports, header size, security, and typical use cases.
      </p>
      <div className="mt-6">
        <CompareView catalog={catalog} />
      </div>
    </main>
  );
}
