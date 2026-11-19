import type { Metadata } from "next";
import { getCatalog } from "@/lessons";
import { PathsView } from "./PathsView";

export const metadata: Metadata = {
  title: "Learning paths",
  description: "Curated learning paths from beginner to advanced, organized by topic.",
};

export default async function PathsPage() {
  const catalog = await getCatalog();
  return (
    <main className="max-w-[1280px] w-full mx-auto px-[max(16px,env(safe-area-inset-left,0px))] py-8">
      <div className="eyebrow">Paths</div>
      <h1 className="text-[34px] font-bold mt-1">Learning paths</h1>
      <p className="text-muted mt-2 max-w-2xl">
        Follow a path from start to finish. Each one builds on what came before, guiding you from beginner to mastery.
      </p>
      <div className="mt-6">
        <PathsView catalog={catalog} />
      </div>
    </main>
  );
}
