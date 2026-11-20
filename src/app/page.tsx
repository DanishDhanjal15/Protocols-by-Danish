import type { Metadata } from "next";
import { compactLesson } from "@/lib/catalog";
import { getHinglish, getLesson, getTryIt } from "@/lessons";
import { Player } from "@/components/player/Player";

export const metadata: Metadata = {
  title: { absolute: "Protocols by Danish · See the internet, packet by packet" },
  description: "Start learning how the internet works with IP, the protocol on every packet, then follow the roadmap lesson by lesson.",
};

// Home: the learning journey starts with IP, right here (no redirect).
export default async function Home() {
  const lesson = await getLesson("ip");
  if (!lesson) return null;
  return <Player lesson={compactLesson(lesson)} hinglish={await getHinglish("ip")} tryit={await getTryIt("ip")} />;
}
