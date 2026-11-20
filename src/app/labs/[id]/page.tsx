import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { compactLesson } from "@/lib/catalog";
import { getLab, LABS } from "@/lib/labs";
import { getLesson } from "@/lessons";
import { LabView } from "@/components/LabView";

export async function generateStaticParams() {
  return LABS.map((l) => ({ id: l.id }));
}

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const lab = getLab((await params).id);
  return lab ? { title: `Lab: ${lab.title.en}`, description: lab.symptom.en } : {};
}

export default async function LabPage({ params }: { params: Promise<{ id: string }> }) {
  const lab = getLab((await params).id);
  if (!lab) notFound();
  const lesson = await getLesson(lab.lesson);
  if (!lesson) notFound();
  // only the scenario used as evidence is needed on the page
  const slim = { ...lesson, scenarios: lesson.scenarios.filter((s) => s.id === lab.scenario) };
  return <LabView lab={lab} lesson={compactLesson(slim)} />;
}
