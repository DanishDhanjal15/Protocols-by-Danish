import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { compactLesson } from "@/lib/catalog";
import { getHinglish, getLesson, getTryIt, lessonIds } from "@/lessons";
import { Player } from "@/components/player/Player";

export async function generateStaticParams() {
  return lessonIds.map((id) => ({ id }));
}

export async function generateMetadata({ params }: { params: Promise<{ id: string }> }): Promise<Metadata> {
  const { id } = await params;
  const l = await getLesson(id);
  if (!l) return {};
  return {
    title: `${l.name}: ${l.tagline.replace(/\.$/, "")}`,
    description: `${l.description} Watch every ${l.name} packet travel, decoded byte by byte.`,
    alternates: { canonical: `/learn/${l.id}` },
    keywords: [l.name, l.full, ...(l.keywords ?? [])],
  };
}

export default async function LessonPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const lesson = await getLesson(id);
  if (!lesson) notFound();
  return (
    <>
      <Player lesson={compactLesson(lesson)} hinglish={await getHinglish(id)} tryit={await getTryIt(id)} />
      {/* Plain-text outline: readable without JavaScript and by search engines */}
      <details className="max-w-[1800px] w-full mx-auto px-4 pb-10 text-[14px] text-muted">
        <summary className="cursor-pointer py-2">Lesson outline: {lesson.name} ({lesson.full})</summary>
        <p className="max-w-3xl">{lesson.description}</p>
        {lesson.scenarios.map((s) => (
          <section key={s.id} className="mt-3 max-w-3xl">
            <h2 className="text-[15px] font-semibold text-ink">{s.name}</h2>
            <ol className="list-decimal pl-5 mt-1 space-y-1">
              {s.steps.map((st) => (
                <li key={st.title}><strong className="text-ink-2">{st.title}.</strong> {st.detail}</li>
              ))}
            </ol>
          </section>
        ))}
      </details>
    </>
  );
}
