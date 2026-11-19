import { redirect } from "next/navigation";

// The site opens on the "Type google.com" journey: the whole internet in one story.
export default function Home() {
  redirect("/learn/journey");
}
