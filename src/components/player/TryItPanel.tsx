"use client";

import { useState } from "react";
import { Check, Copy, Terminal } from "lucide-react";
import type { TryIt } from "@/lib/text";

type Os = "windows" | "unix" | "wireshark";
const OS_LABEL: Record<Os, string> = { windows: "Windows", unix: "Mac / Linux", wireshark: "Wireshark filter" };

/** "Try it yourself": real commands for the student's own computer, and filters for the lesson's .pcap. */
export function TryItPanel({ data, lang, onGoStep, onDownload }: { data: TryIt | null; lang: "en" | "hinglish"; onGoStep: (step: number) => void; onDownload: () => void }) {
  const [os, setOs] = useState<Os>(() => (typeof navigator !== "undefined" && /Mac|Linux/i.test(navigator.userAgent) ? "unix" : "windows"));
  const [copied, setCopied] = useState<number | null>(null);
  const L = (x: { en: string; hinglish: string }) => (lang === "hinglish" ? x.hinglish || x.en : x.en);

  if (!data?.commands.length)
    return (
      <p className="p-4 text-[14px] text-muted">
        {lang === "hinglish" ? "Is lesson ke commands abhi taiyaar ho rahe hain." : "Commands for this lesson are on their way."}
      </p>
    );

  const copy = (text: string, i: number) => {
    navigator.clipboard?.writeText(text).then(() => {
      setCopied(i);
      setTimeout(() => setCopied(null), 1200);
    }).catch(() => {});
  };

  return (
    <div className="p-4 flex flex-col gap-3">
      <p className="text-[13.5px] text-ink-2">
        {lang === "hinglish"
          ? "Ab khud karke dekho. Yeh commands apne computer ke terminal mein chalao, aur Wireshark filters is lesson ki .pcap file par lagao."
          : "Now see it for real. Run these in your own terminal, and use the Wireshark filters on this lesson's .pcap file."}
      </p>
      <div className="flex p-0.5 rounded-lg bg-panel-2" role="tablist" aria-label="Operating system">
        {(Object.keys(OS_LABEL) as Os[]).map((o) => (
          <button key={o} role="tab" aria-selected={os === o} onClick={() => setOs(o)}
            className={`flex-1 h-8 rounded-md text-[12.5px] font-semibold ${os === o ? "bg-panel-3 text-ink" : "text-muted hover:text-ink"}`}>
            {OS_LABEL[o]}
          </button>
        ))}
      </div>
      {os === "wireshark" && (
        <button className="btn self-start" onClick={onDownload}>
          {lang === "hinglish" ? "Is lesson ki .pcap download karo" : "Download this lesson's .pcap"}
        </button>
      )}
      <ol className="flex flex-col gap-3">
        {data.commands.map((c, i) => {
          const cmd = c[os] ?? (os === "unix" ? c.windows : os === "windows" ? c.unix : undefined);
          const fallback = !c[os] && !!cmd;
          return (
            <li key={i} className="rounded-xl border border-line bg-panel-2 p-3 flex flex-col gap-2">
              <div className="flex items-start gap-2">
                <Terminal size={16} className="text-brand mt-0.5 shrink-0" />
                <div className="min-w-0">
                  <div className="font-semibold text-[14px] text-ink">{L(c.title)}</div>
                  <p className="text-[13px] text-ink-2 leading-snug">{L(c.why)}</p>
                </div>
              </div>
              {cmd ? (
                <div className="flex items-stretch rounded-lg overflow-hidden border border-line-2">
                  <code className="flex-1 mono text-[12.5px] px-3 py-2 bg-[var(--bg)] text-ink overflow-x-auto whitespace-pre">{cmd}</code>
                  <button className="px-2.5 bg-panel-3 text-ink-2 hover:text-ink" onClick={() => copy(cmd, i)} aria-label="Copy command">
                    {copied === i ? <Check size={15} /> : <Copy size={15} />}
                  </button>
                </div>
              ) : (
                <p className="text-[12.5px] text-muted">
                  {lang === "hinglish" ? `Iske liye ${OS_LABEL[os]} wala version nahi hai; doosra tab dekho.` : `No ${OS_LABEL[os]} version for this one; try another tab.`}
                </p>
              )}
              {fallback && <p className="text-[11.5px] text-muted">{lang === "hinglish" ? "Doosre OS ka command dikhaya hai; zyaada tar same chalta hai." : "Shown from the other OS; it usually works the same."}</p>}
              <p className="text-[12.5px] text-muted leading-snug"><span className="font-semibold text-ink-2">{lang === "hinglish" ? "Kya dikhega: " : "What you'll see: "}</span>{L(c.expect)}</p>
              {c.step && (
                <button className="self-start text-[12.5px] text-brand hover:underline" onClick={() => onGoStep(c.step! - 1)}>
                  {lang === "hinglish" ? `Lesson ka step ${c.step} dekho` : `See step ${c.step} of the lesson`} →
                </button>
              )}
            </li>
          );
        })}
      </ol>
    </div>
  );
}
