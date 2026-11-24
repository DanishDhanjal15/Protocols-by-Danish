"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowRight, Check, ChevronLeft, ChevronRight, Download, Expand, Keyboard, Layers, ListTree, Menu, Network,
  Pause, Play, RotateCcw, Rows3, Search, SkipForward, Sparkles, Volume2, VolumeX, X, GraduationCap, Terminal, Boxes, Table2,
} from "lucide-react";
import type { Lesson } from "@/lib/lesson";
import { GroupId, OSI_NAMES } from "@/lib/lesson";
import { expandLesson, expandPacket } from "@/lib/catalog";
import { applyText, LessonText, TryIt } from "@/lib/text";
import { downloadPcap } from "@/lib/pcap";
import { MOBILE_H, MOBILE_W, STAGE_H, STAGE_W } from "@/lib/route";
import { useApp } from "../Providers";
import { usePlayer } from "./usePlayer";
import { NetworkView, SequenceView } from "./Stage";
import { CaptureTable, Inspector } from "./Packets";
import { CheatSheet, Facts, QuizCard, QuizRun, StepPanel } from "./Panels";
import { EncapView } from "./EncapView";
import { LiveTables } from "./LiveTables";
import { TryItPanel } from "./TryItPanel";

type Tab = "info" | "inspect" | "quiz" | "try" | "cheat";

const FAMILY: Record<string, GroupId[]> = {
  core: ["journey", "foundations", "lan", "routing"],
  app: ["web", "naming", "realtime", "mail-files", "iot", "india"],
  security: ["security", "vpn"],
};
const FAMILY_NAME = { all: "All", core: "Core", app: "Apps", security: "Security" } as const;

export function Player({ lesson: compact, hinglish, tryit }: { lesson: Lesson; hinglish?: LessonText | null; tryit?: TryIt | null }) {
  const { t, catalog, progress, updateProgress, layer, setLayer, contentLang, setContentLang } = useApp();
  const english = useMemo(() => expandLesson(compact), [compact]);
  const lang = contentLang === "hinglish" && hinglish ? "hinglish" : "en";
  const lesson = useMemo(() => (lang === "hinglish" ? applyText(english, hinglish) : english), [english, hinglish, lang]);

  const [scIdx, setScIdx] = useState(0);
  const scenario = lesson.scenarios[scIdx] ?? lesson.scenarios[0];
  const devices = scenario.devices ?? lesson.devices;
  const links = scenario.links ?? lesson.links;
  const voiceHold = useRef<() => boolean>(() => false);
  const api = usePlayer(scenario, voiceHold);

  const [view, setView] = useState<"network" | "sequence" | "layers">("network");
  const [bottom, setBottom] = useState<"capture" | "tables">("capture");
  const [tab, setTab] = useState<Tab>("info");
  const [sidebar, setSidebarState] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const [panels, setPanels] = useState(true);
  const [family, setFamily] = useState<keyof typeof FAMILY_NAME>("all");
  const [filter, setFilter] = useState("");
  const [predict, setPredict] = useState(false);
  const [narrate, setNarrate] = useState(false);
  const [help, setHelp] = useState(false);
  const [narrow, setNarrow] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const [answers, setAnswers] = useState<Record<string, number>>({});
  const stageRef = useRef<HTMLDivElement>(null);
  const activeRow = useRef<HTMLLIElement>(null);
  const stepper = useRef<HTMLDivElement>(null);
  const urlApplied = useRef(false);

  // the protocol list is hidden by default so the lesson has room; remember the learner's choice
  useEffect(() => {
    try {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      if (localStorage.getItem("pbd:sidebar") === "1") setSidebarState(true);
    } catch {}
  }, []);
  const setSidebar = useCallback((fn: (s: boolean) => boolean) => {
    setSidebarState((s) => {
      const next = fn(s);
      try { localStorage.setItem("pbd:sidebar", next ? "1" : "0"); } catch {}
      return next;
    });
  }, []);
  /** One menu button: docks the list on wide screens, slides it in as a drawer on smaller ones. */
  const toggleList = useCallback(() => {
    if (window.matchMedia("(min-width: 1280px)").matches) setSidebar((s) => !s);
    else setDrawer((d) => !d);
  }, [setSidebar]);

  useEffect(() => {
    const li = activeRow.current;
    const ul = li?.parentElement;
    if (li && ul) ul.scrollTop = li.offsetTop - ul.clientHeight / 3;
  }, [lesson.id, sidebar, drawer, family]);

  // jump to a finished step of a given scenario, after any scenario switch (and its reset) has happened
  const [jump, setJump] = useState<{ sc: number; step: number } | null>(null);
  useEffect(() => {
    if (!jump || jump.sc !== scIdx) return;
    api.showStepDone(Math.min(Math.max(jump.step, 0), scenario.steps.length - 1));
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setJump(null);
  }, [jump, scIdx, api, scenario.steps.length]);
  const goStepIn = useCallback((sc: number, step: number) => {
    setScIdx(sc);
    setJump({ sc, step });
  }, [setScIdx]);

  useEffect(() => {
    if (urlApplied.current) return;
    urlApplied.current = true;
    const sp = new URLSearchParams(window.location.search);
    const s = sp.get("s");
    const i = s ? lesson.scenarios.findIndex((x) => x.id === s) : -1;
    const st = Number(sp.get("step"));
    // applying the shared link's state once after mount is the point of this effect
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (st >= 1) goStepIn(Math.max(i, 0), st - 1);
    else if (i > 0) setScIdx(i);
  }, [lesson, goStepIn, setScIdx]);

  useEffect(() => {
    const mq = matchMedia("(max-width: 640px)");
    const on = () => setNarrow(mq.matches);
    on();
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);

  useEffect(() => {
    const sp = new URLSearchParams();
    if (scIdx > 0) sp.set("s", scenario.id);
    if (api.stepIdx >= 0 && api.stepIdx < scenario.steps.length) sp.set("step", String(api.stepIdx + 1));
    const q = sp.toString();
    window.history.replaceState(null, "", `${window.location.pathname}${q ? `?${q}` : ""}`);
  }, [scIdx, scenario, api.stepIdx]);

  // keep the current step card in view
  useEffect(() => {
    const box = stepper.current;
    const el = box?.querySelector<HTMLElement>(`[data-step="${api.stepIdx}"]`);
    if (el && box) box.scrollTo({ left: el.offsetLeft - box.clientWidth / 2 + el.clientWidth / 2, behavior: "smooth" });
  }, [api.stepIdx]);

  const step = api.stepIdx >= 0 && api.stepIdx < scenario.steps.length ? scenario.steps[api.stepIdx] : null;
  const qKey = `${scenario.id}-${api.stepIdx}`;
  const quizPending = !!(predict && step?.quiz && answers[qKey] === undefined);
  const finished = api.stepIdx >= scenario.steps.length;

  useEffect(() => {
    if (quizPending && api.playing && api.groupIdx === 0) api.setPlaying(false);
  }, [quizPending, api.playing, api.groupIdx, api]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (quizPending) setTab("info");
  }, [quizPending]);

  // voice guide: reads each step aloud; auto-play waits until it finishes speaking
  useEffect(() => {
    voiceHold.current = () => narrate && typeof speechSynthesis !== "undefined" && (speechSynthesis.speaking || speechSynthesis.pending);
  }, [narrate]);

  useEffect(() => {
    if (typeof speechSynthesis === "undefined") return;
    speechSynthesis.cancel();
    if (!narrate) return;
    const text = step
      ? `${lang === "hinglish" ? "Step" : "Step"} ${api.stepIdx + 1}. ${step.title}. ${step.detail}`
      : finished
        ? `${scenario.outro.title}. ${scenario.outro.text}`
        : `${lesson.name}. ${lesson.full}. ${lesson.description}`;
    const u = new SpeechSynthesisUtterance(text);
    const voices = speechSynthesis.getVoices();
    u.voice = voices.find((v) => v.lang === "en-IN") ?? voices.find((v) => v.lang.startsWith("en") && /natural|google|online/i.test(v.name)) ?? voices.find((v) => v.lang.startsWith("en")) ?? null;
    u.lang = u.voice?.lang ?? "en-IN";
    speechSynthesis.speak(u);
    return () => speechSynthesis.cancel();
  }, [narrate, step, finished, api.stepIdx, scenario, lesson, lang]);

  useEffect(() => {
    if (!finished) return;
    updateProgress((p) => (p.done.includes(lesson.id) ? p : { ...p, done: [...p.done, lesson.id] }));
  }, [finished, lesson.id, updateProgress]);

  const selected = useMemo(() => {
    if (!api.captured.length) return undefined;
    return api.captured.find((c) => c.key === sel) ?? api.captured[api.captured.length - 1];
  }, [api.captured, sel]);

  // layers of the packet in flight (or the selected one) for the OSI ladder
  const ladder = useMemo(() => {
    const flying = api.groups[api.groupIdx]?.packets[0];
    const c = (api.playing && flying) || selected;
    const names: Record<number, string> = {};
    if (c) {
      for (const l of expandPacket(c.ev.packet).layers) {
        if (l.id === "data") continue;
        const n = l.osi === 5 ? 6 : l.osi === 1 ? 2 : l.osi;
        names[n] = names[n] ? `${names[n]} · ${l.name}` : l.name;
      }
    }
    return { layers: new Set(Object.keys(names).map(Number)), names };
  }, [api.groups, api.groupIdx, api.playing, selected]);

  const selectPacket = useCallback((k: string) => {
    setSel(k);
    setTab("inspect");
  }, []);

  const movePacket = (d: number) => {
    const i = api.captured.findIndex((c) => c.key === selected?.key);
    const n = api.captured[Math.max(0, Math.min(api.captured.length - 1, i + d))];
    if (n) setSel(n.key);
  };

  const toggleFs = useCallback(async () => {
    try {
      if (!document.fullscreenElement) await stageRef.current?.requestFullscreen();
      else await document.exitFullscreen();
    } catch {}
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (el.closest("input, textarea, select, [contenteditable]") || e.ctrlKey || e.metaKey || e.altKey) return;
      const k = e.key;
      if (k === " ") { e.preventDefault(); api.toggle(); }
      else if (k === "ArrowRight") { e.preventDefault(); api.next(); }
      else if (k === "ArrowLeft") { e.preventDefault(); api.prev(); }
      else if (k === "s" || k === "S") api.stepPacket();
      else if (k === "v" || k === "V") setView((v) => (v === "network" ? "sequence" : v === "sequence" ? "layers" : "network"));
      else if (k === "d" || k === "D") setPanels((p) => !p);
      else if (k === "l" || k === "L") toggleList();
      else if (k === "f" || k === "F") toggleFs();
      else if (k === "p" || k === "P") setPredict((p) => !p);
      else if (k === "r" || k === "R") api.restart();
      else if (k === "?") setHelp((h) => !h);
      else if (k === "Escape") { if (help) setHelp(false); else if (drawer) setDrawer(false); else api.goStep(-1, false); }
      else if (/^[1-9]$/.test(k) && Number(k) <= scenario.steps.length) api.goStep(Number(k) - 1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [api, scenario.steps.length, help, drawer, toggleFs, toggleList]);

  const quizzes = useMemo(() => scenario.steps.flatMap((st, i) => (st.quiz ? [{ step: i, title: st.title, quiz: st.quiz }] : [])), [scenario]);
  const recordQuiz = useCallback((ok: boolean) => {
    updateProgress((p) => {
      const qz = p.quiz[lesson.id] ?? { correct: 0, total: 0 };
      return { ...p, quiz: { ...p.quiz, [lesson.id]: { correct: qz.correct + (ok ? 1 : 0), total: qz.total + 1 } } };
    });
  }, [lesson.id, updateProgress]);

  const idx = catalog.findIndex((c) => c.id === lesson.id);
  const nextLesson = idx >= 0 ? catalog[idx + 1] : undefined;
  const score = Object.entries(answers).filter(([k]) => k.startsWith(`${scenario.id}-`));
  const correct = score.filter(([, v]) => v === 1).length;
  const download = () => downloadPcap(`${lesson.id}-${scenario.id}`, api.allPackets.map((c) => c.ev), lesson.linktype);

  // ---------------------------------------------------------------- protocol list
  const q = filter.trim().toLowerCase();
  const list = catalog.filter(
    (c) =>
      (family === "all" || FAMILY[family].includes(c.group)) &&
      (!layer || c.layer === layer) &&
      (!q || [c.name, c.full, ...c.keywords].some((x) => x.toLowerCase().includes(q)))
  );

  const sidebarEl = (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center justify-between px-4 pt-4">
        <span className="hud-title">Protocols <span className="mono text-[11px] normal-case tracking-normal">· {catalog.length}</span></span>
        <button className="icon-btn xl:hidden" onClick={() => setDrawer(false)} aria-label="Close"><X size={16} /></button>
        <button className="icon-btn hidden xl:inline-grid" onClick={() => setSidebar(() => false)} aria-label="Hide protocol list" title="Hide list (L)"><X size={16} /></button>
      </div>
      <div className="px-4 pt-3 flex flex-col gap-2">
        <label className="flex items-center gap-2 h-9 px-3 rounded-lg bg-panel-2 border border-line focus-within:border-line-2">
          <Search size={15} className="text-muted" />
          <input id="proto-filter" value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter protocols" className="flex-1 bg-transparent outline-none text-[13.5px] min-w-0" />
        </label>
        <div className="flex gap-3 border-b border-line" role="tablist">
          {(Object.keys(FAMILY_NAME) as (keyof typeof FAMILY_NAME)[]).map((f) => (
            <button key={f} role="tab" aria-selected={family === f} onClick={() => setFamily(f)}
              className={`h-8 -mb-px border-b-2 text-[12.5px] font-medium ${family === f ? "border-brand text-ink" : "border-transparent text-muted hover:text-ink"}`}>
              {FAMILY_NAME[f]}
            </button>
          ))}
        </div>
        <select id="layer-filter" value={layer} onChange={(e) => setLayer(Number(e.target.value))} aria-label="OSI layer"
          className="h-8 rounded-lg bg-panel-2 border border-line text-[12.5px] px-2 text-ink-2">
          <option value={0}>All OSI layers</option>
          {[2, 3, 4, 6, 7].map((n) => <option key={n} value={n}>Layer {n}: {OSI_NAMES[n]}</option>)}
        </select>
      </div>
      <ul className="relative flex-1 min-h-0 overflow-y-auto mt-3 px-2 pb-3">
        {list.map((c) => {
          const active = c.id === lesson.id;
          const done = progress.done.includes(c.id);
          return (
            <li key={c.id} ref={active ? activeRow : undefined}>
              <Link href={`/learn/${c.id}`} onClick={() => setDrawer(false)}
                className={`flex items-center gap-2.5 px-2.5 py-2 rounded-lg ${active ? "bg-panel-3" : "hover:bg-panel-2"}`}>
                <span className={`osi-${c.layer} mono text-[10px] font-bold w-7 h-5 grid place-items-center rounded shrink-0`} style={{ background: "var(--ls)", color: "var(--lc)" }}>L{c.layer}</span>
                <span className="flex-1 min-w-0 leading-tight">
                  <span className={`block text-[13.5px] ${active ? "font-semibold text-ink" : "font-medium text-ink-2"}`}>{c.name}</span>
                  <span className="text-[11.5px] text-muted block truncate">{c.full}</span>
                </span>
                {done && <Check size={15} className="text-brand shrink-0" aria-label="Done" />}
              </Link>
            </li>
          );
        })}
        {!list.length && <li className="px-3 py-2 text-muted text-[13px]">No protocol matches.</li>}
      </ul>
    </div>
  );

  // ---------------------------------------------------------------- explanation panel
  const infoEl = (
    <>
      {api.stepIdx === -1 && (
        <div className="flex flex-col gap-4 fade-up">
          <div>
            <h2 className="text-[26px] font-bold leading-tight text-ink">{lesson.name}</h2>
            <p className="text-[14px] text-muted mt-0.5">{lesson.full}</p>
          </div>
          <p className="text-[14.5px] leading-relaxed text-ink-2">{lesson.description}</p>
          <Facts facts={lesson.facts} />
          <div className="text-[13.5px] text-ink-2 rounded-lg p-3 bg-panel-2">
            <span className="font-semibold text-ink">{scenario.name}.</span> {scenario.summary}
          </div>
          <div className="flex flex-wrap gap-2">
            <button className="btn btn-primary" onClick={() => api.goStep(0)}><Play size={14} fill="currentColor" /> {t.start}</button>
            <button className="btn" aria-pressed={predict} onClick={() => setPredict((p) => !p)}><Sparkles size={14} /> {t.predict}: {predict ? "on" : "off"}</button>
          </div>
        </div>
      )}
      {step && (
        <StepPanel step={step} index={api.stepIdx} total={scenario.steps.length}>
          {predict && step.quiz && (
            <>
              <QuizCard key={qKey} quiz={step.quiz} onAnswered={(ok) => {
                setAnswers((a) => ({ ...a, [qKey]: ok ? 1 : 0 }));
                updateProgress((p) => {
                  const qz = p.quiz[lesson.id] ?? { correct: 0, total: 0 };
                  return { ...p, quiz: { ...p.quiz, [lesson.id]: { correct: qz.correct + (ok ? 1 : 0), total: qz.total + 1 } } };
                });
              }} />
              {answers[qKey] !== undefined && api.groupIdx === 0 && !api.playing && (
                <button className="btn btn-primary self-start" onClick={() => api.setPlaying(true)}><Play size={14} fill="currentColor" /> {t.playStep}</button>
              )}
            </>
          )}
          {api.stepDone && !api.playing && (
            <button className="btn self-start" onClick={api.next}>
              {api.stepIdx < scenario.steps.length - 1 ? `${t.next}: ${scenario.steps[api.stepIdx + 1].title}` : t.complete} <ArrowRight size={14} />
            </button>
          )}
        </StepPanel>
      )}
      {finished && (
        <div className="flex flex-col gap-3 fade-up">
          <div className="eyebrow !text-brand">{t.complete}</div>
          <h2 className="text-[22px] font-bold">{scenario.outro.title}</h2>
          <p className="text-[14.5px] leading-relaxed text-ink-2">{scenario.outro.text}</p>
          <Facts facts={scenario.outro.facts} />
          {score.length > 0 && <p className="text-[14px]">{t.score}: <strong className="text-brand">{correct}/{score.length}</strong></p>}
          <div className="flex flex-wrap gap-2">
            {quizzes.length > 0 && <button className="btn btn-primary" onClick={() => setTab("quiz")}><GraduationCap size={15} /> Test yourself ({quizzes.length})</button>}
            <button className="btn" onClick={api.restart}><RotateCcw size={14} /> {t.replay}</button>
            {lesson.scenarios.length > 1 && <button className="btn" onClick={() => setScIdx((scIdx + 1) % lesson.scenarios.length)}>Next scenario</button>}
            {nextLesson && <Link className="btn" href={`/learn/${nextLesson.id}`}>{nextLesson.name} <ArrowRight size={14} /></Link>}
          </div>
          {lesson.related?.length ? (
            <div className="flex flex-wrap gap-1.5 items-center text-[12.5px] text-muted">
              Related:
              {lesson.related.map((r) => {
                const m = catalog.find((c) => c.id === r);
                return m ? <Link key={r} href={`/learn/${r}`} className="chip hover:bg-panel-2">{m.name}</Link> : null;
              })}
            </div>
          ) : null}
        </div>
      )}
    </>
  );

  const TABS: [Tab, string, React.ReactNode][] = [
    ["info", api.stepIdx === -1 ? "Overview" : finished ? "Summary" : "Explain", <Layers key="i" size={14} />],
    ["inspect", "Packet", <ListTree key="i" size={14} />],
    ["quiz", quizzes.length ? `Quiz · ${quizzes.length}` : "Quiz", <GraduationCap key="i" size={14} />],
    ["try", "Try it", <Terminal key="i" size={14} />],
    ["cheat", "Cheat", <Rows3 key="i" size={14} />],
  ];

  const stageAspect = narrow ? `${MOBILE_W} / ${MOBILE_H}` : `${STAGE_W} / ${STAGE_H}`;
  const cols = sidebar
    ? "xl:grid-cols-[250px_minmax(0,1fr)_380px] 2xl:grid-cols-[270px_minmax(0,1fr)_420px]"
    : "xl:grid-cols-[minmax(0,1fr)_380px] 2xl:grid-cols-[minmax(0,1fr)_420px]";
  const c1 = sidebar ? "xl:col-start-2" : "xl:col-start-1";
  const c2 = sidebar ? "xl:col-start-3" : "xl:col-start-2";
  const rows = panels ? "xl:grid-rows-[minmax(0,1fr)_minmax(200px,30%)]" : "xl:grid-rows-[minmax(0,1fr)]";

  return (
    <div className={`w-full flex-1 xl:flex-none min-h-0 p-3 gap-3 grid grid-cols-1 player-grid ${cols} ${rows}`}>
      {/* stage */}
      <section ref={stageRef} className={`hud flex flex-col min-h-0 overflow-hidden order-1 xl:order-none ${c1} xl:row-start-1`}>
        <div className="flex flex-wrap items-center gap-2 px-3 pt-3">
          <button className="icon-btn" onClick={toggleList} aria-pressed={sidebar} aria-label={sidebar ? "Hide protocol list" : "Show protocol list"} title="Protocols (L)"><Menu size={18} /></button>
          <div className="min-w-0 flex-1 basis-[calc(100%-48px)]">
            <h1 className="text-[20px] font-bold leading-tight whitespace-nowrap overflow-hidden text-ellipsis">
              {lesson.name} <span className="text-muted font-medium text-[14px]">{lesson.full}</span>
            </h1>
          </div>
          {lesson.scenarios.length > 1 && (
            <select id="scenario" value={scIdx} onChange={(e) => setScIdx(Number(e.target.value))} aria-label={t.scenario}
              className="h-9 max-w-[260px] rounded-lg border border-line bg-panel-2 px-2 text-[13px] text-ink">
              {lesson.scenarios.map((s, i) => (
                <option key={s.id} value={i}>{s.kind === "attack" ? "Attack: " : s.kind === "failure" ? "What if: " : ""}{s.name}</option>
              ))}
            </select>
          )}
          <div className="flex p-0.5 rounded-lg bg-panel-2" role="tablist" aria-label="View">
            {(["network", "sequence", "layers"] as const).map((v) => (
              <button key={v} role="tab" aria-selected={view === v} onClick={() => setView(v)} title={v === "layers" ? "Encapsulation: watch headers wrap and unwrap" : undefined}
                className={`h-8 px-3 rounded-md text-[13px] font-semibold inline-flex items-center gap-1.5 ${view === v ? "bg-panel-3 text-ink" : "text-muted hover:text-ink"}`}>
                {v === "network" ? <Network size={15} /> : v === "sequence" ? <Rows3 size={15} /> : <Boxes size={15} />}
                <span className="hidden sm:inline">{v === "network" ? t.network : v === "sequence" ? t.sequence : "Layers"}</span>
              </button>
            ))}
          </div>
          <div className="flex p-0.5 rounded-lg bg-panel-2" role="tablist" aria-label="Lesson language">
            {(["en", "hinglish"] as const).map((l) => (
              <button key={l} role="tab" aria-selected={lang === l} disabled={l === "hinglish" && !hinglish} onClick={() => setContentLang(l)}
                title={l === "hinglish" && !hinglish ? "Hinglish for this lesson is coming soon" : undefined}
                className={`h-8 px-2.5 rounded-md text-[12.5px] font-semibold disabled:opacity-40 ${lang === l ? "bg-panel-3 text-ink" : "text-muted hover:text-ink"}`}>
                {l === "en" ? "EN" : "Hinglish"}
              </button>
            ))}
          </div>
          <button className="icon-btn hidden sm:inline-grid" onClick={toggleFs} title={`${t.fullscreen} (F)`} aria-label={t.fullscreen}><Expand size={17} /></button>
          <button className={`icon-btn hidden ${sidebar ? "2xl:inline-grid" : "sm:inline-grid"}`} onClick={() => setHelp(true)} title={`${t.shortcuts} (?)`} aria-label={t.shortcuts}><Keyboard size={17} /></button>
        </div>

        <div className="relative flex-1 min-h-[260px] stage-bg mx-3 mt-3 rounded-lg overflow-hidden">
          <div className="absolute inset-0 flex items-center justify-center">
            <div className={view === "layers" ? "w-full h-full" : "w-full max-h-full"} style={view === "layers" ? undefined : { aspectRatio: stageAspect }}>
              {view === "network" ? (
                <NetworkView devices={devices} links={links} api={api} selected={selected?.key} onSelect={selectPacket} narrow={narrow} />
              ) : view === "sequence" ? (
                <SequenceView devices={devices} links={links} scenario={scenario} api={api} selected={selected?.key} onSelect={selectPacket} />
              ) : (
                <EncapView api={api} selected={selected} devices={devices} lang={lang} />
              )}
            </div>
          </div>

          {/* OSI ladder: which layers the current packet carries */}
          {view === "network" && !narrow && (
            <div className="absolute left-3 top-3 flex flex-col gap-1 pointer-events-none" aria-label="Layers in this packet">
              {[7, 6, 4, 3, 2].map((n) => {
                const on = ladder.layers.has(n);
                return (
                  <div key={n} className={`osi-${n} flex items-center gap-2 h-6 pl-1 pr-2.5 rounded-md text-[11.5px] transition-all duration-300 ${on ? "opacity-100" : "opacity-40"}`} style={{ background: on ? "var(--ls)" : "transparent" }}>
                    <span className="mono font-bold text-[10px] w-6 text-center" style={{ color: "var(--lc)" }}>L{n}</span>
                    <span className={on ? "text-ink" : "text-muted"}>{on ? ladder.names[n] : OSI_NAMES[n]}</span>
                  </div>
                );
              })}
            </div>
          )}

          {api.stepIdx === -1 && (
            <div className="absolute inset-0 grid place-items-center bg-[rgba(14,17,22,.55)]">
              <button onClick={() => api.goStep(0)} className="btn btn-primary !h-12 !px-7 !text-[15px] !rounded-full"><Play size={18} fill="currentColor" /> {t.start}</button>
            </div>
          )}
        </div>

        {/* step cards */}
        <div ref={stepper} className="flex gap-2 overflow-x-auto px-3 py-3" aria-label="Steps">
          {scenario.steps.map((s, i) => {
            const state = finished || i < api.stepIdx ? "done" : i === api.stepIdx ? "now" : "todo";
            const pct = state === "done" ? 100 : state === "now" ? (api.groups.length ? (api.groupIdx / api.groups.length) * 100 : 0) : 0;
            return (
              <button key={i} data-step={i} onClick={() => api.goStep(i)}
                className={`relative shrink-0 w-[170px] text-left rounded-lg px-3 pt-2 pb-2.5 overflow-hidden border ${state === "now" ? "bg-panel-3 border-line-2" : "bg-panel-2 border-transparent hover:border-line"}`}>
                <span className="flex items-center gap-2">
                  <span className={`w-5 h-5 shrink-0 rounded-full grid place-items-center mono text-[10.5px] font-bold ${state === "now" ? "bg-brand text-brand-ink" : state === "done" ? "bg-brand-soft text-brand" : "bg-panel-3 text-muted"}`}>
                    {state === "done" ? <Check size={11} /> : i + 1}
                  </span>
                  <span className={`text-[12.5px] font-semibold leading-tight line-clamp-2 ${state === "todo" ? "text-ink-2" : "text-ink"}`}>{s.title}</span>
                </span>
                <span className="absolute left-0 bottom-0 h-[3px] bg-brand transition-[width] duration-300" style={{ width: `${pct}%` }} />
              </button>
            );
          })}
        </div>
      </section>

      {/* explanation / packet / cheat sheet */}
      <section className={`hud flex flex-col min-h-[420px] xl:min-h-0 overflow-hidden order-3 xl:order-none ${c2} xl:row-start-1 xl:row-span-2`}>
        <div className="flex gap-4 px-4 border-b border-line overflow-x-auto" role="tablist">
          {TABS.map(([id, label, icon]) => (
            <button key={id} role="tab" aria-selected={tab === id} onClick={() => setTab(id)}
              className={`h-11 -mb-px border-b-2 text-[13px] font-medium inline-flex items-center gap-1.5 whitespace-nowrap ${tab === id ? "border-brand text-ink" : "border-transparent text-muted hover:text-ink"}`}>
              {icon}{label}
            </button>
          ))}
        </div>
        <div className="flex-1 min-h-0 overflow-y-auto">
          {tab === "info" && <div className="p-4">{infoEl}</div>}
          {tab === "inspect" && <Inspector cap={selected} onPrev={() => movePacket(-1)} onNext={() => movePacket(1)} />}
          {tab === "quiz" && <QuizRun key={scenario.id} items={quizzes} onAnswer={recordQuiz} onGoStep={(i) => { api.showStepDone(i); setTab("info"); }} />}
          {tab === "try" && <TryItPanel data={tryit ?? null} lang={lang} onDownload={download} onGoStep={(i) => { goStepIn(0, i); setTab("info"); }} />}
          {tab === "cheat" && <CheatSheet lesson={lesson} />}
        </div>
      </section>

      {/* protocol list */}
      {sidebar && <aside className="hud hidden xl:flex flex-col min-h-0 xl:col-start-1 xl:row-start-1 xl:row-span-2" aria-label={t.menu}>{sidebarEl}</aside>}
      {drawer && (
        <div className="xl:hidden fixed inset-0 z-50 flex">
          <button className="absolute inset-0 bg-black/60" onClick={() => setDrawer(false)} aria-label="Close" />
          <aside className="hud relative w-[86%] max-w-[340px] h-full !rounded-none">{sidebarEl}</aside>
        </div>
      )}

      {/* playback + capture */}
      {panels && (
        <section className={`hud flex flex-col min-h-[260px] max-h-[60vh] xl:max-h-none xl:min-h-0 overflow-hidden order-2 xl:order-none ${c1} xl:row-start-2`}>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-3 py-2">
            <div className="flex items-center gap-1">
              <button className="icon-btn" onClick={api.prev} title={`${t.prev} (←)`} aria-label={t.prev}><ChevronLeft size={18} /></button>
              <button className="btn btn-primary !rounded-full !px-5" onClick={api.toggle} title="Space">
                {api.playing ? <Pause size={15} fill="currentColor" /> : <Play size={15} fill="currentColor" />}{api.playing ? t.pause : t.play}
              </button>
              <button className="icon-btn" onClick={api.next} title={`${t.next} (→)`} aria-label={t.next}><ChevronRight size={18} /></button>
              <button className="icon-btn" onClick={api.stepPacket} title="Next packet (S)" aria-label="Next packet"><SkipForward size={16} /></button>
              <button className="icon-btn" onClick={api.restart} title={`${t.restart} (R)`} aria-label={t.restart}><RotateCcw size={16} /></button>
              <button className="btn !h-8 !px-3 ml-1" aria-pressed={narrate} onClick={() => setNarrate((n) => !n)} title="The voice guide reads each step aloud; auto-play waits for it to finish">
                {narrate ? <Volume2 size={15} /> : <VolumeX size={15} />}Voice guide{narrate ? ": on" : ""}
              </button>
              <select id="speed" value={api.speed} onChange={(e) => api.setSpeed(Number(e.target.value))} className="h-8 rounded-lg border border-line bg-panel-2 text-[12.5px] mono px-1.5 ml-1" aria-label={t.speed} title={t.speed}>
                {[0.5, 0.75, 1, 1.5, 2, 3].map((s) => <option key={s} value={s}>{s}×</option>)}
              </select>
            </div>
            <div className="flex flex-wrap gap-x-3 gap-y-1 text-[12px] flex-1 min-w-[200px]" aria-label={t.legend}>
              {lesson.legend.map(([c, label]) => (
                <span key={label} className={`c-${c} inline-flex items-center gap-1.5 text-ink-2`}><span className="dot" />{label}</span>
              ))}
            </div>
            <div className="flex items-center gap-1">
              <button className="icon-btn" aria-pressed={api.single} onClick={() => api.setSingle(!api.single)} title={t.single} aria-label={t.single}><ListTree size={16} /></button>
              <button className="icon-btn" aria-pressed={predict} onClick={() => setPredict((p) => !p)} title={`${t.predict} (P)`} aria-label={t.predict}><Sparkles size={16} /></button>
              <button className="icon-btn" onClick={() => setTab("quiz")} title="Quiz" aria-label="Quiz"><GraduationCap size={16} /></button>
              <button className="icon-btn" onClick={download} title={`${t.download}: open in Wireshark`} aria-label={t.download}><Download size={16} /></button>
            </div>
          </div>
          <div className="flex gap-4 px-4 border-b border-line" role="tablist" aria-label="Capture or tables">
            {([["capture", "Capture", <ListTree key="i" size={14} />], ["tables", "Live tables", <Table2 key="i" size={14} />]] as const).map(([id, label, icon]) => (
              <button key={id} role="tab" aria-selected={bottom === id} onClick={() => setBottom(id)}
                className={`h-10 -mb-px border-b-2 text-[13px] font-medium inline-flex items-center gap-1.5 ${bottom === id ? "border-brand text-ink" : "border-transparent text-muted hover:text-ink"}`}>
                {icon}{label}{id === "capture" && <span className="mono text-[11px] text-muted">{api.captured.length}</span>}
              </button>
            ))}
          </div>
          <div className="flex-1 min-h-0">
            {bottom === "capture" ? <CaptureTable rows={api.captured} selected={selected?.key} onSelect={selectPacket} /> : <LiveTables rows={api.captured} lang={lang} />}
          </div>
        </section>
      )}

      {help && <Shortcuts onClose={() => setHelp(false)} />}
    </div>
  );
}

function Shortcuts({ onClose }: { onClose: () => void }) {
  const { t } = useApp();
  const rows: [string, string][] = [
    ["Space", "Play / pause (plays on until you pause)"], ["← →", "Previous / next step"], ["S", "Next packet"], ["1–9", "Jump to step"], ["R", "Restart"],
    ["V", "Network / sequence view"], ["P", "Predict mode"], ["D", "Show or hide the capture"], ["L", "Protocol list"], ["F", "Fullscreen stage"],
    ["Ctrl K", "Search"], ["Esc", "Back to overview"], ["?", "This sheet"],
  ];
  return (
    <div className="fixed inset-0 z-50 grid place-items-center p-4" role="dialog" aria-modal="true" aria-label={t.shortcuts}>
      <button className="absolute inset-0 bg-black/60" onClick={onClose} aria-label="Close" />
      <div className="hud relative p-5 w-full max-w-md fade-up">
        <h2 className="text-[18px] font-bold mb-4">{t.shortcuts}</h2>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-[13.5px]">
          {rows.map(([k, v]) => (
            <div key={k} className="contents"><dt><span className="kbd">{k}</span></dt><dd className="text-ink-2">{v}</dd></div>
          ))}
        </dl>
        <button className="btn mt-5" onClick={onClose}>Close</button>
      </div>
    </div>
  );
}
