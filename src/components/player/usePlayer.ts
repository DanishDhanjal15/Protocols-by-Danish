"use client";

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import type { LessonEvent, NoteEvent, PacketEvent, Scenario } from "@/lib/lesson";

export interface Captured {
  key: string;
  no: number;
  step: number;
  ev: PacketEvent;
}

export interface Group {
  packets: Captured[];
  notes: NoteEvent[];
}

/** Time for one packet to cross the stage at 1× — slow enough to read its label. */
export const BASE_MS = 2300;
const NOTE_MS = 900;
/** Pause between steps while auto-playing, so the step text can be read. */
const STEP_GAP_MS = 1400;

/** Split a step's events into groups that animate together. */
export function groupsOf(events: LessonEvent[], step: number, startNo: number): Group[] {
  const groups: Group[] = [];
  let no = startNo;
  events.forEach((ev, i) => {
    if (ev.type === "note") {
      groups.push({ packets: [], notes: [ev] });
      return;
    }
    const cap: Captured = { key: `${step}-${i}`, no: no++, step, ev };
    const last = groups[groups.length - 1];
    if (ev.parallel && last && last.packets.length) last.packets.push(cap);
    else groups.push({ packets: [cap], notes: [] });
  });
  return groups;
}

// A tiny store for the per-frame progress so only the stage re-renders each frame.
function createStore() {
  let v = 0;
  const subs = new Set<() => void>();
  return {
    get: () => v,
    set: (n: number) => {
      v = n;
      subs.forEach((s) => s());
    },
    sub: (fn: () => void) => {
      subs.add(fn);
      return () => subs.delete(fn);
    },
  };
}
export type ProgressStore = ReturnType<typeof createStore>;
export const useProgress = (s: ProgressStore) => useSyncExternalStore(s.sub, s.get, () => 0);

/** `holdRef.current()` returning true delays auto-advance (e.g. while the voice guide is still talking). */
export function usePlayer(scenario: Scenario, holdRef?: { current: () => boolean }) {
  const stepGroups = useMemo(() => {
    let no = 1;
    return scenario.steps.map((st, i) => {
      const g = groupsOf(st.events, i, no);
      no += g.reduce((n, x) => n + x.packets.length, 0);
      return g;
    });
  }, [scenario]);

  const allPackets = useMemo(() => stepGroups.flat().flatMap((g) => g.packets), [stepGroups]);

  const [stepIdx, setStepIdx] = useState(-1); // -1 overview, steps.length = outro
  const [groupIdx, setGroupIdx] = useState(0); // groups completed in the current step
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1.5);
  const [single, setSingle] = useState(false);
  const store = useMemo(createStore, []);
  const raf = useRef<number>(0);

  const groups = stepIdx >= 0 && stepIdx < stepGroups.length ? stepGroups[stepIdx] : [];
  const stepDone = stepIdx >= 0 && stepIdx < stepGroups.length && groupIdx >= groups.length;

  // reset when the scenario changes
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setStepIdx(-1);
    setGroupIdx(0);
    setPlaying(false);
    store.set(0);
  }, [scenario, store]);

  useEffect(() => {
    if (!playing || stepIdx < 0 || stepIdx >= stepGroups.length) return;
    const gs = stepGroups[stepIdx];
    if (groupIdx >= gs.length) {
      // Keep playing into the next step until the learner presses pause.
      let t = 0;
      const advance = () => {
        if (holdRef?.current()) {
          t = window.setTimeout(advance, 300);
          return;
        }
        store.set(0);
        setGroupIdx(0);
        if (stepIdx + 1 < stepGroups.length) setStepIdx(stepIdx + 1);
        else {
          setStepIdx(stepGroups.length);
          setPlaying(false);
        }
      };
      t = window.setTimeout(advance, STEP_GAP_MS / speed);
      return () => window.clearTimeout(t);
    }
    const g = gs[groupIdx];
    const dur = (g.packets.length ? BASE_MS : NOTE_MS) / speed;
    const start = performance.now() - store.get() * dur;
    const frame = (now: number) => {
      const p = (now - start) / dur;
      if (p >= 1) {
        store.set(0);
        setGroupIdx((x) => x + 1);
        if (single && g.packets.length) setPlaying(false);
        return;
      }
      store.set(p);
      raf.current = requestAnimationFrame(frame);
    };
    raf.current = requestAnimationFrame(frame);
    return () => cancelAnimationFrame(raf.current);
  }, [playing, stepIdx, groupIdx, speed, single, stepGroups, store, holdRef]);

  const captured = useMemo<Captured[]>(() => {
    if (stepIdx < 0) return [];
    if (stepIdx >= stepGroups.length) return allPackets;
    const prev = stepGroups.slice(0, stepIdx).flat().flatMap((g) => g.packets);
    const cur = stepGroups[stepIdx].slice(0, groupIdx).flatMap((g) => g.packets);
    return [...prev, ...cur];
  }, [stepIdx, groupIdx, stepGroups, allPackets]);

  const inflight: Group | null = playing && groups[groupIdx] ? groups[groupIdx] : !playing && groups[groupIdx] && store.get() > 0 ? groups[groupIdx] : null;

  const notes = useMemo(() => {
    if (stepIdx < 0 || stepIdx >= stepGroups.length) return [];
    return stepGroups[stepIdx].slice(0, groupIdx).flatMap((g) => g.notes);
  }, [stepIdx, groupIdx, stepGroups]);

  const goStep = useCallback(
    (i: number, autoplay = true) => {
      store.set(0);
      setStepIdx(i);
      setGroupIdx(0);
      setPlaying(autoplay && i >= 0 && i < stepGroups.length);
    },
    [stepGroups.length, store]
  );

  const showStepDone = useCallback(
    (i: number) => {
      store.set(0);
      setStepIdx(i);
      setGroupIdx(stepGroups[i]?.length ?? 0);
      setPlaying(false);
    },
    [stepGroups, store]
  );

  const toggle = useCallback(() => {
    if (stepIdx < 0) return goStep(0);
    if (stepIdx >= stepGroups.length) return goStep(0);
    if (stepDone) {
      if (stepIdx + 1 < stepGroups.length) return goStep(stepIdx + 1);
      return goStep(stepGroups.length, false);
    }
    setPlaying((p) => !p);
  }, [stepIdx, stepDone, stepGroups.length, goStep]);

  const next = useCallback(() => {
    if (stepIdx + 1 <= stepGroups.length) goStep(stepIdx + 1, stepIdx + 1 < stepGroups.length);
  }, [stepIdx, stepGroups.length, goStep]);

  const prev = useCallback(() => {
    if (stepIdx > 0) goStep(stepIdx - 1);
    else goStep(-1, false);
  }, [stepIdx, goStep]);

  /** advance one packet group (used by the S key / next packet) */
  const stepPacket = useCallback(() => {
    if (stepIdx < 0) return goStep(0, false);
    if (stepDone) return next();
    store.set(0);
    setGroupIdx((g) => g + 1);
  }, [stepIdx, stepDone, next, goStep, store]);

  return {
    stepIdx, groupIdx, groups, stepGroups, playing, speed, single, stepDone, captured, inflight, notes, allPackets, store,
    setPlaying, setSpeed, setSingle, goStep, showStepDone, toggle, next, prev, stepPacket,
    restart: () => goStep(0),
  };
}

export type PlayerApi = ReturnType<typeof usePlayer>;
