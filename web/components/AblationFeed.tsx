"use client";

import { useEffect, useRef } from "react";
import type { AblationEventData } from "@/lib/api";
import { classColour } from "@/lib/provenance";

/**
 * Counterfactuals arriving one at a time.
 *
 * Attribution costs tens of model calls. A spinner over that dead time would say nothing;
 * this says exactly what the system is doing — which segment was removed, what happened
 * to the action, and whether the run stayed comparable.
 *
 * Events carry **hashes, never text**. The excerpt hash is shown rather than the excerpt
 * because a progress feed must not become the disclosure channel, and that rule is
 * enforced on the server with a canary test rather than trusted here.
 */
export function AblationFeed({
  ablations,
  live,
  total,
  truncated,
}: {
  ablations: AblationEventData[];
  live: boolean;
  total?: number;
  truncated?: boolean;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const pinned = useRef(true);

  // Follow the tail only while the reader has not scrolled up to look at something. A feed
  // that yanks you back to the bottom mid-read is worse than one that does not follow.
  useEffect(() => {
    const el = scroller.current;
    if (el && pinned.current) el.scrollTop = el.scrollHeight;
  }, [ablations.length]);

  const onScroll = () => {
    const el = scroller.current;
    if (!el) return;
    pinned.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  return (
    <section className="card flex flex-col p-6">
      <header className="flex items-baseline justify-between gap-4">
        <h3 className="label">Counterfactuals</h3>
        <span className="mono tnum flex items-center gap-2 text-[11px] text-ink-soft">
          {live && (
            <span className="breathe h-1.5 w-1.5 rounded-full bg-accent" aria-hidden />
          )}
          {ablations.length}
          {total ? ` / ${total} calls` : " measured"}
        </span>
      </header>

      <div
        ref={scroller}
        onScroll={onScroll}
        role="log"
        aria-label="Counterfactual measurements as they complete"
        className="mono tnum mt-4 h-[17rem] overflow-y-auto text-[11px] leading-relaxed"
      >
        {ablations.length === 0 && (
          <p className="text-ink-faint">No counterfactual has completed yet.</p>
        )}
        {ablations.map((a) => (
          <div
            key={`${a.sequence}-${a.segment_id}-${a.granularity}`}
            className="row-in flex items-baseline gap-3 border-b border-line/70 py-[5px] last:border-0"
          >
            <span className="w-6 shrink-0 text-right text-ink-faint">{a.sequence}</span>
            <span
              className="w-6 shrink-0 font-medium"
              style={{ color: classColour(a.class) }}
            >
              {a.class}
            </span>
            <span className="w-14 shrink-0 text-ink-faint">{a.granularity}</span>
            <span className="min-w-0 flex-1 truncate text-ink-soft" title={a.excerpt_hash}>
              {a.excerpt_hash.replace(/^sha256:/, "")}
            </span>
            <span className="w-11 shrink-0 text-right font-medium text-ink">
              {a.influence.toFixed(3)}
            </span>
            {/* `comparable` decides whether a zero means invariant or unknown, so it is
                shown rather than left to be inferred from the number beside it. */}
            <span
              className="w-3 shrink-0 text-right"
              style={{ color: a.comparable ? "var(--p0)" : "var(--ink-faint)" }}
              title={
                a.comparable
                  ? "the same tool was still called — this run is comparable"
                  : "the action was cancelled — not comparable, counts toward necessity"
              }
            >
              {a.comparable ? "=" : "×"}
            </span>
          </div>
        ))}
      </div>

      <p className="mt-auto border-t border-line pt-4 text-[12px] leading-relaxed text-ink-faint">
        Hashes, never excerpts — a progress feed must not become the disclosure channel.{" "}
        <span style={{ color: "var(--p0)" }}>=</span> comparable, <span>×</span> cancelled
        the action.
        {truncated && (
          <span style={{ color: "var(--p4)" }}>
            {" "}
            Stopped at the C-18 ceiling; this attribution reports partial evidence.
          </span>
        )}
      </p>
    </section>
  );
}
