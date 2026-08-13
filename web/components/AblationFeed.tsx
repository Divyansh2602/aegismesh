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

  // Follow the tail only while the visitor has not scrolled up to read something. A feed
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
    <div className="rounded-xl border border-line bg-ink-raised p-6">
      <header className="flex items-baseline justify-between gap-4">
        <h2 className="mono text-[11px] uppercase tracking-[0.18em] text-text-faint">
          Counterfactuals
        </h2>
        <span className="mono flex items-center gap-2 text-[11px] text-text-dim">
          {live && <span className="live-dot h-1.5 w-1.5 rounded-full bg-accent" />}
          {ablations.length}
          {total ? ` / ${total} model calls` : " measured"}
        </span>
      </header>

      <div
        ref={scroller}
        onScroll={onScroll}
        className="mono mt-4 h-72 overflow-y-auto pr-1 text-[11px] leading-relaxed"
      >
        {ablations.length === 0 && (
          <p className="text-text-faint">No counterfactual has completed yet.</p>
        )}
        {ablations.map((a) => (
          <div
            key={`${a.sequence}-${a.segment_id}-${a.granularity}`}
            className="flex items-baseline gap-2.5 border-b border-line/60 py-1.5 last:border-0"
          >
            <span className="w-8 shrink-0 text-right text-text-faint">{a.sequence}</span>
            <span
              className="w-6 shrink-0 font-medium"
              style={{ color: classColour(a.class) }}
            >
              {a.class}
            </span>
            <span className="w-16 shrink-0 text-text-faint">{a.granularity}</span>
            <span className="min-w-0 flex-1 truncate text-text-dim" title={a.excerpt_hash}>
              {a.excerpt_hash}
            </span>
            <span className="w-14 shrink-0 text-right text-text">
              {a.influence.toFixed(3)}
            </span>
            {/* `comparable` decides whether a zero means invariant or unknown, so it is
                shown rather than left to be inferred from the number beside it. */}
            <span
              className={`w-4 shrink-0 text-right ${a.comparable ? "text-p0" : "text-text-faint"}`}
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

      <p className="mt-3 border-t border-line pt-3 text-[11px] leading-relaxed text-text-faint">
        Hashes, never excerpts — a progress feed must not become the disclosure channel.
        <span className="text-p0"> =</span> comparable,
        <span className="text-text-dim"> ×</span> cancelled the action.
        {truncated && (
          <span className="text-accent">
            {" "}
            Stopped at the C-18 ceiling; this attribution reports partial evidence.
          </span>
        )}
      </p>
    </div>
  );
}
