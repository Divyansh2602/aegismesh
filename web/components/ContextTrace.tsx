"use client";

import { useState } from "react";
import type { ContextView } from "@/lib/api";
import { PROVENANCE, classColour, classLabel } from "@/lib/provenance";

/**
 * The context the model saw, coloured by provenance class.
 *
 * The point this screen makes on its own: a pinned, well-behaved invoice reader relays a
 * supplier's document, and that document is **P3 untrusted** even though the tool is
 * authentic. Tool integrity is not content provenance (control C-19). Every segment
 * carries the classifier's own reason, so the colour is never asserted without a why.
 */
export function ContextTrace({
  context,
  className = "",
}: {
  context: ContextView;
  className?: string;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const present = new Set(context.segments.map((s) => s.class));

  return (
    <div className={`rounded-xl border border-line bg-ink-raised p-6 ${className}`}>
      <header className="flex flex-wrap items-baseline justify-between gap-4">
        <h2 className="mono text-[11px] uppercase tracking-[0.18em] text-text-faint">
          Classified context · {context.segments.length} segments
        </h2>
        <div className="flex flex-wrap gap-x-4 gap-y-1">
          {Object.entries(PROVENANCE)
            .filter(([cls]) => present.has(cls as keyof typeof PROVENANCE))
            .map(([cls, meta]) => (
              <span key={cls} className="mono flex items-center gap-1.5 text-[10px]">
                <span
                  className="h-2 w-2 rounded-full"
                  style={{ background: meta.colour }}
                />
                <span style={{ color: meta.colour }}>{cls}</span>
                <span className="text-text-faint">{meta.short}</span>
              </span>
            ))}
        </div>
      </header>

      <ul className="mt-5 space-y-2">
        {context.segments.map((segment) => {
          const isOpen = open === segment.segment_id;
          return (
            <li key={segment.segment_id}>
              <button
                type="button"
                onClick={() => setOpen(isOpen ? null : segment.segment_id)}
                aria-expanded={isOpen}
                className="w-full rounded-md border border-line bg-ink px-4 py-3 text-left transition-colors hover:border-line-bright"
                style={{ borderLeft: `3px solid ${classColour(segment.class)}` }}
              >
                <div className="flex items-baseline justify-between gap-3">
                  <span
                    className="mono shrink-0 text-[10px] uppercase tracking-[0.14em]"
                    style={{ color: classColour(segment.class) }}
                  >
                    {segment.class} · {classLabel(segment.class)}
                  </span>
                  <span className="mono truncate text-[10px] text-text-faint">
                    {segment.kind}
                    {segment.origin ? ` · ${segment.origin}` : ""}
                  </span>
                </div>
                <p
                  className={`mt-2 text-sm leading-relaxed text-text-dim ${isOpen ? "" : "line-clamp-2"}`}
                >
                  {segment.text}
                </p>
                {isOpen && (
                  <p className="mt-3 border-t border-line pt-3 text-xs leading-relaxed text-text-faint">
                    <span className="text-text-dim">Why this class: </span>
                    {segment.classification_reason}
                  </p>
                )}
              </button>
            </li>
          );
        })}
      </ul>

      <p className="mt-5 border-t border-line pt-4 text-[11px] leading-relaxed text-text-faint">
        Role does not establish trust. Agent frameworks routinely paste retrieved documents
        into user-role messages, so only text verbatim-matching a declared mandate earns
        P0 — and a pinned conduit tool&apos;s output stays P3 no matter how well-behaved the
        tool is.
      </p>
    </div>
  );
}
