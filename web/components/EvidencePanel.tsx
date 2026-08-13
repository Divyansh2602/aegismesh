"use client";

import type { ArgumentStatus, AttributedEventData } from "@/lib/api";
import { classColour, classLabel } from "@/lib/provenance";

/**
 * Per-argument attribution, in three visually distinct states.
 *
 * This component is where the project's sharpest finding either survives or dies.
 * `attributed`, `invariant` and `unknown` are not three amounts of one quantity, they are
 * three different kinds of answer:
 *
 *   attributed — a class demonstrably caused this field's value
 *   invariant  — removing any single source left the value unchanged; it is redundantly
 *                determined. Evidence of invariance, and the *normal* case for legitimate
 *                actions
 *   unknown    — every counterfactual cancelled the action, so no comparable run exists.
 *                The absence of evidence, not evidence of absence
 *
 * `invariant` and `unknown` both carry zero measured influence. A progress bar renders
 * both as an empty track, which is precisely the flattening that made an earlier version
 * of this system refuse a legitimate payment. So only `attributed` gets a bar; the other
 * two get their own form, not their own shade.
 */
export function EvidencePanel({ attributed }: { attributed?: AttributedEventData }) {
  return (
    <div className="rounded-xl border border-line bg-ink-raised p-6">
      <header className="flex items-baseline justify-between gap-4">
        <h2 className="mono text-[11px] uppercase tracking-[0.18em] text-text-faint">
          Per-argument attribution
        </h2>
        {attributed?.truncated && (
          <span className="mono text-[10px] uppercase tracking-[0.14em] text-accent">
            truncated at C-18
          </span>
        )}
      </header>

      {!attributed ? (
        <p className="mt-6 text-sm text-text-faint">Waiting for the measurement to finish…</p>
      ) : (
        <>
          <ul className="mt-6 space-y-5">
            {Object.entries(attributed.argument_status).map(([field, status]) => (
              <ArgumentRow
                key={field}
                field={field}
                status={status}
                shares={attributed.per_argument[field] ?? {}}
              />
            ))}
          </ul>
          <Legend />
        </>
      )}
    </div>
  );
}

function ArgumentRow({
  field,
  status,
  shares,
}: {
  field: string;
  status: ArgumentStatus;
  shares: Record<string, string>;
}) {
  return (
    <li>
      <div className="flex items-center justify-between gap-3">
        <span className="mono text-sm text-text">{field}</span>
        <StatusTag status={status} />
      </div>
      <div className="mt-2">
        {status === "attributed" && <AttributedBar shares={shares} />}
        {status === "invariant" && <Invariant shares={shares} />}
        {status === "unknown" && <Unknown />}
      </div>
    </li>
  );
}

function StatusTag({ status }: { status: ArgumentStatus }) {
  const style: Record<ArgumentStatus, string> = {
    attributed: "border-text-dim/40 text-text",
    invariant: "border-p0/50 text-p0",
    unknown: "border-line-bright text-text-faint",
  };
  const glyph: Record<ArgumentStatus, string> = {
    attributed: "◆",
    invariant: "▣",
    unknown: "○",
  };
  return (
    <span
      className={`mono shrink-0 rounded-full border px-2.5 py-0.5 text-[10px] uppercase tracking-[0.14em] ${style[status]}`}
    >
      <span aria-hidden className="mr-1.5">
        {glyph[status]}
      </span>
      {status}
    </span>
  );
}

/** The only state that gets a bar, because it is the only one with a magnitude. */
function AttributedBar({ shares }: { shares: Record<string, string> }) {
  const entries = Object.entries(shares).sort((a, b) => Number(b[1]) - Number(a[1]));
  const total = entries.reduce((sum, [, value]) => sum + Number(value), 0) || 1;

  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-ink">
        {entries.map(([cls, value]) => (
          <div
            key={cls}
            className="h-full transition-[width] duration-700 ease-out"
            style={{
              width: `${(Number(value) / total) * 100}%`,
              background: classColour(cls),
            }}
            title={`${classLabel(cls)} ${value}`}
          />
        ))}
      </div>
      <div className="mono mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px]">
        {entries.map(([cls, value]) => (
          <span key={cls} style={{ color: classColour(cls) }}>
            {cls} {value}
            <span className="ml-1 text-text-faint">{classLabel(cls)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * Overlapping chips, not a bar. The value is redundantly determined, which is a statement
 * about *structure* rather than about magnitude -- and it is the normal shape of a
 * legitimate action, where the human and the operator's own records agree.
 */
function Invariant({ shares }: { shares: Record<string, string> }) {
  const classes = Object.keys(shares);
  return (
    <div className="rounded-md border border-p0/30 bg-p0/[0.04] px-3 py-2.5">
      <div className="flex items-center gap-2">
        <span aria-hidden className="text-p0">
          ▣
        </span>
        <p className="text-xs leading-relaxed text-text-dim">
          Removing any single source left this value unchanged — it is{" "}
          <span className="text-p0">redundantly determined</span>.
          {classes.length > 0 && (
            <>
              {" "}
              <span className="mono">{classes.join(" + ")}</span> each supply it
              independently.
            </>
          )}
        </p>
      </div>
      <p className="mt-1.5 pl-6 text-[11px] text-text-faint">
        Evidence of invariance. Not the same as no evidence.
      </p>
    </div>
  );
}

/** Hatching, not an empty bar. An empty bar reads as "zero"; this reads as "no answer". */
function Unknown() {
  return (
    <div className="rounded-md border border-dashed border-line-bright bg-ink px-3 py-2.5">
      <div className="flex items-center gap-2">
        <span aria-hidden className="text-text-faint">
          ○
        </span>
        <p className="text-xs leading-relaxed text-text-dim">
          Every counterfactual cancelled the action, so no comparable run exists.
        </p>
      </div>
      <div className="hatched mt-2 ml-6 h-2.5 rounded-full" />
      <p className="mt-1.5 pl-6 text-[11px] text-text-faint">
        The absence of evidence. Reporting this as zero influence would fabricate a
        finding.
      </p>
    </div>
  );
}

function Legend() {
  return (
    <p className="mt-6 border-t border-line pt-4 text-[11px] leading-relaxed text-text-faint">
      One action can be legitimate in one field and hijacked in another — the human sets
      the amount while an attacker sets the destination. Action-level aggregation averages
      that away, which is why attribution here is per argument.
    </p>
  );
}
