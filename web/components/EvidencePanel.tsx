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
    <section className="card flex flex-col p-6">
      <header className="flex items-baseline justify-between gap-4">
        <h3 className="label">Per-argument attribution</h3>
        {attributed?.truncated && (
          <span className="label" style={{ color: "var(--p4)" }}>
            truncated · C-18
          </span>
        )}
      </header>

      {!attributed ? (
        <p className="mt-6 text-[13px] text-ink-faint">Waiting for the measurement to finish…</p>
      ) : (
        <>
          <ul className="mt-5 space-y-5">
            {Object.entries(attributed.argument_status).map(([field, status]) => (
              <ArgumentRow
                key={field}
                field={field}
                status={status}
                shares={attributed.per_argument[field] ?? {}}
              />
            ))}
          </ul>
          <p className="mt-auto pt-6 text-[12px] leading-relaxed text-ink-faint">
            One action can be legitimate in one field and hijacked in another — the human
            sets the amount while an attacker sets the destination. Action-level aggregation
            averages that away, which is why attribution here is per argument.
          </p>
        </>
      )}
    </section>
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
        <span className="mono text-[13px] font-medium text-ink">{field}</span>
        <StatusTag status={status} />
      </div>
      <div className="mt-2.5">
        {status === "attributed" && <AttributedBar shares={shares} />}
        {status === "invariant" && <Invariant shares={shares} />}
        {status === "unknown" && <Unknown />}
      </div>
    </li>
  );
}

function StatusTag({ status }: { status: ArgumentStatus }) {
  const tone: Record<ArgumentStatus, { fg: string; bg: string; bd: string }> = {
    attributed: { fg: "var(--ink)", bg: "var(--sunken)", bd: "var(--line-strong)" },
    invariant: { fg: "var(--p0)", bg: "rgba(46,107,79,0.06)", bd: "rgba(46,107,79,0.28)" },
    unknown: { fg: "var(--ink-faint)", bg: "transparent", bd: "var(--line-strong)" },
  };
  const glyph: Record<ArgumentStatus, string> = {
    attributed: "◆",
    invariant: "▣",
    unknown: "○",
  };
  const t = tone[status];
  return (
    <span
      className="label shrink-0 rounded-full border px-2.5 py-0.5"
      style={{ color: t.fg, background: t.bg, borderColor: t.bd }}
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
      <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-sunken">
        {entries.map(([cls, value]) => (
          <div
            key={cls}
            className="h-full transition-[width] duration-500 ease-out"
            style={{
              width: `${(Number(value) / total) * 100}%`,
              background: classColour(cls),
            }}
            title={`${classLabel(cls)} ${value}`}
          />
        ))}
      </div>
      <div className="mono tnum mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px]">
        {entries.map(([cls, value]) => (
          <span key={cls}>
            <span style={{ color: classColour(cls) }}>{cls}</span>
            <span className="ml-1 text-ink">{value}</span>
            <span className="ml-1.5 text-ink-faint">{classLabel(cls)}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * A statement about structure, not a magnitude — so it is set as prose in a bordered
 * panel rather than as a track. Redundancy is the normal shape of a legitimate action,
 * where the human and the operator's own records independently agree.
 */
function Invariant({ shares }: { shares: Record<string, string> }) {
  const classes = Object.keys(shares);
  return (
    <div className="rounded-md border border-p0/25 bg-p0/[0.035] px-3.5 py-3">
      <p className="text-[12.5px] leading-relaxed text-ink-soft">
        Removing any single source left this value unchanged — it is{" "}
        <span className="font-medium text-p0">redundantly determined</span>.
        {classes.length > 0 && (
          <>
            {" "}
            <span className="mono text-ink">{classes.join(" + ")}</span> each supply it
            independently.
          </>
        )}
      </p>
      <p className="mt-1.5 text-[11.5px] text-ink-faint">
        Evidence of invariance. Not the same as no evidence.
      </p>
    </div>
  );
}

/** Hatching, not an empty bar. An empty bar reads as “zero”; this reads as “no answer”. */
function Unknown() {
  return (
    <div className="rounded-md border border-dashed border-line-strong px-3.5 py-3">
      <p className="text-[12.5px] leading-relaxed text-ink-soft">
        Every counterfactual cancelled the action, so no comparable run exists.
      </p>
      <div className="hatched mt-2.5 h-1.5 rounded-full" />
      <p className="mt-1.5 text-[11.5px] text-ink-faint">
        The absence of evidence. Reporting this as zero influence would fabricate a finding.
      </p>
    </div>
  );
}
