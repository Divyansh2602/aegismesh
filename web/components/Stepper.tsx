"use client";

import type { RunEvent, RunEventType } from "@/lib/api";

/**
 * The six stages of the pipeline, advancing as the run advances.
 *
 * This is the component that makes the system legible to somebody who will never read the
 * JSON. The measurement panels below it are the evidence; this is the sentence that
 * evidence is arranged into — classify, propose, attribute, issue, log, enforce.
 *
 * Every stage is driven by an event the runner genuinely emitted. A stage is `done`
 * because its event arrived, never because the one after it did, and a run that halts
 * leaves the remaining stages visibly unreached rather than quietly filling them in.
 */
/** Event payloads are heterogeneous by design; each stage reads only its own fields. */
type Payload = Record<string, unknown>;

const count = (value: unknown): number => (Array.isArray(value) ? value.length : 0);

/** "1 tool call", not "1 tool calls". */
const plural = (n: number, noun: string) => `${n} ${noun}${n === 1 ? "" : "s"}`;

const STAGES: ReadonlyArray<{
  key: RunEventType;
  label: string;
  detail: (data: Payload) => string;
}> = [
  { key: "classified", label: "Classify", detail: (d) => plural(Number(d.segments), "segment") },
  { key: "proposed", label: "Propose", detail: (d) => plural(count(d.calls), "tool call") },
  {
    key: "attributed",
    label: "Attribute",
    detail: (d) => plural(Number(d.model_calls), "model call"),
  },
  { key: "issued", label: "Issue", detail: () => "warrant signed" },
  { key: "logged", label: "Log", detail: (d) => `leaf ${d.leaf_index}` },
  { key: "decision", label: "Enforce", detail: (d) => String(d.verdict).toLowerCase() },
];

export function Stepper({ events, running }: { events: RunEvent[]; running: boolean }) {
  const seen = new Map(events.map((e) => [e.type, e.data]));
  const halted = seen.has("halted");
  const firstPending = STAGES.findIndex((s) => !seen.has(s.key));

  return (
    <ol className="grid grid-cols-2 gap-x-4 gap-y-5 sm:grid-cols-3 lg:grid-cols-6">
      {STAGES.map((stage, index) => {
        const data = seen.get(stage.key);
        const done = data !== undefined;
        const active = running && !done && index === firstPending;
        const unreachable = halted && !done;

        return (
          <li key={stage.key} className="relative min-w-0">
            <div className="flex items-center gap-2">
              <Dot done={done} active={active} unreachable={unreachable} />
              {index < STAGES.length - 1 && (
                <span
                  className="hidden h-px flex-1 transition-colors duration-300 lg:block"
                  style={{ background: done ? "var(--accent)" : "var(--line)" }}
                  aria-hidden
                />
              )}
            </div>
            <p
              className="mt-2.5 truncate text-[12.5px] font-medium"
              style={{ color: done ? "var(--ink)" : "var(--ink-faint)" }}
            >
              {stage.label}
            </p>
            <p className="mono tnum mt-0.5 truncate text-[10.5px] text-ink-faint">
              {done
                ? stage.detail(data)
                : unreachable
                  ? "not reached"
                  : active
                    ? "working…"
                    : "—"}
            </p>
          </li>
        );
      })}
    </ol>
  );
}

function Dot({
  done,
  active,
  unreachable,
}: {
  done: boolean;
  active: boolean;
  unreachable: boolean;
}) {
  if (done) {
    return (
      <span
        className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full"
        style={{ background: "var(--accent)" }}
      >
        <svg width="9" height="9" viewBox="0 0 10 10" fill="none" aria-hidden>
          <path
            d="M1.5 5.2 3.9 7.5 8.5 2.6"
            stroke="#fff"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </span>
    );
  }
  return (
    <span
      className={`h-4 w-4 shrink-0 rounded-full border-2 ${active ? "breathe" : ""}`}
      style={{
        borderColor: active ? "var(--accent)" : "var(--line-strong)",
        borderStyle: unreachable ? "dotted" : "solid",
      }}
    />
  );
}
