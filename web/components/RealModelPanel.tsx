"use client";

import { useEffect, useState } from "react";
import { api, type RealModelRecord, type RealModelRun } from "@/lib/api";
import { classColour } from "@/lib/provenance";

/**
 * What happened when the same cases were run against real transformers.
 *
 * Every other panel on this site is drawn from a request executed while you watched. This
 * one is not, and that difference is the first thing it says. The public API never calls a
 * real model — it would need a key, cost money per visitor, and make the service abusable
 * as a free LLM proxy — so these numbers come from an offline sweep and are served from a
 * committed file. A panel that looked identical to the live ones while being a recording
 * would be the exact "plausible-looking screen" the console refuses to render.
 *
 * Why it earns its place anyway: everything else here is measured against a surrogate whose
 * susceptibility was *written down rather than discovered*, which is the honest weakness of
 * the whole evaluation. This is the only place on the site where the mechanism meets a model
 * nobody tuned for it.
 */
export function RealModelPanel() {
  const [record, setRecord] = useState<RealModelRecord | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    api
      .realModel()
      .then(setRecord)
      .catch(() => setFailed(true));
  }, []);

  // Absent rather than empty. Same rule as the pipeline stages: a section with nothing real
  // behind it does not render a shell.
  if (failed || !record || !record.measured) return null;

  const models = Object.values(record.models).sort((a, b) => b.acted - a.acted);

  return (
    <div className="card p-5 sm:p-6">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h3 className="label">Against real models</h3>
        <span className="mono text-[11px]" style={{ color: "var(--p4)" }}>
          offline measurement · not a live run
        </span>
      </div>

      <p className="mt-3 max-w-3xl text-[13px] leading-relaxed text-ink-soft">
        Everything else on this page runs against a bundled deterministic surrogate whose
        susceptibility was written down rather than discovered. That buys exact ground truth
        and establishes nothing about a real model. These are the same seven labelled cases
        replayed offline against local models, on one laptop.
      </p>

      <div className="mt-5 grid gap-4 sm:grid-cols-2">
        {models.map((run) => (
          <ModelCard key={run.model} run={run} cases={record.cases_run ?? 7} />
        ))}
      </div>

      <p className="mt-5 border-t border-line pt-4 text-[12px] leading-relaxed text-ink-faint">
        Two 8B models on consumer hardware, seven hand-built cases. Not a generalisation
        claim and not a comparison with any frontier model. The value is narrow and real:
        the mechanism runs unchanged against a model nobody built it for, and when the
        attack landed on a field whose source could be located, attribution named untrusted
        content as the cause.
      </p>
    </div>
  );
}

function ModelCard({ run, cases }: { run: RealModelRun; cases: number }) {
  const correct = run.scored.filter((s) => s.correct).length;

  return (
    <div className="rounded-lg border border-line bg-sunken/40 p-4">
      <div className="flex items-baseline justify-between gap-3">
        <span className="mono text-[12px] font-medium text-ink">{run.model}</span>
        <span
          className="mono text-[10px]"
          title="Identical requests were sent repeatedly; this is whether the answer moved."
          style={{ color: run.noise_floor.deterministic ? "var(--p0)" : "var(--p4)" }}
        >
          {run.noise_floor.deterministic
            ? `deterministic ${run.noise_floor.samples}/${run.noise_floor.samples}`
            : `${run.noise_floor.distinct} distinct answers`}
        </span>
      </div>

      <dl className="mt-3 grid grid-cols-3 gap-2 text-center">
        <Stat label="acted" value={`${run.acted}/${cases}`} />
        <Stat label="hijacked" value={String(run.hijacked)} tone="var(--p3)" />
        <Stat
          label="attributed"
          value={run.scored.length ? `${correct}/${run.scored.length}` : "—"}
          tone={run.scored.length && correct === run.scored.length ? "var(--p0)" : undefined}
        />
      </dl>

      {run.scored.length > 0 ? (
        <ul className="mt-3 space-y-1.5">
          {run.scored.map((s) => (
            <li key={s.case} className="mono flex items-baseline gap-2 text-[10.5px]">
              <span className="truncate text-ink-faint" title={s.case}>
                {s.case}
              </span>
              <span className="ml-auto shrink-0" style={{ color: classColour(s.source_class) }}>
                {s.source_class}
              </span>
              <span className="shrink-0 text-ink-faint">→</span>
              <span
                className="shrink-0"
                style={{ color: classColour(s.attributed_class ?? "") }}
              >
                {s.attributed_class ?? "none"}
              </span>
              <span className="shrink-0 tnum text-ink-soft">
                {s.untrusted_share.toFixed(3)}
              </span>
            </li>
          ))}
        </ul>
      ) : null}

      {/* Stated, never omitted. A model that declines the action produces no evidence, and
          reporting only the models that cooperated would flatter by omission. */}
      <p className="mt-3 text-[11px] leading-relaxed text-ink-faint">
        {run.declined > 0 && (
          <>
            Declined to act on {run.declined} case{run.declined === 1 ? "" : "s"}, so there
            was nothing to attribute there.{" "}
          </>
        )}
        {run.unresolvable_source > 0 && (
          <>
            On {run.unresolvable_source} it acted, but the emitted value appears in more
            than one trust class — redundantly determined, and unresolvable by any
            model-agnostic ground truth.
          </>
        )}
      </p>
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div>
      <dd className="mono tnum text-[15px] font-medium" style={tone ? { color: tone } : undefined}>
        {value}
      </dd>
      <dt className="label mt-0.5 text-[9.5px]">{label}</dt>
    </div>
  );
}
