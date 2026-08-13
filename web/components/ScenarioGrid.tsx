"use client";

import { useState } from "react";
import { ApiError, api, type EvaluationReport } from "@/lib/api";
import { Button } from "@/components/Button";
import { classColour } from "@/lib/provenance";

/**
 * The whole labelled case set, scored, with the clean rows visible.
 *
 * This is the block that turns single runs into evidence. A detector that flags
 * everything scores perfectly on the four poisoned cases and is worthless — the three
 * clean ones are what make the poisoned ones mean anything, so they are not filler and
 * they are not hidden behind a summary number.
 *
 * The numbers come from ``run_evaluation``, the same function ``demo/phase2_eval.py``
 * calls, so this grid and ``results/phase2_evaluation.json`` cannot drift apart.
 */
export function ScenarioGrid({ session }: { session: string | null }) {
  const [report, setReport] = useState<EvaluationReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ message: string; control: string | null } | null>(null);

  const score = async () => {
    if (!session) return;
    setBusy(true);
    setError(null);
    try {
      setReport(await api.evaluation(session));
    } catch (caught) {
      setError({
        message: caught instanceof Error ? caught.message : String(caught),
        control: caught instanceof ApiError ? caught.control : null,
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card p-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-lg">
          <h3 className="label">All seven cases, scored</h3>
          <p className="mt-2 text-[13px] leading-relaxed text-ink-soft">
            Every case holds the same mandate constant and varies one thing. Any single run
            proves little; the comparison is the evidence — four attacks caught, three clean
            cases left alone, and a cost for each.
          </p>
        </div>
        <Button onClick={score} disabled={busy || !session} variant="quiet">
          {busy && <span className="breathe h-1.5 w-1.5 rounded-full bg-accent" aria-hidden />}
          {busy ? "Scoring…" : report ? "Re-score" : "Score all seven"}
        </Button>
      </div>

      {error && (
        <div className="mt-5 rounded-md border border-p4/30 bg-p4/[0.04] px-4 py-3">
          <p className="label" style={{ color: "var(--p4)" }}>
            {error.control ? `Refused by control ${error.control}` : "Failed"}
          </p>
          <p className="mt-1.5 text-[12.5px] text-ink-soft">{error.message}</p>
        </div>
      )}

      {report && (
        <>
          <dl className="mono tnum mt-6 grid grid-cols-2 gap-x-6 gap-y-4 border-y border-line py-4 text-[11px] sm:grid-cols-5">
            <Metric term="Precision" value={report.precision.toFixed(3)} good />
            <Metric term="Recall" value={report.recall.toFixed(3)} good />
            <Metric term="Localization" value={report.localization_rate.toFixed(3)} good />
            <Metric term="Mean calls" value={report.mean_model_calls.toFixed(1)} />
            <Metric term="Worst case" value={String(report.max_model_calls)} />
          </dl>

          <div className="mt-5 overflow-x-auto">
            <table className="w-full min-w-[38rem] border-collapse text-left">
              <thead>
                <tr className="border-b border-line">
                  <th className="label pb-2 pr-4 font-medium">Case</th>
                  <th className="label pb-2 pr-4 font-medium">Kind</th>
                  <th className="label pb-2 pr-4 font-medium">Destination</th>
                  <th className="label pb-2 pr-4 text-right font-medium">Untrusted</th>
                  <th className="label pb-2 pr-4 font-medium">Flagged</th>
                  <th className="label pb-2 text-right font-medium">Calls</th>
                </tr>
              </thead>
              <tbody>
                {report.outcomes.map((o) => (
                  <tr
                    key={o.name}
                    className="border-b border-line/70 last:border-0"
                    // The clean rows are tinted so the control group reads as a group.
                    style={!o.poisoned ? { background: "rgba(46,107,79,0.028)" } : undefined}
                  >
                    <td className="mono py-2.5 pr-4 text-[11.5px] text-ink">{o.name}</td>
                    <td className="py-2.5 pr-4 text-[12px]">
                      <span style={{ color: o.poisoned ? "var(--p3)" : "var(--p0)" }}>
                        {o.poisoned ? "attack" : "clean"}
                      </span>
                      {o.poisoned && !o.effective && (
                        <span className="ml-1.5 text-[11px] text-ink-faint">didn’t land</span>
                      )}
                    </td>
                    <td className="mono py-2.5 pr-4 text-[11.5px]">
                      <span
                        style={{
                          color:
                            o.destination_status === "attributed"
                              ? classColour(o.dominant_class ?? "")
                              : "var(--ink-faint)",
                        }}
                      >
                        {o.destination_status}
                      </span>
                      {o.dominant_class && (
                        <span className="ml-1.5 text-ink-faint">{o.dominant_class}</span>
                      )}
                    </td>
                    <td className="mono tnum py-2.5 pr-4 text-right text-[11.5px] text-ink-soft">
                      {o.untrusted_share.toFixed(3)}
                    </td>
                    <td className="py-2.5 pr-4 text-[12px]">
                      <Mark correct={o.correct} flagged={o.flagged} />
                    </td>
                    <td className="mono tnum py-2.5 text-right text-[11.5px] text-ink-soft">
                      {o.model_calls}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <p className="mt-4 text-[12px] leading-relaxed text-ink-faint">
            Flagged when untrusted influence on the destination exceeds{" "}
            <span className="mono">{report.flag_threshold}</span>. {report.note}
          </p>
        </>
      )}
    </section>
  );
}

function Metric({ term, value, good }: { term: string; value: string; good?: boolean }) {
  const perfect = good && Number(value) === 1;
  return (
    <div>
      <dt className="label">{term}</dt>
      <dd
        className="mt-1.5 text-[15px] font-medium"
        style={{ color: perfect ? "var(--permit)" : "var(--ink)" }}
      >
        {value}
      </dd>
    </div>
  );
}

/** `correct` is the claim; `flagged` is what it did. Both are shown, never merged. */
function Mark({ correct, flagged }: { correct: boolean; flagged: boolean }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span style={{ color: flagged ? "var(--p3)" : "var(--ink-faint)" }}>
        {flagged ? "flagged" : "clear"}
      </span>
      <span
        title={correct ? "matches ground truth" : "does not match ground truth"}
        style={{ color: correct ? "var(--permit)" : "var(--reject)" }}
      >
        {correct ? "✓" : "✗"}
      </span>
    </span>
  );
}
