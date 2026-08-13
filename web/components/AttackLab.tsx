"use client";

import { useEffect, useState } from "react";
import { ApiError, api, type AttackResult, type AttackSpec } from "@/lib/api";
import { Button } from "@/components/Button";

/**
 * Attack the defence, from the browser.
 *
 * Every one of these runs real code against the run you just produced: the permissive
 * issuer is a real ``WarrantIssuer`` with a real policy, the verdicts come from the
 * session's real PEP, and the fork is a real ``ForkDetected`` out of a real ``Witness``.
 * Nothing here replays a recorded transcript.
 *
 * `defended` is reported as a **measurement**, not promised. If an attack ever wins, this
 * renders that as prominently as a success — two of Phase 4's attack scenes end with the
 * attacker winning and both stay in the output.
 */
export function AttackLab({
  session,
  runId,
}: {
  session: string;
  runId: string;
}) {
  const [specs, setSpecs] = useState<AttackSpec[]>([]);
  const [results, setResults] = useState<Record<string, AttackResult>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    let cancelled = false;
    api
      .attacks(session, runId)
      .then((data) => {
        if (!cancelled) setSpecs(data.attacks);
      })
      .catch(() => {
        /* The lab simply does not render its buttons if the catalogue is unavailable. */
      });
    return () => {
      cancelled = true;
    };
  }, [session, runId]);

  const launch = async (name: string) => {
    setBusy(name);
    setErrors((e) => ({ ...e, [name]: "" }));
    try {
      const result = await api.runAttack(session, runId, name);
      setResults((r) => ({ ...r, [name]: result }));
    } catch (caught) {
      const message =
        caught instanceof ApiError
          ? `${caught.control ? `[${caught.control}] ` : ""}${caught.message}`
          : String(caught);
      setErrors((e) => ({ ...e, [name]: message }));
    } finally {
      setBusy(null);
    }
  };

  if (specs.length === 0) return null;

  return (
    <section className="card p-6">
      <h3 className="label">Attack the defence</h3>
      <p className="mt-2 max-w-2xl text-[13px] leading-relaxed text-ink-soft">
        Four attacks against the warrant you just produced. Each runs the real enforcement
        path — nothing here is a recorded result, and{" "}
        <span className="text-ink">defended</span> is measured rather than promised.
      </p>

      <ul className="mt-6 space-y-3">
        {specs.map((spec) => {
          const result = results[spec.name];
          const failure = errors[spec.name];
          return (
            <li key={spec.name} className="rounded-lg border border-line">
              <div className="flex flex-wrap items-start justify-between gap-4 p-4">
                <div className="min-w-0 flex-1">
                  <p className="text-[13.5px] font-medium text-ink">{spec.title}</p>
                  <p className="mt-1 text-[12.5px] leading-relaxed text-ink-soft">
                    {spec.what_it_does}
                  </p>
                  <p className="mono mt-1.5 text-[11px] text-ink-faint">{spec.control}</p>
                </div>
                <Button
                  onClick={() => launch(spec.name)}
                  disabled={busy !== null}
                  variant="quiet"
                >
                  {busy === spec.name ? "Attacking…" : result ? "Run again" : "Attack"}
                </Button>
              </div>

              {failure && (
                <p className="mono border-t border-line px-4 py-3 text-[11.5px] text-reject">
                  {failure}
                </p>
              )}

              {result && <Outcome result={result} />}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function Outcome({ result }: { result: AttackResult }) {
  // `defended` means the attacker lost. It is deliberately not assumed: an attack that
  // wins must be as visible as one that fails, or this panel becomes an advertisement.
  const colour = result.defended ? "var(--permit)" : "var(--reject)";

  return (
    <div
      className="border-t border-line px-4 py-4"
      style={{ background: result.defended ? "rgba(46,107,79,0.03)" : "rgba(163,53,42,0.05)" }}
    >
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <p className="text-[13px] font-medium" style={{ color: colour }}>
          {result.defended ? "Attack defeated" : "ATTACK SUCCEEDED"}
        </p>
        <p className="mono text-[11px] text-ink-faint">{result.detected_by}</p>
      </div>

      {result.enforcement && (
        <dl className="mono tnum mt-3 flex flex-wrap gap-x-8 gap-y-2 text-[11px]">
          <div>
            <dt className="label">Relying party</dt>
            <dd className="mt-1" style={{ color: colour }}>
              {result.enforcement.verdict}
            </dd>
          </div>
          <div>
            <dt className="label">Issuer claimed</dt>
            <dd className="mt-1 text-ink-soft">{result.enforcement.issuer_decision}</dd>
          </div>
          {result.enforcement.failed_steps.length > 0 && (
            <div>
              <dt className="label">Failed steps</dt>
              <dd className="mt-1 text-reject">
                {result.enforcement.failed_steps.join(", ")}
              </dd>
            </div>
          )}
        </dl>
      )}

      {result.witness && (
        <dl className="mono mt-3 flex flex-wrap gap-x-8 gap-y-2 text-[11px]">
          <div>
            <dt className="label">Fork detected</dt>
            <dd className="mt-1" style={{ color: colour }}>
              {String(result.witness.fork_detected)}
            </dd>
          </div>
          <div className="min-w-0 basis-full">
            <dt className="label">Witness said</dt>
            <dd className="mt-1 text-ink-soft">{result.witness.reason}</dd>
          </div>
        </dl>
      )}

      {typeof result.mutation.description === "string" && (
        <p className="mt-3 text-[12px] leading-relaxed text-ink-soft">
          <span className="text-ink-faint">Mutation — </span>
          {result.mutation.description}
        </p>
      )}

      <p className="mt-2.5 text-[11.5px] leading-relaxed text-ink-faint">{result.note}</p>
    </div>
  );
}
