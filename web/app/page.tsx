"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ApiError,
  api,
  streamEvents,
  type AblationEventData,
  type AttributedEventData,
  type ContextView,
  type DecisionEventData,
  type RunEvent,
  type Scenario,
} from "@/lib/api";
import { AblationFeed } from "@/components/AblationFeed";
import { Button } from "@/components/Button";
import { ContextTrace } from "@/components/ContextTrace";
import { EvidencePanel } from "@/components/EvidencePanel";
import { Reading } from "@/components/Reading";
import { Reveal } from "@/components/Reveal";
import { Stepper } from "@/components/Stepper";
import { TopBar } from "@/components/TopBar";
import { Verdict } from "@/components/Verdict";

type Phase = "idle" | "running" | "complete" | "failed";

export default function Home() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [chosen, setChosen] = useState("injection_via_conduit_tool");
  const [model, setModel] = useState<string | null>(null);
  const [treeSize, setTreeSize] = useState<number | null>(null);
  const [offline, setOffline] = useState<string | null>(null);

  const [phase, setPhase] = useState<Phase>("idle");
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [context, setContext] = useState<ContextView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [control, setControl] = useState<string | null>(null);

  const abort = useRef<AbortController | null>(null);
  const runSection = useRef<HTMLElement>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [cat, health] = await Promise.all([api.scenarios(), api.health()]);
        if (cancelled) return;
        setScenarios(cat.scenarios);
        setModel(cat.model);
        setTreeSize(health.log_tree_size);
      } catch {
        if (!cancelled) setOffline("uvicorn aegis.api.app:app --port 8000");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => () => abort.current?.abort(), []);

  const run = useCallback(async () => {
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;

    setPhase("running");
    setEvents([]);
    setContext(null);
    setError(null);
    setControl(null);

    try {
      const session = await api.createSession();
      const started = await api.startRun(session.session_id, chosen);

      for await (const event of streamEvents(session.session_id, started.run_id, {
        signal: controller.signal,
      })) {
        setEvents((previous) => [...previous, event]);
        if (event.type === "end") {
          const data = event.data as { status: string; error?: string };
          setPhase(data.status === "complete" ? "complete" : "failed");
          if (data.error) setError(data.error);
        }
      }

      // Segment text comes from the stage endpoint, not the stream: events carry hashes
      // only, deliberately.
      const view = await api.stage<ContextView>(session.session_id, started.run_id, "context");
      if (!controller.signal.aborted) setContext(view);
      const log = await api.log();
      if (!controller.signal.aborted) setTreeSize(log.tree_size);
    } catch (caught) {
      if (controller.signal.aborted) return;
      setPhase("failed");
      if (caught instanceof ApiError) {
        setError(caught.message);
        setControl(caught.control);
      } else {
        setError(caught instanceof Error ? caught.message : String(caught));
      }
    }
  }, [chosen]);

  const ablations = events
    .filter((e) => e.type === "ablation")
    .map((e) => e.data as unknown as AblationEventData);

  const attributed = events.find((e) => e.type === "attributed")?.data as
    | AttributedEventData
    | undefined;
  const decision = events.find((e) => e.type === "decision")?.data as
    | DecisionEventData
    | undefined;
  const logged = events.find((e) => e.type === "logged")?.data as
    | { leaf_index: number; tree_size: number; root_hash: string }
    | undefined;
  const issued = events.find((e) => e.type === "issued")?.data as
    | { warrant_id: string; issuer_decision: string }
    | undefined;
  const halted = events.find((e) => e.type === "halted")?.data as
    | { reason: string }
    | undefined;

  const active = scenarios.find((s) => s.name === chosen);

  return (
    <>
      <a
        href="#run"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-accent focus:px-4 focus:py-2 focus:text-sm focus:text-white"
      >
        Skip to the pipeline
      </a>

      <TopBar model={model} treeSize={treeSize} online={!offline} />

      <main className="flex-1">
        {/* ------------------------------------------------------------------ lede */}
        <section className="mx-auto w-full max-w-5xl px-6 pb-14 pt-16 sm:pt-24">
          <p className="label">Action Warrants · EU AI Act Article 12</p>
          <h1 className="serif mt-5 text-[clamp(2.1rem,5.2vw,3.6rem)] leading-[1.1] text-ink">
            We can prove which agent acted.
            <br className="hidden sm:block" />
            <span className="sm:hidden"> </span>
            We cannot prove <em>why</em> it acted.
          </h1>
          <p className="mt-7 max-w-xl text-[15px] leading-[1.75] text-ink-soft">
            Agents today have authentication but no provenance. Every consequential action
            here carries a signed credential binding the human intent that authorized it,
            the delegation chain it travelled, and measured causal evidence of which input
            actually caused it — checkable by a third party who trusts neither the agent nor
            its operator.
          </p>

          <dl className="mono mt-10 flex flex-wrap gap-x-8 gap-y-4 border-t border-line pt-5 text-[11px]">
            <Meta term="Model">{model ?? "—"}</Meta>
            <Meta term="Shared log">
              {treeSize === null
                ? "—"
                : `${treeSize} ${treeSize === 1 ? "entry" : "entries"}`}
            </Meta>
            <Meta term="Evidence">measured, not asserted</Meta>
          </dl>
        </section>

        {/* ---------------------------------------------------------------- runner */}
        <section
          id="run"
          ref={runSection}
          aria-labelledby="run-heading"
          className="mx-auto w-full max-w-5xl scroll-mt-20 px-6 pb-28"
        >
          <h2 id="run-heading" className="sr-only">
            Run the pipeline
          </h2>

          {offline && (
            <div className="mb-8 rounded-lg border border-reject/25 bg-reject/[0.03] p-5">
              <p className="text-sm font-medium text-reject">The API is not running</p>
              <p className="mt-2 text-[13px] text-ink-soft">
                Start it from the repository root, then reload:
              </p>
              <code className="mono mt-2 block rounded border border-line bg-sunken px-3 py-2 text-[12px] text-ink">
                {offline}
              </code>
            </div>
          )}

          <div className="card p-6 sm:p-7">
            <div className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
              <div className="min-w-0 flex-1">
                <label htmlFor="scenario" className="label">
                  Scenario
                </label>
                <select
                  id="scenario"
                  value={chosen}
                  onChange={(e) => setChosen(e.target.value)}
                  disabled={phase === "running" || !!offline}
                  className="mt-2.5 w-full rounded-md border border-line bg-surface px-3.5 py-2.5 text-sm text-ink transition-colors hover:border-line-strong focus:border-accent focus:outline-none disabled:bg-sunken disabled:text-ink-faint"
                >
                  {scenarios.length === 0 && <option>loading…</option>}
                  {scenarios.map((s) => (
                    <option key={s.name} value={s.name}>
                      {s.title}
                    </option>
                  ))}
                </select>
                {active && (
                  <p className="mt-3 max-w-lg text-[13px] leading-relaxed text-ink-soft">
                    {active.summary}
                  </p>
                )}
              </div>

              <Button onClick={run} disabled={phase === "running" || !!offline}>
                {phase === "running" && (
                  <span className="breathe h-1.5 w-1.5 rounded-full bg-white" aria-hidden />
                )}
                {phase === "running" ? "Running" : "Run the pipeline"}
              </Button>
            </div>

            {phase !== "idle" && (
              <div className="mt-7 border-t border-line pt-6">
                <Stepper events={events} running={phase === "running"} />
              </div>
            )}
          </div>

          {/* Announced to assistive tech without stealing focus: a stream that only
              exists visually is a stream a screen-reader user cannot follow. */}
          <p aria-live="polite" className="sr-only">
            {phase === "running"
              ? `Running. ${ablations.length} counterfactuals measured.`
              : phase === "complete" && decision
                ? `Run complete. The relying party returned ${decision.verdict}.`
                : phase === "failed"
                  ? `Run failed. ${error ?? ""}`
                  : ""}
          </p>

          {control && (
            <div className="mt-5 rounded-lg border border-p4/30 bg-p4/[0.04] p-5">
              <p className="label" style={{ color: "var(--p4)" }}>
                Refused by control {control}
              </p>
              <p className="mt-2 text-[13px] leading-relaxed text-ink-soft">{error}</p>
              <p className="mt-1.5 text-[12px] text-ink-faint">
                This limit is the threat model working, not a workaround for it.
              </p>
            </div>
          )}

          {error && !control && (
            <div className="mt-5 rounded-lg border border-reject/25 bg-reject/[0.03] p-5">
              <p className="label" style={{ color: "var(--reject)" }}>
                Run failed
              </p>
              <p className="mono mt-2 text-[12px] text-ink-soft">{error}</p>
            </div>
          )}

          {phase !== "idle" && (
            <>
              <SectionRule>The measurement</SectionRule>
              {attributed && (
                <div className="mb-5">
                  <Reading attributed={attributed} />
                </div>
              )}
              <div className="grid gap-5 lg:grid-cols-2">
                <AblationFeed
                  ablations={ablations}
                  live={phase === "running"}
                  total={attributed?.model_calls}
                  truncated={attributed?.truncated}
                />
                <EvidencePanel attributed={attributed} />
              </div>
            </>
          )}

          {halted && (
            <div className="card mt-5 p-5">
              <p className="label">Halted</p>
              <p className="mt-2 text-[13px] text-ink-soft">{halted.reason}</p>
              <p className="mt-1.5 text-[12px] text-ink-faint">
                An unattributed action carries no evidence, so there is nothing to warrant
                and nothing for a relying party to admit on.
              </p>
            </div>
          )}

          {decision && (
            <Reveal>
              <SectionRule>The decision</SectionRule>
              <Verdict decision={decision} issued={issued} logged={logged} />
            </Reveal>
          )}

          {context && (
            <Reveal>
              <SectionRule>What the model saw</SectionRule>
              <ContextTrace context={context} />
            </Reveal>
          )}
        </section>
      </main>

      <footer className="mt-auto border-t border-line">
        <div className="mx-auto w-full max-w-5xl px-6 py-8">
          <p className="max-w-3xl text-[12px] leading-relaxed text-ink-faint">
            Every number on this page is produced by <span className="mono">aegis</span>{" "}
            executing — classification by the classifier, attribution by the engine,
            signatures by the issuer, proofs by the log. Where a stage did not run, the
            screen says so rather than showing a plausible placeholder. Measurements are
            against a bundled deterministic mock whose susceptibility was written down
            rather than discovered, so they establish that the mechanism works, not how it
            behaves against a frontier model.
          </p>
        </div>
      </footer>
    </>
  );
}

function Meta({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <div className="border-l border-line pl-4 first:border-l-0 first:pl-0">
      <dt className="label">{term}</dt>
      <dd className="mt-1.5 text-ink-soft">{children}</dd>
    </div>
  );
}

function SectionRule({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-5 mt-12 flex items-center gap-4">
      <h3 className="label shrink-0">{children}</h3>
      <span className="h-px flex-1 bg-line" aria-hidden />
    </div>
  );
}
