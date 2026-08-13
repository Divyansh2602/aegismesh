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
import { EvidencePanel } from "@/components/EvidencePanel";
import { ContextTrace } from "@/components/ContextTrace";
import { AblationFeed } from "@/components/AblationFeed";
import { Verdict } from "@/components/Verdict";
import { MagneticButton } from "@/components/MagneticButton";

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
        if (!cancelled) {
          setOffline(
            "The API is not reachable. Start it with: uvicorn aegis.api.app:app --port 8000",
          );
        }
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

      // The context carries segment text, so it comes from the stage endpoint rather than
      // the stream -- events carry hashes only, deliberately.
      const view = await api.stage<ContextView>(
        session.session_id,
        started.run_id,
        "context",
      );
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

  return (
    <main className="flex-1">
      <Hero model={model} treeSize={treeSize} />

      <section className="mx-auto w-full max-w-6xl px-6 pb-32">
        {offline && (
          <div className="mb-10 rounded-lg border border-reject/40 bg-reject/5 p-5">
            <p className="text-sm font-medium text-reject">Backend unreachable</p>
            <p className="mono mt-2 text-xs text-text-dim">{offline}</p>
          </div>
        )}

        <div className="rounded-xl border border-line bg-ink-raised p-6 sm:p-8">
          <div className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between">
            <div className="min-w-0 flex-1">
              <label
                htmlFor="scenario"
                className="mono text-[11px] uppercase tracking-[0.18em] text-text-faint"
              >
                Scenario
              </label>
              <select
                id="scenario"
                value={chosen}
                onChange={(e) => setChosen(e.target.value)}
                disabled={phase === "running" || !!offline}
                className="mt-2 w-full rounded-md border border-line bg-ink px-4 py-3 text-sm text-text outline-none transition-colors hover:border-line-bright focus:border-accent disabled:opacity-40"
              >
                {scenarios.length === 0 && <option>loading…</option>}
                {scenarios.map((s) => (
                  <option key={s.name} value={s.name}>
                    {s.title}
                  </option>
                ))}
              </select>
              <p className="mt-3 max-w-xl text-sm leading-relaxed text-text-dim">
                {scenarios.find((s) => s.name === chosen)?.summary ?? ""}
              </p>
            </div>

            <MagneticButton onClick={run} disabled={phase === "running" || !!offline}>
              {phase === "running" ? "Running…" : "Run the pipeline"}
            </MagneticButton>
          </div>
        </div>

        {control && (
          <div className="mt-6 rounded-lg border border-accent/40 bg-accent/5 p-5">
            <p className="mono text-xs uppercase tracking-[0.16em] text-accent">
              Refused by control {control}
            </p>
            <p className="mt-2 text-sm text-text-dim">{error}</p>
            <p className="mt-2 text-xs text-text-faint">
              This limit is the threat model working, not a workaround for it.
            </p>
          </div>
        )}

        {error && !control && (
          <div className="mt-6 rounded-lg border border-reject/40 bg-reject/5 p-5">
            <p className="mono text-xs uppercase tracking-[0.16em] text-reject">Run failed</p>
            <p className="mono mt-2 text-xs text-text-dim">{error}</p>
          </div>
        )}

        {phase !== "idle" && (
          <div className="mt-10 grid gap-6 lg:grid-cols-2">
            <AblationFeed
              ablations={ablations}
              live={phase === "running"}
              total={attributed?.model_calls}
              truncated={attributed?.truncated}
            />
            <EvidencePanel attributed={attributed} />
          </div>
        )}

        {halted && (
          <div className="mt-6 rounded-lg border border-line bg-ink-raised p-5">
            <p className="mono text-xs uppercase tracking-[0.16em] text-text-faint">Halted</p>
            <p className="mt-2 text-sm text-text-dim">{halted.reason}</p>
            <p className="mt-2 text-xs text-text-faint">
              An unattributed action carries no evidence, so there is nothing to warrant and
              nothing for a relying party to admit on.
            </p>
          </div>
        )}

        {decision && (
          <Verdict
            decision={decision}
            issued={issued}
            logged={logged}
            className="mt-6"
          />
        )}

        {context && <ContextTrace context={context} className="mt-6" />}
      </section>
    </main>
  );
}

function Hero({ model, treeSize }: { model: string | null; treeSize: number | null }) {
  return (
    <section className="relative mx-auto w-full max-w-6xl px-6 pb-16 pt-24 sm:pt-32">
      <p className="mono mb-6 text-[11px] uppercase tracking-[0.28em] text-accent">
        Action Warrants · EU AI Act Article 12
      </p>
      <h1 className="display text-[clamp(3.5rem,12vw,9rem)] uppercase text-text">
        Prove why
        <br />
        your agent
        <br />
        <span className="text-accent">did that.</span>
      </h1>
      <p className="mt-8 max-w-2xl text-lg leading-relaxed text-text-dim">
        Agents today have authentication but no provenance. We can prove <em>who</em> an
        agent is; we cannot prove <em>why it did what it did</em>. Every consequential
        action here carries a signed credential binding the human intent that authorized
        it, the delegation chain it travelled, and measured causal evidence of which input
        actually caused it.
      </p>
      <dl className="mono mt-10 flex flex-wrap gap-x-10 gap-y-4 text-xs">
        <div>
          <dt className="text-text-faint uppercase tracking-[0.16em]">Model</dt>
          <dd className="mt-1 text-text-dim">{model ?? "—"}</dd>
        </div>
        <div>
          <dt className="text-text-faint uppercase tracking-[0.16em]">Shared log</dt>
          <dd className="mt-1 text-text-dim">
            {treeSize === null ? "—" : `${treeSize} entries`}
          </dd>
        </div>
      </dl>
    </section>
  );
}
