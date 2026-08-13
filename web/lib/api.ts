/**
 * The aegis API, typed.
 *
 * Every shape here mirrors something `aegis` actually emits. Nothing in this file
 * invents a field so the UI can render more comfortably -- if a value is not in the
 * response, the screen shows that it is not, because the whole project is an argument
 * against plausible-looking evidence.
 */

export const API_BASE =
  process.env.NEXT_PUBLIC_AEGIS_API ?? "http://localhost:8000";

export const SESSION_HEADER = "X-Aegis-Session";

/** P0 human-mandate, P1 system-policy, P2 trusted-tool, P3 untrusted-external, P4 agent. */
export type ProvenanceClass = "P0" | "P1" | "P2" | "P3" | "P4";

/** The three states design decision 6 exists to keep apart. Never collapse these. */
export type ArgumentStatus = "attributed" | "invariant" | "unknown";

export interface Segment {
  segment_id: string;
  class: ProvenanceClass;
  kind: string;
  origin: string;
  span: { start: number; end: number };
  text: string;
  classification_reason: string;
}

export interface ContextView {
  trace_id: string;
  model: string;
  mandate_id: string;
  principal: string;
  bytes_by_class: Record<string, number>;
  segments: Segment[];
}

export interface ProposedCall {
  tool: string;
  arguments: Record<string, unknown>;
  consequential: boolean;
  gate_reason: string;
}

export interface AblationEventData {
  sequence: number;
  granularity: string;
  segment_id: string;
  class: ProvenanceClass;
  excerpt_hash: string;
  influence: number;
  necessity: number;
  per_field: Record<string, number>;
  /**
   * Whether the counterfactual left the same tool called. Streamed rather than inferred
   * from a zero influence, because `invariant` and `unknown` both present as zero and a
   * consumer forced to tell them apart from the numbers gets it wrong.
   */
  comparable: boolean;
}

export interface AttributedEventData {
  model_calls: number;
  truncated: boolean;
  argument_status: Record<string, ArgumentStatus>;
  per_argument: Record<string, Record<string, string>>;
}

export interface DecisionEventData {
  verdict: "PERMIT" | "REJECT";
  issuer_decision: string;
  failed_steps: number[];
  reasons: string[];
}

export type RunEventType =
  | "classified"
  | "proposed"
  | "queued"
  | "gate"
  | "ablation"
  | "attributed"
  | "halted"
  | "issued"
  | "logged"
  | "decision"
  | "end";

export interface RunEvent {
  seq: number;
  type: RunEventType;
  data: Record<string, unknown>;
}

export interface Scenario {
  name: string;
  title: string;
  summary: string;
  labelled?: boolean;
}

export interface CaseOutcome {
  name: string;
  poisoned: boolean;
  effective: boolean;
  flagged: boolean;
  correct: boolean;
  localized: boolean | null;
  untrusted_share: number;
  confidence: number;
  model_calls: number;
  dominant_class: string | null;
  destination_status: ArgumentStatus | "unknown";
  tags: string[];
}

export interface EvaluationReport {
  cases: number;
  ineffective_injections: number;
  precision: number;
  recall: number;
  f1: number;
  localization_rate: number;
  mean_model_calls: number;
  max_model_calls: number;
  outcomes: CaseOutcome[];
  model: string;
  model_calls: number;
  flag_threshold: number;
  note: string;
}

export interface AttackSpec {
  name: string;
  title: string;
  what_it_does: string;
  expectation: string;
  control: string;
}

export interface AttackResult extends AttackSpec {
  mutation: Record<string, unknown>;
  defended: boolean;
  detected_by: string;
  note: string;
  enforcement?: {
    verdict: "PERMIT" | "REJECT";
    issuer_decision: string;
    failed_steps: number[];
    reasons: string[];
    policy_reasons: string[];
  };
  witness?: { fork_detected: boolean; reason: string; serves_a_root_now: boolean };
}

export interface ReplayFinding {
  check: string;
  verdict: "consistent" | "contradicted" | "inconclusive";
  detail: string;
  signed: string | null;
  replayed: string | null;
}

export interface ReplayReport {
  run_id: string;
  model: string;
  model_calls: number;
  verdict: "consistent" | "contradicted" | "inconclusive";
  checks: number;
  contradictions: number;
  findings: ReplayFinding[];
  note: string;
}

export interface ArtifactBundle {
  warrant: Record<string, unknown>;
  receipt: { leaf_index: number; tree_size: number; root_hash: string; inclusion_proof: string[] };
  trust_anchors: {
    issuer_verification_method: string;
    issuer_public_key_multibase: string;
    log_id: string;
    log_public_key_multibase: string;
    witnessed_root: string;
    witnessed_tree_size: number;
  };
}

export interface WitnessState {
  log_id: string;
  tree_size: number;
  root: string | null;
  note: string;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    /** The control that refused, when a control refused. Rendered, never swallowed. */
    readonly control: string | null,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(
  path: string,
  init: RequestInit & { session?: string } = {},
): Promise<T> {
  const { session, ...rest } = init;
  const response = await fetch(`${API_BASE}${path}`, {
    ...rest,
    headers: {
      "Content-Type": "application/json",
      ...(session ? { [SESSION_HEADER]: session } : {}),
      ...rest.headers,
    },
  });

  if (!response.ok) {
    // A refusal from this API names the control that refused it. Flattening that into
    // "request failed" would discard the most informative thing the response carries.
    const body = await response.json().catch(() => null);
    const detail = body?.detail;
    if (detail && typeof detail === "object") {
      throw new ApiError(
        response.status,
        detail.control ?? null,
        `${detail.control_name ?? "refused"}: ${detail.detail ?? ""}`,
      );
    }
    throw new ApiError(
      response.status,
      null,
      typeof detail === "string" ? detail : `HTTP ${response.status}`,
    );
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; model: string; log_tree_size: number }>("/health"),

  scenarios: () =>
    request<{ model: string; scenarios: Scenario[]; custom: Scenario }>("/v1/scenarios"),

  createSession: () =>
    request<{ session_id: string; issuer_did: string }>("/v1/sessions", {
      method: "POST",
    }),

  startRun: (session: string, scenario: string, injection?: string) =>
    request<{ run_id: string; model: string }>("/v1/runs", {
      method: "POST",
      session,
      body: JSON.stringify({ scenario, injection: injection ?? "" }),
    }),

  stage: <T>(session: string, runId: string, stage: string) =>
    request<T>(`/v1/runs/${runId}/${stage}`, { session }),

  log: () => request<{ tree_size: number; durable: boolean }>("/v1/log"),

  /** Scores the whole labelled case set in one arrival. See the endpoint for why. */
  evaluation: (session: string) =>
    request<EvaluationReport>("/v1/evaluation", { method: "POST", session }),

  attacks: (session: string, runId: string) =>
    request<{ attacks: AttackSpec[]; note: string }>(`/v1/runs/${runId}/attacks`, { session }),

  runAttack: (session: string, runId: string, name: string) =>
    request<AttackResult>(`/v1/runs/${runId}/attacks/${name}`, { method: "POST", session }),

  replay: (session: string, runId: string) =>
    request<ReplayReport>(`/v1/runs/${runId}/replay`, { method: "POST", session }),

  artifacts: (session: string, runId: string) =>
    request<ArtifactBundle>(`/v1/runs/${runId}/artifacts`, { session }),

  witness: (session: string) => request<WitnessState>("/v1/witness", { session }),
};

/**
 * Fetch one auditor file and hand it to the browser as a download.
 *
 * Done through fetch rather than an `<a download href>` because the endpoint needs the
 * session header, which a plain anchor cannot send — the same constraint that rules out
 * EventSource for the event stream.
 */
export async function downloadArtifact(
  session: string,
  runId: string,
  name: "warrant" | "receipt" | "trust_anchors",
): Promise<void> {
  const response = await fetch(`${API_BASE}/v1/runs/${runId}/artifacts/${name}.json`, {
    headers: { [SESSION_HEADER]: session },
  });
  if (!response.ok) {
    throw new ApiError(response.status, null, `could not download ${name}.json`);
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${name}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/**
 * Read a run's event stream.
 *
 * `EventSource` cannot be used here and the reason is worth keeping in the code: the
 * endpoint requires `X-Aegis-Session`, and the browser's EventSource API has no way to
 * set a request header. So the stream is consumed with fetch + ReadableStream and
 * resumed with `?after=`, which the endpoint already supports.
 *
 * Frames are split on a blank line rather than parsed line-by-line, because a chunk
 * boundary can land anywhere -- including mid-frame -- and a parser that assumes each
 * read contains whole events drops data under exactly the conditions streaming exists
 * for. Comment frames (`: keepalive`) are skipped.
 */
export async function* streamEvents(
  session: string,
  runId: string,
  options: { after?: number; signal?: AbortSignal } = {},
): AsyncGenerator<RunEvent> {
  const after = options.after ?? -1;
  const query = after >= 0 ? `?after=${after}` : "";
  const response = await fetch(`${API_BASE}/v1/runs/${runId}/events${query}`, {
    headers: { [SESSION_HEADER]: session },
    signal: options.signal,
  });

  if (!response.ok || !response.body) {
    throw new ApiError(response.status, null, `stream failed: HTTP ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      let split = buffer.indexOf("\n\n");
      while (split !== -1) {
        const frame = buffer.slice(0, split);
        buffer = buffer.slice(split + 2);
        const event = parseFrame(frame);
        if (event) yield event;
        split = buffer.indexOf("\n\n");
      }
    }
  } finally {
    reader.cancel().catch(() => {
      // The stream is already being torn down; a cancel that fails changes nothing.
    });
  }
}

function parseFrame(frame: string): RunEvent | null {
  let seq = -1;
  let type = "";
  const dataLines: string[] = [];

  for (const line of frame.split("\n")) {
    if (line.startsWith(":")) return null; // keepalive comment frame
    if (line.startsWith("id:")) seq = Number(line.slice(3).trim());
    else if (line.startsWith("event:")) type = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
  }

  if (!type || dataLines.length === 0) return null;
  try {
    return { seq, type: type as RunEventType, data: JSON.parse(dataLines.join("\n")) };
  } catch {
    return null;
  }
}
