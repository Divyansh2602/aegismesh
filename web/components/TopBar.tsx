"use client";

/**
 * Persistent chrome: what this is, what is running it, and whether it is reachable.
 *
 * The log size lives here rather than only in the hero because it is the one number that
 * changes while you read — a shared append-only log that grew between two glances is the
 * most convincing thing on the site, and it should be visible when it moves.
 */
export function TopBar({
  model,
  treeSize,
  online,
}: {
  model: string | null;
  treeSize: number | null;
  online: boolean;
}) {
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-paper/85 backdrop-blur-md">
      <div className="mx-auto flex w-full max-w-5xl items-center justify-between gap-4 px-6 py-3">
        <div className="flex items-center gap-2.5">
          <Mark />
          <span className="text-[15px] font-semibold tracking-tight text-ink">AegisMesh</span>
          <span className="hidden text-[12px] text-ink-faint sm:inline">
            provenance for agent actions
          </span>
        </div>

        <div className="mono flex items-center gap-3 text-[11px] sm:gap-5">
          <span className="hidden text-ink-faint md:inline" title={model ?? undefined}>
            {model ? model.split(" ")[0] : "—"}
          </span>
          <span className="hidden text-ink-soft sm:inline">
            <span className="text-ink-faint">log</span>{" "}
            <span className="tnum font-medium text-ink">{treeSize ?? "—"}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span
              className={`h-1.5 w-1.5 rounded-full ${online ? "" : "breathe"}`}
              style={{ background: online ? "var(--permit)" : "var(--reject)" }}
              aria-hidden
            />
            <span className="text-ink-soft">{online ? "live" : "offline"}</span>
          </span>
        </div>
      </div>
    </header>
  );
}

/** A sealed node: the mesh, and the witness that vouches for it. */
function Mark() {
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden>
      <path
        d="M10 1.5 17.4 5.75v8.5L10 18.5 2.6 14.25v-8.5z"
        stroke="var(--accent)"
        strokeWidth="1.3"
        strokeLinejoin="round"
      />
      <circle cx="10" cy="10" r="2.6" fill="var(--accent)" />
    </svg>
  );
}
