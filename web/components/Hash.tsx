"use client";

import { useState } from "react";

/**
 * A hash you can actually check.
 *
 * An auditor's whole job is comparing one of these against another, so truncating without
 * offering the full value would make the page look precise while being useless. The full
 * string is on the title attribute and one click puts it on the clipboard.
 */
export function Hash({
  value,
  head = 10,
  tail = 6,
  label = "value",
}: {
  value: string;
  head?: number;
  tail?: number;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  const bare = value.replace(/^sha256:/, "");
  const short =
    bare.length > head + tail + 1 ? `${bare.slice(0, head)}…${bare.slice(-tail)}` : bare;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      // Clipboard access can be denied; the full value is still on the title attribute,
      // so failing silently leaves the reader no worse off than before they clicked.
    }
  };

  return (
    <button
      type="button"
      onClick={copy}
      title={value}
      aria-label={`Copy ${label} ${value}`}
      className="mono group inline-flex max-w-full items-center gap-1.5 rounded px-1 py-0.5 -mx-1 text-left align-baseline transition-colors hover:bg-sunken"
    >
      <span className="truncate text-ink-soft">{short}</span>
      <span
        aria-hidden
        className="shrink-0 text-[10px] text-ink-faint opacity-0 transition-opacity group-hover:opacity-100"
        style={copied ? { opacity: 1, color: "var(--permit)" } : undefined}
      >
        {copied ? "copied" : "copy"}
      </span>
    </button>
  );
}
