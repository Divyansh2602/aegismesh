"use client";

import type { ReactNode } from "react";

/**
 * One button, two weights. No cursor tricks and nothing that moves the hit target —
 * a control that drifts away from where someone aimed is a control they miss.
 * The feedback is a border and a background shift, which is instant and readable.
 */
export function Button({
  children,
  onClick,
  disabled,
  variant = "primary",
  type = "button",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  variant?: "primary" | "quiet";
  type?: "button" | "submit";
}) {
  const base =
    "inline-flex shrink-0 items-center justify-center gap-2 rounded-md px-5 py-2.5 text-sm "
    + "font-medium transition-colors duration-150 disabled:cursor-not-allowed";

  const styles =
    variant === "primary"
      ? "bg-accent text-white hover:bg-[#173349] disabled:bg-line-strong disabled:text-white/70"
      : "border border-line bg-surface text-ink-soft hover:border-line-strong hover:text-ink "
        + "disabled:text-ink-faint disabled:hover:border-line";

  return (
    <button type={type} onClick={onClick} disabled={disabled} className={`${base} ${styles}`}>
      {children}
    </button>
  );
}
