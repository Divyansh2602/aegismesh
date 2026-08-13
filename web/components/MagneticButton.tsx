"use client";

import { useRef, type ReactNode } from "react";

/**
 * A button that leans toward the cursor.
 *
 * The pull is bounded and released on leave, and it is skipped entirely for coarse
 * pointers and for anyone who asked for reduced motion. A control that moves away from
 * where someone tapped is a control they miss, so the effect is decoration that must
 * never change where the button actually is when it matters.
 */
export function MagneticButton({
  children,
  onClick,
  disabled,
}: {
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
}) {
  const ref = useRef<HTMLButtonElement>(null);

  const pull = (event: React.PointerEvent<HTMLButtonElement>) => {
    const el = ref.current;
    if (!el || disabled) return;
    if (!window.matchMedia("(pointer: fine)").matches) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const box = el.getBoundingClientRect();
    const dx = event.clientX - (box.left + box.width / 2);
    const dy = event.clientY - (box.top + box.height / 2);
    el.style.transform = `translate3d(${dx * 0.22}px, ${dy * 0.3}px, 0)`;
  };

  const release = () => {
    if (ref.current) ref.current.style.transform = "";
  };

  return (
    <button
      ref={ref}
      type="button"
      onClick={onClick}
      onPointerMove={pull}
      onPointerLeave={release}
      onBlur={release}
      disabled={disabled}
      className="group relative shrink-0 overflow-hidden rounded-md border border-accent bg-accent px-8 py-4 text-sm font-medium uppercase tracking-[0.12em] text-ink transition-[transform,opacity] duration-200 ease-out hover:bg-accent/90 disabled:cursor-not-allowed disabled:border-line disabled:bg-transparent disabled:text-text-faint"
    >
      {children}
    </button>
  );
}
