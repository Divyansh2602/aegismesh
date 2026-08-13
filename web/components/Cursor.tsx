"use client";

import { useEffect, useRef, useState } from "react";

/**
 * A custom cursor: a precise dot, and a ring that lags behind it.
 *
 * Only mounts for devices that actually have a fine pointer. On a phone there is no
 * cursor to replace, and on a machine where the visitor has asked for reduced motion a
 * trailing ring is exactly the kind of thing they asked not to have. In both cases the
 * native cursor is left alone rather than hidden -- hiding the system cursor and then
 * declining to draw a replacement is how a page becomes unusable.
 */
export function Cursor() {
  const dot = useRef<HTMLDivElement>(null);
  const ring = useRef<HTMLDivElement>(null);
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    const fine = window.matchMedia("(pointer: fine)").matches;
    const calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!fine || calm) return;
    setEnabled(true);

    let ringX = 0;
    let ringY = 0;
    let pointerX = 0;
    let pointerY = 0;
    let frame = 0;

    const onMove = (event: PointerEvent) => {
      pointerX = event.clientX;
      pointerY = event.clientY;
      if (dot.current) {
        dot.current.style.transform = `translate3d(${pointerX - 3}px, ${pointerY - 3}px, 0)`;
      }
      // The ring is told what the cursor is over, so hovering a control reads as a state
      // change rather than as decoration.
      const target = event.target as HTMLElement | null;
      const interactive = target?.closest("a, button, input, textarea, [data-cursor]");
      ring.current?.setAttribute("data-hot", interactive ? "true" : "false");
    };

    const tick = () => {
      ringX += (pointerX - ringX) * 0.16;
      ringY += (pointerY - ringY) * 0.16;
      if (ring.current) {
        ring.current.style.transform = `translate3d(${ringX - 16}px, ${ringY - 16}px, 0)`;
      }
      frame = requestAnimationFrame(tick);
    };

    window.addEventListener("pointermove", onMove, { passive: true });
    frame = requestAnimationFrame(tick);
    document.documentElement.style.cursor = "none";

    return () => {
      window.removeEventListener("pointermove", onMove);
      cancelAnimationFrame(frame);
      document.documentElement.style.cursor = "";
    };
  }, []);

  if (!enabled) return null;

  return (
    <>
      <div
        ref={dot}
        aria-hidden
        className="pointer-events-none fixed left-0 top-0 z-[70] h-1.5 w-1.5 rounded-full bg-accent"
      />
      <div
        ref={ring}
        aria-hidden
        data-hot="false"
        className="pointer-events-none fixed left-0 top-0 z-[70] h-8 w-8 rounded-full border border-line-bright transition-[width,height,border-color,opacity] duration-200 data-[hot=true]:border-accent data-[hot=true]:opacity-100 opacity-60"
      />
    </>
  );
}
