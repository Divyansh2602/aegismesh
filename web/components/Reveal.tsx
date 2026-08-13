"use client";

import { useEffect, useRef, type ReactNode } from "react";

/**
 * A short fade-and-rise as a section enters the viewport.
 *
 * Two properties make this safe rather than decorative risk. It is **armed by script**,
 * so the markup ships visible and a hydration failure or a disabled-JS reader gets the
 * page rather than a column of invisible divs. And it animates opacity and transform
 * only, so it runs on the compositor and cannot cause layout work while a stream is
 * pushing rows into the same page.
 */
export function Reveal({
  children,
  delay = 0,
  className = "",
}: {
  children: ReactNode;
  delay?: number;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const node = ref.current;
    if (!node) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    node.dataset.armed = "true";
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting) return;
        node.style.transitionDelay = `${delay}ms`;
        node.dataset.shown = "true";
        observer.disconnect();
      },
      { rootMargin: "0px 0px -8% 0px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [delay]);

  return (
    <div ref={ref} className={`rise ${className}`}>
      {children}
    </div>
  );
}
