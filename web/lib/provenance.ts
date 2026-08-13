import type { ProvenanceClass } from "./api";

/**
 * The five provenance classes, with the colour each one carries everywhere on the site.
 *
 * One definition, imported by every component that renders a class. Two components that
 * each decided their own colour for P3 would be a UI that disagrees with itself about
 * which text is untrusted.
 */
export const PROVENANCE: Record<
  ProvenanceClass,
  { label: string; colour: string; short: string }
> = {
  P0: { label: "human mandate", colour: "var(--p0)", short: "human" },
  P1: { label: "system policy", colour: "var(--p1)", short: "system" },
  P2: { label: "trusted tool", colour: "var(--p2)", short: "trusted tool" },
  P3: { label: "untrusted external", colour: "var(--p3)", short: "untrusted" },
  P4: { label: "agent generated", colour: "var(--p4)", short: "agent" },
};

export function classColour(cls: string): string {
  return PROVENANCE[cls as ProvenanceClass]?.colour ?? "var(--text-faint)";
}

export function classLabel(cls: string): string {
  return PROVENANCE[cls as ProvenanceClass]?.label ?? cls;
}
