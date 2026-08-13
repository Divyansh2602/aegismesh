import type { Metadata } from "next";
import { Inter, JetBrains_Mono, Source_Serif_4 } from "next/font/google";
import "./globals.css";

// Editorial serif for display, at restrained sizes. The authority comes from the face and
// the spacing, not from setting it 9rem tall.
const serif = Source_Serif_4({
  variable: "--font-source-serif",
  subsets: ["latin"],
  display: "swap",
});

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

// Hashes, roots and multibase keys get read character by character when someone checks one
// against another, so the monospace face is load-bearing rather than decorative.
const mono = JetBrains_Mono({
  variable: "--font-mono-code",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "AegisMesh — provenance for agent actions",
  description:
    "Every consequential action an AI agent takes carries a signed Action Warrant binding "
    + "human intent, the delegation chain, and measured causal evidence of which input "
    + "caused it — verifiable by a third party who trusts nobody involved.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${serif.variable} ${inter.variable} ${mono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col bg-paper text-ink">{children}</body>
    </html>
  );
}
