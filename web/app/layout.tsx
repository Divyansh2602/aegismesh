import type { Metadata } from "next";
import { Bebas_Neue, DM_Sans, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { Cursor } from "@/components/Cursor";

const bebas = Bebas_Neue({
  variable: "--font-bebas",
  weight: "400",
  subsets: ["latin"],
});

const dmSans = DM_Sans({
  variable: "--font-dm-sans",
  subsets: ["latin"],
});

// Hashes, roots and multibase keys are read character by character when someone is
// checking one against another, so the monospace face is load-bearing rather than styling.
const mono = JetBrains_Mono({
  variable: "--font-mono-code",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "AegisMesh — prove why your agent did that",
  description:
    "Every consequential action an AI agent takes carries a signed Action Warrant binding "
    + "human intent, the delegation chain, and measured causal evidence of which input "
    + "caused it — verifiable by a third party who trusts nobody involved.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${bebas.variable} ${dmSans.variable} ${mono.variable} h-full antialiased`}
    >
      <body className="noise min-h-full flex flex-col bg-ink text-text">
        <Cursor />
        {children}
      </body>
    </html>
  );
}
