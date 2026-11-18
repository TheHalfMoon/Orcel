import type { Metadata } from "next";
import { Geist_Mono, Inter, Instrument_Serif } from "next/font/google";
import type { CSSProperties, ReactNode } from "react";
import "./globals.css";

// Orcel type system (identity v5). next/font downloads these at build time and serves them from this
// site (Latin subsets, SIL Open Font License; licences are published in /fonts), so a visitor's
// browser never requests a font from a third party.
const display = Inter({ subsets: ["latin"], weight: "600", variable: "--font-display", display: "swap" });
const text = Inter({ subsets: ["latin"], variable: "--font-text", display: "swap" });
const mono = Geist_Mono({ subsets: ["latin"], variable: "--font-mono", display: "swap" });
const serif = Instrument_Serif({ subsets: ["latin"], weight: "400", variable: "--font-serif", display: "swap" });

const siteUrl = "https://thehalfmoon.github.io/Orcel/";
const title = "Orcel — Your computer, your terms";
const description =
  "Local-first, policy-checked computer access for MCP-compatible AI agents.";
const socialDescription =
  "A governed path from MCP-compatible AI agents to your own computer.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title,
  description,
  applicationName: "Orcel",
  alternates: {
    canonical: siteUrl
  },
  openGraph: {
    title,
    description: socialDescription,
    type: "website",
    url: siteUrl,
    siteName: "Orcel",
    images: [{ url: siteUrl + "brand/orcel-social-dark.png", width: 1200, height: 630, alt: "Orcel — Your computer, your terms" }]
  },
  twitter: {
    card: "summary",
    images: [siteUrl + "brand/orcel-social-dark.png"],
    title,
    description: socialDescription
  }
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  const basePath = process.env.ORCEL_WEB_BASE_PATH ?? "";
  const style = {
    "--orcel-mark-mask": `url("${basePath}/brand/orcel-mark-red.svg")`
  } as CSSProperties;

  return (
    <html lang="en" className={`${display.variable} ${text.variable} ${mono.variable} ${serif.variable}`}>
      <body style={style}>{children}</body>
    </html>
  );
}
