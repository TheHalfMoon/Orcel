import type { Metadata } from "next";
import localFont from "next/font/local";
import type { CSSProperties, ReactNode } from "react";
import "./globals.css";

// Halfmoon type system, self-hosted at build time (Latin subsets, SIL Open Font License;
// licences are published in /fonts). No font is requested from a third party.
const display = localFont({ src: "./fonts/bricolage-grotesque-600.woff2", weight: "600", variable: "--font-display", display: "swap" });
const text = localFont({ src: "./fonts/geist-variable.woff2", weight: "100 900", variable: "--font-text", display: "swap" });
const mono = localFont({ src: "./fonts/geist-mono-variable.woff2", weight: "100 900", variable: "--font-mono", display: "swap" });
const serif = localFont({ src: "./fonts/instrument-serif-regular.woff2", weight: "400", variable: "--font-serif", display: "swap" });

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
    "--orcel-mark-mask": `url("${basePath}/brand/orcel-o-white.svg")`
  } as CSSProperties;

  return (
    <html lang="en" className={`${display.variable} ${text.variable} ${mono.variable} ${serif.variable}`}>
      <body style={style}>{children}</body>
    </html>
  );
}
