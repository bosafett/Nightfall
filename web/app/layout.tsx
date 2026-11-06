import type { Metadata, Viewport } from "next";
import { IBM_Plex_Sans_Condensed, JetBrains_Mono } from "next/font/google";
import "./globals.css";

// next/font downloads these at build time and serves them from this app (no runtime CDN).
const plex = IBM_Plex_Sans_Condensed({ subsets: ["latin"], weight: ["400", "500", "600", "700"], variable: "--font-plex" });
const mono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-jetbrains" });

export const metadata: Metadata = {
  title: { default: "JANUS", template: "%s · JANUS" },
  description: "Adversarial intelligence & operations platform",
  icons: { icon: "/nightfall-mark.svg" },
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: "#0A0A0C", colorScheme: "dark" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${plex.variable} ${mono.variable}`}>
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
