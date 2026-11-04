/**
 * Design tokens (review §15). app/globals.css must declare the same values; a unit test
 * checks both that they match and that text tokens meet WCAG AA contrast.
 *
 * Colour is never the only signal: severities and statuses always carry a text label.
 * No purple/violet, no pastels (colour-vision accessibility).
 */
export const colors = {
  bg: "#0A0A0C",
  surface: "#121216",
  "surface-2": "#18181D",
  border: "#24242A",
  "border-strong": "#33333B",
  text: "#E8E8EC",
  muted: "#9A9AA3",
  faint: "#6B6B75", // decoration only, never text
  crimson: "#E5192E", // critical, primary accents (icons, borders, fills)
  "crimson-strong": "#CC1426", // primary button background (white text 5.7:1)
  "crimson-text": "#FF4D5E", // crimson used as text
  orange: "#FF7A1A", // high
  yellow: "#FFC21A", // medium
  blue: "#2F7BFF", // low / informational fills
  "blue-text": "#5B97FF",
  green: "#22C55E", // healthy, validated
  gray: "#8B8B95", // neutral, info, inactive
} as const;

export type ColorToken = keyof typeof colors;

/** Tokens used as text on bg / surface / surface-2. */
export const textTokens: ColorToken[] = [
  "text", "muted", "crimson-text", "orange", "yellow", "blue-text", "green", "gray",
];

export const backgrounds: ColorToken[] = ["bg", "surface", "surface-2"];

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}
