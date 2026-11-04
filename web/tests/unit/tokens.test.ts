import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { backgrounds, colors, contrast, textTokens } from "@/lib/tokens";

describe("design tokens", () => {
  it("globals.css declares exactly the tokens in lib/tokens.ts", () => {
    const css = readFileSync(path.resolve(import.meta.dirname, "../../app/globals.css"), "utf8");
    const declared = Object.fromEntries(
      [...css.matchAll(/--color-([a-z0-9-]+):\s*(#[0-9A-Fa-f]{6});/g)].map((m) => [m[1], m[2]!.toUpperCase()]),
    );
    const expected = Object.fromEntries(Object.entries(colors).map(([k, v]) => [k, v.toUpperCase()]));
    expect(declared).toEqual(expected);
  });

  it.each(textTokens.flatMap((t) => backgrounds.map((b) => [t, b] as const)))(
    "%s text on %s meets WCAG AA (4.5:1)",
    (text, bg) => {
      expect(contrast(colors[text], colors[bg])).toBeGreaterThanOrEqual(4.5);
    },
  );

  it("primary button text meets WCAG AA", () => {
    expect(contrast("#FFFFFF", colors["crimson-strong"])).toBeGreaterThanOrEqual(4.5);
  });

  it("contains no purple/violet hues", () => {
    for (const hex of Object.values(colors)) {
      const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
      const isPurple = b! > g! + 30 && r! > g! + 30;
      expect(isPurple, hex).toBe(false);
    }
  });
});
