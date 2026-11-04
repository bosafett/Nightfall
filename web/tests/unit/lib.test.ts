import { describe, expect, it } from "vitest";
import { parseError } from "@/lib/api/errors";
import { formatDateTime, formatRelative, groupSecret } from "@/lib/format";
import { can, mfaRequired } from "@/lib/labels";
import { NAV, isActive } from "@/lib/nav";

describe("parseError", () => {
  it("reads the API's error shape", () => {
    const e = parseError(403, { detail: { code: "forbidden", message: "Your role can't do that." } });
    expect([e.status, e.code, e.message]).toEqual([403, "forbidden", "Your role can't do that."]);
  });
  it("summarises validation errors", () => {
    const e = parseError(422, { detail: [{ loc: ["body", "name"], msg: "String should have at least 1 character" }] });
    expect(e.message).toBe("name: String should have at least 1 character");
  });
  it("falls back on unknown bodies", () => {
    expect(parseError(500, null).message).toMatch(/Something went wrong/);
  });
});

describe("format", () => {
  it("formats timestamps in UTC", () => {
    expect(formatDateTime("2026-11-04T09:05:00Z")).toBe("Nov 04, 2026, 09:05 UTC");
    expect(formatDateTime(null)).toBe("—");
  });
  it("formats relative times", () => {
    const now = new Date("2026-11-04T12:00:00Z");
    expect(formatRelative("2026-11-04T10:00:00Z", now)).toBe("2 hours ago");
    expect(formatRelative("2026-11-04T11:59:50Z", now)).toBe("just now");
  });
  it("groups TOTP secrets", () => {
    expect(groupSecret("ABCDEFGHIJ")).toBe("ABCD EFGH IJ");
  });
});

describe("permissions mirror the API", () => {
  it("matches role rules", () => {
    expect(can.writeRegistry("viewer")).toBe(false);
    expect(can.writeRegistry("analyst")).toBe(true);
    expect(can.manageMembers("operator")).toBe(false);
    expect(can.assign("admin", "owner")).toBe(false);
    expect(can.assign("owner", "owner")).toBe(true);
    expect(mfaRequired("operator")).toBe(true);
    expect(mfaRequired("analyst")).toBe(false);
  });
});

describe("navigation", () => {
  it("has the eight spec sections in order", () => {
    expect(NAV.map((n) => n.label)).toEqual([
      "Command Center", "Target Registry", "Reconnaissance", "Findings",
      "Attack Graph", "War Room", "Reports", "Settings",
    ]);
  });
  it("marks the active section", () => {
    const targets = NAV[1]!;
    expect(isActive(targets, "w1", "/w/w1/targets/abc")).toBe(true);
    expect(isActive(NAV[0]!, "w1", "/w/w1/targets")).toBe(false);
    expect(isActive(NAV[0]!, "w1", "/w/w1")).toBe(true);
  });
});
