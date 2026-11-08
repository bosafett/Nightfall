import { describe, expect, it } from "vitest";
import { parseError } from "@/lib/api/errors";
import { formatDateTime, formatRelative, groupSecret } from "@/lib/format";
import { can, mfaRequired } from "@/lib/labels";
import { NAV, NAV_GROUPS, isActive, isPlanned } from "@/lib/nav";
import { initialsOf } from "@/components/shell/UserMenu";

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
  it("groups pages into the Addendum 5 divisions", () => {
    expect(NAV_GROUPS.map((g) => g.label)).toEqual([null, "SWORD", "SHIELD", "JANUS CORE", "SYSTEM"]);
    expect(NAV.map((n) => n.label)).toEqual([
      "Command Center", "Target Registry", "Reconnaissance", "BLACKSITE", "Attack Graph", "Findings", "Reports",
      "AEGIS Overview", "Monitoring", "Alerts & Detection", "BLACK BOX", "NEXUS",
      "Agents", "War Room", "Audit Log", "Settings",
    ]);
  });
  it("never links an unbuilt module", () => {
    const shield = NAV_GROUPS.find((g) => g.key === "shield")!;
    // SHIELD v1: overview, monitoring and alerts are built; the rest stay labels.
    expect(shield.items.filter((i) => !isPlanned(i)).map((i) => i.key)).toEqual(["aegis", "monitoring", "alerts"]);
    expect(NAV.some((n) => ["warpath", "hunting", "countermeasures", "incidents", "recovery"].includes(n.key))).toBe(false);
    expect(new Set(NAV.map((n) => n.href("w"))).size).toBe(NAV.length);
  });
  it("marks only BLACKSITE as restricted", () => {
    expect(NAV.filter((n) => n.restricted).map((n) => n.key)).toEqual(["blacksite"]);
  });
  it("marks the active section", () => {
    const targets = NAV.find((n) => n.key === "targets")!;
    expect(isActive(targets, "w1", "/w/w1/targets/abc")).toBe(true);
    expect(isActive(NAV[0]!, "w1", "/w/w1/targets")).toBe(false);
    expect(isActive(NAV[0]!, "w1", "/w/w1")).toBe(true);
  });
});

describe("initialsOf", () => {
  it("uses letters and digits only", () => {
    expect(initialsOf("Nick (preview)")).toBe("NP");
    expect(initialsOf("ana lyst")).toBe("AL");
    expect(initialsOf("Émile Zola")).toBe("ÉZ");
    expect(initialsOf("(  )")).toBe("?");
  });
});
