// Web screen helpers that run without a DOM.

import { describe, expect, it } from "vitest";
import { recheckCounts } from "../web/src/views/recheck.js";

describe("recheck summary bar", () => {
  it("leaves info items out of every count", () => {
    const f = (confidence: "confirmed" | "review" | "info", recheck?: string) => ({ confidence, recheck });
    const findings = [
      f("confirmed", "remaining"),
      f("review", "same_key"),
      f("confirmed", "moved"),
      f("confirmed", "downgraded"),
      f("info", "remaining"),
      f("info", "new"),
      f("confirmed", "new"),
      f("review", "lock_mismatch"),
      f("confirmed", "not_checked"),
      f("info", "not_checked"),
      f("confirmed"), // first scan: no status
    ];
    const resolved = [{ confidence: "confirmed" as const }, { confidence: "info" as const }, {}];
    expect(recheckCounts(findings, resolved)).toEqual({ resolved: 2, remaining: 4, new: 1, check: 2 });
    expect(recheckCounts([], [])).toEqual({ resolved: 0, remaining: 0, new: 0, check: 0 });
  });
});
