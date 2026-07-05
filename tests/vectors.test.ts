import { describe, expect, it } from "vitest";

import { runVectorChecks } from "./protocol-vectors.js";

describe("protocol v1 test vectors (Node)", () => {
  it("recomputes every pinned value", async () => {
    const report = await runVectorChecks(globalThis.crypto.subtle);
    for (const check of report.checks) {
      expect.soft(check.pass, `${check.name}${check.detail ? ` — ${check.detail}` : ""}`).toBe(
        true,
      );
    }
    expect(report.pass).toBe(true);
    expect(report.checks).toHaveLength(8);
  });
});
