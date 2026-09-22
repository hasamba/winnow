// A scan must be idempotent. The judge and sample commands re-scan before they run, so
// "scan then judge" reads the file twice in the normal flow — and an incrementing count made
// jev_dupe_count wrong the moment an analyst did the obvious thing.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DecisionStore } from "../src/triage/store.js";
import { scanTimeline } from "../src/triage/scan.js";
import type { Verdict } from "../src/types.js";

const FIXTURE = fileURLToPath(new URL("./fixtures/fixture.l2t.csv", import.meta.url));

const VERDICT: Verdict = {
  malicious: 0.9,
  category: "execution",
  categoryConfidence: 0.8,
  severity: 3.5,
  severityLevel: "High",
  needsAnalyst: 0.7,
};

let dir: string;
let store: DecisionStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "winnow-rescan-"));
  store = DecisionStore.open(join(dir, "case.sqlite"));
});
afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

async function scan(): Promise<number> {
  const r = await scanTimeline({
    filePath: FIXTURE,
    store,
    questionsHash: "fixed-hash",
    concurrency: 1,
  });
  return r.distinctKeys;
}

describe("re-scanning the same timeline", () => {
  it("counts each entry once, however many times the file is read", async () => {
    await scan();
    const first = store.undecided({}).map((r) => r.occurrences);
    expect(first.some((n) => n > 0)).toBe(true);

    await scan();
    await scan();
    const third = store.undecided({}).map((r) => r.occurrences);

    expect(third).toEqual(first);
  });

  it("keeps the distinct-entry count stable", async () => {
    const a = await scan();
    const b = await scan();
    expect(b).toBe(a);
  });

  it("does not re-buy verdicts that were already paid for", async () => {
    await scan();
    const pending = store.undecided({});
    const target = pending[0];
    expect(target).toBeDefined();
    store.recordVerdict(target!.keyHash, VERDICT);
    expect(store.counts().decided).toBe(1);

    await scan();

    // The verdict survives, and the entry is not offered for judging a second time.
    expect(store.counts().decided).toBe(1);
    expect(store.get(target!.keyHash)?.verdict?.category).toBe("execution");
    expect(store.undecided({}).some((r) => r.keyHash === target!.keyHash)).toBe(false);
  });

  it("restores first-seen times rather than leaving them blank", async () => {
    await scan();
    await scan();
    const stamped = store.undecided({}).filter((r) => r.firstSeenTs !== "");
    expect(stamped.length).toBeGreaterThan(0);
  });
});
