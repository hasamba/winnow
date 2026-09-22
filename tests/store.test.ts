import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { JevState, TimelineRow, Verdict } from "../src/types.js";
import { decisionKey, jevStateFrom } from "../src/triage/key.js";
import { DecisionStore } from "../src/triage/store.js";

const QH = "questions-hash";

let dir: string;
let dbPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "triage-store-"));
  dbPath = join(dir, "decisions.sqlite");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function row(over: Partial<TimelineRow> = {}): TimelineRow {
  const base: TimelineRow = {
    rowNo: 1,
    timestamp: "2026-01-01T00:00:00Z",
    message: "a message",
    source: "LOG",
    timestampDesc: "Content Modification Time",
    path: "",
    host: "",
    raw: {},
  };
  return { ...base, ...over };
}

function verdict(over: Partial<Verdict> = {}): Verdict {
  return {
    malicious: 0.9,
    category: "execution",
    categoryConfidence: 0.8,
    severity: 3.4,
    severityLevel: "High",
    needsAnalyst: 0.7,
    ...over,
  };
}

/** Observe `n` distinct keys once each; returns their key hashes in seed order. */
function seed(store: DecisionStore, n: number): string[] {
  const hashes: string[] = [];
  store.transaction(() => {
    for (let i = 0; i < n; i += 1) {
      const r = row({ message: `event ${i}` });
      const key = decisionKey(r, QH);
      store.observe(key, jevStateFrom(r), `2026-01-0${(i % 9) + 1}T00:00:00Z`);
      hashes.push(key.keyHash);
    }
  });
  return hashes;
}

describe("observe", () => {
  it("keeps two rows that differ only by an IP address apart", () => {
    const store = DecisionStore.open(dbPath);
    const a = row({ message: "Connection to 192.0.2.5" });
    const b = row({ message: "Connection to 192.0.2.77" });
    store.observe(decisionKey(a, QH), jevStateFrom(a), a.timestamp);
    store.observe(decisionKey(b, QH), jevStateFrom(b), b.timestamp);

    expect(store.counts().total).toBe(2);
    store.close();
  });

  it("collapses a MACB expansion to one key with occurrences 4 and the earliest first_seen_ts", () => {
    const store = DecisionStore.open(dbPath);
    const timestamps = [
      "2026-03-03T00:00:00Z",
      "2026-01-01T00:00:00Z",
      "2026-02-02T00:00:00Z",
      "2026-04-04T00:00:00Z",
    ];
    for (const timestamp of timestamps) {
      const r = row({ timestamp, message: "$MFT entry for C:\\Users\\a\\note.txt" });
      store.observe(decisionKey(r, QH), jevStateFrom(r), timestamp);
    }

    expect(store.counts().total).toBe(1);
    const only = store.undecided()[0];
    expect(only?.occurrences).toBe(4);
    expect(only?.firstSeenTs).toBe("2026-01-01T00:00:00Z");
    store.close();
  });

  it("does not let an empty timestamp overwrite a real first_seen_ts", () => {
    const store = DecisionStore.open(dbPath);
    const r = row();
    const key = decisionKey(r, QH);
    store.observe(key, jevStateFrom(r), "");
    store.observe(key, jevStateFrom(r), "2026-05-05T00:00:00Z");
    store.observe(key, jevStateFrom(r), "");

    const rec = store.get(key.keyHash);
    expect(rec?.occurrences).toBe(3);
    expect(rec?.firstSeenTs).toBe("2026-05-05T00:00:00Z");
    store.close();
  });

  it("stores the sample state so the judge can send Jev a structured record", () => {
    const store = DecisionStore.open(dbPath);
    const r = row({ path: "C:\\Windows\\Temp\\a.ps1", host: "WS01" });
    const key = decisionKey(r, QH);
    store.observe(key, jevStateFrom(r), r.timestamp);

    const sample = store.get(key.keyHash)?.sample as JevState;
    expect(sample.path).toBe("C:\\Windows\\Temp\\a.ps1");
    expect(sample.host).toBe("WS01");
    store.close();
  });
});

describe("resumability", () => {
  it("returns only the undecided keys after reopening a half-finished run", () => {
    const first = DecisionStore.open(dbPath);
    const hashes = seed(first, 10);
    const decided = hashes.slice(0, 4);
    decided.forEach((h, i) => first.recordVerdict(h, verdict({ malicious: 0.1 * i })));
    first.close();

    const second = DecisionStore.open(dbPath);
    const pending = second.undecided().map((r) => r.keyHash);
    expect(pending.sort()).toEqual(hashes.slice(4).sort());
    expect(pending).toHaveLength(6);

    // Re-judging the pending rows leaves the already-decided four untouched.
    for (const h of pending) second.recordVerdict(h, verdict({ category: "later" }));
    decided.forEach((h, i) => {
      const rec = second.get(h);
      expect(rec?.verdict?.category).toBe("execution");
      expect(rec?.verdict?.malicious).toBeCloseTo(0.1 * i);
    });
    expect(second.undecided()).toHaveLength(0);
    second.close();
  });

  it("round-trips every verdict field", () => {
    const store = DecisionStore.open(dbPath);
    const [h] = seed(store, 1);
    const v = verdict({ malicious: 0.42, severity: 2.5, severityLevel: "Medium" });
    store.recordVerdict(h as string, v);

    expect(store.get(h as string)?.verdict).toEqual(v);
    expect(store.get(h as string)?.decidedAt).toMatch(/^\d{4}-/);
    store.close();
  });

  it("returns undefined for an unknown key hash", () => {
    const store = DecisionStore.open(dbPath);
    expect(store.get("nope")).toBeUndefined();
    store.close();
  });
});

describe("errors", () => {
  it("includes an errored row by default and excludes it with retryErrors false", () => {
    const store = DecisionStore.open(dbPath);
    const hashes = seed(store, 3);
    store.recordVerdict(hashes[0] as string, verdict());
    store.recordError(hashes[1] as string, "429 rate limited");

    const withRetry = store.undecided().map((r) => r.keyHash);
    expect(withRetry.sort()).toEqual([hashes[1], hashes[2]].sort());

    const withoutRetry = store.undecided({ retryErrors: false }).map((r) => r.keyHash);
    expect(withoutRetry).toEqual([hashes[2]]);

    const errored = store.get(hashes[1] as string);
    expect(errored?.error).toBe("429 rate limited");
    expect(errored?.verdict).toBeUndefined();
    store.close();
  });

  it("clears the error when the retry succeeds", () => {
    const store = DecisionStore.open(dbPath);
    const [h] = seed(store, 1);
    store.recordError(h as string, "timeout");
    store.recordVerdict(h as string, verdict());

    const rec = store.get(h as string);
    expect(rec?.error).toBeUndefined();
    expect(rec?.verdict?.category).toBe("execution");
    expect(store.undecided()).toHaveLength(0);
    store.close();
  });
});

describe("undecided ordering", () => {
  it("returns the lowest-occurrence key first with rareFirst", () => {
    const store = DecisionStore.open(dbPath);
    const common = row({ message: "seen a lot" });
    const rare = row({ message: "seen once" });
    const middling = row({ message: "seen twice" });
    const commonKey = decisionKey(common, QH);
    const rareKey = decisionKey(rare, QH);
    const middlingKey = decisionKey(middling, QH);

    for (let i = 0; i < 5; i += 1) {
      store.observe(commonKey, jevStateFrom(common), common.timestamp);
    }
    store.observe(rareKey, jevStateFrom(rare), rare.timestamp);
    store.observe(middlingKey, jevStateFrom(middling), middling.timestamp);
    store.observe(middlingKey, jevStateFrom(middling), middling.timestamp);

    const order = store.undecided({ rareFirst: true }).map((r) => r.keyHash);
    expect(order).toEqual([rareKey.keyHash, middlingKey.keyHash, commonKey.keyHash]);

    // The default order is insertion order, not rarity.
    expect(store.undecided().map((r) => r.keyHash)).toEqual([
      commonKey.keyHash,
      rareKey.keyHash,
      middlingKey.keyHash,
    ]);
    store.close();
  });

  it("honours limit", () => {
    const store = DecisionStore.open(dbPath);
    seed(store, 10);
    expect(store.undecided({ limit: 3 })).toHaveLength(3);
    store.close();
  });
});

describe("counts and stats", () => {
  it("counts total, decided, errored and malicious rows", () => {
    const store = DecisionStore.open(dbPath);
    const hashes = seed(store, 5);
    store.recordVerdict(hashes[0] as string, verdict({ malicious: 0.9 }));
    store.recordVerdict(hashes[1] as string, verdict({ malicious: 0.35 }));
    store.recordVerdict(hashes[2] as string, verdict({ malicious: 0.34 }));
    store.recordError(hashes[3] as string, "boom");

    expect(store.counts()).toEqual({
      total: 5,
      decided: 3,
      errored: 1,
      malicious: 2,
    });
    store.close();
  });

  it("reports the category distribution and the highest-scoring rows", () => {
    const store = DecisionStore.open(dbPath);
    const hashes = seed(store, 4);
    store.recordVerdict(hashes[0] as string, verdict({ malicious: 0.2, category: "noise" }));
    store.recordVerdict(hashes[1] as string, verdict({ malicious: 0.95, category: "execution" }));
    store.recordVerdict(hashes[2] as string, verdict({ malicious: 0.8, category: "execution" }));
    store.recordVerdict(hashes[3] as string, verdict({ malicious: 0.5, category: "persistence" }));

    const stats = store.stats(2);
    expect(stats.distribution).toEqual({ execution: 2, noise: 1, persistence: 1 });
    expect(stats.topMalicious.map((r) => r.keyHash)).toEqual([hashes[1], hashes[2]]);
    expect(stats.topMalicious[0]?.verdict?.malicious).toBeCloseTo(0.95);
    store.close();
  });

  it("stats(0) still returns the whole distribution (cli.ts asks for exactly that)", () => {
    const store = DecisionStore.open(dbPath);
    const hashes = seed(store, 2);
    store.recordVerdict(hashes[0] as string, verdict({ category: "execution" }));
    store.recordVerdict(hashes[1] as string, verdict({ category: "noise" }));

    const stats = store.stats(0);
    expect(stats.distribution).toEqual({ execution: 1, noise: 1 });
    expect(stats.topMalicious).toEqual([]);
    store.close();
  });

  it("verdictLookup holds every decided key, errors included, and no undecided one", () => {
    const store = DecisionStore.open(dbPath);
    const hashes = seed(store, 4);
    store.recordVerdict(hashes[0] as string, verdict());
    store.recordVerdict(hashes[1] as string, verdict());
    store.recordError(hashes[2] as string, "boom");

    const lookup = store.verdictLookup();
    expect(lookup.size).toBe(3);
    expect(lookup.get(hashes[0] as string)?.verdict?.category).toBe("execution");

    // An errored key belongs in the lookup precisely because it has no verdict. Leave it out
    // and the exporter sees nothing for that row, printing it as `unjudged` — which claims the
    // key was never sent. The analyst must be able to tell a failed call from an unasked one.
    const errored = lookup.get(hashes[2] as string);
    expect(errored).toBeDefined();
    expect(errored?.verdict).toBeUndefined();
    expect(errored?.error).toBe("boom");

    expect(lookup.has(hashes[3] as string)).toBe(false);
    store.close();
  });
});

describe("meta", () => {
  it("stores and reads values, and survives a reopen", () => {
    const store = DecisionStore.open(dbPath);
    expect(store.meta.get("questions_hash")).toBeUndefined();
    store.meta.set("questions_hash", QH);
    store.meta.set("source_sha256", "abc123");
    store.meta.set("source_sha256", "def456");
    store.close();

    const reopened = DecisionStore.open(dbPath);
    expect(reopened.meta.get("questions_hash")).toBe(QH);
    expect(reopened.meta.get("source_sha256")).toBe("def456");
    expect(reopened.meta.get("schema_version")).toBe("1");
    reopened.close();
  });
});

describe("transaction", () => {
  it("returns the callback result and rolls back on a throw", () => {
    const store = DecisionStore.open(dbPath);
    expect(store.transaction(() => seed(store, 2).length)).toBe(2);

    expect(() =>
      store.transaction(() => {
        seed(store, 3);
        throw new Error("abort");
      }),
    ).toThrow("abort");

    expect(store.counts().total).toBe(2);
    store.close();
  });
});
