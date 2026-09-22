import { afterEach, beforeEach, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { decisionKey, jevStateFrom } from "../src/triage/key.js";
import { DecisionStore } from "../src/triage/store.js";
import { queryRows } from "../src/server/rows.js";
import type { TimelineRow, Verdict } from "../src/types.js";

const QH = "questions-hash";

let dir: string;
let store: DecisionStore;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "winnow-rows-"));
  store = DecisionStore.open(join(dir, "decisions.sqlite"));
});

afterEach(() => {
  store.close();
  rmSync(dir, { recursive: true, force: true });
});

function row(over: Partial<TimelineRow> = {}): TimelineRow {
  return {
    rowNo: 1,
    timestamp: "2026-01-01T00:00:00Z",
    message: "a message",
    source: "LOG",
    timestampDesc: "Content Modification Time",
    path: "",
    host: "",
    raw: {},
    ...over,
  };
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

/** Observe one key `times` times at `ts`, and return its hash. */
function observe(over: Partial<TimelineRow>, ts: string, times = 1): string {
  const r = row(over);
  const key = decisionKey(r, QH);
  store.transaction(() => {
    for (let i = 0; i < times; i += 1) store.observe(key, jevStateFrom(r), ts);
  });
  return key.keyHash;
}

/** Four judged keys, one errored key and one undecided key. */
function seed(): Record<string, string> {
  const high = observe({ message: "psexec ran" }, "2026-03-04T00:00:00Z", 2);
  const mid = observe({ message: "schtasks created" }, "2026-03-02T00:00:00Z", 9);
  const low = observe({ message: "notepad opened" }, "2026-03-03T00:00:00Z", 5);
  const percent = observe({ message: "cpu at 100% for an hour" }, "2026-03-05T00:00:00Z", 1);
  const literal = observe({ message: "cpu at 100 percent for an hour" }, "2026-03-06T00:00:00Z", 1);
  const failed = observe({ message: "a call that failed" }, "2026-03-01T00:00:00Z", 3);
  const undecided = observe({ message: "never asked" }, "2026-03-07T00:00:00Z", 4);

  store.recordVerdict(high, verdict({ malicious: 0.95, category: "execution" }));
  store.recordVerdict(mid, verdict({ malicious: 0.5, category: "persistence" }));
  store.recordVerdict(low, verdict({ malicious: 0.05, category: "benign" }));
  store.recordVerdict(percent, verdict({ malicious: 0.4, category: "benign" }));
  store.recordVerdict(literal, verdict({ malicious: 0.4, category: "benign" }));
  store.recordError(failed, "429 from the API");
  return { high, mid, low, percent, literal, failed, undecided };
}

it("leaves undecided rows out by default, and keeps errored ones", () => {
  const keys = seed();
  const page = queryRows(store, {});
  const hashes = page.rows.map((r) => r.keyHash);
  expect(hashes).toContain(keys.failed);
  expect(hashes).not.toContain(keys.undecided);
  expect(page.total).toBe(6);
});

it("includes undecided rows when asked", () => {
  const keys = seed();
  const page = queryRows(store, { includeUndecided: true });
  expect(page.rows.map((r) => r.keyHash)).toContain(keys.undecided);
  expect(page.total).toBe(7);
});

it("sorts by malicious descending with nulls last", () => {
  seed();
  const page = queryRows(store, {});
  const scores = page.rows.map((r) => r.malicious);
  expect(scores.slice(0, 5)).toEqual([0.95, 0.5, 0.4, 0.4, 0.05]);
  expect(scores[5]).toBeUndefined();
});

it("sorts by occurrences and by first seen time", () => {
  seed();
  expect(queryRows(store, { sort: "occurrences" }).rows.map((r) => r.occurrences)).toEqual([
    9, 5, 3, 2, 1, 1,
  ]);
  expect(queryRows(store, { sort: "time" }).rows.map((r) => r.firstSeenTs)[0]).toBe(
    "2026-03-01T00:00:00Z",
  );
});

it("filters on a minimum malicious score and on an exact category", () => {
  seed();
  expect(queryRows(store, { min: 0.5 }).total).toBe(2);
  expect(queryRows(store, { category: "benign" }).total).toBe(3);
  expect(queryRows(store, { category: "beni" }).total).toBe(0);
});

it("matches a percent sign in the search text literally", () => {
  const keys = seed();
  const page = queryRows(store, { q: "100%" });
  expect(page.rows.map((r) => r.keyHash)).toEqual([keys.percent]);
  expect(queryRows(store, { q: "100" }).total).toBe(2);
});

it("matches an underscore in the search text literally", () => {
  observe({ message: "a_b" }, "2026-03-08T00:00:00Z");
  const other = observe({ message: "axb" }, "2026-03-09T00:00:00Z");
  store.recordVerdict(other, verdict());
  store.recordVerdict(decisionKey(row({ message: "a_b" }), QH).keyHash, verdict());
  const page = queryRows(store, { q: "a_b" });
  expect(page.total).toBe(1);
});

it("pages with a total counted before the limit", () => {
  seed();
  const first = queryRows(store, { limit: 2 });
  expect(first.rows).toHaveLength(2);
  expect(first.total).toBe(6);
  const second = queryRows(store, { limit: 2, offset: 2 });
  expect(second.rows).toHaveLength(2);
  expect(second.total).toBe(6);
  expect(second.rows.map((r) => r.keyHash)).not.toEqual(first.rows.map((r) => r.keyHash));
});

it("caps the limit at 1000 however large a limit is asked for", () => {
  store.transaction(() => {
    for (let i = 0; i < 1100; i += 1) {
      const r = row({ message: `event ${i}` });
      const key = decisionKey(r, QH);
      store.observe(key, jevStateFrom(r), "2026-03-01T00:00:00Z");
      store.recordVerdict(key.keyHash, verdict({ malicious: i / 1100 }));
    }
  });
  const page = queryRows(store, { limit: 5000 });
  expect(page.rows).toHaveLength(1000);
  expect(page.total).toBe(1100);
});

it("splits the decision key into its source, timestamp description and message", () => {
  const hash = observe(
    { message: "psexec ran", source: "LOG", timestampDesc: "Last Access Time" },
    "2026-03-04T00:00:00Z",
  );
  store.recordVerdict(hash, verdict());
  const first = queryRows(store, {}).rows[0];
  expect(first).toBeDefined();
  expect(first?.source).toBe("LOG");
  expect(first?.timestampDesc).toBe("Last Access Time");
  expect(first?.text).toBe("psexec ran");
  expect(first?.text).not.toContain("\x1f");
});

it("reports an errored row with its message and no verdict", () => {
  const keys = seed();
  const page = queryRows(store, { includeUndecided: true });
  const failed = page.rows.find((r) => r.keyHash === keys.failed);
  expect(failed?.error).toBe("429 from the API");
  expect(failed?.malicious).toBeUndefined();
  expect(failed?.category).toBeUndefined();
});
