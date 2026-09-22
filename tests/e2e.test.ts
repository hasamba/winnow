// The whole pipeline over a real fixture, with no network anywhere: scan the timeline into
// the decision cache, seed verdicts the way a Jev run would have, export, and read the CSV
// back. This is the test that catches a seam breaking between two modules.

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DecisionStore } from "../src/triage/store.js";
import { scanTimeline, readHeaders } from "../src/triage/scan.js";
import { readTimeline } from "../src/plaso/flavor.js";
import { decisionKey, hashQuestions } from "../src/triage/key.js";
import { exportMalicious } from "../src/export/csv.js";
import { parseCsvRecords } from "../src/plaso/csvRead.js";
import { DEFAULT_THRESHOLDS, type Verdict } from "../src/types.js";

const FIXTURES = fileURLToPath(new URL("./fixtures/", import.meta.url));
const QUESTIONS_HASH = hashQuestions('{"malicious":{"type":"noul"}}');

/**
 * Stands in for Jev. Keyword matching, not intelligence — the point is a deterministic
 * verdict per row so the plumbing can be asserted without a model in the loop.
 */
const MALICIOUS_MARKERS = [
  "mimikatz",
  "sekurlsa",
  "wevtutil",
  "audit log was cleared",
  "log file was cleared",
  "minidump",
  "lsass.dmp",
  "downloadstring",
  "windows\\temp\\update_check.ps1",
  "windows/temp/update_check.ps1",
  "scheduled task was created",
  "schtasks",
  "gate.php",
  "onedrivesync",
  "was added to a security-enabled local group",
  "user account was created",
];

function fakeVerdict(keyText: string): Verdict {
  const hay = keyText.toLowerCase();
  const hit = MALICIOUS_MARKERS.some((m) => hay.includes(m));
  return {
    malicious: hit ? 0.92 : 0.04,
    category: hit ? "execution" : "benign_system",
    categoryConfidence: 0.8,
    severity: hit ? 3.6 : 0.2,
    severityLevel: hit ? "High" : "Informational",
    needsAnalyst: hit ? 0.9 : 0.05,
  };
}

let dir: string;
let opened: DecisionStore[];

/**
 * Open a store and remember it, so afterEach can close it. Windows refuses to unlink a file
 * that still has an open handle, so a store left open fails the temp-directory cleanup with
 * EBUSY — a failure that never appears on Linux, where unlink succeeds regardless.
 */
function openStore(name: string): DecisionStore {
  const store = DecisionStore.open(join(dir, name));
  opened.push(store);
  return store;
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "triage-e2e-"));
  opened = [];
});
afterEach(() => {
  for (const store of opened) {
    try {
      store.close();
    } catch {
      // Already closed by the test itself; nothing to do.
    }
  }
  rmSync(dir, { recursive: true, force: true });
});

describe.each([
  ["l2tcsv", "fixture.l2t.csv"],
  ["dynamic", "fixture.dynamic.csv"],
])("%s end to end", (flavor, fixture) => {
  const source = join(FIXTURES, fixture);

  it("scans, judges, exports and round-trips", async () => {
    const store = openStore("case.sqlite");

    const report = await scanTimeline({
      filePath: source,
      store,
      questionsHash: QUESTIONS_HASH,
      concurrency: 16,
    });

    expect(report.flavor).toBe(flavor);
    expect(report.totalRows).toBeGreaterThan(20);
    expect(report.distinctKeys).toBeGreaterThan(0);
    expect(report.distinctKeys).toBeLessThanOrEqual(report.totalRows);
    expect(report.earliest).not.toBe("");
    expect(report.earliest <= report.latest).toBe(true);
    expect(report.estimatedCostUsd).toBeCloseTo(report.undecidedKeys * 0.00003, 10);

    // Judge every distinct entry the way a real run would, one verdict at a time.
    for (const record of store.undecided({})) {
      store.recordVerdict(record.keyHash, fakeVerdict(record.keyText));
    }
    expect(store.counts().decided).toBe(report.distinctKeys);

    const headers = await readHeaders(source);
    const lookup = store.verdictLookup();
    const outPath = join(dir, "out.malicious.csv");

    const result = await exportMalicious({
      rows: readTimeline(source),
      lookup: (row) => lookup.get(decisionKey(row, QUESTIONS_HASH).keyHash),
      headers,
      outPath,
      thresholds: DEFAULT_THRESHOLDS,
    });

    expect(result.scanned).toBe(report.totalRows);
    expect(result.written).toBeGreaterThan(0);
    expect(result.written).toBeLessThan(result.scanned); // benign rows were left out
    expect(result.unjudged).toBe(0);

    const records = [...parseCsvRecords(readFileSync(outPath, "utf8"))];
    const outHeader = records[0];
    expect(outHeader).toBeDefined();

    // Every original column survives, in order, and exactly six are appended.
    expect(outHeader!.slice(0, headers.length)).toEqual(headers);
    expect(outHeader!.slice(headers.length)).toEqual([
      "jev_malicious",
      "jev_confidence",
      "jev_category",
      "jev_severity",
      "jev_needs_analyst",
      "jev_dupe_count",
    ]);

    // Every data row has exactly the header's width — no column drift from a ragged row.
    const dataRows = records.slice(1);
    expect(dataRows.length).toBe(result.written);
    for (const r of dataRows) expect(r.length).toBe(outHeader!.length);

    const body = readFileSync(outPath, "utf8").toLowerCase();
    expect(body).toContain("mimikatz");
    expect(body).toContain("wevtutil");
    expect(body).not.toContain("notepad.exe");
  });

  it("collapses only identical text, and never merges two different addresses", async () => {
    const store = openStore("keys.sqlite");
    await scanTimeline({ filePath: source, store, questionsHash: QUESTIONS_HASH, concurrency: 1 });

    const texts = store.undecided({}).map((r) => r.keyText);
    expect(new Set(texts).size).toBe(texts.length);

    // Two entries differing only by an octet must remain two decisions. Companion's own
    // aggregation key would have collapsed them; this tool deliberately does not.
    const addressed = texts.filter((t) => /\b(192\.0\.2|198\.51\.100)\.\d+/.test(t));
    if (addressed.length > 1) {
      expect(new Set(addressed).size).toBe(addressed.length);
    }
  });

  it("resumes without re-judging what it already decided", async () => {
    const first = openStore("resume.sqlite");
    await scanTimeline({ filePath: source, store: first, questionsHash: QUESTIONS_HASH, concurrency: 1 });

    const all = first.undecided({});
    const half = Math.floor(all.length / 2);
    for (const record of all.slice(0, half)) {
      first.recordVerdict(record.keyHash, fakeVerdict(record.keyText));
    }
    first.close();

    const second = openStore("resume.sqlite");
    expect(second.undecided({}).length).toBe(all.length - half);
    expect(second.counts().decided).toBe(half);
    second.close();
  });

  it("keeps a row it could not judge, flagged rather than dropped", async () => {
    const store = openStore("errors.sqlite");
    await scanTimeline({ filePath: source, store, questionsHash: QUESTIONS_HASH, concurrency: 1 });

    const pending = store.undecided({});
    const doomed = pending[0]!;
    store.recordError(doomed.keyHash, "HTTP 500: upstream exploded");
    for (const record of pending.slice(1)) {
      store.recordVerdict(record.keyHash, fakeVerdict(record.keyText));
    }

    const headers = await readHeaders(source);
    const lookup = store.verdictLookup();
    const outPath = join(dir, "errors.malicious.csv");
    const result = await exportMalicious({
      rows: readTimeline(source),
      lookup: (row) => lookup.get(decisionKey(row, QUESTIONS_HASH).keyHash),
      headers,
      outPath,
      thresholds: DEFAULT_THRESHOLDS,
    });

    const text = readFileSync(outPath, "utf8");
    expect(text).toContain("error");
    expect(result.written).toBeGreaterThan(0);
  });
});
