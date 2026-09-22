import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  cell,
  exportMalicious,
  row,
  shouldInclude,
  verdictCells,
  VERDICT_COLUMNS,
} from "../src/export/csv.js";
import {
  DEFAULT_THRESHOLDS,
  type DecisionRecord,
  type RawRow,
  type Thresholds,
  type TimelineRow,
  type Verdict,
} from "../src/types.js";

const dirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tt-export-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  while (dirs.length > 0) {
    const dir = dirs.pop();
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  }
});

/** A minimal RFC 4180 reader, so the tests parse the output instead of trusting it. */
function parseCsv(text: string): string[][] {
  const records: string[][] = [];
  let record: string[] = [];
  let field = "";
  let quoted = false;
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        quoted = false;
        i += 1;
        continue;
      }
      field += ch;
      i += 1;
      continue;
    }
    if (ch === '"') {
      quoted = true;
      i += 1;
      continue;
    }
    if (ch === ",") {
      record.push(field);
      field = "";
      i += 1;
      continue;
    }
    if (ch === "\n") {
      record.push(field);
      records.push(record);
      record = [];
      field = "";
      i += 1;
      continue;
    }
    field += ch;
    i += 1;
  }
  if (field !== "" || record.length > 0) {
    record.push(field);
    records.push(record);
  }
  return records;
}

function verdict(over: Partial<Verdict> = {}): Verdict {
  return {
    malicious: 0.01,
    category: "benign_noise",
    categoryConfidence: 0.9,
    severity: 0.2,
    severityLevel: "Info",
    needsAnalyst: 0.05,
    ...over,
  };
}

function record(over: Partial<DecisionRecord> = {}): DecisionRecord {
  const base: DecisionRecord = {
    keyHash: "a".repeat(64),
    keyText: "LOG\x1fmtime\x1fa message",
    occurrences: 3,
    firstSeenTs: "2026-01-01T00:00:00Z",
    sample: { source: "LOG", timestamp_desc: "mtime", message: "a message" },
    verdict: verdict(),
  };
  return { ...base, ...over };
}

function errored(): DecisionRecord {
  const { verdict: _unused, ...rest } = record();
  return { ...rest, error: "HTTP 429 after 5 retries" };
}

function timelineRow(rowNo: number, raw: RawRow): TimelineRow {
  return {
    rowNo,
    timestamp: "2026-01-01T00:00:00Z",
    message: String(raw["message"] ?? ""),
    source: String(raw["source_long"] ?? ""),
    timestampDesc: String(raw["timestamp_desc"] ?? ""),
    path: "",
    host: "",
    raw,
  };
}

describe("cell", () => {
  it("guards a formula that starts with '='", () => {
    expect(cell(`=cmd|'/c calc'!A1`)).toBe(`"'=cmd|'/c calc'!A1"`);
  });

  it.each([
    ["+", "+1+1"],
    ["-", "-2+3"],
    ["@", "@SUM(A1)"],
    ["tab", "\tlead"],
    ["carriage return", "\rlead"],
  ])("guards a value starting with a %s", (_label, value) => {
    expect(cell(value)).toBe(`"'${value}"`);
  });

  it("leaves an ordinary value unguarded but still quoted", () => {
    expect(cell("C:\\Windows\\Temp\\a.ps1")).toBe(`"C:\\Windows\\Temp\\a.ps1"`);
  });

  it("doubles an embedded double quote", () => {
    expect(cell(`he said "run this"`)).toBe(`"he said ""run this"""`);
  });

  it("survives a round trip when the value contains a newline", () => {
    const value = 'line one\nline two with a " quote';
    const parsed = parseCsv(row([value, "after"]) + "\n");
    expect(parsed).toHaveLength(1);
    expect(parsed[0]).toEqual([value, "after"]);
  });

  it("keeps the fields apart when a value contains a comma", () => {
    const parsed = parseCsv(row(["a,b", "c"]) + "\n");
    expect(parsed[0]).toEqual(["a,b", "c"]);
  });
});

describe("shouldInclude", () => {
  const t: Thresholds = DEFAULT_THRESHOLDS;

  it("includes a row exactly at the malicious threshold", () => {
    expect(shouldInclude(record({ verdict: verdict({ malicious: 0.35 }) }), t)).toBe(true);
  });

  it("excludes a row just below the malicious threshold", () => {
    expect(shouldInclude(record({ verdict: verdict({ malicious: 0.3499 }) }), t)).toBe(false);
  });

  it("includes a needs-analyst-only row", () => {
    expect(
      shouldInclude(record({ verdict: verdict({ malicious: 0.02, needsAnalyst: 0.6 }) }), t),
    ).toBe(true);
  });

  it("excludes a row just below the needs-analyst threshold", () => {
    expect(
      shouldInclude(record({ verdict: verdict({ malicious: 0.02, needsAnalyst: 0.5999 }) }), t),
    ).toBe(false);
  });

  it("includes an errored record, because a row the tool failed to judge is not evidence to drop", () => {
    expect(shouldInclude(errored(), t)).toBe(true);
  });

  it("includes an unjudged row", () => {
    expect(shouldInclude(undefined, t)).toBe(true);
  });

  it("honours a custom threshold set", () => {
    const strict: Thresholds = { malicious: 0.9, needsAnalyst: 0.95, confident: 0.99 };
    expect(shouldInclude(record({ verdict: verdict({ malicious: 0.5 }) }), strict)).toBe(false);
    expect(shouldInclude(record({ verdict: verdict({ malicious: 0.9 }) }), strict)).toBe(true);
  });
});

describe("verdictCells", () => {
  const t = DEFAULT_THRESHOLDS;

  it("has one value per declared column", () => {
    expect(VERDICT_COLUMNS).toHaveLength(6);
    expect(VERDICT_COLUMNS).toEqual([
      "jev_malicious",
      "jev_confidence",
      "jev_category",
      "jev_severity",
      "jev_needs_analyst",
      "jev_dupe_count",
    ]);
  });

  it("returns 6 values for a judged record", () => {
    const cells = verdictCells(
      record({
        verdict: verdict({
          malicious: 0.8125,
          category: "lateral_movement",
          severity: 3.4,
          severityLevel: "High",
          needsAnalyst: 0.5,
        }),
      }),
      t,
    );
    expect(cells).toHaveLength(6);
    expect(cells[0]).toBe("0.813");
    expect(cells[1]).toBe("confident");
    expect(cells[2]).toBe("lateral_movement");
    expect(cells[3]).toBe("High (3.4)");
    expect(cells[5]).toBe("3");
  });

  it("returns 6 values for an unjudged row and says so", () => {
    const cells = verdictCells(undefined, t);
    expect(cells).toHaveLength(6);
    expect(cells[0]).toBe("");
    expect(cells[1]).toBe("unjudged");
  });

  it("returns 6 values for an errored record and says so", () => {
    const cells = verdictCells(errored(), t);
    expect(cells).toHaveLength(6);
    expect(cells[0]).toBe("");
    expect(cells[1]).toBe("error");
    expect(cells[5]).toBe("3");
  });

  it("calls a verdict below the confident threshold uncertain", () => {
    const cells = verdictCells(record({ verdict: verdict({ malicious: 0.4 }) }), t);
    expect(cells[1]).toBe("uncertain");
  });

  it("calls a verdict at the confident threshold confident", () => {
    const cells = verdictCells(
      record({ verdict: verdict({ malicious: DEFAULT_THRESHOLDS.confident }) }),
      t,
    );
    expect(cells[1]).toBe("confident");
  });
});

const HEADERS = [
  "datetime",
  "timestamp_desc",
  "source",
  "source_long",
  "message",
  "parser",
  "display_name",
  "tag",
] as const;

function fixtureRows(): TimelineRow[] {
  const rows: TimelineRow[] = [];
  for (let n = 1; n <= 20; n += 1) {
    rows.push(
      timelineRow(n, {
        datetime: "2026-01-0" + ((n % 9) + 1) + "T00:00:00+00:00",
        timestamp_desc: "Content Modification Time",
        source: "LOG",
        source_long: "System log",
        message: `row ${n} message`,
        parser: "winevtx",
        display_name: "OS:/var/log/x",
        tag: "",
      }),
    );
  }
  return rows;
}

async function* iterate(rows: readonly TimelineRow[]): AsyncIterable<TimelineRow> {
  for (const r of rows) yield r;
}

/**
 * rows 1-4, 13-16, 19-20 benign; 5-8 malicious; 9-12 needs-analyst only;
 * 17 errored; 18 has no record at all.
 */
function lookupFor(r: TimelineRow): DecisionRecord | undefined {
  const n = r.rowNo;
  if (n === 18) return undefined;
  if (n === 17) return errored();
  if (n >= 5 && n <= 8) {
    return record({
      verdict: verdict({
        malicious: 0.92,
        category: "execution",
        severity: 3.4,
        severityLevel: "High",
        needsAnalyst: 0.8,
      }),
    });
  }
  if (n >= 9 && n <= 12) {
    return record({ verdict: verdict({ malicious: 0.1, needsAnalyst: 0.7 }) });
  }
  return record();
}

describe("exportMalicious", () => {
  it("writes the original headers first, then exactly the six appended columns", async () => {
    const outPath = join(tempDir(), "malicious.csv");
    await exportMalicious({
      rows: iterate(fixtureRows()),
      lookup: lookupFor,
      headers: HEADERS,
      outPath,
    });
    const parsed = parseCsv(readFileSync(outPath, "utf8"));
    const header = parsed[0];
    expect(header).toBeDefined();
    expect(header).toHaveLength(14);
    expect(header?.slice(0, 8)).toEqual([...HEADERS]);
    expect(header?.slice(8)).toEqual([...VERDICT_COLUMNS]);
  });

  it("emits 14 cells for a row with 8 original columns, and returns the right counts", async () => {
    const outPath = join(tempDir(), "malicious.csv");
    const counts = await exportMalicious({
      rows: iterate(fixtureRows()),
      lookup: lookupFor,
      headers: HEADERS,
      outPath,
    });
    expect(counts).toEqual({ written: 10, scanned: 20, unjudged: 2 });

    const parsed = parseCsv(readFileSync(outPath, "utf8"));
    expect(parsed).toHaveLength(11);
    for (const line of parsed) expect(line).toHaveLength(14);
  });

  it("keeps a malicious row and drops a clearly benign one", async () => {
    const outPath = join(tempDir(), "malicious.csv");
    await exportMalicious({
      rows: iterate(fixtureRows()),
      lookup: lookupFor,
      headers: HEADERS,
      outPath,
    });
    const messages = parseCsv(readFileSync(outPath, "utf8"))
      .slice(1)
      .map((line) => line[4]);
    expect(messages).toContain("row 5 message");
    expect(messages).toContain("row 17 message");
    expect(messages).toContain("row 18 message");
    expect(messages).not.toContain("row 1 message");
    expect(messages).not.toContain("row 20 message");
  });

  it("writes every original column verbatim, including an attacker-supplied formula", async () => {
    const outPath = join(tempDir(), "malicious.csv");
    const nasty = timelineRow(1, {
      datetime: "2026-01-01T00:00:00+00:00",
      timestamp_desc: "Content Modification Time",
      source: "LOG",
      source_long: "System log",
      message: `=cmd|'/c calc'!A1 and a "quote" and a\nnewline`,
      parser: "winevtx",
      display_name: "OS:/var/log/x",
      tag: "",
    });
    await exportMalicious({
      rows: iterate([nasty]),
      lookup: () => record({ verdict: verdict({ malicious: 0.9 }) }),
      headers: HEADERS,
      outPath,
    });
    const text = readFileSync(outPath, "utf8");
    expect(text).toContain(`"'=cmd|'/c calc'!A1`);
    const parsed = parseCsv(text);
    expect(parsed[1]?.[4]).toBe(`'${nasty.raw["message"]}`);
  });

  it("emits an empty cell for a header missing from raw, rather than shifting the columns", async () => {
    const outPath = join(tempDir(), "malicious.csv");
    const headers = ["datetime", "absent_col", "message"] as const;
    const partial: TimelineRow = timelineRow(1, {
      datetime: "2026-01-01T00:00:00+00:00",
      message: "a message",
    });
    await exportMalicious({
      rows: iterate([partial]),
      lookup: () => record({ verdict: verdict({ malicious: 0.9 }) }),
      headers,
      outPath,
    });
    const parsed = parseCsv(readFileSync(outPath, "utf8"));
    expect(parsed[1]).toHaveLength(9);
    expect(parsed[1]?.[0]).toBe("2026-01-01T00:00:00+00:00");
    expect(parsed[1]?.[1]).toBe("");
    expect(parsed[1]?.[2]).toBe("a message");
  });

  it("honours a custom threshold set", async () => {
    const outPath = join(tempDir(), "malicious.csv");
    const counts = await exportMalicious({
      rows: iterate(fixtureRows()),
      lookup: lookupFor,
      headers: HEADERS,
      outPath,
      thresholds: { malicious: 0.99, needsAnalyst: 0.99, confident: 0.99 },
    });
    // rows 17 and 18 carry no verdict, so they stay in whatever the thresholds are.
    expect(counts.written).toBe(2);
  });

  it("streams a large row count without losing a row", async () => {
    const outPath = join(tempDir(), "big.csv");
    async function* many(): AsyncIterable<TimelineRow> {
      for (let n = 1; n <= 5000; n += 1) {
        yield timelineRow(n, { datetime: "", message: `m${n}` });
      }
    }
    const counts = await exportMalicious({
      rows: many(),
      lookup: () => record({ verdict: verdict({ malicious: 0.9 }) }),
      headers: ["datetime", "message"],
      outPath,
    });
    expect(counts).toEqual({ written: 5000, scanned: 5000, unjudged: 0 });
    expect(parseCsv(readFileSync(outPath, "utf8"))).toHaveLength(5001);
  });
});
