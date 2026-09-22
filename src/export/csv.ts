// The malicious-rows CSV: the one artifact an analyst opens in a spreadsheet.
//
// Every string that reaches this file was written by the thing under investigation, so the
// quoting and the formula guard below are correctness, not polish. There is exactly ONE
// implementation of `cell` in this tool, and every exporter goes through it.

import { createWriteStream } from "node:fs";
import { once } from "node:events";
import type { DecisionRecord, Thresholds, TimelineRow } from "../types.js";
import { DEFAULT_THRESHOLDS } from "../types.js";

/** How many decimals a 0..1 score is written with. */
const SCORE_DECIMALS = 3;

/**
 * Quote one field, and disarm a spreadsheet formula.
 *
 * A value that opens with `=`, `+`, `-`, `@`, a tab or a carriage return is executed by Excel
 * and LibreOffice when the file is opened, so it gets a leading apostrophe first. Every field
 * is then quoted unconditionally, and an embedded quote is doubled per RFC 4180.
 */
export function cell(value: string): string {
  const guarded = /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
  return `"${guarded.replace(/"/g, '""')}"`;
}

/** One CSV line, without the trailing newline. */
export function row(values: readonly string[]): string {
  return values.map(cell).join(",");
}

/** The six columns this tool appends to the original timeline columns, in order. */
export const VERDICT_COLUMNS = [
  "jev_malicious",
  "jev_confidence",
  "jev_category",
  "jev_severity",
  "jev_needs_analyst",
  "jev_dupe_count",
] as const;

function score(value: number): string {
  return value.toFixed(SCORE_DECIMALS);
}

/**
 * The six appended values for one row. Always six, whatever the record's state — a short
 * array here would shift every later column in the analyst's spreadsheet.
 */
export function verdictCells(record: DecisionRecord | undefined, t: Thresholds): string[] {
  if (record === undefined) {
    return ["", "unjudged", "", "", "", ""];
  }
  const dupes = String(record.occurrences);
  const v = record.verdict;
  if (v === undefined) {
    // No verdict: either the call failed, or the key was never sent. The row still ships,
    // and this column is how the analyst tells the two apart.
    return ["", record.error !== undefined ? "error" : "unjudged", "", "", "", dupes];
  }
  const confidence = v.malicious >= t.confident ? "confident" : "uncertain";
  return [
    score(v.malicious),
    record.error !== undefined ? "error" : confidence,
    v.category,
    `${v.severityLevel} (${v.severity})`,
    score(v.needsAnalyst),
    dupes,
  ];
}

/**
 * Does this row belong in the malicious CSV?
 *
 * An errored or unjudged record is INCLUDED. Silently dropping a row the tool failed to judge
 * would hide evidence from the analyst, which is the one thing this tool must never do: a
 * missing verdict is a gap in the triage, not a statement that the row is benign. The
 * `jev_confidence` column says which of the two happened, so the gap stays visible in the
 * spreadsheet instead of disappearing from it.
 */
export function shouldInclude(record: DecisionRecord | undefined, t: Thresholds): boolean {
  const v = record?.verdict;
  if (v === undefined) return true;
  return v.malicious >= t.malicious || v.needsAnalyst >= t.needsAnalyst;
}

export interface ExportParams {
  readonly rows: AsyncIterable<TimelineRow>;
  readonly lookup: (row: TimelineRow) => DecisionRecord | undefined;
  /** The source file's headers, in the source file's order. */
  readonly headers: readonly string[];
  readonly outPath: string;
  readonly thresholds?: Thresholds;
}

export interface ExportCounts {
  /** Rows written to the CSV. */
  readonly written: number;
  /** Rows read from the source. */
  readonly scanned: number;
  /** Rows that carried no verdict — no record at all, or a record that errored. */
  readonly unjudged: number;
}

/**
 * Stream the included rows to `outPath`. The row source is a parameter and so is the verdict
 * lookup, so this function never needs the parser or the decision store to run.
 */
export async function exportMalicious(params: ExportParams): Promise<ExportCounts> {
  const t = params.thresholds ?? DEFAULT_THRESHOLDS;
  const stream = createWriteStream(params.outPath, { encoding: "utf8" });
  let failure: Error | undefined;
  let signalFailure!: (err: Error) => void;
  // One rejection channel for the whole run, so a stalled drain cannot hang the export and a
  // per-write listener cannot pile up on the stream.
  const failed = new Promise<never>((_resolve, reject) => {
    signalFailure = reject;
  });
  failed.catch(() => undefined);
  stream.on("error", (err: Error) => {
    failure = err;
    signalFailure(err);
  });

  // Honour backpressure: a million-row timeline must not queue in memory waiting for the disk.
  const write = async (line: string): Promise<void> => {
    if (failure !== undefined) throw failure;
    if (!stream.write(line)) {
      await Promise.race([once(stream, "drain"), failed]);
    }
  };

  let scanned = 0;
  let written = 0;
  let unjudged = 0;
  try {
    await write(`${row([...params.headers, ...VERDICT_COLUMNS])}\n`);
    for await (const timelineRow of params.rows) {
      scanned += 1;
      const record = params.lookup(timelineRow);
      if (record?.verdict === undefined) unjudged += 1;
      if (!shouldInclude(record, t)) continue;
      // Every original column, verbatim from `raw`, in the source file's order. A header the
      // row does not carry emits "" so the columns stay aligned.
      const original = params.headers.map((header) => timelineRow.raw[header] ?? "");
      await write(`${row([...original, ...verdictCells(record, t)])}\n`);
      written += 1;
    }
  } finally {
    // "close" fires whether the stream finished or errored, so the cleanup cannot hang.
    await new Promise<void>((resolve) => {
      stream.once("close", () => resolve());
      stream.end();
    });
  }
  if (failure !== undefined) throw failure;
  return { written, scanned, unjudged };
}
