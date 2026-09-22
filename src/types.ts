// The contract every module in this tool shares. Nothing here does work; it only fixes the
// shapes, so the parser, the store, the Jev client, the exporter and the narrator can be
// written and tested against each other without importing each other's internals.

/** Which Plaso CSV dialect a file is written in. */
export type PlasoFlavor = "dynamic" | "l2tcsv";

/** One raw CSV record: the header names mapped to this row's cell values, verbatim. */
export type RawRow = Readonly<Record<string, string>>;

/**
 * The parts of a row the triage cares about, pulled out of whichever dialect it came from.
 * `raw` keeps the original record so the exporter can write every original column back out
 * unchanged — the evidence must survive the round trip byte for byte.
 */
export interface TimelineRow {
  /** 1-based position in the source file, counting data rows only (the header is not row 1). */
  readonly rowNo: number;
  /** UTC ISO-8601, or "" when the source timestamp could not be parsed. */
  readonly timestamp: string;
  /** The free-text description: `message` in dynamic, `desc`/`short` in l2tcsv. */
  readonly message: string;
  /** The artifact source: `source_long`/`source` in dynamic, `sourcetype`/`source` in l2tcsv. */
  readonly source: string;
  /** What the timestamp means: `timestamp_desc` in dynamic, `type` in l2tcsv. */
  readonly timestampDesc: string;
  /** A filesystem path when the row carries one, else "". */
  readonly path: string;
  /** The host the row belongs to when the dialect records one, else "". */
  readonly host: string;
  readonly raw: RawRow;
}

/**
 * The deduplication key. Two rows share a decision only when all three parts match
 * character for character — no lowercasing, no digit or GUID substitution. Two different
 * IP addresses must stay two different decisions.
 */
export interface DecisionKey {
  /** source, timestampDesc and message joined by the unit separator, exactly as written. */
  readonly keyText: string;
  /** sha256 of keyText plus the questions-file hash, so editing a question re-judges. */
  readonly keyHash: string;
}

/** What Jev answered about one distinct key. Undefined fields mean the call failed. */
export interface Verdict {
  /** 0 = certainly benign, 1 = certainly attacker activity. */
  readonly malicious: number;
  readonly category: string;
  readonly categoryConfidence: number;
  /** A number that may land between levels, e.g. 3.4 between High and Critical. */
  readonly severity: number;
  readonly severityLevel: string;
  readonly needsAnalyst: number;
}

/** A row in the decision cache: the key, how often it occurs, and its verdict if judged. */
export interface DecisionRecord {
  readonly keyHash: string;
  readonly keyText: string;
  readonly occurrences: number;
  /** The earliest timestamp seen for this key, for chronological ordering. */
  readonly firstSeenTs: string;
  /** A sample row's fields, so the judge can send Jev a structured record. */
  readonly sample: JevState;
  readonly verdict?: Verdict;
  /** Set when the last attempt failed; the row stays eligible for a retry. */
  readonly error?: string;
  readonly decidedAt?: string;
}

/** What gets sent to Jev as `state`: a structured object, never a flattened string. */
export interface JevState {
  readonly source: string;
  readonly timestamp_desc: string;
  readonly message: string;
  readonly path?: string;
  readonly host?: string;
}

/** The questions map, as loaded from questions.json. Validated at the boundary. */
export type QuestionSet = Readonly<Record<string, JevQuestion>>;

export type JevQuestion =
  | {
      readonly type: "noul";
      readonly instructions: string;
      readonly criteria: Readonly<Record<string, string>>;
    }
  | {
      readonly type: "choice";
      readonly instructions: string;
      readonly criteria: Readonly<Record<string, string>>;
    }
  | {
      readonly type: "score";
      readonly instructions: string;
      readonly criteria: readonly string[];
    };

/** Thresholds that decide what lands in the malicious CSV and what is flagged uncertain. */
export interface Thresholds {
  /** A row is malicious at or above this. Deliberately below 0.5: a miss costs more. */
  readonly malicious: number;
  /** A row is kept for a human at or above this, even when not judged malicious. */
  readonly needsAnalyst: number;
  /** Between `malicious` and this, the row is included but flagged uncertain. */
  readonly confident: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  malicious: 0.35,
  needsAnalyst: 0.6,
  confident: 0.75,
};

/** What the scan pass measured, and what the judge pass would therefore cost. */
export interface ScanReport {
  readonly flavor: PlasoFlavor;
  readonly totalRows: number;
  readonly distinctKeys: number;
  readonly undecidedKeys: number;
  readonly earliest: string;
  readonly latest: string;
  readonly unparsedTimestamps: number;
  readonly estimatedCostUsd: number;
  readonly estimatedSeconds: number;
}

/** Measured on 2026-09-22: a four-question call on a short record. */
export const COST_PER_CALL_USD = 0.00003;
export const SECONDS_PER_CALL = 0.5;
