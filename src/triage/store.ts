// The decision cache: one SQLite row per distinct key, written as each verdict lands.
//
// Two jobs. It is the dedupe table — 10 million timeline rows collapse into the distinct
// questions worth asking — and it is the resume log: a run killed with Ctrl-C after four hours
// restarts from the keys that have no verdict yet, not from the first row of the file.

import Database from "better-sqlite3";
import type { DecisionRecord, JevState, Verdict } from "../types.js";
import { DEFAULT_THRESHOLDS } from "../types.js";

/** Bumped only when the `decisions` columns change in a way an old file cannot satisfy. */
const SCHEMA_VERSION = "1";

/** `meta` keys this module owns. Callers use their own strings for the rest. */
const META_SCHEMA_VERSION = "schema_version";

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS decisions (
  key_hash TEXT PRIMARY KEY,
  key_text TEXT NOT NULL,
  occurrences INTEGER NOT NULL DEFAULT 0,
  first_seen_ts TEXT NOT NULL DEFAULT '',
  sample_json TEXT NOT NULL,
  malicious REAL, category TEXT, category_confidence REAL,
  severity REAL, severity_level TEXT, needs_analyst REAL,
  error TEXT, decided_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_undecided ON decisions(decided_at) WHERE decided_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_occurrences ON decisions(occurrences);
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
`;

/**
 * Insert at one occurrence, or bump the counter and keep the EARLIEST non-empty timestamp.
 * An unparsed source timestamp arrives as "" and must never displace a real one, in either
 * direction, so the empty cases are handled before the comparison.
 */
const OBSERVE_SQL = `
INSERT INTO decisions (key_hash, key_text, occurrences, first_seen_ts, sample_json)
VALUES (@keyHash, @keyText, 1, @timestamp, @sampleJson)
ON CONFLICT(key_hash) DO UPDATE SET
  occurrences = decisions.occurrences + 1,
  first_seen_ts = CASE
    WHEN excluded.first_seen_ts = '' THEN decisions.first_seen_ts
    WHEN decisions.first_seen_ts = '' THEN excluded.first_seen_ts
    WHEN excluded.first_seen_ts < decisions.first_seen_ts THEN excluded.first_seen_ts
    ELSE decisions.first_seen_ts
  END
`;

const COLUMNS = `key_hash, key_text, occurrences, first_seen_ts, sample_json,
  malicious, category, category_confidence, severity, severity_level, needs_analyst,
  error, decided_at`;

/** One `decisions` row exactly as SQLite hands it back. */
interface DecisionRow {
  readonly key_hash: string;
  readonly key_text: string;
  readonly occurrences: number;
  readonly first_seen_ts: string;
  readonly sample_json: string;
  readonly malicious: number | null;
  readonly category: string | null;
  readonly category_confidence: number | null;
  readonly severity: number | null;
  readonly severity_level: string | null;
  readonly needs_analyst: number | null;
  readonly error: string | null;
  readonly decided_at: string | null;
}

export interface UndecidedOptions {
  /** Judge the least-repeated keys first — the rare ones carry the interesting evidence. */
  readonly rareFirst?: boolean;
  readonly limit?: number;
  /** Default true: a transient 429 must not lose a row for good. */
  readonly retryErrors?: boolean;
}

export interface StoreCounts {
  readonly total: number;
  readonly decided: number;
  readonly errored: number;
  readonly malicious: number;
}

export interface StoreStats {
  readonly distribution: Record<string, number>;
  readonly topMalicious: DecisionRecord[];
}

/** The `meta` table, as a two-method accessor. */
export interface MetaAccessor {
  get(k: string): string | undefined;
  set(k: string, v: string): void;
}

function toRecord(row: DecisionRow): DecisionRecord {
  // exactOptionalPropertyTypes: an absent verdict/error/decidedAt is an omitted key, never
  // a key set to undefined, so each one is spread in only when the column holds a value.
  const verdict: Verdict | undefined =
    row.malicious === null
      ? undefined
      : {
          malicious: row.malicious,
          category: row.category ?? "",
          categoryConfidence: row.category_confidence ?? 0,
          severity: row.severity ?? 0,
          severityLevel: row.severity_level ?? "",
          needsAnalyst: row.needs_analyst ?? 0,
        };
  return {
    keyHash: row.key_hash,
    keyText: row.key_text,
    occurrences: row.occurrences,
    firstSeenTs: row.first_seen_ts,
    sample: JSON.parse(row.sample_json) as JevState,
    ...(verdict !== undefined ? { verdict } : {}),
    ...(row.error !== null ? { error: row.error } : {}),
    ...(row.decided_at !== null ? { decidedAt: row.decided_at } : {}),
  };
}

export class DecisionStore {
  private readonly db: Database.Database;
  private readonly observeStmt: Database.Statement;
  private readonly verdictStmt: Database.Statement;
  private readonly errorStmt: Database.Statement;
  private readonly getStmt: Database.Statement;
  private readonly metaGetStmt: Database.Statement;
  private readonly metaSetStmt: Database.Statement;

  readonly meta: MetaAccessor;

  constructor(dbPath: string) {
    this.db = new Database(dbPath);
    // WAL plus NORMAL: a crash can lose the last few verdicts, which costs a few re-judged
    // rows. At ten million observe() calls, the fsync per write costs hours.
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("synchronous = NORMAL");
    this.db.exec(SCHEMA_SQL);

    this.observeStmt = this.db.prepare(OBSERVE_SQL);
    this.verdictStmt = this.db.prepare(`
      UPDATE decisions SET
        malicious = @malicious, category = @category,
        category_confidence = @categoryConfidence, severity = @severity,
        severity_level = @severityLevel, needs_analyst = @needsAnalyst,
        error = NULL, decided_at = @decidedAt
      WHERE key_hash = @keyHash
    `);
    this.errorStmt = this.db.prepare(`
      UPDATE decisions SET
        malicious = NULL, category = NULL, category_confidence = NULL,
        severity = NULL, severity_level = NULL, needs_analyst = NULL,
        error = @error, decided_at = @decidedAt
      WHERE key_hash = @keyHash
    `);
    this.getStmt = this.db.prepare(`SELECT ${COLUMNS} FROM decisions WHERE key_hash = ?`);
    this.metaGetStmt = this.db.prepare("SELECT v FROM meta WHERE k = ?");
    this.metaSetStmt = this.db.prepare(
      "INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
    );

    this.meta = {
      get: (k: string): string | undefined => {
        const row = this.metaGetStmt.get(k) as { v: string } | undefined;
        return row?.v;
      },
      set: (k: string, v: string): void => {
        this.metaSetStmt.run(k, v);
      },
    };

    if (this.meta.get(META_SCHEMA_VERSION) === undefined) {
      this.meta.set(META_SCHEMA_VERSION, SCHEMA_VERSION);
    }
  }

  static open(dbPath: string): DecisionStore {
    return new DecisionStore(dbPath);
  }

  close(): void {
    this.db.close();
  }

  /**
   * Run `fn` inside one SQLite transaction. The scan pass wraps its whole file in this: one
   * transaction for ten million observe() calls is the difference between minutes and hours,
   * because each committed write otherwise pays its own WAL round trip. Nested calls become
   * savepoints, so a helper that also uses transaction() is safe to call from inside one.
   */
  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  observe(key: { keyHash: string; keyText: string }, state: JevState, timestamp: string): void {
    this.observeStmt.run({
      keyHash: key.keyHash,
      keyText: key.keyText,
      timestamp,
      sampleJson: JSON.stringify(state),
    });
  }

  /** Written the moment a verdict lands — that, not an end-of-run flush, is what resumes. */
  recordVerdict(keyHash: string, verdict: Verdict): void {
    this.verdictStmt.run({
      keyHash,
      malicious: verdict.malicious,
      category: verdict.category,
      categoryConfidence: verdict.categoryConfidence,
      severity: verdict.severity,
      severityLevel: verdict.severityLevel,
      needsAnalyst: verdict.needsAnalyst,
      decidedAt: new Date().toISOString(),
    });
  }

  /** Stamps `decided_at` but leaves the verdict columns null, so the row is still retryable. */
  recordError(keyHash: string, message: string): void {
    this.errorStmt.run({
      keyHash,
      error: message,
      decidedAt: new Date().toISOString(),
    });
  }

  undecided(opts: UndecidedOptions = {}): DecisionRecord[] {
    const retryErrors = opts.retryErrors ?? true;
    const where = retryErrors
      ? "decided_at IS NULL OR error IS NOT NULL"
      : "decided_at IS NULL";
    const order = opts.rareFirst === true ? "occurrences ASC, rowid ASC" : "rowid ASC";
    const limit = opts.limit === undefined ? "" : " LIMIT @limit";
    const stmt = this.db.prepare(
      `SELECT ${COLUMNS} FROM decisions WHERE ${where} ORDER BY ${order}${limit}`,
    );
    const rows = (opts.limit === undefined
      ? stmt.all()
      : stmt.all({ limit: opts.limit })) as DecisionRow[];
    return rows.map(toRecord);
  }

  get(keyHash: string): DecisionRecord | undefined {
    const row = this.getStmt.get(keyHash) as DecisionRow | undefined;
    return row === undefined ? undefined : toRecord(row);
  }

  counts(): StoreCounts {
    const row = this.db
      .prepare(
        `SELECT
           COUNT(*) AS total,
           SUM(CASE WHEN malicious IS NOT NULL THEN 1 ELSE 0 END) AS decided,
           SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) AS errored,
           SUM(CASE WHEN malicious >= @threshold THEN 1 ELSE 0 END) AS malicious
         FROM decisions`,
      )
      .get({ threshold: DEFAULT_THRESHOLDS.malicious }) as {
      total: number | null;
      decided: number | null;
      errored: number | null;
      malicious: number | null;
    };
    return {
      total: row.total ?? 0,
      decided: row.decided ?? 0,
      errored: row.errored ?? 0,
      malicious: row.malicious ?? 0,
    };
  }

  /**
   * Every decided key, in memory, keyed by key_hash, for the export pass to join against.
   *
   * This holds the DISTINCT KEYS, not the timeline rows — which is the whole reason dedupe
   * happens before export. A 10-million-row supertimeline collapses to a few hundred thousand
   * distinct keys, so this map fits in a few hundred megabytes while the rows themselves never
   * would. The exporter streams the CSV and looks each row's key up here; it must never build
   * the opposite map.
   *
   * It returns every key the judge pass FINISHED with, which includes the ones whose call
   * failed. Filtering on a verdict instead would hand the exporter nothing for an errored key,
   * and its row would print as `unjudged` — indistinguishable from a key that was never sent.
   * The analyst has to be able to tell "the model failed here" from "this was never asked".
   */
  verdictLookup(): Map<string, DecisionRecord> {
    const rows = this.db
      .prepare(`SELECT ${COLUMNS} FROM decisions WHERE decided_at IS NOT NULL`)
      .all() as DecisionRow[];
    const lookup = new Map<string, DecisionRecord>();
    for (const row of rows) lookup.set(row.key_hash, toRecord(row));
    return lookup;
  }

  /** Category spread and the worst offenders, for the `sample` command's output. */
  stats(limit: number): StoreStats {
    const categoryRows = this.db
      .prepare(
        `SELECT category AS category, COUNT(*) AS n FROM decisions
         WHERE malicious IS NOT NULL AND category IS NOT NULL
         GROUP BY category ORDER BY n DESC, category ASC`,
      )
      .all() as { category: string; n: number }[];
    const distribution: Record<string, number> = {};
    for (const row of categoryRows) distribution[row.category] = row.n;

    const topRows = this.db
      .prepare(
        `SELECT ${COLUMNS} FROM decisions WHERE malicious IS NOT NULL
         ORDER BY malicious DESC, rowid ASC LIMIT @limit`,
      )
      .all({ limit }) as DecisionRow[];

    return { distribution, topMalicious: topRows.map(toRecord) };
  }
}
