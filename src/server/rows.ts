// The verdict table behind the dashboard: one SELECT over the decision cache, with the
// filter, the sort and the page the analyst asked for.
//
// It reads `decisions` directly instead of going through DecisionStore's typed methods
// because the query shape belongs to the screen, not to the cache: the store's job is to make
// a verdict durable the moment it lands, and it should not grow a method per column the table
// can sort on. The handle it hands over is read-only by contract (store.readonlyDb) — nothing
// here writes.

import type { DecisionStore } from "../triage/store.js";
import type { RowPage, RowQuery, VerdictRow } from "./contract.js";

/** ASCII unit separator: what decisionKeyText() joined the three parts of the key with. */
const US = "\x1f";

const DEFAULT_LIMIT = 100;

/**
 * The hard ceiling on one page. A real supertimeline holds hundreds of thousands of distinct
 * keys; a request for all of them would build the whole table in this process's memory and
 * then ask the browser to render it. The dashboard pages instead.
 */
const MAX_LIMIT = 1000;

/** The `decisions` columns the table shows. */
const COLUMNS = `key_hash, key_text, occurrences, first_seen_ts,
  malicious, category, severity, severity_level, needs_analyst, error`;

interface Row {
  readonly key_hash: string;
  readonly key_text: string;
  readonly occurrences: number;
  readonly first_seen_ts: string;
  readonly malicious: number | null;
  readonly category: string | null;
  readonly severity: number | null;
  readonly severity_level: string | null;
  readonly needs_analyst: number | null;
  readonly error: string | null;
}

/** ORDER BY clauses, keyed by the sort the dashboard asks for. */
const ORDER: Record<NonNullable<RowQuery["sort"]>, string> = {
  // (malicious IS NULL) sorts the unjudged keys last without relying on NULLS LAST, and the
  // rowid tiebreak keeps page 2 from repeating a row page 1 already showed.
  malicious: "(malicious IS NULL) ASC, malicious DESC, rowid ASC",
  occurrences: "occurrences DESC, rowid ASC",
  time: "first_seen_ts ASC, rowid ASC",
};

export function queryRows(store: DecisionStore, q: RowQuery): RowPage {
  const db = store.readonlyDb;
  const where: string[] = [];
  const params: Record<string, string | number> = {};

  // "Undecided" means never asked. An errored key WAS asked and the call failed, which the
  // analyst has to be able to see — that is a gap in the evidence, not an absence of one.
  if (q.includeUndecided !== true) where.push("(malicious IS NOT NULL OR error IS NOT NULL)");

  if (q.q !== undefined && q.q !== "") {
    // The analyst types evidence, not a pattern: a "%" in a PowerShell one-liner or a "_" in
    // a service name is a character to find, never a wildcard. Both are escaped, and so is
    // the escape character itself, before the search is wrapped in the wildcards we DO mean.
    where.push(`key_text LIKE @like ESCAPE '\\'`);
    params["like"] = `%${escapeLike(q.q)}%`;
  }

  if (q.min !== undefined) {
    where.push("malicious >= @min");
    params["min"] = q.min;
  }

  if (q.category !== undefined && q.category !== "") {
    where.push("category = @category");
    params["category"] = q.category;
  }

  const clause = where.length === 0 ? "" : ` WHERE ${where.join(" AND ")}`;
  const order = ORDER[q.sort ?? "malicious"];

  // Counted before the page is cut, so the dashboard can say "1–100 of 12,418" and page.
  const counted = db.prepare(`SELECT COUNT(*) AS n FROM decisions${clause}`).get(params) as {
    n: number;
  };

  const limit = clamp(q.limit, DEFAULT_LIMIT, MAX_LIMIT);
  const offset = clamp(q.offset, 0, Number.MAX_SAFE_INTEGER);
  const rows = db
    .prepare(`SELECT ${COLUMNS} FROM decisions${clause} ORDER BY ${order} LIMIT @limit OFFSET @offset`)
    .all({ ...params, limit, offset }) as Row[];

  return { rows: rows.map(toVerdictRow), total: counted.n };
}

/**
 * Split the decision key back into the three fields it was built from. The table shows them
 * as three columns, so `text` is the message alone — a row reading
 * "LOG\x1fLast Access Time\x1fPrefetch […]" in the message column would be unreadable.
 */
function toVerdictRow(row: Row): VerdictRow {
  const parts = row.key_text.split(US);
  return {
    keyHash: row.key_hash,
    source: parts[0] ?? "",
    timestampDesc: parts[1] ?? "",
    // Joined back rather than indexed: the separator cannot occur in a Plaso field, but a key
    // written by some future dialect that did contain one must not lose the tail of its text.
    text: parts.slice(2).join(US),
    firstSeenTs: row.first_seen_ts,
    occurrences: row.occurrences,
    // exactOptionalPropertyTypes: an unjudged column is an omitted key, never undefined.
    ...(row.malicious !== null ? { malicious: row.malicious } : {}),
    ...(row.category !== null ? { category: row.category } : {}),
    ...(row.severity !== null ? { severity: row.severity } : {}),
    ...(row.severity_level !== null ? { severityLevel: row.severity_level } : {}),
    ...(row.needs_analyst !== null ? { needsAnalyst: row.needs_analyst } : {}),
    ...(row.error !== null ? { error: row.error } : {}),
  };
}

function escapeLike(text: string): string {
  return text.replace(/[\\%_]/g, (c) => `\\${c}`);
}

function clamp(value: number | undefined, fallback: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) return fallback;
  return Math.min(Math.max(0, Math.floor(value)), max);
}
