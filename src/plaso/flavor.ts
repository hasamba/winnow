// Which Plaso CSV dialect a file is in, and how to pull a `TimelineRow` out of one of its records.
//
// `psort` writes two CSV shapes, and they share no column names:
//   • dynamic (the psort default) — datetime, timestamp_desc, source, source_long, message,
//     parser, display_name, tag. `datetime` is ISO-8601 with an offset, usually to microseconds.
//   • l2tcsv (the legacy `-o l2tcsv`) — date, time, timezone, MACB, source, sourcetype, type,
//     user, host, short, desc, version, filename, inode, notes, format, extra. The date is
//     MM/DD/YYYY, the time a bare wall clock, and the zone a separate column.
//
// Ported from DFIR Companion's `analysis/plasoImport.ts`, minus everything that made a Companion
// event: no description string, no 600-character clip, no severity, no IOC scrape, no aggregation
// key. This tool hands the untouched original text to a judge and then back out to a CSV, so a
// field that gets rewritten here is evidence that is lost downstream. `raw` keeps the whole record.

import type { PlasoFlavor, RawRow, TimelineRow } from "../types.js";
import { parseCsvRecordsFromLines, readLines } from "./csvRead.js";

/** The value l2tcsv writes in a column it has nothing for. */
const L2T_NULL = "-";

/** A canonical UTC stamp: what `TimelineRow.timestamp` is allowed to hold. */
const UTC_ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/;

/** A trailing numeric timezone offset, e.g. `+02:00` or `-0500`. */
const TZ_OFFSET = /[+-]\d{2}:?\d{2}$/;

/** Fractional seconds immediately before that offset, for re-attaching sub-ms precision. */
const SUBSEC = /\.(\d+)(?=[+-]\d{2}:?\d{2}$)/;

/** "YYYY-MM-DD" + " " or "T" + "HH:MM:SS" + optional fraction, with no zone of its own. */
const NAIVE_ISO = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?Z?$/;

// ───────────────────────────── header normalization ─────────────────────────────

/** Drop a leading UTF-8 BOM. A BOM is a file-encoding artifact, never part of a column name. */
function stripBom(s: string): string {
  return s.replace(/^﻿/, "");
}

/** The form a header is compared in: no BOM, no surrounding space, lower case. */
function normHeader(h: string): string {
  return stripBom(h).trim().toLowerCase();
}

/**
 * The first non-empty value across candidate column names, compared case-insensitively.
 * The returned value is trimmed; `raw` keeps the verbatim one.
 */
export function firstStr(
  headers: readonly string[],
  cells: readonly string[],
  keys: readonly string[],
): string {
  for (const key of keys) {
    const want = key.toLowerCase();
    for (let i = 0; i < headers.length; i++) {
      const h = headers[i];
      if (h === undefined || normHeader(h) !== want) continue;
      const v = (cells[i] ?? "").trim();
      if (v) return v;
    }
  }
  return "";
}

/** Collapse any run of line breaks and surrounding space into a single space. */
export function oneLine(s: string): string {
  return s.replace(/\s*[\r\n]+\s*/g, " ").trim();
}

// ───────────────────────────── timestamps ─────────────────────────────

/**
 * A timestamp carrying an explicit numeric offset, converted to canonical UTC.
 *
 * Conservative on purpose, and inlined from Companion's `timeUtc.ts` rather than imported:
 * a stamp with no offset is left alone, because `new Date()` would reinterpret a naive wall clock
 * in the server's own zone and silently shift it. Sub-millisecond precision survives, since an
 * offset only ever shifts whole minutes, so the fraction is invariant under the conversion.
 */
function toUtcIso(ts: string): string {
  const s = ts.trim();
  if (!s || !TZ_OFFSET.test(s)) return s;
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return s;
  const iso = d.toISOString(); // canonical UTC, truncated to milliseconds
  const frac = SUBSEC.exec(s);
  const digits = frac?.[1] ?? "";
  return digits.length > 3 ? iso.replace(/\.\d{3}Z$/, `.${digits}Z`) : iso;
}

/**
 * Normalize a forensic stamp to UTC ISO-8601, or "" when it cannot be read.
 *
 * Equivalent to Companion's `normalizeTime` for Plaso input, with one deliberate difference: an
 * unrecognizable string comes back empty instead of being passed through. `TimelineRow.timestamp`
 * is declared as UTC ISO or "", and letting raw junk through would put a value in the field that
 * every consumer would have to re-validate.
 */
function toUtcIsoOrEmpty(value: string): string {
  const t = value.trim();
  if (!t) return "";
  // A naive stamp is read as UTC — psort is normally run in UTC, and there is nothing else to go on.
  const m = NAIVE_ISO.exec(t);
  const out =
    m && !/[+-]\d{2}:?\d{2}$|Z$/.test(t) ? `${m[1]}T${m[2]}${m[3] ?? ""}Z` : toUtcIso(t);
  return UTC_ISO.test(out) ? out : "";
}

/**
 * l2tcsv "MM/DD/YYYY" + "HH:MM:SS" + a timezone column → UTC ISO.
 *
 * Only a numeric offset in the timezone column is honoured. A zone NAME (`UTC`, `Europe/Berlin`)
 * falls back to reading the wall clock as UTC — documented behaviour, and the right default since
 * psort is normally run in UTC. A date that is not MM/DD/YYYY returns "".
 */
export function l2tTime(date: string, time: string, tz: string): string {
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(date.trim());
  if (!m) return "";
  const mm = (m[1] ?? "").padStart(2, "0");
  const dd = (m[2] ?? "").padStart(2, "0");
  const yyyy = m[3] ?? "";
  const zone = tz.trim();
  const z = /^[+-]\d{2}:?\d{2}$/.test(zone) ? zone : "Z";
  return toUtcIsoOrEmpty(`${yyyy}-${mm}-${dd}T${time.trim()}${z}`);
}

/**
 * dynamic `datetime` → UTC ISO. psort writes microseconds; JS `Date` is millisecond-resolution,
 * so the fraction is truncated to three digits before the conversion rather than after it.
 */
export function dynTime(v: string): string {
  return toUtcIsoOrEmpty(v.trim().replace(/(\.\d{3})\d+/, "$1"));
}

// ───────────────────────────── fields ─────────────────────────────

/**
 * Plaso's `display_name` / `filename` carries a source-type prefix — `TSK:/Windows/…`,
 * `OS:/Users/…`, `GZIP:…`. Strip it and keep the path. A URL is not a path, and neither is a bare
 * token with no separator in it.
 */
export function pathFrom(display: string): string {
  let p = display.trim();
  if (!p || /^https?:\/\//i.test(p)) return "";
  const m = /^[A-Z0-9]{2,6}:(.+)$/.exec(p);
  if (m?.[1]) p = m[1];
  return /[\\/]/.test(p) ? p : "";
}

// ───────────────────────────── detection and mapping ─────────────────────────────

/**
 * Which dialect a header row is, or null when it is neither.
 * Comparison ignores case, surrounding whitespace and a UTF-8 BOM.
 */
export function detectFlavor(headers: readonly string[]): PlasoFlavor | null {
  const set = new Set(headers.map(normHeader));
  if (set.has("datetime") && set.has("message")) return "dynamic";
  if (set.has("date") && set.has("time") && (set.has("desc") || set.has("short"))) return "l2tcsv";
  return null;
}

/**
 * The header→cell record, verbatim. Values are untouched — not trimmed, not unescaped beyond what
 * CSV quoting already required — because the exporter writes these columns back out unchanged.
 * A record with fewer cells than headers fills the missing tail with "".
 */
function rawFrom(headers: readonly string[], cells: readonly string[]): RawRow {
  const out: Record<string, string> = {};
  for (let i = 0; i < headers.length; i++) {
    const h = headers[i];
    if (h === undefined) continue;
    out[stripBom(h)] = cells[i] ?? "";
  }
  return out;
}

/**
 * One CSV record → a `TimelineRow`, or null when the record carries no message text.
 *
 * `rowNo` is the caller's 1-based count of data rows, so it still matches the file after a row is
 * dropped for having no message.
 */
export function mapRow(
  flavor: PlasoFlavor,
  headers: readonly string[],
  cells: readonly string[],
  rowNo: number,
): TimelineRow | null {
  const raw = rawFrom(headers, cells);
  const at = (keys: readonly string[]): string => firstStr(headers, cells, keys);

  if (flavor === "dynamic") {
    const message = at(["message"]);
    if (!message) return null;
    return {
      rowNo,
      timestamp: dynTime(at(["datetime"])),
      message,
      source: at(["source_long", "source"]),
      timestampDesc: at(["timestamp_desc"]),
      path: pathFrom(at(["display_name"])),
      host: "",
      raw,
    };
  }

  const message = at(["desc", "short"]);
  if (!message) return null;
  const host = at(["host"]);
  return {
    rowNo,
    timestamp: l2tTime(at(["date"]), at(["time"]), at(["timezone"])),
    message,
    source: at(["sourcetype", "source"]),
    timestampDesc: at(["type"]),
    path: pathFrom(at(["filename"])),
    host: host === L2T_NULL ? "" : host,
    raw,
  };
}

/**
 * Stream a Plaso CSV as `TimelineRow`s: read the header, detect the dialect, map each data row.
 *
 * Nothing is buffered beyond the record in hand, so a multi-hundred-megabyte super-timeline costs
 * whatever the caller chooses to keep. Throws when the header matches no known dialect, or when
 * the file holds no header at all.
 */
export async function* readTimeline(filePath: string): AsyncGenerator<TimelineRow> {
  let headers: readonly string[] | null = null;
  let flavor: PlasoFlavor | null = null;
  let rowNo = 0;

  for await (const rec of parseCsvRecordsFromLines(readLines(filePath))) {
    if (headers === null) {
      headers = rec;
      flavor = detectFlavor(headers);
      if (flavor === null) {
        throw new Error(
          `${filePath}: the header is neither Plaso dialect. ` +
            `A dynamic export needs "datetime" and "message"; an l2tcsv export needs "date", ` +
            `"time" and "desc" or "short". Found: ${rec.join(", ")}`,
        );
      }
      continue;
    }
    rowNo++;
    if (flavor === null) continue; // unreachable: the header pass either set it or threw
    const row = mapRow(flavor, headers, rec, rowNo);
    if (row !== null) yield row;
  }

  if (headers === null) throw new Error(`${filePath}: the file is empty, so it has no CSV header.`);
}
