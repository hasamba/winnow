// Reading a Plaso super-timeline CSV without ever holding it as one string.
//
// A real psort export runs to hundreds of megabytes. V8's maximum string length is about 512 MB,
// so `readFileSync(file, "utf8")` on a 555 MB timeline throws "Invalid string length" outright —
// the file is unreadable, not merely slow. Everything here therefore streams: `readLines` hands
// out one physical line at a time, and `parseCsvRecordsFromLines` joins only as many lines as one
// logical record needs before yielding it and dropping the buffer.
//
// The parser is a minimal RFC-4180 reader — quoted fields, embedded delimiters, embedded newlines
// and doubled quotes — with no dependency. It is ported from DFIR Companion's
// `analysis/csvImport.ts`, which has read these same Plaso exports in production.

import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";

/** Default per-record cap. A record larger than this is force-flushed; see below. */
const MAX_RECORD_CHARS = 8 * 1024 * 1024;

/**
 * Yield the file one physical line at a time, decoded as UTF-8.
 *
 * `crlfDelay: Infinity` makes readline treat CRLF as one break, so a Windows-authored export does
 * not leave a trailing `\r` on every line. The line terminator itself is not returned, which is
 * why `parseCsvRecordsFromLines` re-joins with `\n`.
 */
export async function* readLines(filePath: string): AsyncGenerator<string> {
  const stream = createReadStream(filePath, { encoding: "utf8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  try {
    for await (const line of rl) yield line;
  } finally {
    rl.close();
    stream.destroy();
  }
}

/**
 * Parse CSV text into records, one `string[]` at a time.
 *
 * The sync twin of `parseCsvRecordsFromLines`, for tests and for inputs small enough to hold in
 * memory. A fully empty record (the blank line a trailing newline leaves) is skipped, so the first
 * yield is always the header.
 */
export function* parseCsvRecords(text: string, delimiter = ","): Generator<string[]> {
  let field = "";
  let record: string[] = [];
  let inQuotes = false;
  let started = false; // did the current record receive any field or character?

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"'; // a doubled quote is one literal quote
          i++;
        } else {
          inQuotes = false;
        }
      } else if (ch === "\r" && text[i + 1] === "\n") {
        // A CRLF inside a quoted field becomes a bare LF, so this parser agrees with the
        // streaming one, which reads through readline and never sees the CR. Without this a
        // Windows-written timeline puts a stray \r inside the value — which then travels into
        // the deduplication key and out into the exported CSV.
        continue;
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
      started = true;
      continue;
    }
    if (ch === delimiter) {
      record.push(field);
      field = "";
      started = true;
      continue;
    }
    if (ch === "\r") continue; // CRLF tolerance
    if (ch === "\n") {
      record.push(field);
      field = "";
      if (!(record.length === 1 && record[0] === "")) yield record;
      record = [];
      started = false;
      continue;
    }
    field += ch;
    started = true;
  }
  // Flush a final record that was not newline-terminated.
  if (started || field.length > 0) {
    record.push(field);
    if (!(record.length === 1 && record[0] === "")) yield record;
  }
}

/**
 * Parse CSV records from a line source, for files too large to hold as one string.
 *
 * Physical lines are joined into one logical record until the running double-quote count is
 * balanced: a quoted Plaso `message` may contain newlines and so span several source lines. The
 * re-joined buffer is then handed to `parseCsvRecords`, which treats a `\n` inside an open quote
 * as part of the field — so the original logical record is reproduced exactly.
 *
 * `maxRecordChars` force-flushes an over-long buffer. Without it a single stray quote anywhere in
 * the file never balances, and the parser would append every remaining line into one ever-growing
 * field until the process runs out of memory.
 */
export async function* parseCsvRecordsFromLines(
  lines: AsyncIterable<string>,
  delimiter = ",",
  maxRecordChars = MAX_RECORD_CHARS,
): AsyncGenerator<string[]> {
  let buf = "";
  let quotes = 0;
  let have = false;
  for await (const line of lines) {
    buf = have ? `${buf}\n${line}` : line;
    have = true;
    for (let i = 0; i < line.length; i++) if (line[i] === '"') quotes++;
    if (quotes % 2 === 0 || buf.length > maxRecordChars) {
      for (const rec of parseCsvRecords(buf, delimiter)) yield rec;
      buf = "";
      quotes = 0;
      have = false;
    }
  }
  if (have) for (const rec of parseCsvRecords(buf, delimiter)) yield rec;
}
