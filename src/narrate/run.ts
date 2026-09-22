// Turning a CSV of flagged rows into a written account.
//
// Two stages, the shape of DFIR Companion's deep pass: when the set fits in one prompt it is
// synthesised directly; when it does not, every chunk is observed first and one synthesis reads
// the observations. See chunk.ts for why the split works the way it does.
//
// THE RULE THIS FILE ENFORCES: the document never truncates silently. Its header states how many
// rows were read out of how many the file held, how many chunks were used, which model wrote it
// and how long the run took. A row cap, or a chunk whose call failed, is written out in plain
// words. An analyst must never have to guess whether they are reading the whole set.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join } from "node:path";
import {
  DEFAULT_CHUNK_BUDGET_TOKENS,
  DEFAULT_MAX_ROWS_PER_CHUNK,
  planChunks,
} from "./chunk.js";
import { OBSERVE_PROMPT, SYNTHESIS_PROMPT } from "./prompts.js";
import type { Narrator } from "./provider.js";

/** One CSV record: header name to cell value, verbatim. */
export type CsvRow = Readonly<Record<string, string>>;

export interface CsvTable {
  readonly headers: readonly string[];
  readonly rows: readonly CsvRow[];
}

export interface NarrateParams {
  csvPath: string;
  narrator: Narrator;
  outPath: string;
  /** "host" writes one document per host, so a multi-host timeline does not blur into one story. */
  groupBy?: "host" | "none";
  /** A hard cap on rows read. Hitting it is stated in the document, never swallowed. */
  maxRows?: number;
  onProgress?: (stage: string, i: number, n: number) => void;
}

export interface NarrateOutcome {
  readonly rowsRead: number;
  readonly chunks: number;
  readonly outPaths: string[];
}

/** Header names that carry a host, in the order they are looked for. */
const HOST_COLUMNS = ["host", "hostname", "computer_name", "computer", "machine"];

/** Where rows with no host land, so they are narrated rather than dropped. */
const NO_HOST = "unknown-host";

// ── CSV reading ────────────────────────────────────────────────────────────────────────────
// A local reader on purpose. src/plaso/ owns the supertimeline dialects; this one only has to
// read back a file this tool wrote, so it stays small: RFC 4180 quoting, doubled quotes, CRLF.

export function parseCsv(text: string): CsvTable {
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const records: string[][] = [];
  let field = "";
  let record: string[] = [];
  let quoted = false;
  let started = false;

  const endField = (): void => {
    record.push(field);
    field = "";
    started = false;
  };
  const endRecord = (): void => {
    endField();
    records.push(record);
    record = [];
  };

  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (quoted) {
      if (ch === '"') {
        if (body[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"' && !started) {
      quoted = true;
      started = true;
    } else if (ch === ",") {
      endField();
    } else if (ch === "\n") {
      endRecord();
    } else if (ch === "\r") {
      // a CRLF line ending; the \n that follows closes the record
    } else {
      field += ch;
      started = true;
    }
  }
  if (field !== "" || record.length > 0) endRecord();

  const headerRecord = records.shift();
  if (!headerRecord) return { headers: [], rows: [] };
  const headers = headerRecord.map((h) => h.trim());
  const rows: CsvRow[] = [];
  for (const rec of records) {
    // A trailing newline leaves one empty record. It is not a row.
    if (rec.length === 1 && rec[0] === "") continue;
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => {
      row[h] = rec[idx] ?? "";
    });
    rows.push(row);
  }
  return { headers, rows };
}

// ── rendering ──────────────────────────────────────────────────────────────────────────────

/** The header that carries the host, when the file has one. */
export function hostColumn(headers: readonly string[]): string | undefined {
  for (const candidate of HOST_COLUMNS) {
    const match = headers.find((h) => h.toLowerCase() === candidate);
    if (match) return match;
  }
  return undefined;
}

/** One row as one line: every non-empty cell, in the file's own column order. */
export function renderRow(row: CsvRow, headers: readonly string[]): string {
  const parts: string[] = [];
  for (const h of headers) {
    const v = row[h];
    if (v !== undefined && v !== "") parts.push(`${h}=${v}`);
  }
  return parts.join(" | ");
}

function renderRows(rows: readonly CsvRow[], headers: readonly string[], offset: number): string {
  return rows.map((r, i) => `ROW ${offset + i + 1}: ${renderRow(r, headers)}`).join("\n");
}

function slug(value: string): string {
  const cleaned = value.replace(/[^A-Za-z0-9._-]+/g, "_").replace(/^_+|_+$/g, "");
  return cleaned || NO_HOST;
}

/** `/x/story.md` plus `DC01` becomes `/x/story.DC01.md`. */
export function pathForHost(outPath: string, host: string): string {
  const ext = extname(outPath) || ".md";
  const stem = basename(outPath, ext);
  return join(dirname(outPath), `${stem}.${slug(host)}${ext}`);
}

// ── the document ───────────────────────────────────────────────────────────────────────────

interface DocumentFacts {
  readonly csvPath: string;
  readonly host?: string;
  readonly rowsRead: number;
  readonly rowsInFile: number;
  readonly chunks: number;
  readonly narratorName: string;
  readonly model: string;
  readonly seconds: number;
  readonly costUsd?: number;
  readonly capped: boolean;
  readonly maxRows?: number;
  readonly failures: readonly string[];
}

function buildDocument(facts: DocumentFacts, narrative: string): string {
  const lines: string[] = [];
  lines.push(`# Incident narrative${facts.host ? ` — ${facts.host}` : ""}`);
  lines.push("");
  lines.push("## How this document was produced");
  lines.push("");
  lines.push(`- **Source file:** \`${facts.csvPath}\``);
  if (facts.host) lines.push(`- **Host:** ${facts.host}`);
  lines.push(`- **Rows read:** ${facts.rowsRead} of ${facts.rowsInFile} in the file`);
  lines.push(`- **Chunks:** ${facts.chunks}`);
  lines.push(`- **Narrator:** ${facts.narratorName} (${facts.model})`);
  lines.push(`- **Run time:** ${facts.seconds.toFixed(1)} s`);
  if (facts.costUsd !== undefined) lines.push(`- **Reported cost:** $${facts.costUsd.toFixed(4)}`);
  lines.push("");
  lines.push(
    "> Every row in the source was flagged by an automated triage model, not by an analyst.",
  );
  lines.push("> A flagged row is a lead, not a finding, and the set may hold false positives.");
  lines.push("");

  if (facts.capped) {
    const missed = facts.rowsInFile - facts.rowsRead;
    lines.push(
      `**Row cap reached.** The source file holds ${facts.rowsInFile} rows. A cap of ` +
        `${facts.maxRows ?? facts.rowsRead} rows was set, so ${missed} rows were not read and are ` +
        `not covered anywhere in this document.`,
    );
    lines.push("");
  }

  if (facts.failures.length > 0) {
    lines.push("**Incomplete.** Some of the input was not read, because these calls failed:");
    lines.push("");
    for (const f of facts.failures) lines.push(`- ${f}`);
    lines.push("");
    lines.push("The account below is missing whatever those rows held.");
    lines.push("");
  }

  lines.push("---");
  lines.push("");
  lines.push(narrative.trim());
  lines.push("");
  return lines.join("\n");
}

function emptyDocument(facts: DocumentFacts): string {
  return buildDocument(
    facts,
    "No rows. The source file holds no flagged rows for this scope, so there is nothing to narrate.",
  );
}

// ── orchestration ──────────────────────────────────────────────────────────────────────────

interface GroupResult {
  readonly narrative: string;
  readonly chunks: number;
  readonly costUsd?: number;
  readonly failures: string[];
}

async function narrateGroup(
  rows: readonly CsvRow[],
  headers: readonly string[],
  narrator: Narrator,
  onProgress: ((stage: string, i: number, n: number) => void) | undefined,
  label: string,
): Promise<GroupResult> {
  const chunks = planChunks(
    rows,
    (r) => renderRow(r, headers),
    DEFAULT_CHUNK_BUDGET_TOKENS,
    DEFAULT_MAX_ROWS_PER_CHUNK,
  );
  const failures: string[] = [];
  let cost = 0;
  let sawCost = false;

  const take = (costUsd: number | undefined): void => {
    if (typeof costUsd === "number") {
      cost += costUsd;
      sawCost = true;
    }
  };

  // One chunk: there is nothing to reassemble, so the observation pass would only add a
  // lossy round trip. Synthesise straight from the rows.
  if (chunks.length === 1) {
    const only = chunks[0] ?? [];
    onProgress?.(`synthesising ${label}`, 1, 1);
    const res = await narrator.generate({
      systemPrompt: SYNTHESIS_PROMPT,
      userPrompt: `The flagged rows, in the order the timeline holds them:\n\n${renderRows(only, headers, 0)}`,
    });
    take(res.costUsd);
    return {
      narrative: res.text,
      chunks: 1,
      ...(sawCost ? { costUsd: cost } : {}),
      failures,
    };
  }

  const observations: string[] = [];
  let offset = 0;
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i] ?? [];
    onProgress?.(`observing ${label}`, i + 1, chunks.length);
    try {
      const res = await narrator.generate({
        systemPrompt: OBSERVE_PROMPT,
        userPrompt:
          `Slice ${i + 1} of ${chunks.length} of the flagged rows, in timeline order:\n\n` +
          renderRows(chunk, headers, offset),
      });
      take(res.costUsd);
      observations.push(`### Observations from slice ${i + 1} of ${chunks.length}\n\n${res.text.trim()}`);
    } catch (err) {
      failures.push(
        `slice ${i + 1} of ${chunks.length} (${chunk.length} rows) produced no observations — ${(err as Error).message}`,
      );
    }
    offset += chunk.length;
  }

  if (observations.length === 0) {
    throw new Error(
      `every one of the ${chunks.length} observation calls failed; no narrative was written. ` +
        `First failure: ${failures[0] ?? "unknown"}`,
    );
  }

  onProgress?.(`synthesising ${label}`, chunks.length, chunks.length);
  const res = await narrator.generate({
    systemPrompt: SYNTHESIS_PROMPT,
    userPrompt:
      `Observations collected from ${chunks.length} slices of the flagged rows, in timeline ` +
      `order. Write the account from these.\n\n${observations.join("\n\n")}`,
  });
  take(res.costUsd);
  return {
    narrative: res.text,
    chunks: chunks.length,
    ...(sawCost ? { costUsd: cost } : {}),
    failures,
  };
}

export async function narrate(params: NarrateParams): Promise<NarrateOutcome> {
  const started = Date.now();
  const table = parseCsv(readFileSync(params.csvPath, "utf8"));
  const rowsInFile = table.rows.length;

  const cap = params.maxRows !== undefined && params.maxRows > 0 ? params.maxRows : undefined;
  const rows = cap !== undefined ? table.rows.slice(0, cap) : table.rows;
  const capped = rows.length < rowsInFile;

  // Group first, so each document covers exactly the rows its header claims.
  const groups = new Map<string, CsvRow[]>();
  const column = params.groupBy === "host" ? hostColumn(table.headers) : undefined;
  if (params.groupBy === "host" && column) {
    for (const row of rows) {
      const host = (row[column] ?? "").trim() || NO_HOST;
      const bucket = groups.get(host);
      if (bucket) bucket.push(row);
      else groups.set(host, [row]);
    }
  } else {
    groups.set("", [...rows]);
  }

  const outPaths: string[] = [];
  let totalChunks = 0;

  const write = (path: string, text: string): void => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, text, "utf8");
    outPaths.push(path);
  };

  const names = [...groups.keys()].sort();
  for (const host of names) {
    const groupRows = groups.get(host) ?? [];
    const path = host ? pathForHost(params.outPath, host) : params.outPath;
    const base = {
      csvPath: params.csvPath,
      ...(host ? { host } : {}),
      rowsRead: groupRows.length,
      rowsInFile,
      narratorName: params.narrator.name,
      model: params.narrator.model,
      capped,
      ...(cap !== undefined ? { maxRows: cap } : {}),
    };

    if (groupRows.length === 0) {
      write(
        path,
        emptyDocument({
          ...base,
          chunks: 0,
          seconds: (Date.now() - started) / 1000,
          failures: [],
        }),
      );
      continue;
    }

    const result = await narrateGroup(
      groupRows,
      table.headers,
      params.narrator,
      params.onProgress,
      host || basename(params.csvPath),
    );
    totalChunks += result.chunks;
    write(
      path,
      buildDocument(
        {
          ...base,
          chunks: result.chunks,
          seconds: (Date.now() - started) / 1000,
          ...(result.costUsd !== undefined ? { costUsd: result.costUsd } : {}),
          failures: result.failures,
        },
        result.narrative,
      ),
    );
  }

  return { rowsRead: rows.length, chunks: totalChunks, outPaths };
}
