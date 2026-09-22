// The counting pass. It reads the whole supertimeline, records every distinct row in the
// decision cache, and reports what a judge pass would cost. It sends nothing anywhere: a
// scan is free and works offline, so an analyst can size a job before committing to it.

import { readTimeline, detectFlavor } from "../plaso/flavor.js";
import { readLines, parseCsvRecordsFromLines } from "../plaso/csvRead.js";
import { decisionKey, jevStateFrom } from "./key.js";
import type { DecisionStore } from "./store.js";
import {
  COST_PER_CALL_USD,
  SECONDS_PER_CALL,
  type PlasoFlavor,
  type ScanReport,
} from "../types.js";

/** How many rows are folded into one SQLite transaction. */
const OBSERVE_BATCH = 20_000;

export interface ScanParams {
  readonly filePath: string;
  readonly store: DecisionStore;
  readonly questionsHash: string;
  readonly concurrency: number;
  readonly onProgress?: (rows: number) => void;
}

/**
 * Read the header row on its own, so the exporter can write every original column back out
 * in its original order. `readTimeline` deliberately hides the header, because the rest of
 * the pipeline works on mapped fields rather than raw columns.
 */
export async function readHeaders(filePath: string): Promise<string[]> {
  for await (const record of parseCsvRecordsFromLines(readLines(filePath))) {
    return record.map((h) => h.replace(/^﻿/, "").trim());
  }
  throw new Error(`${filePath} is empty — no header row found`);
}

export async function scanTimeline(params: ScanParams): Promise<ScanReport> {
  const { filePath, store, questionsHash, concurrency, onProgress } = params;

  const headers = await readHeaders(filePath);
  const flavor: PlasoFlavor | null = detectFlavor(headers);
  if (!flavor) {
    throw new Error(
      `${filePath} is not a Plaso CSV this tool recognises. ` +
        `Expected psort dynamic (datetime, message) or l2tcsv (date, time, desc) columns.`,
    );
  }

  let totalRows = 0;
  let unparsedTimestamps = 0;
  let earliest = "";
  let latest = "";

  // Rows are observed in batches inside one transaction each. One transaction per row would
  // turn a ten-million-row scan from minutes into hours.
  let batch: Array<() => void> = [];
  const flush = (): void => {
    if (batch.length === 0) return;
    const pending = batch;
    batch = [];
    store.transaction(() => {
      for (const write of pending) write();
    });
  };

  for await (const row of readTimeline(filePath)) {
    totalRows += 1;

    if (row.timestamp === "") {
      unparsedTimestamps += 1;
    } else {
      if (earliest === "" || row.timestamp < earliest) earliest = row.timestamp;
      if (latest === "" || row.timestamp > latest) latest = row.timestamp;
    }

    const key = decisionKey(row, questionsHash);
    const state = jevStateFrom(row);
    const ts = row.timestamp;
    batch.push(() => store.observe(key, state, ts));

    if (batch.length >= OBSERVE_BATCH) {
      flush();
      onProgress?.(totalRows);
    }
  }
  flush();
  onProgress?.(totalRows);

  const counts = store.counts();
  const undecidedKeys = counts.total - counts.decided;

  return {
    flavor,
    totalRows,
    distinctKeys: counts.total,
    undecidedKeys,
    earliest,
    latest,
    unparsedTimestamps,
    estimatedCostUsd: undecidedKeys * COST_PER_CALL_USD,
    estimatedSeconds: (undecidedKeys * SECONDS_PER_CALL) / Math.max(1, concurrency),
  };
}
