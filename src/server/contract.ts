// The contract between the dashboard, the HTTP layer and the job runner.
//
// The dashboard drives long operations it cannot block on: a judge pass over a real
// supertimeline runs for hours. So every operation is a JOB — started with a POST, watched
// over a server-sent-event stream, and cancellable. The browser holds no state worth losing;
// the truth is the SQLite decision cache on disk, exactly as in the CLI.

import type { ScanReport, Thresholds } from "../types.js";

export const DEFAULT_PORT = 4774;

/** Only ever bound to loopback. The server reads arbitrary paths on this machine. */
export const BIND_HOST = "127.0.0.1";

export type JobKind = "scan" | "judge" | "export" | "narrate";

export type JobState = "idle" | "running" | "done" | "error" | "cancelled";

export interface JobStatus {
  readonly kind: JobKind;
  readonly state: JobState;
  /** Human-readable line for the dashboard, e.g. "1,204,000 rows read". */
  readonly message: string;
  /** 0..1 when known, undefined when the total is not yet knowable (a scan cannot know). */
  readonly progress?: number;
  readonly startedAt: string;
  readonly finishedAt?: string;
  readonly costUsd?: number;
  readonly errors?: number;
  readonly error?: string;
}

/** Everything the dashboard needs to render itself after a refresh. */
export interface ServerState {
  readonly file?: string;
  readonly dbPath?: string;
  readonly job?: JobStatus;
  readonly scan?: ScanReport;
  readonly counts?: {
    readonly total: number;
    readonly decided: number;
    readonly errored: number;
    readonly malicious: number;
  };
  readonly thresholds: Thresholds;
  readonly artifacts: {
    readonly maliciousCsv?: string;
    readonly manifest?: string;
    readonly narratives: readonly string[];
  };
  readonly questionsHash: string;
}

/** One row in the verdict table. */
export interface VerdictRow {
  readonly keyHash: string;
  readonly text: string;
  readonly source: string;
  readonly timestampDesc: string;
  readonly firstSeenTs: string;
  readonly occurrences: number;
  readonly malicious?: number;
  readonly category?: string;
  readonly severity?: number;
  readonly severityLevel?: string;
  readonly needsAnalyst?: number;
  readonly error?: string;
}

export interface RowQuery {
  /** Free text, matched against the entry text. */
  readonly q?: string;
  /** Only rows at or above this malicious score. */
  readonly min?: number;
  readonly category?: string;
  /** "malicious" (default), "occurrences", or "time". */
  readonly sort?: "malicious" | "occurrences" | "time";
  readonly limit?: number;
  readonly offset?: number;
  /** Include rows that have no verdict yet. */
  readonly includeUndecided?: boolean;
}

export interface RowPage {
  readonly rows: readonly VerdictRow[];
  readonly total: number;
}

/** A directory listing for the file picker. A browser cannot hand over a real path. */
export interface BrowseResult {
  readonly path: string;
  readonly parent?: string;
  readonly dirs: readonly string[];
  /** CSV files only, with their size in bytes. */
  readonly files: readonly { readonly name: string; readonly bytes: number }[];
}

/** The event stream. One JSON object per SSE message. */
export type ServerEvent =
  | { readonly type: "job"; readonly job: JobStatus }
  | { readonly type: "state"; readonly state: ServerState }
  | { readonly type: "log"; readonly line: string };
