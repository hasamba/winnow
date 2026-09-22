// One job at a time, watched by any number of browser tabs.
//
// A judge pass over a real supertimeline runs for hours, so nothing here blocks an HTTP
// request. A POST starts a job and returns immediately; progress arrives on the event stream.
// Refusing a second concurrent job is deliberate: two judge passes against one decision cache
// would race on the same rows, and two scans would double every occurrence count.

import { basename } from "node:path";
import { statSync } from "node:fs";
import { DecisionStore } from "../triage/store.js";
import { scanTimeline, readHeaders } from "../triage/scan.js";
import { judgeUndecided } from "../triage/judge.js";
import { readTimeline } from "../plaso/flavor.js";
import { decisionKey, hashQuestions } from "../triage/key.js";
import { loadQuestions } from "../jev/questions.js";
import { loadApiKey, JEV_MODEL } from "../jev/client.js";
import { exportMalicious } from "../export/csv.js";
import { buildManifest, writeManifest, readToolInfo, sha256File } from "../export/manifest.js";
import { buildNarrator, type NarratorName } from "../narrate/provider.js";
import { narrate } from "../narrate/run.js";
import { DEFAULT_THRESHOLDS, type ScanReport, type Thresholds } from "../types.js";
import type { JobKind, JobStatus, ServerEvent, ServerState } from "./contract.js";

export interface JudgeOptions {
  readonly workers: number;
  readonly rareFirst: boolean;
  readonly maxCostUsd?: number;
  readonly limit?: number;
  readonly random?: boolean;
}

export interface NarrateOptions {
  readonly narrator: NarratorName;
  readonly model?: string;
  readonly groupBy: "host" | "none";
}

type Listener = (event: ServerEvent) => void;

/** Thrown when a second job is asked for while one is running. The route turns it into a 409. */
export class BusyError extends Error {
  constructor(running: JobKind) {
    super(`A ${running} job is already running. Cancel it or wait for it to finish.`);
    this.name = "BusyError";
  }
}

export class JobRunner {
  private listeners = new Set<Listener>();
  private store: DecisionStore | undefined;
  private controller: AbortController | undefined;

  private file: string | undefined;
  private dbPath: string | undefined;
  private job: JobStatus | undefined;
  private scanReport: ScanReport | undefined;
  private thresholds: Thresholds = DEFAULT_THRESHOLDS;
  private artifacts: { maliciousCsv?: string; manifest?: string; narratives: string[] } = {
    narratives: [],
  };

  constructor(private readonly questionsPath?: string) {}

  // ---- events -------------------------------------------------------------

  subscribe(listener: Listener): () => void {
    this.listeners.add(listener);
    listener({ type: "state", state: this.state() });
    return () => this.listeners.delete(listener);
  }

  private emit(event: ServerEvent): void {
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // A dead browser tab must never take down a running job.
      }
    }
  }

  private setJob(patch: Partial<JobStatus> & Pick<JobStatus, "kind" | "state">): void {
    this.job = {
      message: "",
      startedAt: this.job?.startedAt ?? new Date().toISOString(),
      ...this.job,
      ...patch,
    };
    this.emit({ type: "job", job: this.job });
  }

  // ---- state --------------------------------------------------------------

  questionsHash(): string {
    return hashQuestions(loadQuestions(this.questionsPath).json);
  }

  state(): ServerState {
    const counts = this.store?.counts();
    return {
      ...(this.file ? { file: this.file } : {}),
      ...(this.dbPath ? { dbPath: this.dbPath } : {}),
      ...(this.job ? { job: this.job } : {}),
      ...(this.scanReport ? { scan: this.scanReport } : {}),
      ...(counts ? { counts } : {}),
      thresholds: this.thresholds,
      artifacts: {
        ...(this.artifacts.maliciousCsv ? { maliciousCsv: this.artifacts.maliciousCsv } : {}),
        ...(this.artifacts.manifest ? { manifest: this.artifacts.manifest } : {}),
        narratives: [...this.artifacts.narratives],
      },
      questionsHash: this.questionsHash(),
    };
  }

  currentStore(): DecisionStore | undefined {
    return this.store;
  }

  currentFile(): string | undefined {
    return this.file;
  }

  setThresholds(t: Thresholds): void {
    this.thresholds = t;
    this.emit({ type: "state", state: this.state() });
  }

  isRunning(): boolean {
    return this.job?.state === "running";
  }

  cancel(): boolean {
    if (!this.isRunning()) return false;
    this.controller?.abort();
    return true;
  }

  close(): void {
    this.store?.close();
    this.store = undefined;
  }

  // ---- the jobs -----------------------------------------------------------

  /**
   * Refuse a second job, synchronously.
   *
   * This has to run in the caller, before `void this.run(...)` floats the promise: thrown
   * inside `run` it would become a discarded rejection, the route would answer 202, and the
   * process would log an unhandled rejection while the analyst saw a job that never started.
   * Every `start*` method calls this first, and the check and the start are one synchronous
   * block, so no second request can slip between them.
   */
  private claim(): void {
    if (this.isRunning()) throw new BusyError(this.job!.kind);
  }

  /**
   * Run `body` as the one active job. Errors are reported through the job status rather than
   * thrown, because nothing is waiting on the promise — the browser is watching events.
   */
  private async run(kind: JobKind, body: (signal: AbortSignal) => Promise<void>): Promise<void> {
    this.controller = new AbortController();
    this.job = { kind, state: "running", message: "Starting…", startedAt: new Date().toISOString() };
    this.emit({ type: "job", job: this.job });

    try {
      await body(this.controller.signal);
      this.setJob({
        kind,
        state: this.controller.signal.aborted ? "cancelled" : "done",
        finishedAt: new Date().toISOString(),
      });
    } catch (err) {
      this.setJob({
        kind,
        state: this.controller.signal.aborted ? "cancelled" : "error",
        error: err instanceof Error ? err.message : String(err),
        finishedAt: new Date().toISOString(),
      });
    } finally {
      this.emit({ type: "state", state: this.state() });
    }
  }

  async startScan(filePath: string): Promise<void> {
    this.claim();
    statSync(filePath); // throws a clear ENOENT before the job is claimed
    void this.run("scan", async () => {
      // A new file gets a new cache. Reopening the same one keeps every verdict already paid for.
      if (this.file !== filePath) {
        this.store?.close();
        this.store = undefined;
        this.scanReport = undefined;
        this.artifacts = { narratives: [] };
      }
      this.file = filePath;
      this.dbPath = `${filePath}.winnow.sqlite`;
      this.store ??= DecisionStore.open(this.dbPath);

      const questions = loadQuestions(this.questionsPath);
      this.store.meta.set("source_file", basename(filePath));

      this.scanReport = await scanTimeline({
        filePath,
        store: this.store,
        questionsHash: hashQuestions(questions.json),
        concurrency: 16,
        onProgress: (rows) =>
          this.setJob({ kind: "scan", state: "running", message: `${rows.toLocaleString()} rows read` }),
      });
      this.setJob({
        kind: "scan",
        state: "running",
        message: `${this.scanReport.distinctKeys.toLocaleString()} distinct entries`,
        progress: 1,
      });
    });
  }

  async startJudge(opts: JudgeOptions): Promise<void> {
    this.claim();
    const store = this.requireStore();
    const questions = loadQuestions(this.questionsPath);
    const apiKey = loadApiKey();

    void this.run("judge", async (signal) => {
      const result = await judgeUndecided({
        store,
        questions: questions.questions,
        apiKey,
        concurrency: opts.workers,
        rareFirst: opts.rareFirst,
        ...(opts.maxCostUsd !== undefined ? { maxCostUsd: opts.maxCostUsd } : {}),
        ...(opts.limit !== undefined ? { limit: opts.limit } : {}),
        ...(opts.random ? { random: true } : {}),
        signal,
        onProgress: (done, total, costUsd, errors) =>
          this.setJob({
            kind: "judge",
            state: "running",
            message: `${done.toLocaleString()} of ${total.toLocaleString()} judged`,
            progress: total === 0 ? 1 : done / total,
            costUsd,
            errors,
          }),
      });
      this.setJob({
        kind: "judge",
        state: "running",
        message: result.stoppedOnCost
          ? `Stopped at the cost ceiling after ${result.decided.toLocaleString()} entries`
          : `${result.decided.toLocaleString()} judged`,
        costUsd: result.costUsd,
        errors: result.errors,
        progress: 1,
      });
    });
  }

  async startExport(): Promise<void> {
    this.claim();
    const store = this.requireStore();
    const file = this.requireFile();
    const questions = loadQuestions(this.questionsPath);
    const questionsHash = hashQuestions(questions.json);
    const startedAt = new Date().toISOString();

    void this.run("export", async () => {
      const headers = await readHeaders(file);
      const lookup = store.verdictLookup();
      const outPath = `${file}.malicious.csv`;

      const result = await exportMalicious({
        rows: readTimeline(file),
        lookup: (row) => lookup.get(decisionKey(row, questionsHash).keyHash),
        headers,
        outPath,
        thresholds: this.thresholds,
      });

      const counts = store.counts();
      const manifestPath = `${file}.run.json`;
      const tool = await readToolInfo();
      await writeManifest(
        manifestPath,
        buildManifest({
          toolName: tool.name,
          toolVersion: tool.version,
          model: JEV_MODEL,
          questionsText: questions.json,
          questionsHash,
          thresholds: this.thresholds,
          sourcePath: file,
          sourceBytes: statSync(file).size,
          sourceSha256: await sha256File(file),
          totalRows: result.scanned,
          distinctKeys: counts.total,
          decidedKeys: counts.decided,
          erroredKeys: counts.errored,
          verdictsByCategory: store.stats(0).distribution,
          rowsWritten: result.written,
          startedAt,
          finishedAt: new Date().toISOString(),
          totalCostUsd: Number(store.meta.get("total_cost_usd") ?? 0),
          workers: 0,
        }),
      );

      this.artifacts = { ...this.artifacts, maliciousCsv: outPath, manifest: manifestPath };
      this.setJob({
        kind: "export",
        state: "running",
        message: `${result.written.toLocaleString()} of ${result.scanned.toLocaleString()} rows written`,
        progress: 1,
      });
    });
  }

  async startNarrate(opts: NarrateOptions): Promise<void> {
    this.claim();
    const csvPath = this.artifacts.maliciousCsv;
    if (!csvPath) throw new Error("Export the malicious CSV before narrating it.");
    const narrator = buildNarrator(opts.narrator, { ...(opts.model ? { model: opts.model } : {}) });

    void this.run("narrate", async () => {
      const result = await narrate({
        csvPath,
        narrator,
        outPath: `${csvPath.replace(/\.csv$/, "")}.narrative.md`,
        groupBy: opts.groupBy,
        onProgress: (stage, i, n) =>
          this.setJob({
            kind: "narrate",
            state: "running",
            message: `${stage} ${i}/${n}`,
            ...(n === 0 ? {} : { progress: i / n }),
          }),
      });
      this.artifacts = { ...this.artifacts, narratives: [...result.outPaths] };
      this.setJob({
        kind: "narrate",
        state: "running",
        message: `${result.rowsRead.toLocaleString()} rows read in ${result.chunks} pass(es)`,
        progress: 1,
      });
    });
  }

  private requireStore(): DecisionStore {
    if (!this.store) throw new Error("Scan a timeline first.");
    return this.store;
  }

  private requireFile(): string {
    if (!this.file) throw new Error("Scan a timeline first.");
    return this.file;
  }
}
