#!/usr/bin/env node
// The command line. Every command that costs money says what it will cost and waits for a
// yes, because the run size is not knowable until the file has been read.

import { createInterface } from "node:readline/promises";
import { basename, resolve } from "node:path";
import { statSync } from "node:fs";
import { DecisionStore } from "./triage/store.js";
import { scanTimeline, readHeaders } from "./triage/scan.js";
import { judgeUndecided } from "./triage/judge.js";
import { readTimeline } from "./plaso/flavor.js";
import { decisionKey, hashQuestions } from "./triage/key.js";
import { loadQuestions } from "./jev/questions.js";
import { loadApiKey, JEV_MODEL } from "./jev/client.js";
import { exportMalicious } from "./export/csv.js";
import { writeManifest, buildManifest, readToolInfo, sha256File } from "./export/manifest.js";
import { buildNarrator, type NarratorName } from "./narrate/provider.js";
import { narrate } from "./narrate/run.js";
import { DEFAULT_THRESHOLDS, type Thresholds } from "./types.js";
import { parseArgs, flagNumber, flagString, flagBool, USAGE, type ParsedArgs } from "./args.js";
import { loadEnvFiles } from "./env.js";
import { serve } from "./server/http.js";
import { DEFAULT_PORT } from "./server/contract.js";
import { num, usd, duration, percent, bytes, progressLine, endProgress } from "./format.js";

function requireFile(args: ParsedArgs): string {
  if (!args.file) {
    throw new Error(`${args.command} needs a file. See "triage help".`);
  }
  const path = resolve(args.file);
  statSync(path); // throws a clear ENOENT naming the path
  return path;
}

function dbPathFor(args: ParsedArgs, file: string): string {
  return flagString(args.flags, "db") ?? `${file}.winnow.sqlite`;
}

function thresholdsFrom(args: ParsedArgs): Thresholds {
  return {
    malicious: flagNumber(args.flags, "threshold", DEFAULT_THRESHOLDS.malicious),
    needsAnalyst: flagNumber(args.flags, "needs-analyst", DEFAULT_THRESHOLDS.needsAnalyst),
    confident: flagNumber(args.flags, "confident", DEFAULT_THRESHOLDS.confident),
  };
}

async function confirm(question: string, skip: boolean): Promise<boolean> {
  if (skip) return true;
  if (!process.stdin.isTTY) {
    throw new Error(`${question}\nNot a terminal — pass --yes to proceed without confirming.`);
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const answer = await rl.question(`${question} [y/N] `);
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

/** The shared opening of every command that touches the cache: questions, store, scan. */
async function prepare(args: ParsedArgs): Promise<{
  file: string;
  store: DecisionStore;
  questions: ReturnType<typeof loadQuestions>;
  questionsHash: string;
  workers: number;
}> {
  const file = requireFile(args);
  const questionsPath = flagString(args.flags, "questions");
  const questions = loadQuestions(questionsPath);
  const questionsHash = hashQuestions(questions.json);
  const store = DecisionStore.open(dbPathFor(args, file));
  store.meta.set("questions_hash", questionsHash);
  store.meta.set("source_file", basename(file));
  return { file, store, questions, questionsHash, workers: flagNumber(args.flags, "workers", envNumber("WINNOW_WORKERS", 16)) };
}

async function ensureScanned(
  args: ParsedArgs,
  ctx: Awaited<ReturnType<typeof prepare>>,
): Promise<ReturnType<typeof scanTimeline>> {
  process.stderr.write(`Reading ${basename(ctx.file)} (${bytes(statSync(ctx.file).size)})\n`);
  const report = await scanTimeline({
    filePath: ctx.file,
    store: ctx.store,
    questionsHash: ctx.questionsHash,
    concurrency: ctx.workers,
    onProgress: (rows) => progressLine(`  ${num(rows)} rows read`),
  });
  endProgress();
  return report;
}

function printScan(report: Awaited<ReturnType<typeof scanTimeline>>): void {
  const dupes = report.totalRows - report.distinctKeys;
  process.stdout.write(
    [
      `${num(report.totalRows)} rows · ${report.flavor} · ${report.earliest || "?"} → ${report.latest || "?"}`,
      `  ${num(report.distinctKeys)} distinct entries (${percent(dupes, report.totalRows)} duplicate)`,
      report.unparsedTimestamps > 0
        ? `  ${num(report.unparsedTimestamps)} rows had an unreadable timestamp`
        : "",
      `  ${num(report.undecidedKeys)} still to judge`,
      `  Estimate: ${usd(report.estimatedCostUsd)} · ${duration(report.estimatedSeconds)}`,
    ]
      .filter(Boolean)
      .join("\n") + "\n",
  );
}

async function cmdScan(args: ParsedArgs): Promise<void> {
  const ctx = await prepare(args);
  try {
    printScan(await ensureScanned(args, ctx));
    process.stderr.write("Nothing was sent anywhere. A scan is free and offline.\n");
  } finally {
    ctx.store.close();
  }
}

async function cmdSample(args: ParsedArgs): Promise<void> {
  const ctx = await prepare(args);
  try {
    const report = await ensureScanned(args, ctx);
    printScan(report);
    const n = Math.min(flagNumber(args.flags, "n", 500), report.undecidedKeys);
    if (n <= 0) {
      process.stdout.write("Nothing left to sample — every entry already has a verdict.\n");
      return;
    }
    const cost = n * 0.00003;
    if (!(await confirm(`Judge ${num(n)} random entries for about ${usd(cost)}?`, flagBool(args.flags, "yes")))) {
      process.stderr.write("Stopped.\n");
      return;
    }
    const result = await runJudge(args, ctx, { limit: n, random: true });
    process.stdout.write(`\n${num(result.decided)} judged, ${num(result.errors)} failed, ${usd(result.costUsd)}\n\n`);
    printStats(ctx.store);
    process.stdout.write(
      "\nRead those verdicts. If they do not look like an analyst's, edit questions.json\n" +
        "and run sample again — the wording is the part that decides the whole run.\n",
    );
  } finally {
    ctx.store.close();
  }
}

async function runJudge(
  args: ParsedArgs,
  ctx: Awaited<ReturnType<typeof prepare>>,
  opts: { limit?: number; random?: boolean } = {},
): Promise<Awaited<ReturnType<typeof judgeUndecided>>> {
  const apiKey = loadApiKey();
  const controller = new AbortController();
  const onSigint = (): void => {
    process.stderr.write("\nStopping. Verdicts already in hand are saved; rerun to continue.\n");
    controller.abort();
  };
  process.once("SIGINT", onSigint);
  try {
    const result = await judgeUndecided({
      store: ctx.store,
      questions: ctx.questions.questions,
      apiKey,
      concurrency: ctx.workers,
      rareFirst: flagBool(args.flags, "rare-first"),
      ...(args.flags["max-cost"] !== undefined
        ? { maxCostUsd: flagNumber(args.flags, "max-cost", Infinity) }
        : {}),
      ...(flagString(args.flags, "model") ? { model: flagString(args.flags, "model")! } : {}),
      ...(opts.limit !== undefined ? { limit: opts.limit } : {}),
      ...(opts.random ? { random: true } : {}),
      signal: controller.signal,
      onProgress: (done, total, cost, errors) =>
        progressLine(
          `  ${num(done)}/${num(total)} · ${usd(cost)} · ${num(errors)} failed · ${percent(done, total)}`,
        ),
    });
    endProgress();
    if (result.stoppedOnCost) {
      process.stderr.write(`Stopped at the --max-cost ceiling. Rerun to continue.\n`);
    }
    return result;
  } finally {
    process.removeListener("SIGINT", onSigint);
  }
}

function printStats(store: DecisionStore): void {
  const { distribution, topMalicious } = store.stats(25);
  process.stdout.write("Verdict distribution\n");
  for (const [category, count] of Object.entries(distribution).sort((a, b) => b[1] - a[1])) {
    process.stdout.write(`  ${category.padEnd(20)} ${num(count)}\n`);
  }
  if (topMalicious.length > 0) {
    process.stdout.write("\nHighest-scoring entries\n");
    for (const r of topMalicious) {
      const score = r.verdict?.malicious.toFixed(2) ?? "?";
      const text = r.keyText.split("\x1f").slice(2).join(" ").slice(0, 110);
      process.stdout.write(`  ${score}  ×${String(r.occurrences).padEnd(6)} ${text}\n`);
    }
  }
}

async function cmdJudge(args: ParsedArgs): Promise<void> {
  const ctx = await prepare(args);
  try {
    const report = await ensureScanned(args, ctx);
    printScan(report);
    if (report.undecidedKeys === 0) {
      process.stdout.write("Every entry already has a verdict.\n");
      return;
    }
    const question = `Judge ${num(report.undecidedKeys)} entries for about ${usd(report.estimatedCostUsd)} (${duration(report.estimatedSeconds)})?`;
    if (!(await confirm(question, flagBool(args.flags, "yes")))) {
      process.stderr.write("Stopped. Nothing was sent.\n");
      return;
    }
    const result = await runJudge(args, ctx);
    process.stdout.write(
      `\n${num(result.decided)} judged, ${num(result.errors)} failed, ${usd(result.costUsd)}\n\n`,
    );
    printStats(ctx.store);
  } finally {
    ctx.store.close();
  }
}

async function cmdExport(args: ParsedArgs): Promise<void> {
  const ctx = await prepare(args);
  const startedAt = new Date().toISOString();
  try {
    const headers = await readHeaders(ctx.file);
    const lookupMap = ctx.store.verdictLookup();
    const thresholds = thresholdsFrom(args);
    const outPath = flagString(args.flags, "out") ?? `${ctx.file}.malicious.csv`;

    const result = await exportMalicious({
      rows: readTimeline(ctx.file),
      lookup: (row) => lookupMap.get(decisionKey(row, ctx.questionsHash).keyHash),
      headers,
      outPath,
      thresholds,
    });

    const counts = ctx.store.counts();
    const manifestPath = `${ctx.file}.run.json`;
    const tool = await readToolInfo();
    await writeManifest(
      manifestPath,
      buildManifest({
        toolName: tool.name,
        toolVersion: tool.version,
        model: JEV_MODEL,
        questionsText: ctx.questions.json,
        questionsHash: ctx.questionsHash,
        thresholds,
        sourcePath: ctx.file,
        sourceBytes: statSync(ctx.file).size,
        sourceSha256: await sha256File(ctx.file),
        totalRows: result.scanned,
        distinctKeys: counts.total,
        decidedKeys: counts.decided,
        erroredKeys: counts.errored,
        verdictsByCategory: ctx.store.stats(0).distribution,
        rowsWritten: result.written,
        startedAt,
        finishedAt: new Date().toISOString(),
        totalCostUsd: Number(ctx.store.meta.get("total_cost_usd") ?? 0),
        workers: ctx.workers,
      }),
    );

    process.stdout.write(
      `${num(result.written)} of ${num(result.scanned)} rows written to ${basename(outPath)}\n` +
        (result.unjudged > 0
          ? `  ${num(result.unjudged)} rows had no verdict and were kept, flagged "unjudged"\n`
          : "") +
        `  Manifest: ${basename(manifestPath)}\n`,
    );
  } finally {
    ctx.store.close();
  }
}

async function cmdNarrate(args: ParsedArgs): Promise<void> {
  const file = requireFile(args);
  const name = (flagString(args.flags, "narrator") ??
    process.env["WINNOW_NARRATOR"] ??
    "claude-api") as NarratorName;
  const model = flagString(args.flags, "model") ?? process.env["WINNOW_MODEL"];
  const narrator = buildNarrator(name, { ...(model ? { model } : {}) });
  const outPath = flagString(args.flags, "out") ?? `${file.replace(/\.csv$/, "")}.narrative.md`;

  process.stderr.write(`Narrating with ${narrator.name} (${narrator.model})\n`);
  const result = await narrate({
    csvPath: file,
    narrator,
    outPath,
    groupBy: flagString(args.flags, "group-by") === "host" ? "host" : "none",
    onProgress: (stage, i, n) => progressLine(`  ${stage} ${i}/${n}`),
  });
  endProgress();
  process.stdout.write(
    `${num(result.rowsRead)} rows read in ${num(result.chunks)} ${result.chunks === 1 ? "pass" : "passes"}\n` +
      result.outPaths.map((p) => `  ${basename(p)}\n`).join(""),
  );
}

async function cmdRun(args: ParsedArgs): Promise<void> {
  await cmdJudge(args);
  await cmdExport(args);
  if (flagString(args.flags, "narrator") ?? process.env["WINNOW_NARRATOR"]) {
    const file = resolve(args.file);
    await cmdNarrate({
      ...args,
      command: "narrate",
      file: flagString(args.flags, "out") ?? `${file}.malicious.csv`,
    });
  } else {
    process.stderr.write("\nNo --narrator given, so step 2 was skipped.\n");
  }
}

async function cmdServe(args: ParsedArgs): Promise<void> {
  const questionsPath = flagString(args.flags, "questions");
  const { url } = await serve({
    port: flagNumber(args.flags, "port", envNumber("WINNOW_PORT", DEFAULT_PORT)),
    ...(questionsPath ? { questionsPath } : {}),
    open: !flagBool(args.flags, "no-open"),
  });
  process.stdout.write(`winnow dashboard: ${url}\n`);
  process.stdout.write("Loopback only. Press Ctrl-C to stop.\n");
  // Hold the process open; the server keeps the event loop alive on its own, and a job in
  // flight must not be cut short by the CLI returning.
  await new Promise<void>((resolve) => process.once("SIGINT", () => resolve()));
  process.stderr.write("\nStopped. Verdicts already judged are saved.\n");
}

const HANDLERS: Record<string, (args: ParsedArgs) => Promise<void>> = {
  serve: cmdServe,
  scan: cmdScan,
  sample: cmdSample,
  judge: cmdJudge,
  export: cmdExport,
  narrate: cmdNarrate,
  run: cmdRun,
};

/** A numeric default from the environment, ignoring anything unparseable. */
function envNumber(name: string, fallback: number): number {
  const raw = process.env[name];
  const parsed = raw === undefined ? NaN : Number(raw);
  return Number.isFinite(parsed) ? parsed : fallback;
}

async function main(): Promise<void> {
  loadEnvFiles();
  const args = parseArgs(process.argv.slice(2));
  const handler = HANDLERS[args.command];
  if (!handler) {
    process.stdout.write(USAGE);
    process.exitCode = args.command === "help" ? 0 : 1;
    return;
  }
  await handler(args);
}

main().catch((err: unknown) => {
  // The message is for an analyst, not a stack trace reader. The stack goes to --debug only.
  process.stderr.write(`\nError: ${err instanceof Error ? err.message : String(err)}\n`);
  if (process.argv.includes("--debug") && err instanceof Error) {
    process.stderr.write(`${err.stack}\n`);
  }
  process.exitCode = 1;
});
