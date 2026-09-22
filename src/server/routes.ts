// The request handler. One function, one switch, no framework: the whole API is twenty
// endpoints over a loopback socket, and a router dependency would be more code than this file.
//
// Two rules run through everything here.
//
// 1. NO PATH PARAMETER IS EVER OPENED ON TRUST. This process reads the analyst's whole disk —
//    that is the point of it — so "?path=" on a download is an arbitrary-file-read primitive
//    unless it is checked. It is checked against the allowlist of paths the runner itself
//    produced, never sanitised. Sanitising is a losing game (".."; a symlink; "....//"; a
//    UNC path; percent-encoding), and it answers the wrong question: the question is not
//    "does this path look safe" but "is this one of the three files we just wrote".
// 2. No CORS header, anywhere. The server binds to loopback, so a page on another origin has
//    no business reading a case. Not sending Access-Control-Allow-Origin is what stops it.

import { createReadStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadQuestions, validateQuestions } from "../jev/questions.js";
import type { DecisionStore } from "../triage/store.js";
import type { NarratorName } from "../narrate/provider.js";
import { hashQuestions } from "../triage/key.js";
import type { Thresholds } from "../types.js";
import { browse } from "./browse.js";
import type { RowQuery, ServerEvent } from "./contract.js";
import { BusyError, type JobRunner, type JudgeOptions, type NarrateOptions } from "./jobs.js";
import { queryRows } from "./rows.js";

export interface RouteContext {
  readonly runner: JobRunner;
  readonly questionsPath?: string;
  readonly publicDir: string;
}

/**
 * The cap on a JSON request body. Every body this API takes is a handful of settings; a
 * megabyte is already three orders of magnitude more than the largest of them. An oversize
 * body is DISCARDED as it arrives rather than buffered, so it costs loopback bandwidth and
 * no memory.
 */
const MAX_BODY_BYTES = 1024 * 1024;

/**
 * A silent event stream is indistinguishable from a dead one. A proxy, a laptop that slept,
 * or a NAT table that timed out will drop a connection that says nothing for minutes, and the
 * dashboard would sit watching a socket that will never speak again while a four-hour judge
 * pass runs on the other side of it. The comment frame carries no data; it only proves the
 * connection is still there.
 */
const HEARTBEAT_MS = 20_000;

/** How many of the worst offenders the dashboard's summary panel shows. */
const STATS_LIMIT = 25;

/** questions.json sits at the package root, two levels up from src/server and from dist/server. */
const DEFAULT_QUESTIONS_PATH = fileURLToPath(new URL("../../questions.json", import.meta.url));

const NARRATORS: readonly NarratorName[] = ["openrouter", "claude-api", "claude-cli", "codex-cli"];
const SORTS: readonly NonNullable<RowQuery["sort"]>[] = ["malicious", "occurrences", "time"];

const JSON_TYPE = "application/json; charset=utf-8";

/** An error that already knows what the status code should be. */
class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: RouteContext,
): Promise<void> {
  // On every response, including the errors and the static files: the dashboard renders
  // strings an adversary wrote into a timeline, and a browser must never be free to decide
  // for itself that one of them is HTML.
  res.setHeader("X-Content-Type-Options", "nosniff");

  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  try {
    await route(req, res, url, ctx);
  } catch (err) {
    sendError(res, err);
  }
}

async function route(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  ctx: RouteContext,
): Promise<void> {
  const { runner } = ctx;
  const method = req.method ?? "GET";
  const path = url.pathname;

  if (method === "GET" || method === "HEAD") {
    switch (path) {
      case "/":
      case "/index.html":
        return sendFile(res, join(ctx.publicDir, "dashboard.html"), "text/html; charset=utf-8");
      case "/app.js":
        return sendFile(res, join(ctx.publicDir, "app.js"), "text/javascript; charset=utf-8");
      case "/app.css":
        return sendFile(res, join(ctx.publicDir, "app.css"), "text/css; charset=utf-8");
      case "/api/state":
        return sendJson(res, 200, runner.state());
      case "/api/browse":
        return sendJson(res, 200, browseOr400(url.searchParams.get("path")));
      case "/api/rows":
        return sendJson(res, 200, queryRows(requireStore(runner), rowQuery(url)));
      case "/api/stats":
        return sendJson(res, 200, requireStore(runner).stats(STATS_LIMIT));
      case "/api/questions": {
        const json = loadQuestions(ctx.questionsPath).json;
        return sendJson(res, 200, { json, hash: hashQuestions(json) });
      }
      case "/api/narrative":
        return sendNarrative(res, url.searchParams.get("path"), runner);
      case "/api/download":
        return sendDownload(res, url.searchParams.get("path"), runner);
      case "/events":
        return sendEvents(req, res, runner);
      default:
        throw new HttpError(404, `No route for ${method} ${path}.`);
    }
  }

  if (method === "POST") {
    const body = await readJsonBody(req);
    switch (path) {
      case "/api/scan": {
        const file = requireString(body, "file");
        requireIdle(runner);
        await startScan(runner, file);
        return sendJson(res, 202, { started: "scan" });
      }
      case "/api/judge": {
        const opts = judgeOptions(body);
        requireIdle(runner);
        await runner.startJudge(opts);
        return sendJson(res, 202, { started: "judge" });
      }
      case "/api/export": {
        requireIdle(runner);
        await runner.startExport();
        return sendJson(res, 202, { started: "export" });
      }
      case "/api/narrate": {
        const opts = narrateOptions(body);
        requireIdle(runner);
        await runner.startNarrate(opts);
        return sendJson(res, 202, { started: "narrate" });
      }
      case "/api/cancel":
        return sendJson(res, 200, { cancelled: runner.cancel() });
      case "/api/thresholds": {
        const thresholds = readThresholds(body);
        runner.setThresholds(thresholds);
        return sendJson(res, 200, thresholds);
      }
      default:
        throw new HttpError(404, `No route for ${method} ${path}.`);
    }
  }

  if (method === "PUT" && path === "/api/questions") {
    const body = await readJsonBody(req);
    return writeQuestions(res, body, ctx);
  }

  throw new HttpError(405, `${method} is not allowed on ${path}.`);
}

// ---- the jobs -------------------------------------------------------------------------

/**
 * The runner refuses a second job by throwing BusyError out of its own promise, which nothing
 * awaits — so the route asks first. This is the whole concurrency control: it and the call it
 * guards run in one synchronous block, and Node gives us no second request in the middle of it.
 */
function requireIdle(runner: JobRunner): void {
  const job = runner.state().job;
  if (runner.isRunning() && job !== undefined) throw new BusyError(job.kind);
}

async function startScan(runner: JobRunner, file: string): Promise<void> {
  try {
    await runner.startScan(file);
  } catch (err) {
    // startScan stats the file before it claims the job, so a bad path fails here. The path
    // came out of the request, which makes this the analyst's typo, not a server fault.
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "EACCES" || code === "EISDIR") {
      throw new HttpError(400, `Cannot read ${file}: ${(err as Error).message}`);
    }
    throw err;
  }
}

function judgeOptions(body: Record<string, unknown>): JudgeOptions {
  const workers = optionalNumber(body, "workers") ?? 8;
  if (!Number.isInteger(workers) || workers < 1 || workers > 256) {
    throw new HttpError(400, `"workers" must be a whole number from 1 to 256.`);
  }
  const maxCostUsd = optionalNumber(body, "maxCostUsd");
  const limit = optionalNumber(body, "limit");
  if (maxCostUsd !== undefined && maxCostUsd <= 0) {
    throw new HttpError(400, `"maxCostUsd" must be greater than zero.`);
  }
  if (limit !== undefined && (!Number.isInteger(limit) || limit < 1)) {
    throw new HttpError(400, `"limit" must be a whole number of at least 1.`);
  }
  return {
    workers,
    rareFirst: optionalBoolean(body, "rareFirst") ?? false,
    ...(maxCostUsd !== undefined ? { maxCostUsd } : {}),
    ...(limit !== undefined ? { limit } : {}),
    ...(optionalBoolean(body, "random") !== undefined
      ? { random: optionalBoolean(body, "random") === true }
      : {}),
  };
}

function narrateOptions(body: Record<string, unknown>): NarrateOptions {
  const narrator = requireString(body, "narrator");
  if (!NARRATORS.includes(narrator as NarratorName)) {
    throw new HttpError(400, `"narrator" must be one of ${NARRATORS.join(", ")}.`);
  }
  const groupBy = body["groupBy"] ?? "host";
  if (groupBy !== "host" && groupBy !== "none") {
    throw new HttpError(400, `"groupBy" must be "host" or "none".`);
  }
  const model = body["model"];
  if (model !== undefined && typeof model !== "string") {
    throw new HttpError(400, `"model" must be a string.`);
  }
  return {
    narrator: narrator as NarratorName,
    groupBy,
    ...(typeof model === "string" && model !== "" ? { model } : {}),
  };
}

function readThresholds(body: Record<string, unknown>): Thresholds {
  const read = (name: keyof Thresholds): number => {
    const value = body[name];
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0 || value > 1) {
      throw new HttpError(400, `"${name}" must be a number from 0 to 1.`);
    }
    return value;
  };
  return { malicious: read("malicious"), needsAnalyst: read("needsAnalyst"), confident: read("confident") };
}

// ---- questions ------------------------------------------------------------------------

async function writeQuestions(
  res: ServerResponse,
  body: Record<string, unknown>,
  ctx: RouteContext,
): Promise<void> {
  // Refused mid-run, before the file is even parsed. The questions text is folded into every
  // decision key, so saving a new one while a judge pass is in flight would leave one cache
  // holding answers to two different question sets, with no way to tell which row got which.
  const job = ctx.runner.state().job;
  if (ctx.runner.isRunning() && job !== undefined) {
    throw new HttpError(
      409,
      `A ${job.kind} job is running. Editing the questions now would mix two question sets ` +
        `into one decision cache. Wait for it to finish, or cancel it.`,
    );
  }

  const json = requireString(body, "json");
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    throw new HttpError(400, `That is not valid JSON: ${(err as Error).message}`);
  }
  try {
    // Validated before a byte is written: a malformed question costs a failed call per row,
    // and the error names the question so the analyst knows which one to fix.
    validateQuestions(parsed);
  } catch (err) {
    throw new HttpError(400, (err as Error).message);
  }

  await writeFile(ctx.questionsPath ?? DEFAULT_QUESTIONS_PATH, json, "utf8");
  return sendJson(res, 200, { hash: hashQuestions(json) });
}

// ---- the artifacts --------------------------------------------------------------------

/**
 * The allowlist: the paths the runner itself wrote in this session, and nothing else.
 *
 * Membership is an exact string match against what the runner reports. No resolve(), no
 * realpath(), no prefix check — a path that is not literally one of these is refused, which
 * is the only test that cannot be talked around by a cleverer spelling of "/etc/shadow".
 */
function producedPaths(runner: JobRunner): readonly string[] {
  const { artifacts } = runner.state();
  return [
    ...(artifacts.maliciousCsv !== undefined ? [artifacts.maliciousCsv] : []),
    ...(artifacts.manifest !== undefined ? [artifacts.manifest] : []),
    ...artifacts.narratives,
  ];
}

function requireProduced(path: string | null, allowed: readonly string[]): string {
  if (path === null || path === "") throw new HttpError(400, `A "path" parameter is required.`);
  if (!allowed.includes(path)) {
    // The message says nothing about whether the file exists. Answering "no such file" for
    // one path and "forbidden" for another turns this endpoint into a directory oracle.
    throw new HttpError(403, `That path is not one of this run's artifacts.`);
  }
  return path;
}

async function sendNarrative(
  res: ServerResponse,
  path: string | null,
  runner: JobRunner,
): Promise<void> {
  const allowed = runner.state().artifacts.narratives;
  const file = requireProduced(path, allowed);
  return sendFile(res, file, "text/markdown; charset=utf-8");
}

function sendDownload(res: ServerResponse, path: string | null, runner: JobRunner): void {
  const file = requireProduced(path, producedPaths(runner));
  const name = basename(file).replace(/["\\\r\n]/g, "_");
  res.writeHead(200, {
    "Content-Type": contentTypeFor(file),
    "Content-Disposition": `attachment; filename="${name}"`,
    "X-Content-Type-Options": "nosniff",
  });
  const stream = createReadStream(file);
  // The response headers are already out, so a read failure can only be reported by hanging
  // up. An analyst sees a truncated download, which is the honest signal.
  stream.on("error", () => res.destroy());
  stream.pipe(res);
}

function contentTypeFor(file: string): string {
  if (file.endsWith(".csv")) return "text/csv; charset=utf-8";
  if (file.endsWith(".json")) return JSON_TYPE;
  if (file.endsWith(".md")) return "text/markdown; charset=utf-8";
  return "application/octet-stream";
}

// ---- the event stream -----------------------------------------------------------------

function sendEvents(req: IncomingMessage, res: ServerResponse, runner: JobRunner): void {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "X-Content-Type-Options": "nosniff",
  });
  res.flushHeaders();

  const heartbeat = setInterval(() => res.write(": keep-alive\n\n"), HEARTBEAT_MS);
  // The stream must not be a reason the process stays up after the last tab closes.
  heartbeat.unref();

  const unsubscribe = runner.subscribe((event: ServerEvent) => {
    res.write(`data: ${JSON.stringify(event)}\n\n`);
  });

  let stopped = false;
  const stop = (): void => {
    if (stopped) return;
    stopped = true;
    clearInterval(heartbeat);
    // Unsubscribed on close, or every closed tab would leave a listener writing to a dead
    // socket for the rest of the run.
    unsubscribe();
  };
  req.on("close", stop);
  res.on("close", stop);
}

// ---- request and response plumbing ------------------------------------------------------

function requireStore(runner: JobRunner): DecisionStore {
  const store = runner.currentStore();
  if (store === undefined) throw new HttpError(409, "Scan a timeline first.");
  return store;
}

function browseOr400(path: string | null): ReturnType<typeof browse> {
  try {
    return browse(path ?? undefined);
  } catch (err) {
    // The path came from the request, so an unreadable or missing directory is a bad
    // parameter, not a server fault.
    throw new HttpError(400, `Cannot list that directory: ${(err as Error).message}`);
  }
}

function rowQuery(url: URL): RowQuery {
  const params = url.searchParams;
  const q = params.get("q");
  const min = numberParam(params.get("min"), "min");
  const category = params.get("category");
  const sort = params.get("sort");
  if (sort !== null && !SORTS.includes(sort as NonNullable<RowQuery["sort"]>)) {
    throw new HttpError(400, `"sort" must be one of ${SORTS.join(", ")}.`);
  }
  return {
    ...(q !== null && q !== "" ? { q } : {}),
    ...(min !== undefined ? { min } : {}),
    ...(category !== null && category !== "" ? { category } : {}),
    ...(sort !== null ? { sort: sort as NonNullable<RowQuery["sort"]> } : {}),
    ...(numberParam(params.get("limit"), "limit") !== undefined
      ? { limit: numberParam(params.get("limit"), "limit") as number }
      : {}),
    ...(numberParam(params.get("offset"), "offset") !== undefined
      ? { offset: numberParam(params.get("offset"), "offset") as number }
      : {}),
    ...(isTrue(params.get("includeUndecided")) ? { includeUndecided: true } : {}),
  };
}

function isTrue(value: string | null): boolean {
  return value === "1" || value === "true" || value === "yes";
}

function numberParam(value: string | null, name: string): number | undefined {
  if (value === null || value === "") return undefined;
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) throw new HttpError(400, `"${name}" must be a number.`);
  return parsed;
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  let oversize = false;

  for await (const chunk of req) {
    const buffer = chunk as Buffer;
    bytes += buffer.length;
    if (bytes > MAX_BODY_BYTES) {
      // Past the cap nothing more is kept, but the rest is still read off the socket so the
      // client gets a 413 rather than a connection reset it cannot interpret.
      oversize = true;
      chunks.length = 0;
      continue;
    }
    chunks.push(buffer);
  }

  if (oversize) {
    throw new HttpError(413, `The request body is larger than ${MAX_BODY_BYTES} bytes.`);
  }

  const text = Buffer.concat(chunks).toString("utf8");
  if (text.trim() === "") return {};

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new HttpError(400, `The request body is not valid JSON: ${(err as Error).message}`);
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new HttpError(400, "The request body must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

function requireString(body: Record<string, unknown>, name: string): string {
  const value = body[name];
  if (typeof value !== "string" || value === "") {
    throw new HttpError(400, `"${name}" must be a non-empty string.`);
  }
  return value;
}

function optionalNumber(body: Record<string, unknown>, name: string): number | undefined {
  const value = body[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new HttpError(400, `"${name}" must be a number.`);
  }
  return value;
}

function optionalBoolean(body: Record<string, unknown>, name: string): boolean | undefined {
  const value = body[name];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "boolean") throw new HttpError(400, `"${name}" must be true or false.`);
  return value;
}

async function sendFile(res: ServerResponse, file: string, contentType: string): Promise<void> {
  let data: Buffer;
  try {
    data = await readFile(file);
  } catch {
    throw new HttpError(404, `${basename(file)} is not there.`);
  }
  res.writeHead(200, {
    "Content-Type": contentType,
    "Content-Length": data.byteLength,
    "X-Content-Type-Options": "nosniff",
  });
  res.end(data);
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": JSON_TYPE,
    "Content-Length": Buffer.byteLength(text),
    "X-Content-Type-Options": "nosniff",
  });
  res.end(text);
}

/**
 * The one place a status code is decided for a thrown error.
 *
 * The body carries the message and never a stack: a stack names this machine's directory
 * layout and this tool's internals, and it would be read by whoever the analyst forwards a
 * screenshot to.
 */
function sendError(res: ServerResponse, err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  const status =
    err instanceof HttpError
      ? err.status
      : err instanceof BusyError || isPreconditionMessage(message)
        ? 409
        : 500;

  if (res.headersSent) {
    // A download or an event stream that failed mid-flight. The status is long gone; hanging
    // up is the only signal left.
    res.destroy();
    return;
  }
  sendJson(res, status, { error: message });
}

/**
 * The runner's two "you are not in a state to ask for this" errors. Both are 409 rather than
 * 500: nothing is broken, the step before this one simply has not been run.
 */
function isPreconditionMessage(message: string): boolean {
  return (
    message === "Scan a timeline first." || message === "Export the malicious CSV before narrating it."
  );
}
