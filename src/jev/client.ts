// The Jev (TypeSafe System One) decisions client: one HTTP call per distinct timeline row,
// four questions in that one call. Ported from ~/.claude/skills/jev-sort/jev.py (`ask` and
// `flatten`), which is the runner that has been proven against the live API.
//
// Three facts, each of which has already cost a debugging session:
//
//  1. The endpoint is `POST https://openrouter.ai/api/alpha/decisions`, NOT
//     `/v1/chat/completions`. It is an alpha route and it has already moved once, so it
//     lives in exactly one exported constant below.
//  2. The model id is exactly `typesafe/jev-1.13`. Both `typesafe/jev-latest` and
//     `typesafe/jev` answer `400 Model does not exist` on OpenRouter — `jev-latest` is an
//     alias on TypeSafe's own host only. One exported constant, bumped when a version lands.
//  3. Jev is absent from `GET /api/v1/models`. That catalogue lists chat models only, so its
//     absence there is not evidence that the model is gone. Do not "fix" the id from it.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import type { JevState, QuestionSet, Verdict } from "../types.js";

/** Fact 1. The alpha decisions route. Change it here and nowhere else. */
export const JEV_ENDPOINT = "https://openrouter.ai/api/alpha/decisions";

/** Fact 2. The pinned model id. `jev-latest` and `jev` both 400 on OpenRouter. */
export const JEV_MODEL = "typesafe/jev-1.13";

/** The four question ids the exporter depends on, in the order a verdict reads. */
export const REQUIRED_ANSWER_IDS = ["malicious", "category", "severity", "needs_analyst"] as const;

/** Statuses worth trying again: rate limits, and the gateway's own bad days. */
const RETRY_STATUSES: ReadonlySet<number> = new Set([429, 500, 502, 503, 524, 529]);

const DEFAULT_RETRIES = 4;
const FIRST_BACKOFF_MS = 1000;
const ERROR_BODY_CHARS = 400;
const KEY_ENV_VAR = "OPENROUTER_API_KEY";
const KEY_LINE_PREFIX = `${KEY_ENV_VAR}=`;

/** What one call produced: a verdict, or an error, plus what it cost and how long it took. */
export interface JevCallResult {
  readonly verdict?: Verdict;
  readonly error?: string;
  readonly costUsd: number;
  readonly seconds: number;
}

export interface AskJevOptions {
  readonly model?: string;
  readonly retries?: number;
  readonly signal?: AbortSignal;
  /** Injected so tests never touch the network. */
  readonly fetchImpl?: typeof fetch;
  /** Injected so tests never actually wait out a backoff. */
  readonly sleep?: (ms: number) => Promise<void>;
}

const realSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Read the OpenRouter API key: the environment first, then the key file at
 * `~/.config/typesafe/openrouter.env` (mode 600, outside every git repo).
 *
 * THE KEY IS A SECRET. It is never logged, never put into an Error message, never written
 * into the run manifest or any other output file. The only place it goes is the
 * Authorization header of the request below. Keep it that way.
 */
export function loadApiKey(env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv = env[KEY_ENV_VAR]?.trim();
  if (fromEnv) return fromEnv;

  const home = env["HOME"] ?? homedir();
  const keyFile = join(home, ".config", "typesafe", "openrouter.env");
  if (existsSync(keyFile)) {
    for (const line of readFileSync(keyFile, "utf8").split(/\r?\n/)) {
      if (!line.startsWith(KEY_LINE_PREFIX)) continue;
      const value = line.slice(KEY_LINE_PREFIX.length).trim();
      if (value) return value;
    }
  }
  // Names both sources and carries no key material of its own.
  throw new Error(
    `No OpenRouter API key. Set the ${KEY_ENV_VAR} environment variable, ` +
      `or write the line "${KEY_LINE_PREFIX}<your key>" into ${keyFile} and chmod it 600.`,
  );
}

/**
 * Ask Jev every question about one row, in one call.
 *
 * `state` is sent as the object it is — never flattened into a string. Structured records
 * decide better than concatenated lines (jev-sort rule 2).
 */
export async function askJev(
  state: JevState,
  questions: QuestionSet,
  key: string,
  opts: AskJevOptions = {},
): Promise<JevCallResult> {
  const doFetch = opts.fetchImpl ?? fetch;
  const sleep = opts.sleep ?? realSleep;
  const retries = Math.max(1, opts.retries ?? DEFAULT_RETRIES);
  const body = JSON.stringify({ model: opts.model ?? JEV_MODEL, state, questions });
  const started = Date.now();
  const elapsed = (): number => Math.round((Date.now() - started)) / 1000;

  let delay = FIRST_BACKOFF_MS;
  let lastError = "no attempt was made";

  for (let attempt = 0; attempt < retries; attempt += 1) {
    if (opts.signal?.aborted) return { error: "aborted", costUsd: 0, seconds: elapsed() };
    try {
      const response = await doFetch(JEV_ENDPOINT, {
        method: "POST",
        headers: {
          // The one place the key is used. Never echoed anywhere else.
          Authorization: `Bearer ${key}`,
          "Content-Type": "application/json",
        },
        body,
        ...(opts.signal ? { signal: opts.signal } : {}),
      });

      if (!response.ok) {
        const detail = (await readBodyText(response)).slice(0, ERROR_BODY_CHARS);
        if (RETRY_STATUSES.has(response.status) && attempt < retries - 1) {
          await sleep(delay);
          delay *= 2;
          continue;
        }
        // A 4xx that is not 429 is the caller's fault and will fail identically forever.
        return { error: httpErrorText(response.status, detail), costUsd: 0, seconds: elapsed() };
      }

      const parsed = parseJson(await readBodyText(response));
      if (parsed === undefined) {
        return { error: "the response body was not JSON", costUsd: 0, seconds: elapsed() };
      }
      const payload = asRecord(parsed);
      const costUsd = readCost(payload?.["usage"]);
      const verdict = flattenAnswers(payload?.["answers"]);
      if (!verdict) {
        // A 200 whose answers do not parse is deterministic; retrying only spends money.
        return { error: "the response carried no usable answers", costUsd, seconds: elapsed() };
      }
      return { verdict, costUsd, seconds: elapsed() };
    } catch (err) {
      lastError = describeThrown(err);
      if (opts.signal?.aborted) return { error: lastError, costUsd: 0, seconds: elapsed() };
      if (attempt < retries - 1) {
        await sleep(delay);
        delay *= 2;
        continue;
      }
      return { error: lastError, costUsd: 0, seconds: elapsed() };
    }
  }
  return { error: lastError, costUsd: 0, seconds: elapsed() };
}

/**
 * Turn the API's `answers` map into a Verdict — the port of jev.py's `flatten()`.
 *
 * A `noul` answer yields its number; a `choice` yields the pick plus its confidence; a
 * `score` yields the number, its confidence, and the level name looked up in that answer's
 * own `legend` by the rounded score.
 *
 * This is an external API response and is not trusted. Anything malformed returns undefined
 * rather than throwing, so one odd row cannot end a 300,000-row run.
 */
export function flattenAnswers(answers: unknown): Verdict | undefined {
  const map = asRecord(answers);
  if (!map) return undefined;
  for (const id of REQUIRED_ANSWER_IDS) {
    if (!(id in map)) return undefined;
  }

  const malicious = readNoul(map["malicious"]);
  const needsAnalyst = readNoul(map["needs_analyst"]);
  const category = readChoice(map["category"]);
  const severity = readScore(map["severity"]);
  if (malicious === undefined || needsAnalyst === undefined || !category || !severity) {
    return undefined;
  }

  return {
    malicious,
    category: category.choice,
    categoryConfidence: category.confidence,
    severity: severity.score,
    severityLevel: severity.level,
    needsAnalyst,
  };
}

/** A noul answer: one number, 0 = no to 1 = yes. It carries no confidence field. */
function readNoul(answer: unknown): number | undefined {
  const a = asRecord(answer);
  if (!a || a["type"] !== "noul") return undefined;
  return finiteNumber(a["noul"]);
}

function readChoice(answer: unknown): { choice: string; confidence: number } | undefined {
  const a = asRecord(answer);
  if (!a || a["type"] !== "choice") return undefined;
  const choice = a["choice"];
  if (typeof choice !== "string" || choice === "") return undefined;
  return { choice, confidence: finiteNumber(a["confidence"]) ?? 0 };
}

function readScore(answer: unknown): { score: number; level: string } | undefined {
  const a = asRecord(answer);
  if (!a || a["type"] !== "score") return undefined;
  const score = finiteNumber(a["score"]);
  if (score === undefined) return undefined;
  const legend = asRecord(a["legend"]);
  const named = legend?.[String(Math.round(score))];
  // A legend is a convenience, not a contract: no entry means no level name, not a failure.
  return { score, level: typeof named === "string" ? named : "" };
}

function readCost(usage: unknown): number {
  return finiteNumber(asRecord(usage)?.["cost"]) ?? 0;
}

function httpErrorText(status: number, detail: string): string {
  if (status === 422) {
    // 422 is always a malformed question; the body names the offending field.
    return `HTTP 422: a malformed question in questions.json. The API said: ${detail}`;
  }
  return `HTTP ${status}: ${detail}`;
}

function describeThrown(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  return String(err);
}

async function readBodyText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return "";
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function finiteNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}
