// The narrator contract: one call in, prose out.
//
// The shapes here are a narrowed copy of DFIR Companion's `AIProvider` family
// (companion/src/providers/provider.ts), so this folder can be lifted back into that repo with
// the names it already uses. What is dropped: images, thinking budgets, token accounting and the
// provider registry. What is kept: the error kinds, the HTTP status mapping and the combined
// timeout/cancel signal.
//
// SECRET HANDLING — a rule, not a preference. An API key never appears in an error message, in a
// log line, in a process argument list or in any file this tool writes. Every message built from a
// provider's own response body goes through `redact()` first, because a provider that echoes the
// submitted key back in its error body would otherwise put it on an analyst's screen and into a
// case file. Never add a message that interpolates `opts.apiKey`.

import { homedir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";

// The four provider modules import this one back. ESM resolves the cycle because
// buildNarrator only touches these classes when it is called, long after both modules load.
import { OpenRouterNarrator } from "./openrouter.js";
import { AnthropicNarrator } from "./anthropic.js";
import { ClaudeCliNarrator } from "./claudeCli.js";
import { CodexCliNarrator } from "./codexCli.js";

export type NarratorName = "openrouter" | "claude-api" | "claude-cli" | "codex-cli";

export type NarratorErrorKind =
  | "auth"
  | "rate_limit"
  | "timeout"
  | "transport"
  | "context"
  | "not_installed"
  | "other";

export interface NarrateRequest {
  systemPrompt: string;
  userPrompt: string;
  maxTokens?: number;
  signal?: AbortSignal;
}

export interface NarrateResult {
  text: string;
  /** Real dollars, when the provider reports them. OpenRouter is the only one of the four. */
  costUsd?: number;
  /** The concrete model the provider served the call with, when it says. */
  model?: string;
}

export interface Narrator {
  readonly name: NarratorName;
  readonly model: string;
  generate(req: NarrateRequest): Promise<NarrateResult>;
}

export class NarratorError extends Error {
  constructor(
    message: string,
    readonly kind: NarratorErrorKind,
  ) {
    super(message);
    this.name = "NarratorError";
  }
}

// ── injection points ───────────────────────────────────────────────────────────────────────

export type FetchFn = typeof fetch;

/** The part of a spawned child this module uses. A real ChildProcess satisfies it. */
export interface ChildLike {
  readonly stdin: { write(chunk: string): unknown; end(): unknown } | null;
  readonly stdout: { on(event: "data", cb: (chunk: Buffer | string) => void): unknown } | null;
  readonly stderr: { on(event: "data", cb: (chunk: Buffer | string) => void): unknown } | null;
  on(event: "error", cb: (err: NodeJS.ErrnoException) => void): unknown;
  on(event: "close", cb: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
  kill(signal?: NodeJS.Signals): unknown;
}

export interface SpawnOptionsLike {
  readonly cwd?: string;
  readonly stdio?: readonly ["pipe", "pipe", "pipe"];
}

export type SpawnFn = (
  command: string,
  args: readonly string[],
  options: SpawnOptionsLike,
) => ChildLike;

export interface NarratorOptions {
  model?: string;
  apiKey?: string;
  baseUrl?: string;
  fetchImpl?: FetchFn;
  spawnImpl?: SpawnFn;
  timeoutMs?: number;
}

/** A narrative is prose, not a document dump: a few thousand tokens is a generous ceiling. */
export const DEFAULT_MAX_TOKENS = 8_000;
/** An HTTP narration call is one round trip; a CLI one drives a local agent and takes far longer. */
export const DEFAULT_HTTP_TIMEOUT_MS = 180_000;
export const DEFAULT_CLI_TIMEOUT_MS = 900_000;

// ── errors ─────────────────────────────────────────────────────────────────────────────────

/**
 * Remove a secret from text before it is shown. `secret` is usually the API key; a short or empty
 * value is ignored so a stray "" never blanks the whole message.
 */
export function redact(text: string, secret?: string): string {
  if (!secret || secret.length < 8) return text;
  return text.split(secret).join("[redacted]");
}

/** True when a provider's 400 is really "your prompt is too long for this model". */
export function isContextComplaint(body: string | undefined): boolean {
  if (!body) return false;
  return /context length|context window|maximum context|too many tokens|reduce the length|prompt is too long/i.test(
    body,
  );
}

export function httpErrorKind(status: number, body?: string): NarratorErrorKind {
  if (status === 400 && isContextComplaint(body)) return "context";
  if (status === 401 || status === 403 || status === 402) return "auth";
  if (status === 429 || status === 529) return "rate_limit";
  if (status === 408) return "timeout";
  if (status >= 500) return "transport";
  return "other";
}

/**
 * A short, actionable message for a failed HTTP call. The provider's own body is included as a
 * snippet because it usually names the real cause — redacted first (see the file header).
 */
export function httpErrorMessage(
  provider: string,
  status: number,
  body: string | undefined,
  secret?: string,
): string {
  const snippet = body ? ` — ${redact(body, secret).replace(/\s+/g, " ").trim().slice(0, 200)}` : "";
  if (status === 400 && isContextComplaint(body)) {
    return (
      `${provider} HTTP 400 (context too large): the chunk exceeds the model's context window. ` +
      `Lower the chunk budget or the rows-per-chunk cap and run again.${snippet}`
    );
  }
  switch (status) {
    case 401:
    case 403:
      return `${provider} HTTP ${status} (auth): the API key is missing, invalid, or has no access to this model.${snippet}`;
    case 402:
      return `${provider} HTTP 402 (payment required): the account has no credits or no active billing.${snippet}`;
    case 429:
    case 529:
      return `${provider} HTTP ${status} (rate limit): too many requests, quota exhausted, or the model is overloaded. Wait and run again.${snippet}`;
    default:
      return `${provider} HTTP ${status}${snippet}`;
  }
}

/** The per-request timeout, combined with the caller's cancel signal when there is one. */
export function requestSignal(timeoutMs: number, external?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return external ? AbortSignal.any([external, timeout]) : timeout;
}

/** Turn a thrown fetch/abort failure into a narrator error of the right kind. */
export function transportError(provider: string, err: unknown, timeoutMs: number): NarratorError {
  const e = err as Error;
  if (e?.name === "TimeoutError") {
    return new NarratorError(`${provider} timed out after ${timeoutMs}ms`, "timeout");
  }
  if (e?.name === "AbortError") return new NarratorError(`${provider} call was cancelled`, "transport");
  return new NarratorError(`${provider} transport error: ${e?.message ?? String(err)}`, "transport");
}

// ── key discovery ──────────────────────────────────────────────────────────────────────────

/**
 * Read `NAME=value` out of a dotenv-style file. Returns undefined when the file is absent or the
 * name is not in it. The value is never logged.
 */
export function readKeyFile(path: string, name: string): string | undefined {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    return undefined;
  }
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const eq = trimmed.indexOf("=");
    if (eq < 0) continue;
    if (trimmed.slice(0, eq).replace(/^export\s+/, "").trim() !== name) continue;
    const value = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
    if (value) return value;
  }
  return undefined;
}

/** Where the OpenRouter key lives when it is not in the environment. */
export const OPENROUTER_KEY_FILE = join(homedir(), ".config", "typesafe", "openrouter.env");

export function resolveOpenRouterKey(explicit?: string): string | undefined {
  return explicit || process.env.OPENROUTER_API_KEY || readKeyFile(OPENROUTER_KEY_FILE, "OPENROUTER_API_KEY");
}

export function resolveAnthropicKey(explicit?: string): string | undefined {
  return explicit || process.env.ANTHROPIC_API_KEY;
}

export function requireKey(provider: string, key: string | undefined, where: string): string {
  if (key) return key;
  throw new NarratorError(`${provider}: no API key. Set ${where}.`, "auth");
}

// ── CLI running ────────────────────────────────────────────────────────────────────────────

export interface CliRun {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | null;
  readonly timedOut: boolean;
  readonly spawnError?: NodeJS.ErrnoException;
}

export interface CliRunInput {
  readonly spawn: SpawnFn;
  readonly bin: string;
  readonly args: readonly string[];
  /** The whole prompt. It goes on stdin, never in `args` — a timeline digest blows past the OS
   * argv limit (and on Windows past cmd.exe's ~8KB command line). */
  readonly stdin: string;
  readonly timeoutMs: number;
  readonly cwd?: string;
  readonly signal?: AbortSignal;
}

/** Run a CLI to completion, capturing stdout. Never rejects: failures come back in the result. */
export async function runCli(input: CliRunInput): Promise<CliRun> {
  return await new Promise<CliRun>((resolve) => {
    let child: ChildLike;
    try {
      child = input.spawn(input.bin, input.args, {
        ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
        stdio: ["pipe", "pipe", "pipe"] as const,
      });
    } catch (err) {
      resolve({ stdout: "", stderr: "", code: null, timedOut: false, spawnError: err as NodeJS.ErrnoException });
      return;
    }

    let stdout = "";
    let stderr = "";
    let settled = false;
    let timedOut = false;

    const finish = (run: CliRun): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      input.signal?.removeEventListener("abort", onAbort);
      resolve(run);
    };

    const stop = (): void => {
      try {
        child.kill("SIGTERM");
      } catch {
        /* the child is already gone */
      }
    };

    const timer = setTimeout(() => {
      timedOut = true;
      stop();
      finish({ stdout, stderr, code: null, timedOut: true });
    }, input.timeoutMs);
    // A narration run must not hold the process open on its own.
    (timer as unknown as { unref?: () => void }).unref?.();

    const onAbort = (): void => {
      stop();
      finish({ stdout, stderr, code: null, timedOut: false });
    };
    input.signal?.addEventListener("abort", onAbort, { once: true });

    child.stdout?.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr?.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.on("error", (err) => {
      finish({ stdout, stderr, code: null, timedOut, spawnError: err });
    });
    child.on("close", (code) => {
      finish({ stdout, stderr, code, timedOut });
    });

    try {
      child.stdin?.write(input.stdin);
      child.stdin?.end();
    } catch {
      /* a child that died before stdin was written reports through 'error'/'close' */
    }
  });
}

/**
 * The real spawn, adapted to `SpawnFn`. Tests inject their own and never reach this, which is the
 * point: no test run may start a real `claude` or `codex` process.
 */
export const nodeSpawn: SpawnFn = (command, args, options) =>
  spawn(command, [...args], {
    ...(options.cwd !== undefined ? { cwd: options.cwd } : {}),
    stdio: ["pipe", "pipe", "pipe"],
  });

/** The message an analyst can act on when a CLI is not on PATH. */
export function notInstalledError(label: string, bin: string, install: string): NarratorError {
  return new NarratorError(
    `${label} CLI not found (tried "${bin}"). Install it — ${install} — or point the narrator at a different provider.`,
    "not_installed",
  );
}

/** Classify a non-zero CLI exit from what it printed. The output is never a secret we set. */
export function cliErrorKind(stderr: string): NarratorErrorKind {
  const s = (stderr || "").toLowerCase();
  if (/rate limit|usage limit|quota|429|too many requests/.test(s)) return "rate_limit";
  if (/unauthor|not (logged|signed) in|auth|login|api key|401|403/.test(s)) return "auth";
  if (/context (length|window)|too many tokens|prompt is too long/.test(s)) return "context";
  if (/5\d\d|network|econn|socket|timed out/.test(s)) return "transport";
  return "other";
}

// ── factory ────────────────────────────────────────────────────────────────────────────────

/**
 * Build one of the four narrators. The imports are deliberately at the bottom of the dependency
 * graph: each provider module imports this one, and this function is only called after both
 * modules have loaded, so the cycle is harmless.
 */
export function buildNarrator(name: NarratorName, opts: NarratorOptions = {}): Narrator {
  switch (name) {
    case "openrouter":
      return new OpenRouterNarrator(opts);
    case "claude-api":
      return new AnthropicNarrator(opts);
    case "claude-cli":
      return new ClaudeCliNarrator(opts);
    case "codex-cli":
      return new CodexCliNarrator(opts);
    default: {
      const unknown: never = name;
      throw new NarratorError(`unknown narrator: ${String(unknown)}`, "other");
    }
  }
}
