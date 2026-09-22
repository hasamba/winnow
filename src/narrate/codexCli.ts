// The Codex CLI, driven headless: `codex exec`.
//
// The prompt goes on STDIN for the same reason as the Claude CLI narrator — argv cannot hold a
// timeline digest, and a process list is not a place for evidence text.
//
// `--skip-git-repo-check` lets the run happen anywhere. A narration reads a CSV and writes a
// markdown file; it has nothing to do with a git working tree, and without the flag Codex refuses
// to start outside a repository.
//
// This narrator sends no API key; the CLI carries its own session.

import { tmpdir } from "node:os";
import {
  DEFAULT_CLI_TIMEOUT_MS,
  NarratorError,
  cliErrorKind,
  nodeSpawn,
  notInstalledError,
  runCli,
  type NarrateRequest,
  type NarrateResult,
  type Narrator,
  type NarratorOptions,
  type SpawnFn,
} from "./provider.js";

export const CODEX_CLI_DEFAULT_MODEL = "gpt-5-codex";
export const CODEX_CLI_BIN = "codex";
const INSTALL_HINT = "`npm i -g @openai/codex`, then `codex login`";

// Lines codex prints on a perfectly successful run. They are not the answer.
const NOISE = /^(Reading prompt from stdin|\[.*\] (thinking|exec|tokens used)|--------|workdir:|model:|provider:|approval:|sandbox:|reasoning )/i;

function answerText(stdout: string): string {
  return stdout
    .split(/\r?\n/)
    .filter((line) => !NOISE.test(line.trim()))
    .join("\n")
    .trim();
}

export class CodexCliNarrator implements Narrator {
  readonly name = "codex-cli" as const;
  readonly model: string;
  private readonly spawnImpl: SpawnFn;
  private readonly timeoutMs: number;

  constructor(opts: NarratorOptions = {}) {
    this.model = opts.model?.trim() || CODEX_CLI_DEFAULT_MODEL;
    this.spawnImpl = opts.spawnImpl ?? nodeSpawn;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_CLI_TIMEOUT_MS;
  }

  async generate(req: NarrateRequest): Promise<NarrateResult> {
    const stdin = `${req.systemPrompt}\n\n${req.userPrompt}\n`;
    const cwd = tmpdir(); // a neutral directory: the run reads nothing from the working tree
    const args = [
      "exec",
      "--skip-git-repo-check",
      "--sandbox",
      "read-only",
      "-C",
      cwd,
      ...(this.model ? ["-m", this.model] : []),
    ];

    const run = await runCli({
      spawn: this.spawnImpl,
      bin: CODEX_CLI_BIN,
      args,
      stdin,
      timeoutMs: this.timeoutMs,
      cwd,
      ...(req.signal ? { signal: req.signal } : {}),
    });

    if (run.spawnError) {
      if (run.spawnError.code === "ENOENT") {
        throw notInstalledError("Codex", CODEX_CLI_BIN, INSTALL_HINT);
      }
      throw new NarratorError(`Codex failed to start: ${run.spawnError.message}`, "transport");
    }
    if (run.timedOut) {
      throw new NarratorError(`Codex timed out after ${this.timeoutMs}ms`, "timeout");
    }

    if ((run.code ?? 0) !== 0) {
      const snippet = (run.stderr || run.stdout || "no output").replace(/\s+/g, " ").trim().slice(0, 300);
      throw new NarratorError(`Codex: ${snippet}`, cliErrorKind(run.stderr || run.stdout));
    }

    const text = answerText(run.stdout);
    if (!text) throw new NarratorError("Codex returned no content", "other");
    return { text, model: this.model };
  }
}
