// The Claude Code CLI, driven headless: `claude -p --output-format text`.
//
// The prompt goes on STDIN, never in argv. A timeline digest is tens of thousands of characters
// and would blow past the OS argument limit (and, on Windows, past cmd.exe's ~8KB command line),
// so an argv prompt fails on exactly the large cases this tool exists for. It also keeps evidence
// text out of the process list, where any local user can read it.
//
// This narrator sends no API key; the CLI carries its own session.

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

export const CLAUDE_CLI_DEFAULT_MODEL = "sonnet";
export const CLAUDE_CLI_BIN = "claude";
const INSTALL_HINT = "`npm i -g @anthropic-ai/claude-code`, then `claude auth login`";

export class ClaudeCliNarrator implements Narrator {
  readonly name = "claude-cli" as const;
  readonly model: string;
  private readonly spawnImpl: SpawnFn;
  private readonly timeoutMs: number;

  constructor(opts: NarratorOptions = {}) {
    this.model = opts.model?.trim() || CLAUDE_CLI_DEFAULT_MODEL;
    this.spawnImpl = opts.spawnImpl ?? nodeSpawn;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_CLI_TIMEOUT_MS;
  }

  async generate(req: NarrateRequest): Promise<NarrateResult> {
    // Both halves ride on stdin. `--system-prompt` would put the instructions in argv, which is
    // the limit this provider exists to avoid.
    const stdin = `${req.systemPrompt}\n\n${req.userPrompt}\n`;
    const args = [
      "-p",
      "--output-format",
      "text",
      ...(this.model ? ["--model", this.model] : []),
    ];

    const run = await runCli({
      spawn: this.spawnImpl,
      bin: CLAUDE_CLI_BIN,
      args,
      stdin,
      timeoutMs: this.timeoutMs,
      ...(req.signal ? { signal: req.signal } : {}),
    });

    if (run.spawnError) {
      if (run.spawnError.code === "ENOENT") {
        throw notInstalledError("Claude Code", CLAUDE_CLI_BIN, INSTALL_HINT);
      }
      throw new NarratorError(`Claude Code failed to start: ${run.spawnError.message}`, "transport");
    }
    if (run.timedOut) {
      throw new NarratorError(`Claude Code timed out after ${this.timeoutMs}ms`, "timeout");
    }

    const text = run.stdout.trim();
    if ((run.code ?? 0) !== 0) {
      const snippet = (run.stderr || run.stdout || "no output").replace(/\s+/g, " ").trim().slice(0, 300);
      throw new NarratorError(`Claude Code: ${snippet}`, cliErrorKind(run.stderr || run.stdout));
    }
    if (!text) throw new NarratorError("Claude Code returned no content", "other");
    return { text, model: this.model };
  }
}
