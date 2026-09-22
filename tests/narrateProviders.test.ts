import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import {
  NarratorError,
  buildNarrator,
  type NarratorName,
  type SpawnFn,
} from "../src/narrate/provider.js";

/** A key shape that is obviously fake, and that no error message may ever repeat. */
const FAKE_KEY = "sk-fake-0000-never-leak-this-value";

const SYSTEM = "You are a DFIR narrator.";
const USER = "ROW 1: rundll32 loaded a DLL from the user temp folder at 2026-01-02T03:04:05Z.";

// ── fetch doubles ──────────────────────────────────────────────────────────────────────────

interface FetchCall {
  readonly url: string;
  readonly headers: Record<string, string>;
  readonly body: Record<string, unknown>;
}

function fakeFetch(make: () => Response): { impl: typeof fetch; calls: FetchCall[] } {
  const calls: FetchCall[] = [];
  const impl = (async (input: unknown, init?: RequestInit): Promise<Response> => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
      headers[k.toLowerCase()] = v;
    }
    let body: Record<string, unknown> = {};
    if (typeof init?.body === "string") body = JSON.parse(init.body) as Record<string, unknown>;
    calls.push({ url: String(input), headers, body });
    return make();
  }) as unknown as typeof fetch;
  return { impl, calls };
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

const OPENROUTER_OK = {
  choices: [{ message: { content: "The attacker ran rundll32." } }],
  usage: { cost: 0.0042 },
  model: "anthropic/claude-sonnet-4.5",
};

const ANTHROPIC_OK = {
  content: [{ type: "text", text: "The attacker ran rundll32." }],
  model: "claude-sonnet-4-5",
};

// ── spawn double ───────────────────────────────────────────────────────────────────────────

interface FakeRun {
  readonly stdout?: string;
  readonly stderr?: string;
  readonly code?: number;
  readonly spawnError?: NodeJS.ErrnoException;
}

interface SpawnCapture {
  readonly impl: SpawnFn;
  readonly calls: { command: string; args: readonly string[] }[];
  readonly stdin: string[];
}

function fakeSpawn(run: FakeRun): SpawnCapture {
  const calls: { command: string; args: readonly string[] }[] = [];
  const stdin: string[] = [];
  const impl = ((command: string, args: readonly string[]) => {
    calls.push({ command, args });
    const child = new EventEmitter() as EventEmitter & Record<string, unknown>;
    const out = new PassThrough();
    const err = new PassThrough();
    const input = new PassThrough();
    input.on("data", (chunk: Buffer | string) => stdin.push(String(chunk)));
    child.stdout = out;
    child.stderr = err;
    child.stdin = input;
    child.kill = () => true;
    setTimeout(() => {
      if (run.spawnError) {
        child.emit("error", run.spawnError);
        return;
      }
      out.end(run.stdout ?? "");
      err.end(run.stderr ?? "");
      setTimeout(() => child.emit("close", run.code ?? 0, null), 0);
    }, 0);
    return child;
  }) as unknown as SpawnFn;
  return { impl, calls, stdin };
}

function enoent(): NodeJS.ErrnoException {
  const e = new Error("spawn claude ENOENT") as NodeJS.ErrnoException;
  e.code = "ENOENT";
  return e;
}

async function failure(fn: () => Promise<unknown>): Promise<NarratorError> {
  try {
    await fn();
  } catch (err) {
    expect(err).toBeInstanceOf(NarratorError);
    return err as NarratorError;
  }
  throw new Error("expected the call to fail");
}

// ── OpenRouter ─────────────────────────────────────────────────────────────────────────────

describe("openrouter narrator", () => {
  it("returns the text and the reported dollar cost", async () => {
    const { impl, calls } = fakeFetch(() => json(200, OPENROUTER_OK));
    const n = buildNarrator("openrouter", { apiKey: FAKE_KEY, fetchImpl: impl });
    const res = await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    expect(res.text).toBe("The attacker ran rundll32.");
    expect(res.costUsd).toBe(0.0042);
    expect(calls[0]?.url).toBe("https://openrouter.ai/api/v1/chat/completions");
    expect(calls[0]?.headers.authorization).toBe(`Bearer ${FAKE_KEY}`);
  });

  it("sends an OpenAI-shaped body with the system prompt as the first message", async () => {
    const { impl, calls } = fakeFetch(() => json(200, OPENROUTER_OK));
    const n = buildNarrator("openrouter", { apiKey: FAKE_KEY, fetchImpl: impl });
    await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    const messages = calls[0]?.body.messages as { role: string; content: string }[];
    expect(messages[0]).toEqual({ role: "system", content: SYSTEM });
    expect(messages[1]).toEqual({ role: "user", content: USER });
  });

  it("honours a custom base url", async () => {
    const { impl, calls } = fakeFetch(() => json(200, OPENROUTER_OK));
    const n = buildNarrator("openrouter", {
      apiKey: FAKE_KEY,
      baseUrl: "https://proxy.example.com/v1",
      fetchImpl: impl,
    });
    await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    expect(calls[0]?.url).toBe("https://proxy.example.com/v1/chat/completions");
  });

  it("raises kind auth on 401", async () => {
    const { impl } = fakeFetch(() => json(401, { error: { message: "invalid credentials" } }));
    const n = buildNarrator("openrouter", { apiKey: FAKE_KEY, fetchImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("auth");
  });

  it("raises kind rate_limit on 429", async () => {
    const { impl } = fakeFetch(() => json(429, { error: { message: "slow down" } }));
    const n = buildNarrator("openrouter", { apiKey: FAKE_KEY, fetchImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("rate_limit");
  });

  it("raises kind context when the model complains about context length", async () => {
    const { impl } = fakeFetch(() =>
      json(400, { error: { message: "maximum context length is 128000 tokens" } }),
    );
    const n = buildNarrator("openrouter", { apiKey: FAKE_KEY, fetchImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("context");
  });
});

// ── Anthropic ──────────────────────────────────────────────────────────────────────────────

describe("claude-api narrator", () => {
  it("returns the text", async () => {
    const { impl, calls } = fakeFetch(() => json(200, ANTHROPIC_OK));
    const n = buildNarrator("claude-api", { apiKey: FAKE_KEY, fetchImpl: impl });
    const res = await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    expect(res.text).toBe("The attacker ran rundll32.");
    expect(calls[0]?.url).toBe("https://api.anthropic.com/v1/messages");
    expect(calls[0]?.headers["x-api-key"]).toBe(FAKE_KEY);
    expect(calls[0]?.headers["anthropic-version"]).toBe("2023-06-01");
  });

  it("puts the system prompt in the top-level system field, never in messages", async () => {
    const { impl, calls } = fakeFetch(() => json(200, ANTHROPIC_OK));
    const n = buildNarrator("claude-api", { apiKey: FAKE_KEY, fetchImpl: impl });
    await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    const body = calls[0]?.body ?? {};
    expect(body.system).toBe(SYSTEM);
    const messages = body.messages as { role: string; content: string }[];
    expect(messages).toHaveLength(1);
    expect(messages[0]?.role).toBe("user");
    expect(JSON.stringify(messages)).not.toContain(SYSTEM);
  });

  it("raises kind auth on 401", async () => {
    const { impl } = fakeFetch(() => json(401, { error: { message: "invalid x-api-key" } }));
    const n = buildNarrator("claude-api", { apiKey: FAKE_KEY, fetchImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("auth");
  });

  it("raises kind rate_limit on 429 and on 529 overloaded", async () => {
    for (const status of [429, 529]) {
      const { impl } = fakeFetch(() => json(status, { error: { message: "overloaded" } }));
      const n = buildNarrator("claude-api", { apiKey: FAKE_KEY, fetchImpl: impl });
      const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
      expect(err.kind).toBe("rate_limit");
    }
  });
});

// ── CLI providers ──────────────────────────────────────────────────────────────────────────

describe("claude-cli narrator", () => {
  it("returns the stdout text", async () => {
    const { impl } = fakeSpawn({ stdout: "The attacker ran rundll32.\n" });
    const n = buildNarrator("claude-cli", { spawnImpl: impl });
    const res = await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    expect(res.text).toBe("The attacker ran rundll32.");
  });

  it("writes the prompt on stdin and keeps it out of argv", async () => {
    const cap = fakeSpawn({ stdout: "ok" });
    const n = buildNarrator("claude-cli", { spawnImpl: cap.impl });
    await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    const argv = (cap.calls[0]?.args ?? []).join(" ");
    expect(argv).toContain("--output-format");
    expect(argv).not.toContain("rundll32");
    expect(argv).not.toContain("DFIR narrator");
    const written = cap.stdin.join("");
    expect(written).toContain(USER);
    expect(written).toContain(SYSTEM);
  });

  it("raises kind not_installed when the binary is missing", async () => {
    const { impl } = fakeSpawn({ spawnError: enoent() });
    const n = buildNarrator("claude-cli", { spawnImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("not_installed");
    expect(err.message).toMatch(/install/i);
  });

  it("raises kind auth when the CLI reports it is not logged in", async () => {
    const { impl } = fakeSpawn({ code: 1, stderr: "Not logged in. Run `claude auth login`." });
    const n = buildNarrator("claude-cli", { spawnImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("auth");
  });

  it("raises kind rate_limit when the CLI reports a usage limit", async () => {
    const { impl } = fakeSpawn({ code: 1, stderr: "usage limit reached, try again later" });
    const n = buildNarrator("claude-cli", { spawnImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("rate_limit");
  });
});

describe("codex-cli narrator", () => {
  it("returns the stdout text", async () => {
    const { impl } = fakeSpawn({ stdout: "The attacker ran rundll32.\n" });
    const n = buildNarrator("codex-cli", { spawnImpl: impl });
    const res = await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    expect(res.text).toBe("The attacker ran rundll32.");
  });

  it("runs `codex exec --skip-git-repo-check` with the prompt on stdin", async () => {
    const cap = fakeSpawn({ stdout: "ok" });
    const n = buildNarrator("codex-cli", { spawnImpl: cap.impl });
    await n.generate({ systemPrompt: SYSTEM, userPrompt: USER });
    const args = cap.calls[0]?.args ?? [];
    expect(args[0]).toBe("exec");
    expect(args).toContain("--skip-git-repo-check");
    const argv = args.join(" ");
    expect(argv).not.toContain("rundll32");
    expect(argv).not.toContain("DFIR narrator");
    expect(cap.stdin.join("")).toContain(USER);
  });

  it("raises kind not_installed when the binary is missing", async () => {
    const { impl } = fakeSpawn({ spawnError: enoent() });
    const n = buildNarrator("codex-cli", { spawnImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("not_installed");
    expect(err.message).toMatch(/install/i);
  });

  it("raises kind rate_limit when the CLI reports a rate limit", async () => {
    const { impl } = fakeSpawn({ code: 1, stderr: "429 too many requests" });
    const n = buildNarrator("codex-cli", { spawnImpl: impl });
    const err = await failure(() => n.generate({ systemPrompt: SYSTEM, userPrompt: USER }));
    expect(err.kind).toBe("rate_limit");
  });
});

// ── the rule that outranks every other assertion here ──────────────────────────────────────

describe("no narrator leaks the API key", () => {
  const names: NarratorName[] = ["openrouter", "claude-api", "claude-cli", "codex-cli"];

  it("keeps the key out of every thrown message, for every failure kind", async () => {
    const http = (status: number) => fakeFetch(() => json(status, { error: { message: "denied" } }));
    const cases: { name: NarratorName; make: () => ReturnType<typeof buildNarrator> }[] = [
      {
        name: "openrouter",
        make: () => buildNarrator("openrouter", { apiKey: FAKE_KEY, fetchImpl: http(401).impl }),
      },
      {
        name: "openrouter",
        make: () => buildNarrator("openrouter", { apiKey: FAKE_KEY, fetchImpl: http(429).impl }),
      },
      {
        name: "claude-api",
        make: () => buildNarrator("claude-api", { apiKey: FAKE_KEY, fetchImpl: http(401).impl }),
      },
      {
        name: "claude-api",
        make: () => buildNarrator("claude-api", { apiKey: FAKE_KEY, fetchImpl: http(500).impl }),
      },
      {
        name: "claude-cli",
        make: () =>
          buildNarrator("claude-cli", {
            apiKey: FAKE_KEY,
            spawnImpl: fakeSpawn({ spawnError: enoent() }).impl,
          }),
      },
      {
        name: "codex-cli",
        make: () =>
          buildNarrator("codex-cli", {
            apiKey: FAKE_KEY,
            spawnImpl: fakeSpawn({ code: 1, stderr: "boom" }).impl,
          }),
      },
    ];
    for (const c of cases) {
      const err = await failure(() => c.make().generate({ systemPrompt: SYSTEM, userPrompt: USER }));
      expect(err.message, `${c.name} leaked the key`).not.toContain(FAKE_KEY);
      expect(String(err.stack ?? ""), `${c.name} leaked the key`).not.toContain(FAKE_KEY);
    }
  });

  it("names every narrator it can build", () => {
    for (const name of names) {
      const n = buildNarrator(name, { apiKey: FAKE_KEY });
      expect(n.name).toBe(name);
      expect(n.model.length).toBeGreaterThan(0);
    }
  });
});
