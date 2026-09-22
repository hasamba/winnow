import { afterEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildManifest,
  readToolInfo,
  sha256File,
  writeManifest,
  type ManifestInputs,
} from "../src/export/manifest.js";
import { DEFAULT_THRESHOLDS } from "../src/types.js";

const dirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "tt-manifest-"));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  delete process.env["OPENROUTER_API_KEY"];
  while (dirs.length > 0) {
    const dir = dirs.pop();
    if (dir !== undefined) rmSync(dir, { recursive: true, force: true });
  }
});

function inputs(over: Partial<ManifestInputs> = {}): ManifestInputs {
  const base: ManifestInputs = {
    toolName: "timeline-triage",
    toolVersion: "0.1.0",
    model: "typesafe/jev-1.13",
    questionsText: '{"malicious": {"type": "noul"}}',
    questionsHash: "b".repeat(64),
    thresholds: DEFAULT_THRESHOLDS,
    sourcePath: "/home/analyst/cases/C-42/timeline.csv",
    sourceBytes: 4_294_967_296,
    sourceSha256: "c".repeat(64),
    totalRows: 1_200_000,
    distinctKeys: 38_412,
    decidedKeys: 38_400,
    erroredKeys: 12,
    verdictsByCategory: { benign_noise: 37_000, execution: 900, lateral_movement: 500 },
    rowsWritten: 2_311,
    startedAt: "2026-09-22T08:00:00.000Z",
    finishedAt: "2026-09-22T08:41:07.000Z",
    totalCostUsd: 1.1524,
    workers: 8,
  };
  return { ...base, ...over };
}

describe("sha256File", () => {
  it("matches a known digest for a small file", async () => {
    const path = join(tempDir(), "small.txt");
    writeFileSync(path, "abc", "utf8");
    // The published sha256 of "abc".
    await expect(sha256File(path)).resolves.toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("matches node:crypto over a larger multi-chunk file", async () => {
    const path = join(tempDir(), "large.bin");
    const body = Buffer.alloc(3 * 1024 * 1024, 0x41);
    writeFileSync(path, body);
    const expected = createHash("sha256").update(body).digest("hex");
    await expect(sha256File(path)).resolves.toBe(expected);
  });

  it("rejects when the file is missing", async () => {
    await expect(sha256File(join(tempDir(), "nope.bin"))).rejects.toThrow();
  });
});

describe("readToolInfo", () => {
  it("reads the tool name and version from package.json", async () => {
    const info = await readToolInfo();
    expect(info.name).toBe("timeline-triage");
    expect(info.version).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("buildManifest", () => {
  it("records every field the run needs to be reproducible", () => {
    const m = buildManifest(inputs());
    expect(m.tool).toBe("timeline-triage");
    expect(m.version).toBe("0.1.0");
    expect(m.jevModel).toBe("typesafe/jev-1.13");
    expect(m.questionsText).toContain("malicious");
    expect(m.questionsHash).toBe("b".repeat(64));
    expect(m.thresholds).toEqual(DEFAULT_THRESHOLDS);
    expect(m.sourceBytes).toBe(4_294_967_296);
    expect(m.sourceSha256).toBe("c".repeat(64));
    expect(m.totalRows).toBe(1_200_000);
    expect(m.distinctKeys).toBe(38_412);
    expect(m.decidedKeys).toBe(38_400);
    expect(m.erroredKeys).toBe(12);
    expect(m.rowsWritten).toBe(2_311);
    expect(m.distribution["execution"]).toBe(900);
    expect(m.startedAt).toBe("2026-09-22T08:00:00.000Z");
    expect(m.finishedAt).toBe("2026-09-22T08:41:07.000Z");
    expect(m.costUsd).toBe(1.1524);
    expect(m.workers).toBe(8);
  });

  it("keeps only the source file name, never the path that led to it", () => {
    const m = buildManifest(inputs());
    expect(m.sourceFile).toBe("timeline.csv");
    expect(JSON.stringify(m)).not.toContain("/home/analyst");
  });
});

describe("writeManifest", () => {
  it("writes pretty-printed JSON that parses back to the same manifest", async () => {
    const path = join(tempDir(), "manifest.json");
    const m = buildManifest(inputs());
    await writeManifest(path, m);
    const text = readFileSync(path, "utf8");
    expect(text).toContain("\n  ");
    expect(JSON.parse(text)).toEqual(JSON.parse(JSON.stringify(m)));
  });

  it("never leaks an API key, an environment dump or an outside path", async () => {
    const secret = "sk-or-v1-0123456789abcdef0123456789abcdef";
    process.env["OPENROUTER_API_KEY"] = secret;
    const dir = tempDir();
    const path = join(dir, "manifest.json");
    await writeManifest(
      path,
      buildManifest(inputs({ sourcePath: join(dir, "supertimeline.csv") })),
    );
    const text = readFileSync(path, "utf8");
    expect(text).not.toContain(secret);
    expect(text).not.toContain("OPENROUTER");
    expect(text).not.toContain("API_KEY");
    expect(text).not.toContain(dir);
    expect(text).not.toContain(process.env["HOME"] ?? "/home");
    expect(JSON.parse(text).sourceFile).toBe("supertimeline.csv");
  });

  it("strips a path a caller assembled by hand into the manifest object", async () => {
    const dir = tempDir();
    const path = join(dir, "manifest.json");
    const m = { ...buildManifest(inputs()), sourceFile: "/home/analyst/cases/C-42/timeline.csv" };
    await writeManifest(path, m);
    const text = readFileSync(path, "utf8");
    expect(text).not.toContain("/home/analyst");
    expect(JSON.parse(text).sourceFile).toBe("timeline.csv");
  });
});
