import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadEnvFiles, projectRoot } from "../src/env.js";

let dir: string;
const TOUCHED = ["WINNOW_TEST_A", "WINNOW_TEST_B"];

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "winnow-env-"));
  for (const k of TOUCHED) delete process.env[k];
});
afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
  for (const k of TOUCHED) delete process.env[k];
});

describe("loadEnvFiles", () => {
  it("reads a .env from the working directory", () => {
    writeFileSync(join(dir, ".env"), "WINNOW_TEST_A=from-file\n");
    const loaded = loadEnvFiles(dir);
    expect(loaded).toContain(join(dir, ".env"));
    expect(process.env["WINNOW_TEST_A"]).toBe("from-file");
  });

  it("does not override a variable already in the environment", () => {
    // The precedence that matters: a key exported for one command, or set by CI, must beat
    // whatever is sitting in a .env file from a previous case.
    process.env["WINNOW_TEST_B"] = "from-environment";
    writeFileSync(join(dir, ".env"), "WINNOW_TEST_B=from-file\n");
    loadEnvFiles(dir);
    expect(process.env["WINNOW_TEST_B"]).toBe("from-environment");
  });

  it("is silent when there is no .env at all", () => {
    expect(() => loadEnvFiles(dir)).not.toThrow();
  });

  it("survives a malformed .env rather than killing a run that needs no key", () => {
    writeFileSync(join(dir, ".env"), "\u0000 not = a valid env \u0000\n");
    expect(() => loadEnvFiles(dir)).not.toThrow();
  });

  it("resolves a project root that contains package.json", async () => {
    const { existsSync } = await import("node:fs");
    expect(existsSync(join(projectRoot(), "package.json"))).toBe(true);
  });
});
