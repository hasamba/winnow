import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DEFAULT_MAX_ROWS_PER_CHUNK } from "../src/narrate/chunk.js";
import type { NarrateRequest, NarrateResult, Narrator } from "../src/narrate/provider.js";
import { narrate } from "../src/narrate/run.js";

let dir = "";

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "narrate-run-"));
});

afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
  dir = "";
});

/** A narrator that records every call and answers from a canned script. */
class StubNarrator implements Narrator {
  readonly name = "openrouter" as const;
  readonly model = "stub/model-1";
  readonly calls: NarrateRequest[] = [];
  constructor(private readonly reply: (req: NarrateRequest, n: number) => string = () => "narrative") {}
  async generate(req: NarrateRequest): Promise<NarrateResult> {
    this.calls.push(req);
    return { text: this.reply(req, this.calls.length), model: this.model };
  }
}

const HEADER = "timestamp,host,source,message,jev_confidence";

function writeCsv(name: string, lines: readonly string[]): string {
  const path = join(dir, name);
  writeFileSync(path, [HEADER, ...lines].join("\n") + "\n", "utf8");
  return path;
}

function rows(count: number, host = "WS01"): string[] {
  return Array.from(
    { length: count },
    (_, i) =>
      `2026-01-0${(i % 9) + 1}T00:00:0${i % 10}Z,${host},EVT,"event number ${i + 1} on ${host}",0.9`,
  );
}

describe("narrate", () => {
  it("uses one synthesis call for a small file", async () => {
    const csv = writeCsv("malicious.csv", rows(5));
    const out = join(dir, "story.md");
    const narrator = new StubNarrator();
    const res = await narrate({ csvPath: csv, narrator, outPath: out });
    expect(res.rowsRead).toBe(5);
    expect(res.chunks).toBe(1);
    expect(narrator.calls).toHaveLength(1);
    expect(res.outPaths).toEqual([out]);
    expect(readFileSync(out, "utf8")).toContain("narrative");
  });

  it("observes each chunk then synthesises once when the input is large", async () => {
    const count = DEFAULT_MAX_ROWS_PER_CHUNK * 2 + 5;
    const csv = writeCsv("malicious.csv", rows(count));
    const out = join(dir, "story.md");
    const narrator = new StubNarrator((_req, n) => `observation ${n}`);
    const res = await narrate({ csvPath: csv, narrator, outPath: out });
    expect(res.rowsRead).toBe(count);
    expect(res.chunks).toBe(3);
    // three observe calls plus one synthesis
    expect(narrator.calls).toHaveLength(4);
    const last = narrator.calls[narrator.calls.length - 1];
    expect(last?.userPrompt).toContain("observation 1");
    expect(last?.userPrompt).toContain("observation 3");
  });

  it("writes a header block naming the rows, the chunks, the model and the run time", async () => {
    const csv = writeCsv("malicious.csv", rows(4));
    const out = join(dir, "story.md");
    await narrate({ csvPath: csv, narrator: new StubNarrator(), outPath: out });
    const md = readFileSync(out, "utf8");
    expect(md).toMatch(/Rows read.*\b4\b/);
    expect(md).toMatch(/Chunks.*\b1\b/);
    expect(md).toContain("stub/model-1");
    expect(md).toMatch(/Run time/i);
  });

  it("says in plain words when a row cap was hit, instead of truncating silently", async () => {
    const csv = writeCsv("malicious.csv", rows(50));
    const out = join(dir, "story.md");
    const res = await narrate({ csvPath: csv, narrator: new StubNarrator(), outPath: out, maxRows: 10 });
    expect(res.rowsRead).toBe(10);
    const md = readFileSync(out, "utf8");
    expect(md).toMatch(/cap/i);
    expect(md).toContain("50");
    expect(md).toContain("40");
  });

  it("makes no cap statement when every row was read", async () => {
    const csv = writeCsv("malicious.csv", rows(6));
    const out = join(dir, "story.md");
    await narrate({ csvPath: csv, narrator: new StubNarrator(), outPath: out });
    expect(readFileSync(out, "utf8")).not.toMatch(/row cap/i);
  });

  it("writes one file per host when grouping by host", async () => {
    const csv = writeCsv("malicious.csv", [...rows(3, "WS01"), ...rows(2, "DC01")]);
    const out = join(dir, "story.md");
    const narrator = new StubNarrator();
    const res = await narrate({ csvPath: csv, narrator, outPath: out, groupBy: "host" });
    expect(res.outPaths).toHaveLength(2);
    expect(res.rowsRead).toBe(5);
    const written = readdirSync(dir).filter((f) => f.endsWith(".md"));
    expect(written).toHaveLength(2);
    const joined = res.outPaths.map((p) => readFileSync(p, "utf8")).join("\n");
    expect(joined).toContain("DC01");
    expect(joined).toContain("WS01");
    // each host was narrated on its own, so neither story blurs into the other
    expect(narrator.calls).toHaveLength(2);
  });

  it("writes a single file when grouping is off, even with several hosts", async () => {
    const csv = writeCsv("malicious.csv", [...rows(3, "WS01"), ...rows(2, "DC01")]);
    const out = join(dir, "story.md");
    const res = await narrate({ csvPath: csv, narrator: new StubNarrator(), outPath: out, groupBy: "none" });
    expect(res.outPaths).toEqual([out]);
  });

  it("reports progress for every stage", async () => {
    const count = DEFAULT_MAX_ROWS_PER_CHUNK + 1;
    const csv = writeCsv("malicious.csv", rows(count));
    const out = join(dir, "story.md");
    const seen: string[] = [];
    await narrate({
      csvPath: csv,
      narrator: new StubNarrator(),
      outPath: out,
      onProgress: (stage) => seen.push(stage),
    });
    expect(seen.some((s) => /observ/i.test(s))).toBe(true);
    expect(seen.some((s) => /synth/i.test(s))).toBe(true);
  });

  it("carries the flagged-rows caveat into the prompt it sends", async () => {
    const csv = writeCsv("malicious.csv", rows(3));
    const out = join(dir, "story.md");
    const narrator = new StubNarrator();
    await narrate({ csvPath: csv, narrator, outPath: out });
    const sys = narrator.calls[0]?.systemPrompt ?? "";
    expect(sys).toMatch(/lead/i);
    expect(sys).toContain("jev_confidence");
  });

  it("reads a quoted field that holds a comma", async () => {
    const csv = writeCsv("malicious.csv", [
      `2026-01-01T00:00:00Z,WS01,EVT,"net use \\\\dc01\\c$, then whoami",0.8`,
    ]);
    const out = join(dir, "story.md");
    const narrator = new StubNarrator();
    const res = await narrate({ csvPath: csv, narrator, outPath: out });
    expect(res.rowsRead).toBe(1);
    expect(narrator.calls[0]?.userPrompt).toContain("then whoami");
  });

  it("returns zero rows and still writes a document for an empty malicious set", async () => {
    const csv = writeCsv("malicious.csv", []);
    const out = join(dir, "story.md");
    const narrator = new StubNarrator();
    const res = await narrate({ csvPath: csv, narrator, outPath: out });
    expect(res.rowsRead).toBe(0);
    expect(res.chunks).toBe(0);
    expect(narrator.calls).toHaveLength(0);
    expect(readFileSync(out, "utf8")).toMatch(/no rows/i);
  });
});
