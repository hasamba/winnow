import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseCsvRecords, parseCsvRecordsFromLines, readLines } from "../src/plaso/csvRead.js";

const DYNAMIC_FIXTURE = fileURLToPath(new URL("./fixtures/fixture.dynamic.csv", import.meta.url));
const L2T_FIXTURE = fileURLToPath(new URL("./fixtures/fixture.l2t.csv", import.meta.url));

/** Feed a literal CSV text to the streaming parser the way readLines would. */
async function* asLines(text: string): AsyncGenerator<string> {
  for (const line of text.split("\n")) yield line;
}

async function collect<T>(it: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of it) out.push(v);
  return out;
}

describe("parseCsvRecords", () => {
  it("keeps a comma inside a quoted field in one cell", () => {
    const recs = [...parseCsvRecords('a,"one, two",c\n')];
    expect(recs).toEqual([["a", "one, two", "c"]]);
  });

  it("unescapes a doubled quote into a single quote", () => {
    const recs = [...parseCsvRecords('a,"he said ""hi""",c\n')];
    expect(recs).toEqual([["a", 'he said "hi"', "c"]]);
  });

  it("keeps an embedded newline inside a quoted field", () => {
    const recs = [...parseCsvRecords('a,"line one\nline two",c\n')];
    expect(recs).toEqual([["a", "line one\nline two", "c"]]);
  });

  it("keeps a trailing empty field", () => {
    const recs = [...parseCsvRecords("a,b,\n")];
    expect(recs).toEqual([["a", "b", ""]]);
  });

  it("flushes a final record that has no trailing newline", () => {
    const recs = [...parseCsvRecords("a,b,c")];
    expect(recs).toEqual([["a", "b", "c"]]);
  });

  it("skips a fully empty record so the header is the first yield", () => {
    const recs = [...parseCsvRecords("h1,h2\n\nv1,v2\n")];
    expect(recs).toEqual([
      ["h1", "h2"],
      ["v1", "v2"],
    ]);
  });

  it("tolerates CRLF line endings", () => {
    const recs = [...parseCsvRecords("a,b\r\nc,d\r\n")];
    expect(recs).toEqual([
      ["a", "b"],
      ["c", "d"],
    ]);
  });

  it("honours a non-comma delimiter", () => {
    const recs = [...parseCsvRecords('a\t"x\ty"\tc\n', "\t")];
    expect(recs).toEqual([["a", "x\ty", "c"]]);
  });

  it("leaves a comma alone when the delimiter is a tab", () => {
    const recs = [...parseCsvRecords("a,b\tc\n", "\t")];
    expect(recs).toEqual([["a,b", "c"]]);
  });
});

describe("parseCsvRecordsFromLines", () => {
  it("keeps a comma inside a quoted field in one cell", async () => {
    const recs = await collect(parseCsvRecordsFromLines(asLines('a,"one, two",c')));
    expect(recs).toEqual([["a", "one, two", "c"]]);
  });

  it("unescapes a doubled quote into a single quote", async () => {
    const recs = await collect(parseCsvRecordsFromLines(asLines('a,"he said ""hi""",c')));
    expect(recs).toEqual([["a", 'he said "hi"', "c"]]);
  });

  it("joins a quoted field that spans several source lines into one record", async () => {
    const recs = await collect(
      parseCsvRecordsFromLines(asLines('a,"line one\nline two\nline three",c\nd,e,f')),
    );
    expect(recs).toEqual([
      ["a", "line one\nline two\nline three", "c"],
      ["d", "e", "f"],
    ]);
  });

  it("keeps a trailing empty field", async () => {
    const recs = await collect(parseCsvRecordsFromLines(asLines("a,b,")));
    expect(recs).toEqual([["a", "b", ""]]);
  });

  it("honours a non-comma delimiter", async () => {
    const recs = await collect(parseCsvRecordsFromLines(asLines('a\t"x\ty"\tc'), "\t"));
    expect(recs).toEqual([["a", "x\ty", "c"]]);
  });

  it("force-flushes rather than swallowing the file after a stray unbalanced quote", async () => {
    // maxRecordChars is deliberately tiny: a lone quote never balances, so without the cap the
    // parser would append every later line into one ever-growing field.
    const recs = await collect(
      parseCsvRecordsFromLines(asLines('a,"unterminated\nb,c\nd,e'), ",", 8),
    );
    expect(recs.length).toBeGreaterThan(1);
  });
});

describe("readLines", () => {
  it("yields the fixture one physical line at a time", async () => {
    const lines = await collect(readLines(L2T_FIXTURE));
    expect(lines).toHaveLength(41); // 1 header + 40 data rows, none of which wrap
    expect(lines[0]).toBe(
      "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra",
    );
  });

  it("does not split a quoted field that wraps onto more source lines", async () => {
    const lines = await collect(readLines(DYNAMIC_FIXTURE));
    const recs = await collect(parseCsvRecordsFromLines(readLines(DYNAMIC_FIXTURE)));
    expect(lines.length).toBe(44); // one record wraps over four physical lines
    expect(recs.length).toBe(41); // 1 header + 40 data rows
    const wrapped = recs.find((r) => r.some((c) => c.includes("PSEXESVC.exe\nService Type")));
    expect(wrapped).toBeDefined();
  });

  it("treats a CRLF file the same as an LF one, quoted fields included", async () => {
    // A Plaso CSV written on Windows uses CRLF, including inside a quoted multi-line field.
    // The streaming parser reads through readline and never sees the CR; the sync one sees the
    // raw text. They must still agree, or the same file deduplicates differently depending on
    // which path read it, and a stray CR travels into the exported CSV.
    const lf = 'a,b\nplain,"line one\nline two"\nlast,value\n';
    const crlf = lf.replace(/\n/g, "\r\n");

    const syncLf = [...parseCsvRecords(lf)];
    const syncCrlf = [...parseCsvRecords(crlf)];
    expect(syncCrlf).toEqual(syncLf);
    expect(syncCrlf[1]?.[1]).toBe("line one\nline two");
    expect(JSON.stringify(syncCrlf)).not.toContain("\\r");

    const tmp = mkdtempSync(join(tmpdir(), "triage-crlf-"));
    try {
      const file = join(tmp, "crlf.csv");
      writeFileSync(file, crlf);
      const streamed = await collect(parseCsvRecordsFromLines(readLines(file)));
      expect(streamed).toEqual(syncLf);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("agrees with the sync parser over the whole fixture", async () => {
    const streamed = await collect(parseCsvRecordsFromLines(readLines(DYNAMIC_FIXTURE)));
    const { readFileSync } = await import("node:fs");
    const sync = [...parseCsvRecords(readFileSync(DYNAMIC_FIXTURE, "utf8"))];
    expect(streamed).toEqual(sync);
  });
});
