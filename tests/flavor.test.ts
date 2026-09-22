import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";

import type { TimelineRow } from "../src/types.js";
import { detectFlavor, dynTime, l2tTime, mapRow, readTimeline } from "../src/plaso/flavor.js";

const DYNAMIC_FIXTURE = fileURLToPath(new URL("./fixtures/fixture.dynamic.csv", import.meta.url));
const L2T_FIXTURE = fileURLToPath(new URL("./fixtures/fixture.l2t.csv", import.meta.url));

const DYN_HEADERS = [
  "datetime",
  "timestamp_desc",
  "source",
  "source_long",
  "message",
  "parser",
  "display_name",
  "tag",
] as const;

const L2T_HEADERS = [
  "date",
  "time",
  "timezone",
  "MACB",
  "source",
  "sourcetype",
  "type",
  "user",
  "host",
  "short",
  "desc",
  "version",
  "filename",
  "inode",
  "notes",
  "format",
  "extra",
] as const;

async function collect<T>(it: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const v of it) out.push(v);
  return out;
}

describe("detectFlavor", () => {
  it("calls datetime + message the dynamic dialect", () => {
    expect(detectFlavor(DYN_HEADERS)).toBe("dynamic");
  });

  it("calls date + time + desc the l2tcsv dialect", () => {
    expect(detectFlavor(L2T_HEADERS)).toBe("l2tcsv");
  });

  it("accepts short in place of desc for l2tcsv", () => {
    expect(detectFlavor(["date", "time", "short", "host"])).toBe("l2tcsv");
  });

  it("returns null when the header matches neither dialect", () => {
    expect(detectFlavor(["Timestamp", "EventID", "Computer"])).toBeNull();
  });

  it("returns null for l2tcsv headers missing both desc and short", () => {
    expect(detectFlavor(["date", "time", "timezone", "host"])).toBeNull();
  });

  it("looks through a UTF-8 BOM, mixed case and padding", () => {
    expect(detectFlavor(["\uFEFFDateTime", " Timestamp_Desc ", "MESSAGE"])).toBe("dynamic");
    expect(detectFlavor(["\uFEFFDate", " Time ", "DESC"])).toBe("l2tcsv");
  });

  it("returns null for an empty header", () => {
    expect(detectFlavor([])).toBeNull();
  });
});

describe("l2tTime", () => {
  it("reads a UTC zone as UTC", () => {
    expect(l2tTime("03/14/2026", "09:11:04", "UTC")).toBe("2026-03-14T09:11:04Z");
  });

  it("shifts an explicit +02:00 offset back to UTC", () => {
    expect(l2tTime("03/14/2026", "09:11:04", "+02:00")).toBe("2026-03-14T07:11:04.000Z");
  });

  it("accepts an offset written without a colon", () => {
    expect(l2tTime("03/14/2026", "09:11:04", "-0500")).toBe("2026-03-14T14:11:04.000Z");
  });

  it("falls back to reading the wall clock as UTC for an odd zone name", () => {
    expect(l2tTime("03/14/2026", "09:11:04", "Europe/Berlin")).toBe("2026-03-14T09:11:04Z");
  });

  it("pads a single-digit month and day", () => {
    expect(l2tTime("3/4/2026", "01:02:03", "UTC")).toBe("2026-03-04T01:02:03Z");
  });

  it("returns an empty string for a malformed date", () => {
    expect(l2tTime("2026-03-14", "09:11:04", "UTC")).toBe("");
    expect(l2tTime("", "09:11:04", "UTC")).toBe("");
    expect(l2tTime("14/03/26", "09:11:04", "UTC")).toBe("");
  });
});

describe("dynTime", () => {
  it("truncates 6-digit microseconds to milliseconds", () => {
    expect(dynTime("2026-03-14T09:11:04.123456+00:00")).toBe("2026-03-14T09:11:04.123Z");
  });

  it("truncates microseconds on a Z-suffixed stamp too", () => {
    expect(dynTime("2026-03-14T09:11:04.123456Z")).toBe("2026-03-14T09:11:04.123Z");
  });

  it("shifts a non-zero offset back to UTC", () => {
    expect(dynTime("2026-03-14T09:11:04.000000+02:00")).toBe("2026-03-14T07:11:04.000Z");
  });

  it("marks a naive stamp as UTC rather than shifting it", () => {
    expect(dynTime("2026-03-14 09:11:04")).toBe("2026-03-14T09:11:04Z");
  });

  it("returns an empty string for an empty value", () => {
    expect(dynTime("")).toBe("");
    expect(dynTime("   ")).toBe("");
  });
});

describe("mapRow", () => {
  it("returns null when the row carries no message text", () => {
    const cells = ["2026-03-14T09:11:04.000000+00:00", "Creation Time", "FILE", "NTFS", "   "];
    expect(mapRow("dynamic", DYN_HEADERS, cells, 7)).toBeNull();
  });

  it("returns null when an l2tcsv row has neither desc nor short", () => {
    const headers = ["date", "time", "timezone", "desc", "short"];
    expect(mapRow("l2tcsv", headers, ["03/14/2026", "09:11:04", "UTC", "", ""], 3)).toBeNull();
  });

  it("maps every dynamic field, preferring source_long", () => {
    const cells = [
      "2026-03-14T09:08:19.000000+00:00",
      "Recorded Time",
      "EVT",
      "WinEVTX",
      "mimikatz.exe sekurlsa::logonpasswords",
      "winevtx",
      "TSK:/Windows/System32/winevt/Logs/Security.evtx",
      "",
    ];
    const row = mapRow("dynamic", DYN_HEADERS, cells, 12);
    expect(row).not.toBeNull();
    const r = row as TimelineRow;
    expect(r.rowNo).toBe(12);
    expect(r.timestamp).toBe("2026-03-14T09:08:19.000Z");
    expect(r.message).toBe("mimikatz.exe sekurlsa::logonpasswords");
    expect(r.source).toBe("WinEVTX");
    expect(r.timestampDesc).toBe("Recorded Time");
    expect(r.path).toBe("/Windows/System32/winevt/Logs/Security.evtx");
    expect(r.host).toBe("");
  });

  it("falls back to source when a dynamic row has no source_long", () => {
    const cells = ["2026-03-14T09:08:19.000000+00:00", "Recorded Time", "EVT", "", "a message"];
    const r = mapRow("dynamic", DYN_HEADERS, cells, 1) as TimelineRow;
    expect(r.source).toBe("EVT");
  });

  it("maps every l2tcsv field, preferring desc and sourcetype", () => {
    const cells = [
      "03/14/2026",
      "09:11:04",
      "UTC",
      "MACB",
      "EVT",
      "WinEVTX",
      "Recorded Time",
      "SYSTEM",
      "WKSTN01",
      "4698 task created",
      "[4698] A scheduled task was created.",
      "2",
      "TSK:/Windows/System32/winevt/Logs/Security.evtx",
      "4416",
      "-",
      "winevtx",
      "-",
    ];
    const r = mapRow("l2tcsv", L2T_HEADERS, cells, 18) as TimelineRow;
    expect(r.rowNo).toBe(18);
    expect(r.timestamp).toBe("2026-03-14T09:11:04Z");
    expect(r.message).toBe("[4698] A scheduled task was created.");
    expect(r.source).toBe("WinEVTX");
    expect(r.timestampDesc).toBe("Recorded Time");
    expect(r.path).toBe("/Windows/System32/winevt/Logs/Security.evtx");
    expect(r.host).toBe("WKSTN01");
  });

  it("falls back to short when an l2tcsv row has no desc", () => {
    const headers = ["date", "time", "timezone", "short", "desc"];
    const r = mapRow("l2tcsv", headers, ["03/14/2026", "09:11:04", "UTC", "short text", ""], 2);
    expect((r as TimelineRow).message).toBe("short text");
  });

  it("treats an l2tcsv host of '-' as no host", () => {
    const headers = ["date", "time", "timezone", "desc", "host"];
    const dash = mapRow("l2tcsv", headers, ["03/14/2026", "09:11:04", "UTC", "m", "-"], 1);
    const blank = mapRow("l2tcsv", headers, ["03/14/2026", "09:11:04", "UTC", "m", ""], 1);
    expect((dash as TimelineRow).host).toBe("");
    expect((blank as TimelineRow).host).toBe("");
  });

  it("leaves path empty when the display name is a URL or has no separator", () => {
    const url = ["2026-03-14T09:00:00.000000+00:00", "t", "s", "sl", "m", "p", "https://a.example.com/x"];
    const bare = ["2026-03-14T09:00:00.000000+00:00", "t", "s", "sl", "m", "p", "NOTAPATH"];
    expect((mapRow("dynamic", DYN_HEADERS, url, 1) as TimelineRow).path).toBe("");
    expect((mapRow("dynamic", DYN_HEADERS, bare, 1) as TimelineRow).path).toBe("");
  });

  it("keeps raw exactly as the file wrote it, untrimmed", () => {
    const headers = ["datetime", "message", "source", "note"];
    const cells = ["  2026-03-14T09:00:00.000000+00:00 ", "  spaced message  ", "FILE", "  "];
    const r = mapRow("dynamic", headers, cells, 5) as TimelineRow;
    expect(r.raw).toEqual({
      datetime: "  2026-03-14T09:00:00.000000+00:00 ",
      message: "  spaced message  ",
      source: "FILE",
      note: "  ",
    });
    // The pulled-out fields are trimmed; only `raw` is verbatim.
    expect(r.message).toBe("spaced message");
    expect(r.timestamp).toBe("2026-03-14T09:00:00.000Z");
  });

  it("fills a short row's missing trailing cells with empty strings in raw", () => {
    const headers = ["datetime", "message", "source", "parser"];
    const r = mapRow("dynamic", headers, ["2026-03-14T09:00:00.000000+00:00", "m"], 1) as TimelineRow;
    expect(r.raw).toEqual({
      datetime: "2026-03-14T09:00:00.000000+00:00",
      message: "m",
      source: "",
      parser: "",
    });
  });

  it("strips a BOM from the first raw key but keeps the header spelling otherwise", () => {
    const headers = ["\uFEFFdatetime", "Message"];
    const r = mapRow("dynamic", headers, ["2026-03-14T09:00:00.000000+00:00", "m"], 1) as TimelineRow;
    expect(Object.keys(r.raw)).toEqual(["datetime", "Message"]);
  });

  it("leaves the timestamp empty rather than guessing when the source stamp is malformed", () => {
    // TimelineRow.timestamp is declared "UTC ISO-8601, or empty" — junk must not leak through.
    const r = mapRow("dynamic", ["datetime", "message"], ["not a date", "m"], 1) as TimelineRow;
    expect(r.timestamp).toBe("");
    const l2t = mapRow("l2tcsv", ["date", "time", "desc"], ["bad", "09:00:00", "m"], 1);
    expect((l2t as TimelineRow).timestamp).toBe("");
  });
});

describe("readTimeline", () => {
  it("reads all 40 rows of the dynamic fixture in file order", async () => {
    const rows = await collect(readTimeline(DYNAMIC_FIXTURE));
    expect(rows).toHaveLength(40);
    expect(rows[0]?.rowNo).toBe(1);
    expect(rows[39]?.rowNo).toBe(40);
    expect(rows[0]?.timestamp).toBe("2026-03-14T08:00:03.120Z");
    expect(rows[0]?.source).toBe("NTFS $MFT");
    expect(rows[0]?.host).toBe("");
  });

  it("reads all 40 rows of the l2t fixture and carries the host", async () => {
    const rows = await collect(readTimeline(L2T_FIXTURE));
    expect(rows).toHaveLength(40);
    expect(rows[0]?.timestamp).toBe("2026-03-14T08:00:03Z");
    expect(rows[0]?.host).toBe("WKSTN01");
    // The Defender-scan row carries host "-", which must map to "".
    const dash = rows.find((r) => r.message.includes("mpenginedb.db"));
    expect(dash?.host).toBe("");
  });

  it("carries the adversarial rows through untouched in both dialects", async () => {
    for (const file of [DYNAMIC_FIXTURE, L2T_FIXTURE]) {
      const rows = await collect(readTimeline(file));
      const formula = rows.find((r) => r.message.startsWith("=cmd|"));
      expect(formula, `formula row missing in ${file}`).toBeDefined();
      expect(formula?.message).toContain("=cmd|' /C calc.exe'!A0");

      const quoted = rows.find((r) => r.message.includes('"Debugger"'));
      expect(quoted, `quoted row missing in ${file}`).toBeDefined();
      expect(quoted?.message).toContain('Registry value "Debugger" set on');
    }
  });

  it("keeps the obviously malicious rows and does not grade or truncate them", async () => {
    const rows = await collect(readTimeline(DYNAMIC_FIXTURE));
    const joined = rows.map((r) => r.message).join("\n");
    expect(joined).toContain("mimikatz.exe");
    expect(joined).toContain("wevtutil.exe cl Security");
    expect(joined).toContain("A scheduled task was created");
    expect(joined).toContain("C:\\Windows\\Temp\\update_check.ps1");
    // No description is built and nothing is clipped at 600 chars.
    for (const r of rows) expect(r.message.startsWith("Plaso")).toBe(false);
  });

  it("keeps a message whose quoted field wrapped over several source lines", async () => {
    const rows = await collect(readTimeline(DYNAMIC_FIXTURE));
    const svc = rows.find((r) => r.message.includes("PSEXESVC"));
    expect(svc?.message).toContain("Service Name: PSEXESVC");
    expect(svc?.message).toContain("Service Type: user mode service");
  });

  it("keeps every original column in raw so the exporter can write them back", async () => {
    const rows = await collect(readTimeline(L2T_FIXTURE));
    const first = rows[0];
    expect(first).toBeDefined();
    expect(Object.keys(first?.raw ?? {})).toEqual([...L2T_HEADERS]);
    expect(first?.raw["inode"]).toBe("9114");
  });

  it("throws an error naming the file when the header matches no known dialect", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "tt-flavor-"));
    const bad = join(dir, "not-plaso.csv");
    writeFileSync(bad, "Timestamp,EventID,Computer\n1,2,3\n", "utf8");
    await expect(collect(readTimeline(bad))).rejects.toThrow(/not-plaso\.csv/);
    await expect(collect(readTimeline(bad))).rejects.toThrow(/dynamic|l2tcsv|Plaso/i);
  });

  it("throws an error naming the file when it is empty", async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const dir = mkdtempSync(join(tmpdir(), "tt-flavor-"));
    const empty = join(dir, "empty.csv");
    writeFileSync(empty, "", "utf8");
    await expect(collect(readTimeline(empty))).rejects.toThrow(/empty\.csv/);
  });
});
