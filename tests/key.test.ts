import { describe, expect, it } from "vitest";
import type { TimelineRow } from "../src/types.js";
import {
  decisionKey,
  decisionKeyText,
  hashQuestions,
  jevStateFrom,
} from "../src/triage/key.js";

const US = "\x1f";

function row(over: Partial<TimelineRow> = {}): TimelineRow {
  const base: TimelineRow = {
    rowNo: 1,
    timestamp: "2026-01-01T00:00:00Z",
    message: "a message",
    source: "LOG",
    timestampDesc: "Content Modification Time",
    path: "",
    host: "",
    raw: {},
  };
  return { ...base, ...over };
}

describe("decisionKeyText", () => {
  it("joins source, timestampDesc and message with the unit separator", () => {
    const text = decisionKeyText(
      row({ source: "FILE", timestampDesc: "mtime", message: "hello" }),
    );
    expect(text).toBe(`FILE${US}mtime${US}hello`);
  });

  it("keeps two IP addresses apart instead of folding digits to '#'", () => {
    const a = decisionKeyText(row({ message: "Connection to 192.0.2.5 on 443" }));
    const b = decisionKeyText(row({ message: "Connection to 192.0.2.77 on 443" }));
    expect(a).not.toBe(b);
  });

  // Each of these bites one clause of Companion's aggKey (plasoImport.ts:202):
  // toLowerCase, the GUID substitution, the /\d{3,}/ -> "#" substitution, and slice(0, 400).
  // If someone reintroduces that normalisation here, one of them goes red.

  it("keeps two ports apart instead of collapsing every 3+ digit run to '#'", () => {
    const a = decisionKeyText(row({ message: "Outbound to 198.51.100.7 port 4444" }));
    const b = decisionKeyText(row({ message: "Outbound to 198.51.100.7 port 8080" }));
    expect(a).not.toBe(b);
  });

  it("keeps two last octets apart when both are 3 digits", () => {
    const a = decisionKeyText(row({ message: "dst 198.51.100.100" }));
    const b = decisionKeyText(row({ message: "dst 198.51.100.200" }));
    expect(a).not.toBe(b);
  });

  it("keeps two GUIDs apart instead of substituting them", () => {
    const a = decisionKeyText(
      row({ message: "Task {6f3a1b2c-1111-4d5e-8f90-a1b2c3d4e5f6} ran" }),
    );
    const b = decisionKeyText(
      row({ message: "Task {6f3a1b2c-2222-4d5e-8f90-a1b2c3d4e5f6} ran" }),
    );
    expect(a).not.toBe(b);
  });

  it("keeps a case difference apart: ADMIN$ is not admin$", () => {
    const a = decisionKeyText(row({ message: "Share ADMIN$ mounted" }));
    const b = decisionKeyText(row({ message: "Share admin$ mounted" }));
    expect(a).not.toBe(b);
  });

  it("does not truncate a long message, so a tail-only difference still splits", () => {
    const head = "x".repeat(500);
    const a = decisionKeyText(row({ message: `${head} -enc BENIGN` }));
    const b = decisionKeyText(row({ message: `${head} -enc PAYLOAD` }));
    expect(a).not.toBe(b);
  });

  it("is verbatim: no lowercasing and no trimming of the message", () => {
    const text = decisionKeyText(
      row({ source: "EVT", timestampDesc: "Creation", message: "  MiXeD Case  " }),
    );
    expect(text).toBe(`EVT${US}Creation${US}  MiXeD Case  `);
  });

  it("ignores the timestamp, so a MACB expansion collapses to one text", () => {
    const texts = new Set(
      ["2026-01-01T00:00:00Z", "2026-02-02T00:00:00Z", "2026-03-03T00:00:00Z"].map(
        (timestamp) => decisionKeyText(row({ timestamp })),
      ),
    );
    expect(texts.size).toBe(1);
  });
});

describe("decisionKey", () => {
  it("produces a 64-char hex sha256 over keyText and the questions hash", () => {
    const key = decisionKey(row(), "q0000000");
    expect(key.keyText).toBe(decisionKeyText(row()));
    expect(key.keyHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("gives two different IPs two different key hashes", () => {
    const a = decisionKey(row({ message: "dst 192.0.2.5" }), "q1");
    const b = decisionKey(row({ message: "dst 192.0.2.77" }), "q1");
    expect(a.keyHash).not.toBe(b.keyHash);
  });

  it("changes the key hash when the questions hash changes", () => {
    const a = decisionKey(row(), "questions-v1");
    const b = decisionKey(row(), "questions-v2");
    expect(a.keyText).toBe(b.keyText);
    expect(a.keyHash).not.toBe(b.keyHash);
  });

  it("is stable for the same row and questions hash", () => {
    expect(decisionKey(row(), "q").keyHash).toBe(decisionKey(row(), "q").keyHash);
  });
});

describe("hashQuestions", () => {
  it("returns 16 hex chars and changes when the text changes", () => {
    const a = hashQuestions('{"malicious":{"type":"score"}}');
    const b = hashQuestions('{"malicious":{"type":"noul"}}');
    expect(a).toMatch(/^[0-9a-f]{16}$/);
    expect(b).toMatch(/^[0-9a-f]{16}$/);
    expect(a).not.toBe(b);
    expect(hashQuestions("same")).toBe(hashQuestions("same"));
  });
});

describe("jevStateFrom", () => {
  it("always carries source, timestamp_desc and message", () => {
    const state = jevStateFrom(
      row({ source: "FILE", timestampDesc: "mtime", message: "m" }),
    );
    expect(state.source).toBe("FILE");
    expect(state.timestamp_desc).toBe("mtime");
    expect(state.message).toBe("m");
  });

  it("omits path and host when they are empty", () => {
    const state = jevStateFrom(row({ path: "", host: "" }));
    expect("path" in state).toBe(false);
    expect("host" in state).toBe(false);
  });

  it("includes path and host when they are present", () => {
    const state = jevStateFrom(row({ path: "C:\\Windows\\Temp\\a.ps1", host: "WS01" }));
    expect(state.path).toBe("C:\\Windows\\Temp\\a.ps1");
    expect(state.host).toBe("WS01");
  });
});
