import { describe, expect, it } from "vitest";
import { REQUIRED_QUESTION_IDS, loadQuestions, validateQuestions } from "../src/jev/questions.js";

/** A minimal valid set, rebuilt per test so a mutation cannot leak between them. */
function validRaw(): Record<string, unknown> {
  return {
    malicious: {
      type: "noul",
      instructions: "Is this attacker activity?",
      criteria: { true: "Attacker tooling", false: "Normal activity" },
    },
    category: {
      type: "choice",
      instructions: "What kind of activity is this?",
      criteria: { execution: "A program being run", benign_system: "Routine OS activity" },
    },
    severity: {
      type: "score",
      instructions: "How serious is it?",
      criteria: ["Informational", "Low", "Medium", "High", "Critical"],
    },
    needs_analyst: {
      type: "noul",
      instructions: "Does a human need to look?",
      criteria: { true: "Ambiguous", false: "Routine" },
    },
  };
}

describe("validateQuestions", () => {
  it("accepts a well-formed set", () => {
    const q = validateQuestions(validRaw());
    expect(Object.keys(q).sort()).toEqual([...REQUIRED_QUESTION_IDS].sort());
    expect(q["severity"]?.type).toBe("score");
  });

  it("rejects a missing required id, naming it", () => {
    const raw = validRaw();
    delete raw["needs_analyst"];
    expect(() => validateQuestions(raw)).toThrow(/needs_analyst/);
  });

  it("rejects an unknown question type, naming the question", () => {
    const raw = validRaw();
    raw["category"] = { type: "ranking", instructions: "hm", criteria: { a: "b" } };
    expect(() => validateQuestions(raw)).toThrow(/category/);
  });

  it("rejects a score with only one level", () => {
    const raw = validRaw();
    raw["severity"] = { type: "score", instructions: "How serious?", criteria: ["Critical"] };
    expect(() => validateQuestions(raw)).toThrow(/severity/);
  });

  it("rejects a score with more than ten levels", () => {
    const raw = validRaw();
    raw["severity"] = {
      type: "score",
      instructions: "How serious?",
      criteria: Array.from({ length: 11 }, (_, i) => `level ${i}`),
    };
    expect(() => validateQuestions(raw)).toThrow(/severity/);
  });

  it("rejects empty instructions", () => {
    const raw = validRaw();
    raw["malicious"] = { type: "noul", instructions: "   ", criteria: { true: "a", false: "b" } };
    expect(() => validateQuestions(raw)).toThrow(/malicious/);
  });

  it("rejects criteria of the wrong shape", () => {
    const raw = validRaw();
    raw["malicious"] = { type: "noul", instructions: "Attacker?", criteria: ["true", "false"] };
    expect(() => validateQuestions(raw)).toThrow(/malicious/);

    const raw2 = validRaw();
    raw2["severity"] = { type: "score", instructions: "How serious?", criteria: { a: "b" } };
    expect(() => validateQuestions(raw2)).toThrow(/severity/);
  });

  it("rejects a choice with more than 255 options", () => {
    const raw = validRaw();
    const criteria: Record<string, string> = {};
    for (let i = 0; i < 256; i += 1) criteria[`opt${i}`] = `option ${i}`;
    raw["category"] = { type: "choice", instructions: "Which?", criteria };
    expect(() => validateQuestions(raw)).toThrow(/category/);
  });

  it("rejects a non-object", () => {
    expect(() => validateQuestions(null)).toThrow();
    expect(() => validateQuestions([])).toThrow();
    expect(() => validateQuestions("questions")).toThrow();
  });
});

describe("loadQuestions", () => {
  it("loads the shipped default set and returns its exact text", () => {
    const { questions, json } = loadQuestions();
    expect(Object.keys(questions).sort()).toEqual([...REQUIRED_QUESTION_IDS].sort());
    expect(questions["category"]?.type).toBe("choice");
    const category = questions["category"];
    if (category?.type !== "choice") throw new Error("category must be a choice");
    expect(Object.keys(category.criteria)).toHaveLength(8);
    const severity = questions["severity"];
    if (severity?.type !== "score") throw new Error("severity must be a score");
    expect(severity.criteria).toEqual(["Informational", "Low", "Medium", "High", "Critical"]);
    // The text is returned verbatim so the key hash can fold in the questions file.
    expect(JSON.parse(json)).toEqual(questions);
  });

  it("throws a readable error for a missing file", () => {
    expect(() => loadQuestions("/nonexistent/questions.json")).toThrow(/questions/i);
  });
});
