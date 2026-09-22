// Loading and validating questions.json — the file a human reviews and edits. The wording is
// the product (jev-sort rule 6), so the file ships readable and is validated hard at the
// boundary: a malformed question costs a 422 per call, or worse, a whole run of poor verdicts.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { JevQuestion, QuestionSet } from "../types.js";

/** The exporter reads these four by name, so all four must be present. */
export const REQUIRED_QUESTION_IDS = [
  "malicious",
  "category",
  "severity",
  "needs_analyst",
] as const;

/** Limits from the jev-sort skill. */
const MAX_CHOICE_OPTIONS = 255;
const MIN_SCORE_LEVELS = 2;
const MAX_SCORE_LEVELS = 10;

/** questions.json sits at the package root, two levels up from src/jev and from dist/jev. */
const DEFAULT_QUESTIONS_PATH = fileURLToPath(new URL("../../questions.json", import.meta.url));

/**
 * Read a questions file. Returns the validated set and the file's exact text, because the
 * decision key folds in a hash of that text: edit a question and old verdicts stop matching.
 */
export function loadQuestions(path: string = DEFAULT_QUESTIONS_PATH): {
  questions: QuestionSet;
  json: string;
} {
  let json: string;
  try {
    json = readFileSync(path, "utf8");
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`Cannot read the questions file ${path}: ${reason}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(json) as unknown;
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`The questions file ${path} is not valid JSON: ${reason}`);
  }

  return { questions: validateQuestions(raw), json };
}

/** Validate an untrusted questions object. Throws an Error naming the offending question. */
export function validateQuestions(raw: unknown): QuestionSet {
  const map = asRecord(raw);
  if (!map) throw new Error("The questions file must hold a JSON object mapping ids to questions.");

  const out: Record<string, JevQuestion> = {};
  for (const [id, value] of Object.entries(map)) {
    out[id] = validateOne(id, value);
  }

  const missing = REQUIRED_QUESTION_IDS.filter((id) => !(id in out));
  if (missing.length > 0) {
    throw new Error(
      `The questions file is missing the required question(s): ${missing.join(", ")}. ` +
        `The exporter reads all of ${REQUIRED_QUESTION_IDS.join(", ")} by name.`,
    );
  }
  return out;
}

function validateOne(id: string, value: unknown): JevQuestion {
  const q = asRecord(value);
  if (!q) throw new Error(`Question "${id}" must be an object.`);

  const instructions = q["instructions"];
  if (typeof instructions !== "string" || instructions.trim() === "") {
    throw new Error(`Question "${id}" needs a non-empty "instructions" string.`);
  }

  const type = q["type"];
  if (type === "noul" || type === "choice") {
    const criteria = asStringRecord(q["criteria"]);
    if (!criteria) {
      throw new Error(
        `Question "${id}" is a ${type}, so its "criteria" must be an object of ` +
          `option name to rubric text.`,
      );
    }
    const count = Object.keys(criteria).length;
    if (count < MIN_SCORE_LEVELS) {
      throw new Error(`Question "${id}" needs at least ${MIN_SCORE_LEVELS} criteria, has ${count}.`);
    }
    if (type === "choice" && count > MAX_CHOICE_OPTIONS) {
      throw new Error(
        `Question "${id}" has ${count} options; a choice takes at most ${MAX_CHOICE_OPTIONS}.`,
      );
    }
    return { type, instructions, criteria };
  }

  if (type === "score") {
    const criteria = q["criteria"];
    if (!Array.isArray(criteria) || criteria.some((c) => typeof c !== "string" || c.trim() === "")) {
      throw new Error(`Question "${id}" is a score, so its "criteria" must be an array of level names.`);
    }
    if (criteria.length < MIN_SCORE_LEVELS || criteria.length > MAX_SCORE_LEVELS) {
      throw new Error(
        `Question "${id}" has ${criteria.length} levels; a score takes ` +
          `${MIN_SCORE_LEVELS} to ${MAX_SCORE_LEVELS}.`,
      );
    }
    return { type, instructions, criteria: criteria as readonly string[] };
  }

  throw new Error(
    `Question "${id}" has an unknown type ${JSON.stringify(type)}. Use "noul", "choice" or "score".`,
  );
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  return value as Record<string, unknown>;
}

function asStringRecord(value: unknown): Record<string, string> | undefined {
  const record = asRecord(value);
  if (!record) return undefined;
  for (const entry of Object.values(record)) {
    if (typeof entry !== "string") return undefined;
  }
  return record as Record<string, string>;
}
