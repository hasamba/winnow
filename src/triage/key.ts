// The deduplication key: what makes two timeline rows "the same question".
//
// A supertimeline repeats itself enormously — the MACB expansion alone turns one file into
// four rows that differ only in the timestamp — so the judge must see each distinct question
// once. This module decides what "distinct" means, and nothing else.

import { createHash } from "node:crypto";
import type { DecisionKey, JevState, TimelineRow } from "../types.js";

/** ASCII unit separator. It cannot occur in a Plaso field, so the join is unambiguous. */
const US = "\x1f";

/** How many hex characters of the questions digest travel with every key. */
const QUESTIONS_HASH_LENGTH = 16;

/**
 * The text two rows must match on to share one decision: source, timestampDesc and message,
 * joined verbatim. The timestamp is deliberately absent — that is the MACB collapse.
 *
 * DO NOT NORMALISE THIS TEXT. No lowercasing, no trimming, no digit or GUID substitution.
 *
 * Companion's `aggKey` (plasoImport.ts:202) replaces every run of 3+ digits with "#" so that
 * near-identical rows group for display. That is right for a display bucket and wrong here:
 * "192.0.2.5" and "192.0.2.77" would collapse into one key, one Jev call and one verdict, so a
 * beacon to an attacker host would inherit the verdict of a call to a benign one. The same
 * applies to ports, PIDs, session IDs and GUIDs. Every one of them can be the reason a row is
 * malicious. Dedupe here is an exact-match cache, not a similarity bucket. Collapsing more rows
 * is cheaper and wrong; if this ever needs to be looser, that is a new feature with its own
 * evidence, not an optimisation of this line.
 */
export function decisionKeyText(row: TimelineRow): string {
  return `${row.source}${US}${row.timestampDesc}${US}${row.message}`;
}

/**
 * The full key. The questions hash is folded into the digest, so editing a question changes
 * every key hash and the old verdicts are simply not found — the run re-judges instead of
 * silently reusing answers to a question nobody asks any more.
 */
export function decisionKey(row: TimelineRow, questionsHash: string): DecisionKey {
  const keyText = decisionKeyText(row);
  const keyHash = createHash("sha256")
    .update(`${keyText}${US}${questionsHash}`, "utf8")
    .digest("hex");
  return { keyText, keyHash };
}

/**
 * A short digest of the questions file text. Short because it is also written to `meta` and
 * shown to the analyst; the collision risk over a handful of question sets is negligible.
 */
export function hashQuestions(questionsJson: string): string {
  return createHash("sha256")
    .update(questionsJson, "utf8")
    .digest("hex")
    .slice(0, QUESTIONS_HASH_LENGTH);
}

/**
 * The structured record sent to Jev as `state`. `path` and `host` are omitted entirely when the
 * row has none — an absent key reads as "this dialect does not record it", while a present-but-
 * empty one reads as "it is empty", which is a different claim about the evidence.
 */
export function jevStateFrom(row: TimelineRow): JevState {
  const base = {
    source: row.source,
    timestamp_desc: row.timestampDesc,
    message: row.message,
  };
  return {
    ...base,
    ...(row.path !== "" ? { path: row.path } : {}),
    ...(row.host !== "" ? { host: row.host } : {}),
  };
}
