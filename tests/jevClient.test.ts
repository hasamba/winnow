import { describe, expect, it, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  JEV_ENDPOINT,
  JEV_MODEL,
  askJev,
  flattenAnswers,
  loadApiKey,
} from "../src/jev/client.js";
import type { JevState, QuestionSet } from "../src/types.js";

const STATE: JevState = {
  source: "REG",
  timestamp_desc: "Content Modification Time",
  message: "Run key value: evil.exe",
};

const QUESTIONS: QuestionSet = {
  malicious: { type: "noul", instructions: "Attacker?", criteria: { true: "yes", false: "no" } },
  category: { type: "choice", instructions: "Kind?", criteria: { persistence: "a", benign_system: "b" } },
  severity: { type: "score", instructions: "Serious?", criteria: ["Low", "Medium", "High"] },
  needs_analyst: { type: "noul", instructions: "Human?", criteria: { true: "yes", false: "no" } },
};

/** A complete, well-formed decisions response, shaped like the real API's. */
function goodBody(): unknown {
  return {
    answers: {
      malicious: { type: "noul", noul: 0.92 },
      category: { type: "choice", choice: "persistence", confidence: 0.81 },
      severity: {
        type: "score",
        score: 3.4,
        confidence: 0.77,
        legend: { "1": "Low", "2": "Medium", "3": "High", "4": "Critical" },
      },
      needs_analyst: { type: "noul", noul: 0.64 },
    },
    usage: { cost: 0.000031 },
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

/** Returns a fetch stand-in that yields the given responses in order. */
function fetchReturning(...responses: Array<Response | Error>): {
  impl: typeof fetch;
  calls: () => number;
  lastInit: () => RequestInit | undefined;
} {
  let n = 0;
  let lastInit: RequestInit | undefined;
  const impl = (async (_input: unknown, init?: RequestInit) => {
    lastInit = init;
    const next = responses[Math.min(n, responses.length - 1)];
    n += 1;
    if (next instanceof Error) throw next;
    // A Response body can be read once only, so hand out a clone.
    return (next as Response).clone();
  }) as unknown as typeof fetch;
  return { impl, calls: () => n, lastInit: () => lastInit };
}

describe("askJev", () => {
  it("flattens a well-formed response into a Verdict, level looked up from the legend", async () => {
    const f = fetchReturning(jsonResponse(goodBody()));
    const sleep = vi.fn(async () => {});
    const res = await askJev(STATE, QUESTIONS, "test-key", { fetchImpl: f.impl, sleep });

    expect(res.error).toBeUndefined();
    expect(res.verdict).toEqual({
      malicious: 0.92,
      category: "persistence",
      categoryConfidence: 0.81,
      severity: 3.4,
      severityLevel: "High",
      needsAnalyst: 0.64,
    });
    expect(res.costUsd).toBe(0.000031);
    expect(res.seconds).toBeGreaterThanOrEqual(0);
    expect(sleep).not.toHaveBeenCalled();

    const body = JSON.parse(String(f.lastInit()?.body)) as Record<string, unknown>;
    expect(body["model"]).toBe(JEV_MODEL);
    // Rule 2: the row is sent as an object, never flattened to a string.
    expect(body["state"]).toEqual(STATE);
    expect(body["questions"]).toEqual(QUESTIONS);
  });

  it("posts to the alpha decisions endpoint", async () => {
    const f = fetchReturning(jsonResponse(goodBody()));
    const seen: string[] = [];
    const impl = (async (input: unknown, init?: RequestInit) => {
      seen.push(String(input));
      return (await (f.impl as (i: unknown, x?: RequestInit) => Promise<Response>)(input, init));
    }) as unknown as typeof fetch;
    await askJev(STATE, QUESTIONS, "test-key", { fetchImpl: impl, sleep: async () => {} });
    expect(seen[0]).toBe(JEV_ENDPOINT);
    expect(JEV_ENDPOINT).toBe("https://openrouter.ai/api/alpha/decisions");
    expect(JEV_MODEL).toBe("typesafe/jev-1.13");
  });

  it("retries a 429 once and then succeeds, having slept", async () => {
    const f = fetchReturning(jsonResponse({ error: "slow down" }, 429), jsonResponse(goodBody()));
    const sleep = vi.fn(async () => {});
    const res = await askJev(STATE, QUESTIONS, "k", { fetchImpl: f.impl, sleep });

    expect(res.error).toBeUndefined();
    expect(res.verdict?.malicious).toBe(0.92);
    expect(f.calls()).toBe(2);
    expect(sleep).toHaveBeenCalledTimes(1);
    expect(sleep).toHaveBeenCalledWith(1000);
  });

  it("does not retry a 401 and returns its status as an error", async () => {
    const f = fetchReturning(jsonResponse({ error: "no auth" }, 401));
    const sleep = vi.fn(async () => {});
    const res = await askJev(STATE, QUESTIONS, "k", { fetchImpl: f.impl, sleep });

    expect(res.verdict).toBeUndefined();
    expect(res.error).toContain("401");
    expect(f.calls()).toBe(1);
    expect(sleep).not.toHaveBeenCalled();
  });

  it("explains that a 422 means a malformed question", async () => {
    const f = fetchReturning(jsonResponse({ error: "criteria invalid" }, 422));
    const res = await askJev(STATE, QUESTIONS, "k", { fetchImpl: f.impl, sleep: async () => {} });

    expect(res.error).toContain("422");
    expect(res.error?.toLowerCase()).toContain("malformed question");
    expect(f.calls()).toBe(1);
  });

  it("retries a network throw and gives up after four attempts", async () => {
    const f = fetchReturning(new TypeError("fetch failed"));
    const sleep = vi.fn(async () => {});
    const res = await askJev(STATE, QUESTIONS, "k", { fetchImpl: f.impl, sleep });

    expect(res.verdict).toBeUndefined();
    expect(res.error).toContain("fetch failed");
    expect(f.calls()).toBe(4);
    expect(sleep.mock.calls.map((c: readonly number[]) => c[0])).toEqual([1000, 2000, 4000]);
  });

  it("reports a malformed 200 body as an error rather than throwing", async () => {
    const f = fetchReturning(jsonResponse({ usage: { cost: 0.1 } }));
    const res = await askJev(STATE, QUESTIONS, "k", { fetchImpl: f.impl, sleep: async () => {} });
    expect(res.verdict).toBeUndefined();
    expect(res.error).toBeTruthy();
  });
});

describe("flattenAnswers", () => {
  it("returns undefined when answers are missing", () => {
    expect(flattenAnswers(undefined)).toBeUndefined();
    expect(flattenAnswers(null)).toBeUndefined();
    expect(flattenAnswers({})).toBeUndefined();
    expect(flattenAnswers("answers")).toBeUndefined();
  });

  it("returns undefined when a noul answer lacks its number", () => {
    const body = goodBody() as { answers: Record<string, unknown> };
    body.answers["malicious"] = { type: "noul" };
    expect(flattenAnswers(body.answers)).toBeUndefined();
  });

  it("returns undefined when a required question id is absent", () => {
    const body = goodBody() as { answers: Record<string, unknown> };
    delete body.answers["severity"];
    expect(flattenAnswers(body.answers)).toBeUndefined();
  });

  it("returns undefined when an answer carries the wrong shape", () => {
    const body = goodBody() as { answers: Record<string, unknown> };
    body.answers["category"] = { type: "choice", choice: 7 };
    expect(flattenAnswers(body.answers)).toBeUndefined();
  });

  it("rounds the score to find its level in the legend", () => {
    const body = goodBody() as { answers: Record<string, Record<string, unknown>> };
    body.answers["severity"]!["score"] = 1.4;
    const v = flattenAnswers(body.answers);
    expect(v?.severity).toBe(1.4);
    expect(v?.severityLevel).toBe("Low");
  });

  it("falls back to an empty level when the legend has no entry", () => {
    const body = goodBody() as { answers: Record<string, Record<string, unknown>> };
    delete body.answers["severity"]!["legend"];
    expect(flattenAnswers(body.answers)?.severityLevel).toBe("");
  });
});

describe("loadApiKey", () => {
  it("prefers the environment variable", () => {
    expect(loadApiKey({ OPENROUTER_API_KEY: "env-value" } as NodeJS.ProcessEnv)).toBe("env-value");
  });

  it("throws a helpful error naming both sources, with no key material in it", () => {
    const home = mkdtempSync(join(tmpdir(), "triage-nokey-"));
    let message = "";
    try {
      loadApiKey({ HOME: home } as NodeJS.ProcessEnv);
      throw new Error("expected loadApiKey to throw");
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }
    expect(message).toContain("OPENROUTER_API_KEY");
    expect(message).toContain("openrouter.env");
    expect(message).not.toContain("sk-");
    expect(message).not.toContain("Bearer ");
  });
});
