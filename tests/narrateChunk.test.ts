import { describe, expect, it } from "vitest";
import {
  DEFAULT_CHUNK_BUDGET_TOKENS,
  DEFAULT_MAX_ROWS_PER_CHUNK,
  estimateTokens,
  planChunks,
} from "../src/narrate/chunk.js";

/** A test item: an ordinal plus a body whose length drives the token estimate. */
interface Item {
  readonly n: number;
  readonly body: string;
}

function item(n: number, chars = 40): Item {
  return { n, body: "x".repeat(chars) };
}

const render = (i: Item): string => i.body;

/** The ordinals of every item, chunk by chunk, flattened. */
function order(chunks: readonly Item[][]): number[] {
  return chunks.flat().map((i) => i.n);
}

describe("estimateTokens", () => {
  it("rounds up at about four characters per token", () => {
    expect(estimateTokens("")).toBe(0);
    expect(estimateTokens("abcd")).toBe(1);
    expect(estimateTokens("abcde")).toBe(2);
    expect(estimateTokens("x".repeat(4000))).toBe(1000);
  });
});

describe("planChunks", () => {
  it("returns no chunks for no items", () => {
    expect(planChunks([], render, 1000, 10)).toEqual([]);
  });

  it("puts an under-budget set in a single chunk", () => {
    const items = [item(1), item(2), item(3)];
    const chunks = planChunks(items, render, 10_000, 100);
    expect(chunks).toHaveLength(1);
    expect(chunks[0]).toHaveLength(3);
  });

  it("splits when the token budget is exceeded", () => {
    // Each item is 400 chars = 100 tokens. A 250-token budget holds two.
    const items = [item(1, 400), item(2, 400), item(3, 400), item(4, 400)];
    const chunks = planChunks(items, render, 250, 100);
    expect(chunks).toHaveLength(2);
    expect(chunks[0]?.map((i) => i.n)).toEqual([1, 2]);
    expect(chunks[1]?.map((i) => i.n)).toEqual([3, 4]);
  });

  it("honours the per-chunk count cap even when the budget is huge", () => {
    const items = Array.from({ length: 10 }, (_, i) => item(i + 1));
    const chunks = planChunks(items, render, 1_000_000, 3);
    expect(chunks.map((c) => c.length)).toEqual([3, 3, 3, 1]);
  });

  it("gives an oversized single item its own chunk instead of dropping it", () => {
    const items = [item(1), item(2, 40_000), item(3)];
    const chunks = planChunks(items, render, 100, 100);
    expect(order(chunks)).toEqual([1, 2, 3]);
    const solo = chunks.find((c) => c.length === 1 && c[0]?.n === 2);
    expect(solo).toBeDefined();
  });

  it("never returns an empty chunk", () => {
    const items = Array.from({ length: 25 }, (_, i) => item(i + 1, 1200));
    for (const chunk of planChunks(items, render, 300, 4)) {
      expect(chunk.length).toBeGreaterThan(0);
    }
  });

  it("keeps the input order, so chunks stay chronological", () => {
    const items = Array.from({ length: 50 }, (_, i) => item(i + 1, 200));
    const chunks = planChunks(items, render, 400, 7);
    expect(order(chunks)).toEqual(items.map((i) => i.n));
  });

  it("treats a zero or negative budget and cap as one, never as a dropped item", () => {
    const items = [item(1), item(2), item(3)];
    const chunks = planChunks(items, render, 0, 0);
    expect(order(chunks)).toEqual([1, 2, 3]);
  });
});

describe("default budget constants", () => {
  it("leaves output and system-prompt room inside a 128k context window", () => {
    expect(DEFAULT_CHUNK_BUDGET_TOKENS).toBeGreaterThan(1000);
    expect(DEFAULT_CHUNK_BUDGET_TOKENS).toBeLessThan(128_000);
  });

  it("caps the rows one prompt may carry", () => {
    expect(DEFAULT_MAX_ROWS_PER_CHUNK).toBeGreaterThan(0);
  });
});
