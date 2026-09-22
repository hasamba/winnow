import { describe, expect, it, vi } from "vitest";
import { runPool } from "../src/jev/pool.js";

/** Yields to the event loop, so every started worker overlaps the others. */
const tick = (ms = 1): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

describe("runPool", () => {
  it("never exceeds its concurrency and completes every item", async () => {
    const items = Array.from({ length: 100 }, (_, i) => i);
    let inFlight = 0;
    let peak = 0;
    const results: number[] = [];

    await runPool(
      items,
      async (item) => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await tick();
        inFlight -= 1;
        return item * 2;
      },
      { concurrency: 8, onResult: (r) => results.push(r as number) },
    );

    expect(peak).toBe(8);
    expect(inFlight).toBe(0);
    expect(results).toHaveLength(100);
    expect([...results].sort((a, b) => a - b)).toEqual(items.map((i) => i * 2));
  });

  it("reports a running count in completion order", async () => {
    const seen: number[] = [];
    await runPool([1, 2, 3, 4], async (n) => n, {
      concurrency: 1,
      onResult: (_r, _item, done) => seen.push(done),
    });
    expect(seen).toEqual([1, 2, 3, 4]);
  });

  it("surfaces a throwing worker through onResult and finishes the rest", async () => {
    const results: unknown[] = [];
    await runPool(
      [1, 2, 3, 4, 5],
      async (n) => {
        if (n === 3) throw new Error("worker blew up on 3");
        return n;
      },
      { concurrency: 2, onResult: (r) => results.push(r) },
    );

    expect(results).toHaveLength(5);
    const thrown = results.filter((r) => r instanceof Error) as Error[];
    expect(thrown).toHaveLength(1);
    expect(thrown[0]?.message).toContain("worker blew up on 3");
    expect(results.filter((r) => typeof r === "number").sort()).toEqual([1, 2, 4, 5]);
  });

  it("starts no work at all when the signal is already aborted", async () => {
    const worker = vi.fn(async (n: number) => n);
    const controller = new AbortController();
    controller.abort();

    await runPool([1, 2, 3], worker, { concurrency: 4, signal: controller.signal });

    expect(worker).not.toHaveBeenCalled();
  });

  it("lets in-flight work finish after an abort and keeps its results", async () => {
    const controller = new AbortController();
    const started: number[] = [];
    const results: number[] = [];

    await runPool(
      Array.from({ length: 50 }, (_, i) => i),
      async (item) => {
        started.push(item);
        await tick();
        return item;
      },
      {
        concurrency: 4,
        signal: controller.signal,
        onResult: (r) => {
          results.push(r as number);
          if (results.length === 8) controller.abort();
        },
      },
    );

    expect(results.length).toBeGreaterThanOrEqual(8);
    // The four workers in flight when the abort landed may each add one more result.
    expect(results.length).toBeLessThanOrEqual(12);
    expect(started.length).toBe(results.length);
    expect(started.length).toBeLessThan(50);
  });

  it("resolves immediately on an empty list", async () => {
    const worker = vi.fn(async (n: number) => n);
    await runPool([], worker, { concurrency: 8 });
    expect(worker).not.toHaveBeenCalled();
  });
});
