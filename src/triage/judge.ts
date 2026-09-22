// The Jev pass. It asks the decision model about every distinct row the scan found, and
// writes each verdict to the cache the moment it lands. That write-as-you-go is the whole
// resumability story: interrupt the run and restart it, and it continues where it stopped.

import { askJev, type JevCallResult } from "../jev/client.js";
import { runPool } from "../jev/pool.js";
import type { DecisionStore } from "./store.js";
import type { DecisionRecord, QuestionSet } from "../types.js";

export interface JudgeParams {
  readonly store: DecisionStore;
  readonly questions: QuestionSet;
  readonly apiKey: string;
  readonly concurrency: number;
  readonly rareFirst: boolean;
  /** Judge at most this many entries. Used by the sample command. */
  readonly limit?: number;
  /** Pick the entries at random rather than in store order. Sampling wants a fair spread. */
  readonly random?: boolean;
  /** Stop once this much has been spent. Undefined means no ceiling. */
  readonly maxCostUsd?: number;
  readonly model?: string;
  readonly signal?: AbortSignal;
  readonly onProgress?: (done: number, total: number, costUsd: number, errors: number) => void;
}

export interface JudgeResult {
  readonly decided: number;
  readonly errors: number;
  readonly costUsd: number;
  readonly stoppedOnCost: boolean;
}

export async function judgeUndecided(params: JudgeParams): Promise<JudgeResult> {
  const { store, questions, apiKey, concurrency, rareFirst, maxCostUsd, signal, onProgress } =
    params;

  let pending: DecisionRecord[] = store.undecided({ rareFirst });

  if (params.random) {
    // Fisher-Yates. A sample taken off the top of the store would be all one artifact type,
    // because a supertimeline arrives grouped by parser — and that would make the calibration
    // read of the verdicts worthless.
    for (let i = pending.length - 1; i > 0; i -= 1) {
      const j = Math.floor(Math.random() * (i + 1));
      const a = pending[i];
      const b = pending[j];
      if (a !== undefined && b !== undefined) {
        pending[i] = b;
        pending[j] = a;
      }
    }
  }
  if (params.limit !== undefined && params.limit < pending.length) {
    pending = pending.slice(0, params.limit);
  }

  if (pending.length === 0) {
    return { decided: 0, errors: 0, costUsd: 0, stoppedOnCost: false };
  }

  // A cost ceiling has to stop work already in flight, not just refuse to start more, so it
  // shares the caller's abort signal rather than owning a flag the pool cannot see.
  const budget = new AbortController();
  const abortBudget = (): void => budget.abort();
  signal?.addEventListener("abort", abortBudget, { once: true });

  let decided = 0;
  let errors = 0;
  let costUsd = 0;
  let stoppedOnCost = false;

  try {
    await runPool<DecisionRecord, { record: DecisionRecord; call: JevCallResult }>(
      pending,
      async (record) => ({
        record,
        call: await askJev(record.sample, questions, apiKey, {
          ...(params.model ? { model: params.model } : {}),
          signal: budget.signal,
        }),
      }),
      {
        concurrency,
        signal: budget.signal,
        onResult: (result, _item, done) => {
          const { record, call } = result;
          costUsd += call.costUsd;

          if (call.verdict) {
            store.recordVerdict(record.keyHash, call.verdict);
            decided += 1;
          } else {
            store.recordError(record.keyHash, call.error ?? "no verdict returned");
            errors += 1;
          }

          if (maxCostUsd !== undefined && costUsd >= maxCostUsd && !budget.signal.aborted) {
            stoppedOnCost = true;
            budget.abort();
          }
          onProgress?.(done, pending.length, costUsd, errors);
        },
      },
    );
  } finally {
    signal?.removeEventListener("abort", abortBudget);
    // Cost accumulates across resumed runs, so the manifest reports the true total spend
    // rather than only what the last invocation happened to cost.
    const previous = Number(store.meta.get("total_cost_usd") ?? 0);
    store.meta.set("total_cost_usd", String(previous + costUsd));
  }

  return { decided, errors, costUsd, stoppedOnCost };
}
