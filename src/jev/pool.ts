// A bounded worker pool. This is the one piece DFIR Companion has nothing to copy: every AI
// call there is deliberately sequential, and a sequential run over a supertimeline would
// take days.
//
// Deliberately NOT `Promise.all(items.map(worker))`: at 300,000 distinct keys that allocates
// 300,000 promises, and every worker starts at once. This starts `concurrency` runners and
// each pulls the next item when it is free, so the queue is an index, not an array of
// pending promises.

export interface RunPoolOptions<T, R> {
  /** How many workers may be in flight at once. */
  readonly concurrency: number;
  /**
   * Fires as each item finishes, in completion order, so the caller can persist the verdict
   * straight away. That immediate persistence is what makes a run resumable after a Ctrl-C.
   */
  readonly onResult?: (result: R, item: T, done: number) => void;
  /**
   * Stops new work from starting. Work already in flight is allowed to finish and its
   * results still reach `onResult`, so an interrupt never loses a verdict already paid for.
   */
  readonly signal?: AbortSignal;
}

export async function runPool<T, R>(
  items: readonly T[],
  worker: (item: T, index: number) => Promise<R>,
  opts: RunPoolOptions<T, R>,
): Promise<void> {
  const limit = Math.max(1, Math.floor(opts.concurrency));
  const runners = Math.min(limit, items.length);
  if (runners === 0) return;

  let nextIndex = 0;
  let done = 0;
  /** An onResult failure is the caller's persistence failing — stop, drain, then report it. */
  let fatal: unknown;

  const runner = async (): Promise<void> => {
    for (;;) {
      if (fatal !== undefined) return;
      if (opts.signal?.aborted) return;
      const index = nextIndex;
      if (index >= items.length) return;
      nextIndex += 1;
      const item = items[index] as T;

      let result: R;
      try {
        result = await worker(item, index);
      } catch (err) {
        // A throwing worker must not kill the pool or surface as an unhandled rejection.
        // The thrown value is handed to onResult as this item's result; a caller that needs
        // to tell the two apart checks `instanceof Error`.
        result = err as R;
      }

      done += 1;
      if (!opts.onResult) continue;
      try {
        opts.onResult(result, item, done);
      } catch (err) {
        if (fatal === undefined) fatal = err;
        return;
      }
    }
  };

  await Promise.all(Array.from({ length: runners }, () => runner()));
  if (fatal !== undefined) throw fatal;
}
