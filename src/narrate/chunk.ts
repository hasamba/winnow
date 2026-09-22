// Splitting a malicious set into prompt-sized pieces.
//
// The shape is DFIR Companion's deep pass (companion/src/analysis/deepPass.ts `planBatches` and
// deepPassExecution.ts `executeDeepPassBatches`): chronological batches, one observation pass per
// batch, one synthesis over the collected observations. The difference is that Companion batches
// on a count alone; here a single row can be a whole PowerShell script block, so the split has to
// respect a token budget as well as a count.

/**
 * A cheap token estimate: about four characters per token. Matching Companion's
 * `promptBudget.ts`. A real tokenizer is a heavy dependency for a local tool, and the budget
 * below already carries enough slack to absorb this heuristic's drift.
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * How many tokens of rendered rows one prompt may carry.
 *
 * 60,000 against the common 128,000-token window leaves room for the system prompt, the model's
 * own answer (8,000 by default) and the ~10% the 4-chars-per-token rule can be wrong by on paths,
 * base64 and command lines. Erring low costs one extra call; erring high costs the whole run,
 * because an over-length prompt is an HTTP 400 at the end of a long wait.
 */
export const DEFAULT_CHUNK_BUDGET_TOKENS = 60_000;

/**
 * How many rows one prompt may carry, whatever the token count says.
 *
 * A reading limit, not a size limit. Past a few hundred rows a model stops reporting what it sees
 * and starts summarising, which is the one thing the observation pass must not do. 400 keeps a
 * chunk long enough to hold a whole attack phase and short enough to be read rather than skimmed.
 */
export const DEFAULT_MAX_ROWS_PER_CHUNK = 400;

/**
 * Split items into chunks that respect both a token budget and a count cap.
 *
 * The input order is preserved, so a caller that sorted chronologically gets chunks that each read
 * as a contiguous window of the case. Nothing is ever dropped: an item whose own render exceeds
 * the whole budget is placed in a chunk of its own and sent anyway, because dropping evidence to
 * fit a prompt is the failure this whole file exists to prevent. An empty chunk is never returned.
 *
 * A chunk boundary can still cut an attack chain in half. That is accepted for the same reason
 * Companion accepts it: a chunk only reports observations, and the synthesis reassembles them.
 */
export function planChunks<T>(
  items: readonly T[],
  render: (item: T) => string,
  budgetTokens: number,
  maxPerChunk: number,
): T[][] {
  if (items.length === 0) return [];
  const budget = Math.max(1, Math.floor(budgetTokens) || 1);
  const cap = Math.max(1, Math.floor(maxPerChunk) || 1);

  const chunks: T[][] = [];
  let current: T[] = [];
  let currentTokens = 0;

  for (const item of items) {
    const tokens = estimateTokens(render(item));
    const full = current.length >= cap || currentTokens + tokens > budget;
    if (current.length > 0 && full) {
      chunks.push(current);
      current = [];
      currentTokens = 0;
    }
    current.push(item);
    currentTokens += tokens;
  }
  if (current.length > 0) chunks.push(current);
  return chunks;
}
