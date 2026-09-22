// The Anthropic Messages API.
//
// The system prompt is the top-level `system` field, NOT a message with role "system". The
// Messages API rejects a system role inside `messages`, and a narrator that quietly folded the
// instructions into the user turn would lose the instruction/evidence separation the prompts rely
// on.
//
// The API key is never written into an error message — see the header of provider.ts.

import {
  DEFAULT_HTTP_TIMEOUT_MS,
  DEFAULT_MAX_TOKENS,
  NarratorError,
  httpErrorKind,
  httpErrorMessage,
  redact,
  requestSignal,
  requireKey,
  resolveAnthropicKey,
  transportError,
  type FetchFn,
  type NarrateRequest,
  type NarrateResult,
  type Narrator,
  type NarratorOptions,
} from "./provider.js";

export const ANTHROPIC_DEFAULT_BASE_URL = "https://api.anthropic.com/v1";
export const ANTHROPIC_DEFAULT_MODEL = "claude-sonnet-4-5";
export const ANTHROPIC_VERSION = "2023-06-01";

interface MessagesResponse {
  content?: { type?: string; text?: string }[];
  model?: string;
}

export class AnthropicNarrator implements Narrator {
  readonly name = "claude-api" as const;
  readonly model: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchFn;
  private readonly timeoutMs: number;
  private readonly apiKeyOpt: string | undefined;

  constructor(opts: NarratorOptions = {}) {
    this.model = opts.model?.trim() || ANTHROPIC_DEFAULT_MODEL;
    this.baseUrl = (opts.baseUrl?.trim() || ANTHROPIC_DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    this.apiKeyOpt = opts.apiKey;
  }

  async generate(req: NarrateRequest): Promise<NarrateResult> {
    const key = requireKey("Anthropic", resolveAnthropicKey(this.apiKeyOpt), "ANTHROPIC_API_KEY");

    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/messages`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": key,
          "anthropic-version": ANTHROPIC_VERSION,
        },
        body: JSON.stringify({
          model: this.model,
          max_tokens: req.maxTokens ?? DEFAULT_MAX_TOKENS,
          system: req.systemPrompt,
          messages: [{ role: "user", content: req.userPrompt }],
        }),
        signal: requestSignal(this.timeoutMs, req.signal),
      });
    } catch (err) {
      throw transportError("Anthropic", err, this.timeoutMs);
    }

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new NarratorError(
        httpErrorMessage("Anthropic", res.status, body, key),
        httpErrorKind(res.status, body),
      );
    }

    let json: MessagesResponse;
    try {
      json = (await res.json()) as MessagesResponse;
    } catch (err) {
      throw new NarratorError(
        `Anthropic response error: ${redact((err as Error).message, key)}`,
        "transport",
      );
    }

    const text = json.content
      ?.filter((b) => b.type === "text" && typeof b.text === "string")
      .map((b) => b.text as string)
      .join("")
      .trim();
    if (!text) throw new NarratorError("Anthropic returned no content", "other");
    return { text, ...(json.model ? { model: json.model } : {}) };
  }
}
