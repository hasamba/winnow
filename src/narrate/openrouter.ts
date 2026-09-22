// OpenRouter: an OpenAI-shaped chat completion over HTTP.
//
// It is the only one of the four narrators that reports real dollars (`usage.cost`), which is why
// a run driven through it can print what it actually cost instead of an estimate.
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
  resolveOpenRouterKey,
  transportError,
  type FetchFn,
  type NarrateRequest,
  type NarrateResult,
  type Narrator,
  type NarratorOptions,
} from "./provider.js";

export const OPENROUTER_DEFAULT_BASE_URL = "https://openrouter.ai/api/v1";
export const OPENROUTER_DEFAULT_MODEL = "anthropic/claude-sonnet-4.5";

interface ChatResponse {
  choices?: { message?: { content?: string } }[];
  model?: string;
  usage?: { cost?: number };
}

export class OpenRouterNarrator implements Narrator {
  readonly name = "openrouter" as const;
  readonly model: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchFn;
  private readonly timeoutMs: number;
  private readonly apiKeyOpt: string | undefined;

  constructor(opts: NarratorOptions = {}) {
    this.model = opts.model?.trim() || OPENROUTER_DEFAULT_MODEL;
    this.baseUrl = (opts.baseUrl?.trim() || OPENROUTER_DEFAULT_BASE_URL).replace(/\/+$/, "");
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_HTTP_TIMEOUT_MS;
    this.apiKeyOpt = opts.apiKey;
  }

  async generate(req: NarrateRequest): Promise<NarrateResult> {
    const key = requireKey(
      "OpenRouter",
      resolveOpenRouterKey(this.apiKeyOpt),
      "OPENROUTER_API_KEY, or put it in ~/.config/typesafe/openrouter.env",
    );

    let res: Response;
    try {
      res = await this.fetchImpl(`${this.baseUrl}/chat/completions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${key}`,
        },
        body: JSON.stringify({
          model: this.model,
          max_tokens: req.maxTokens ?? DEFAULT_MAX_TOKENS,
          messages: [
            { role: "system", content: req.systemPrompt },
            { role: "user", content: req.userPrompt },
          ],
        }),
        signal: requestSignal(this.timeoutMs, req.signal),
      });
    } catch (err) {
      throw transportError("OpenRouter", err, this.timeoutMs);
    }

    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new NarratorError(
        httpErrorMessage("OpenRouter", res.status, body, key),
        httpErrorKind(res.status, body),
      );
    }

    let json: ChatResponse;
    try {
      json = (await res.json()) as ChatResponse;
    } catch (err) {
      throw new NarratorError(
        `OpenRouter response error: ${redact((err as Error).message, key)}`,
        "transport",
      );
    }

    const text = json.choices?.[0]?.message?.content?.trim();
    if (!text) throw new NarratorError("OpenRouter returned no content", "other");
    return {
      text,
      ...(typeof json.usage?.cost === "number" ? { costUsd: json.usage.cost } : {}),
      ...(json.model ? { model: json.model } : {}),
    };
  }
}
