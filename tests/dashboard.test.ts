// A smoke test for the three dashboard files.
//
// It cannot prove the page works — nothing here renders anything. It proves the handful of
// properties that are cheap to check statically and expensive to get wrong: no inline
// handlers, no inline script, the markdown renderer escaping before it formats, and no
// fetch to a route the server does not serve.

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(__dirname, "..");
const HTML = readFileSync(join(ROOT, "public", "dashboard.html"), "utf8");
const CSS = readFileSync(join(ROOT, "public", "app.css"), "utf8");
const JS = readFileSync(join(ROOT, "public", "app.js"), "utf8");

/** Every route the server documents. A fetch to anything else is a bug in the page. */
const ROUTES = new Set([
  "/api/state",
  "/api/browse",
  "/api/scan",
  "/api/judge",
  "/api/export",
  "/api/narrate",
  "/api/cancel",
  "/api/thresholds",
  "/api/rows",
  "/api/stats",
  "/api/questions",
  "/api/narrative",
  "/api/download",
  "/events",
]);

/** Cuts a top-level `function name(...) { ... }` out of the source by its closing brace. */
function functionBody(source: string, name: string): string {
  const start = source.indexOf(`function ${name}(`);
  expect(start, `${name} is not defined in app.js`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("\n}", start);
  expect(end, `${name} is not closed at column 0`).toBeGreaterThan(start);
  return source.slice(start, end);
}

describe("the page wires its own listeners", () => {
  it("app.js contains no inline handler attribute", () => {
    expect(JS).not.toMatch(/onclick=/);
    expect(JS).not.toMatch(/\bon(?:click|change|input|submit|keydown)\s*=\s*["']/);
  });

  it("dashboard.html contains no inline handler attribute", () => {
    expect(HTML).not.toMatch(/onclick=/);
    expect(HTML).not.toMatch(/\son(?:click|change|input|submit|load|error|keydown)\s*=/i);
  });

  it("dashboard.html has no inline script body", () => {
    const tags = [...HTML.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)];
    expect(tags.length).toBeGreaterThan(0);
    for (const tag of tags) expect((tag[1] ?? "").trim()).toBe("");
  });

  it("dashboard.html loads the module and the stylesheet from their own files", () => {
    expect(HTML).toMatch(/<script\s+type="module"\s+src="\/app\.js"><\/script>/);
    expect(HTML).toMatch(/<link\s+rel="stylesheet"\s+href="\/app\.css"\s*\/?>/);
    expect(CSS.length).toBeGreaterThan(0);
  });
});

describe("the markdown renderer escapes before it formats", () => {
  it("has an escape function that turns < into an entity", () => {
    expect(JS).toContain("function escapeHtml(");
    expect(JS).toMatch(/"<":\s*"&lt;"/);
    expect(JS).toMatch(/"&":\s*"&amp;"/);
  });

  it("escapes the whole document before it builds a single tag", () => {
    const body = functionBody(JS, "renderMarkdown");
    const escapeAt = body.indexOf("escapeHtml(");
    const firstTagAt = body.search(/["'`]</);
    const firstInlineAt = body.indexOf("inlineMarkdown(");

    expect(escapeAt, "renderMarkdown never calls escapeHtml").toBeGreaterThanOrEqual(0);
    expect(firstTagAt, "renderMarkdown builds no tags at all").toBeGreaterThanOrEqual(0);
    expect(escapeAt).toBeLessThan(firstTagAt);
    expect(escapeAt).toBeLessThan(firstInlineAt);
    expect(body).toMatch(/const escaped = escapeHtml\(source\);/);
  });

  it("assigns innerHTML in exactly one place, and only from the renderer", () => {
    const assignments = [...JS.matchAll(/\.innerHTML\s*=\s*([^;]+);/g)].map((m) => (m[1] ?? "").trim());
    expect(assignments).toEqual(["renderMarkdown(markdown)"]);
  });

  it("builds verdict table cells with textContent", () => {
    const body = functionBody(JS, "cell");
    expect(body).toContain("td.textContent = text");
    expect(body).not.toContain("innerHTML");
  });
});

describe("the page only talks to documented routes", () => {
  it("every fetch is written with a literal path", () => {
    const calls = JS.match(/fetch\(/g) ?? [];
    const literals = [...JS.matchAll(/fetch\(\s*["'`]([^"'`]+)/g)];
    expect(calls.length).toBeGreaterThan(0);
    expect(literals.length).toBe(calls.length);
  });

  it("every fetched path is a documented route", () => {
    for (const match of JS.matchAll(/fetch\(\s*["'`]([^"'`]+)/g)) {
      const path = (match[1] ?? "").split("?")[0] ?? "";
      expect(ROUTES.has(path), `fetch("${path}") is not a documented route`).toBe(true);
    }
  });

  it("every /api literal in the file is a documented route", () => {
    for (const match of JS.matchAll(/["'`](\/(?:api|events)[^"'`?\s]*)/g)) {
      const path = (match[1] ?? "").split("?")[0] ?? "";
      expect(ROUTES.has(path), `"${path}" is not a documented route`).toBe(true);
    }
  });

  it("opens the event stream and only polls when EventSource is missing", () => {
    expect(JS).toContain('new EventSource("/events")');
    const intervals = [...JS.matchAll(/setInterval\(/g)];
    expect(intervals.length).toBe(1);
    const fallback = functionBody(JS, "openStream");
    expect(fallback).toMatch(/typeof window\.EventSource !== "function"/);
    expect(fallback).toContain("setInterval(refreshState, 3000)");
  });
});

describe("the states an analyst must not misread", () => {
  it("names unjudged and error separately", () => {
    const body = functionBody(JS, "verdictRow");
    expect(body).toContain('"unjudged"');
    expect(body).toContain('"error"');
  });

  it("says plainly when a judge pass stopped at the cost ceiling", () => {
    const body = functionBody(JS, "renderCeilingNote");
    expect(body).toMatch(/cost ceiling/i);
    expect(body).toMatch(/NOT complete/);
  });

  it("shows the questions hash", () => {
    expect(HTML).toContain('id="questions-hash"');
    expect(JS).toContain("function setQuestionsHash(");
  });
});

describe("accessibility basics are present in the markup", () => {
  it("gives the progress bar a role and a value", () => {
    expect(HTML).toMatch(/role="progressbar"/);
    expect(HTML).toMatch(/aria-valuemin="0"/);
    expect(JS).toMatch(/setAttribute\("aria-valuenow"/);
  });

  it("gives the status line a polite live region", () => {
    expect(HTML).toMatch(/id="status-line"[^>]*aria-live="polite"/);
  });

  it("labels every form control", () => {
    const controls = [...HTML.matchAll(/<(input|select|textarea)\b[^>]*id="([^"]+)"/g)];
    expect(controls.length).toBeGreaterThan(10);
    for (const [, , id] of controls) {
      expect(HTML.includes(`for="${id}"`), `no <label for="${id}">`).toBe(true);
    }
  });
});

describe("the look is driven by custom properties", () => {
  it("defines colours on :root and redefines them for dark", () => {
    expect(CSS).toMatch(/:root\s*\{/);
    expect(CSS).toContain("@media (prefers-color-scheme: dark)");
    expect(CSS).toContain("--bg:");
    expect(CSS).toContain("--fg:");
  });

  it("marks severity with a glyph, not only a colour", () => {
    expect(CSS).toMatch(/\.sev-critical::before\s*\{\s*content:/);
    expect(CSS).toMatch(/\.sev-high::before\s*\{\s*content:/);
    expect(CSS).toMatch(/\.state-error::before\s*\{\s*content:/);
    expect(CSS).toMatch(/\.state-unjudged::before\s*\{\s*content:/);
  });

  it("gives the verdict table its own scroll container", () => {
    expect(CSS).toMatch(/\.table-wrap\s*\{[^}]*overflow:\s*auto/);
    expect(CSS).toMatch(/overflow-x:\s*hidden/);
  });
});
