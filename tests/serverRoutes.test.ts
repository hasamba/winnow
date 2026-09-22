import { afterEach, expect, it } from "vitest";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { serve } from "../src/server/http.js";
import { DecisionStore } from "../src/triage/store.js";
import type { ServerState } from "../src/server/contract.js";
import type { RowPage } from "../src/server/contract.js";
import type { Verdict } from "../src/types.js";

const FIXTURE = fileURLToPath(new URL("./fixtures/fixture.l2t.csv", import.meta.url));
const QUESTIONS = fileURLToPath(new URL("../questions.json", import.meta.url));

const L2T_HEADER =
  "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n";

const servers: { close: () => Promise<void> }[] = [];
const dirs: string[] = [];

afterEach(async () => {
  while (servers.length > 0) await servers.pop()?.close();
  while (dirs.length > 0) rmSync(dirs.pop() ?? "", { recursive: true, force: true });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "winnow-http-"));
  dirs.push(dir);
  return dir;
}

async function start(questionsPath?: string): Promise<string> {
  const server = await serve({ port: 0, ...(questionsPath ? { questionsPath } : {}) });
  servers.push(server);
  return server.url;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  return (await res.json()) as T;
}

async function post(url: string, body: unknown): Promise<Response> {
  return fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** Poll the state until `done` holds, so a test never sleeps a fixed number of milliseconds. */
async function waitForState(
  base: string,
  done: (s: ServerState) => boolean,
  timeoutMs = 30_000,
): Promise<ServerState> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const state = await getJson<ServerState>(`${base}/api/state`);
    if (done(state)) return state;
    if (Date.now() > deadline) throw new Error(`Timed out: ${JSON.stringify(state.job)}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

const idle = (s: ServerState): boolean => s.job !== undefined && s.job.state !== "running";

/** An l2tcsv big enough that its scan is still running one HTTP round trip later. */
function bigTimeline(path: string, rows: number): void {
  const parts: string[] = [L2T_HEADER];
  for (let i = 0; i < rows; i += 1) {
    parts.push(
      `03/14/2026,08:00:0${i % 10},UTC,M...,FILE,NTFS $MFT,Content Modification Time,-,WKSTN01,` +
        `row ${i},File modified: C:/tmp/file-${i}.txt,2,TSK:/tmp/file-${i}.txt,${i},-,filestat,-\n`,
    );
  }
  writeFileSync(path, parts.join(""));
}

it("serves the idle state", async () => {
  const base = await start();
  const res = await fetch(`${base}/api/state`);
  expect(res.status).toBe(200);
  expect(res.headers.get("x-content-type-options")).toBe("nosniff");
  expect(res.headers.get("access-control-allow-origin")).toBeNull();

  const state = (await res.json()) as ServerState;
  expect(state.job).toBeUndefined();
  expect(state.file).toBeUndefined();
  expect(state.artifacts.narratives).toEqual([]);
  expect(state.thresholds.malicious).toBeGreaterThan(0);
  expect(state.questionsHash).toMatch(/^[0-9a-f]{16}$/);
});

it("scans a fixture timeline and finishes the job", async () => {
  const dir = tempDir();
  const file = join(dir, "fixture.l2t.csv");
  copyFileSync(FIXTURE, file);
  const base = await start();

  const res = await post(`${base}/api/scan`, { file });
  expect(res.status).toBe(202);

  const state = await waitForState(base, idle);
  expect(state.job?.state).toBe("done");
  expect(state.file).toBe(file);
  expect(state.scan?.totalRows).toBe(40);
  expect(state.counts?.total).toBeGreaterThan(0);
});

it("refuses a second job while one is running, with a 409", async () => {
  const dir = tempDir();
  const file = join(dir, "big.l2t.csv");
  bigTimeline(file, 40_000);
  const base = await start();

  expect((await post(`${base}/api/scan`, { file })).status).toBe(202);
  const second = await post(`${base}/api/scan`, { file });
  expect(second.status).toBe(409);
  expect(((await second.json()) as { error: string }).error).toContain("already running");

  expect((await post(`${base}/api/export`, {})).status).toBe(409);
  await waitForState(base, idle);
});

it("rejects a body larger than a megabyte with a 413", async () => {
  const base = await start();
  const res = await post(`${base}/api/scan`, { file: "x".repeat(2 * 1024 * 1024) });
  expect(res.status).toBe(413);
});

it("rejects a body that is not valid JSON with a 400", async () => {
  const base = await start();
  const res = await fetch(`${base}/api/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{not json",
  });
  expect(res.status).toBe(400);
});

it("answers the rows query with a sorted, filtered, paginated page", async () => {
  const dir = tempDir();
  const file = join(dir, "fixture.l2t.csv");
  copyFileSync(FIXTURE, file);
  const base = await start();
  await post(`${base}/api/scan`, { file });
  const scanned = await waitForState(base, idle);
  expect(scanned.job?.state).toBe("done");

  // The judge pass needs an API key, so the verdicts are written straight into the cache the
  // server just built. A second connection to the same WAL database is exactly what a second
  // winnow process would do.
  const store = DecisionStore.open(scanned.dbPath ?? "");
  const undecided = store.undecided({});
  expect(undecided.length).toBeGreaterThan(6);
  const verdict = (over: Partial<Verdict>): Verdict => ({
    malicious: 0.5,
    category: "execution",
    categoryConfidence: 0.8,
    severity: 3,
    severityLevel: "High",
    needsAnalyst: 0.5,
    ...over,
  });
  undecided.slice(0, 3).forEach((r, i) => {
    store.recordVerdict(r.keyHash, verdict({ malicious: 0.9 - i * 0.1, category: "execution" }));
  });
  undecided.slice(3, 6).forEach((r) => {
    store.recordVerdict(r.keyHash, verdict({ malicious: 0.1, category: "benign" }));
  });
  const percentKey = undecided[6];
  expect(percentKey).toBeDefined();
  store.recordVerdict(percentKey?.keyHash ?? "", verdict({ malicious: 0.2, category: "benign" }));
  store.close();

  const all = await getJson<RowPage>(`${base}/api/rows`);
  expect(all.total).toBe(7);
  expect(all.rows.map((r) => r.malicious)).toEqual([0.9, 0.8, 0.7, 0.2, 0.1, 0.1, 0.1]);

  const page = await getJson<RowPage>(`${base}/api/rows?limit=2&offset=1`);
  expect(page.total).toBe(7);
  expect(page.rows).toHaveLength(2);
  expect(page.rows[0]?.malicious).toBe(0.8);

  const filtered = await getJson<RowPage>(`${base}/api/rows?min=0.75&category=execution`);
  expect(filtered.total).toBe(2);

  const undecidedPage = await getJson<RowPage>(`${base}/api/rows?includeUndecided=1`);
  expect(undecidedPage.total).toBe(scanned.counts?.total);

  // A percent sign the analyst typed is data, not a LIKE wildcard.
  const literal = await getJson<RowPage>(`${base}/api/rows?q=${encodeURIComponent("%")}`);
  expect(literal.total).toBe(0);
  const hit = all.rows[0];
  expect(hit).toBeDefined();
  const found = await getJson<RowPage>(
    `${base}/api/rows?q=${encodeURIComponent(hit?.text.slice(0, 12) ?? "")}`,
  );
  expect(found.total).toBeGreaterThan(0);
});

it("answers the rows query with a 409 before anything has been scanned", async () => {
  const base = await start();
  const res = await fetch(`${base}/api/rows`);
  expect(res.status).toBe(409);
  expect(((await res.json()) as { error: string }).error).toContain("Scan a timeline first");
});

it("reads the questions, rejects an invalid set by name, and writes a valid one", async () => {
  const dir = tempDir();
  const questionsPath = join(dir, "questions.json");
  copyFileSync(QUESTIONS, questionsPath);
  const base = await start(questionsPath);

  const loaded = await getJson<{ json: string; hash: string }>(`${base}/api/questions`);
  expect(loaded.hash).toMatch(/^[0-9a-f]{16}$/);
  const parsed = JSON.parse(loaded.json) as Record<string, Record<string, unknown>>;

  const broken = {
    ...parsed,
    severity: { type: "score", instructions: "How bad is it?", criteria: ["Only one level"] },
  };
  const bad = await fetch(`${base}/api/questions`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ json: JSON.stringify(broken, null, 2) }),
  });
  expect(bad.status).toBe(400);
  expect(((await bad.json()) as { error: string }).error).toContain("severity");
  expect(readFileSync(questionsPath, "utf8")).toBe(loaded.json);

  const edited = JSON.parse(loaded.json) as Record<string, Record<string, unknown>>;
  const malicious = edited["malicious"];
  expect(malicious).toBeDefined();
  if (malicious) malicious["instructions"] = `${String(malicious["instructions"])} Be strict.`;
  const good = await fetch(`${base}/api/questions`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ json: JSON.stringify(edited, null, 2) }),
  });
  expect(good.status).toBe(200);
  expect(readFileSync(questionsPath, "utf8")).toContain("Be strict.");
  const after = await getJson<ServerState>(`${base}/api/state`);
  expect(after.questionsHash).not.toBe(loaded.hash);
});

it("refuses a questions edit while a job is running", async () => {
  const dir = tempDir();
  const questionsPath = join(dir, "questions.json");
  copyFileSync(QUESTIONS, questionsPath);
  const file = join(dir, "big.l2t.csv");
  bigTimeline(file, 40_000);
  const base = await start(questionsPath);
  const before = readFileSync(questionsPath, "utf8");

  expect((await post(`${base}/api/scan`, { file })).status).toBe(202);
  const res = await fetch(`${base}/api/questions`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ json: before }),
  });
  expect(res.status).toBe(409);
  expect(readFileSync(questionsPath, "utf8")).toBe(before);
  await waitForState(base, idle);
});

it("serves only a path the runner itself produced", async () => {
  const base = await start();

  const passwd = await fetch(`${base}/api/download?path=${encodeURIComponent("/etc/passwd")}`);
  expect(passwd.status).toBe(403);
  const body = await passwd.text();
  expect(body).not.toContain("root:");
  expect(body).not.toContain("/bin/");

  const traversal = await fetch(
    `${base}/api/download?path=${encodeURIComponent("../../../../etc/passwd")}`,
  );
  expect(traversal.status).toBe(403);
  expect(await traversal.text()).not.toContain("root:");

  const narrative = await fetch(
    `${base}/api/narrative?path=${encodeURIComponent("/etc/hostname")}`,
  );
  expect(narrative.status).toBe(403);
});

it("streams server-sent events and stops on close", async () => {
  const base = await start();
  const controller = new AbortController();
  const res = await fetch(`${base}/events`, { signal: controller.signal });
  expect(res.status).toBe(200);
  expect(res.headers.get("content-type")).toContain("text/event-stream");
  expect(res.headers.get("cache-control")).toBe("no-cache");

  const reader = res.body?.getReader();
  expect(reader).toBeDefined();
  const chunk = await reader?.read();
  const text = new TextDecoder().decode(chunk?.value);
  expect(text).toContain("data: ");
  expect(JSON.parse(text.replace(/^data: /, "").trim())).toMatchObject({ type: "state" });

  controller.abort();
});

it("sets and validates the thresholds", async () => {
  const base = await start();
  const ok = await post(`${base}/api/thresholds`, {
    malicious: 0.4,
    needsAnalyst: 0.6,
    confident: 0.8,
  });
  expect(ok.status).toBe(200);
  expect((await getJson<ServerState>(`${base}/api/state`)).thresholds.malicious).toBe(0.4);

  const bad = await post(`${base}/api/thresholds`, {
    malicious: 1.4,
    needsAnalyst: 0.6,
    confident: 0.8,
  });
  expect(bad.status).toBe(400);
  expect((await getJson<ServerState>(`${base}/api/state`)).thresholds.malicious).toBe(0.4);
});

it("browses the filesystem for the file picker", async () => {
  const dir = tempDir();
  copyFileSync(FIXTURE, join(dir, "fixture.l2t.csv"));
  const base = await start();
  const result = await getJson<{ path: string; files: { name: string }[] }>(
    `${base}/api/browse?path=${encodeURIComponent(dir)}`,
  );
  expect(result.path).toBe(dir);
  expect(result.files.map((f) => f.name)).toEqual(["fixture.l2t.csv"]);

  const missing = await fetch(
    `${base}/api/browse?path=${encodeURIComponent(join(dir, "no-such-dir"))}`,
  );
  expect(missing.status).toBe(400);
});

it("cancels nothing when nothing runs", async () => {
  const base = await start();
  const res = await post(`${base}/api/cancel`, {});
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({ cancelled: false });
});

it("answers an unknown route with a 404", async () => {
  const base = await start();
  const res = await fetch(`${base}/api/nope`);
  expect(res.status).toBe(404);
});
