// winnow dashboard.
//
// No framework, no build step, no dependency. One module, loaded by dashboard.html.
// The server is the only source of truth; this file holds nothing worth losing.
//
// Two rules that the rest of the file obeys without exception:
//   1. Nothing from the server is ever written into the page as HTML except the narrative,
//      and that is escaped first (see renderMarkdown). Every other value goes in with
//      textContent.
//   2. Every call to the server is written with its route as a string literal, so the set
//      of routes this page talks to can be read straight off the source.

/* ------------------------------------------------------------------ helpers */

const byId = (id) => document.getElementById(id);

function on(el, event, handler) {
  if (el) el.addEventListener(event, handler);
}

function showError(el, message) {
  if (!el) return;
  el.textContent = message;
  el.hidden = false;
}

function clearError(el) {
  if (!el) return;
  el.textContent = "";
  el.hidden = true;
}

function setText(id, value) {
  const el = byId(id);
  if (el) el.textContent = value;
}

/* ---------------------------------------------------------- number formats */

const NUM = new Intl.NumberFormat("en-US");

function num(n) {
  return typeof n === "number" && Number.isFinite(n) ? NUM.format(n) : "—";
}

function usd(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "$—";
  if (n > 0 && n < 0.01) return "$" + n.toFixed(4);
  return "$" + n.toFixed(2);
}

function duration(seconds) {
  if (typeof seconds !== "number" || !Number.isFinite(seconds)) return "—";
  const s = Math.round(seconds);
  if (s < 90) return s + " sec";
  const m = Math.round(s / 60);
  if (m < 90) return m + " min";
  const h = Math.floor(m / 60);
  return h + " h " + (m % 60) + " min";
}

function bytes(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u += 1;
  }
  return (u === 0 ? v : v.toFixed(1)) + " " + units[u];
}

function shortTs(iso) {
  if (typeof iso !== "string" || iso === "") return "—";
  return iso.replace("T", " ").replace(/\.\d+Z?$/, "").replace(/Z$/, "");
}

function baseName(p) {
  if (typeof p !== "string") return "";
  const parts = p.split(/[\\/]/);
  return parts[parts.length - 1] || p;
}

/* ------------------------------------------------------------- the API tier */

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function bodyText(res) {
  let raw = "";
  try {
    raw = await res.text();
  } catch {
    raw = "";
  }
  if (raw === "") return "";
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed.error === "string") return parsed.error;
  } catch {
    /* not JSON; the raw text is the message. */
  }
  return raw;
}

/** Reads a response, or throws an ApiError carrying the server's own words. */
async function readJson(res) {
  if (!res.ok) {
    const text = await bodyText(res);
    throw new ApiError(text.trim() || "HTTP " + res.status, res.status);
  }
  const raw = await res.text();
  if (raw.trim() === "") return null;
  return JSON.parse(raw);
}

function postJson(body) {
  return {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  };
}

/**
 * Turns an ApiError into the sentence the analyst should read.
 * A 409 means a job is already running. It is never retried: retrying would either be
 * refused again or start a second pass over the same file.
 */
function explain(err) {
  if (err instanceof ApiError) {
    // 409: the server's own words already name the job that is running. Never retry — a
    // second pass would race the first one on the same decision cache.
    if (err.status === 409) return err.message || "A job is already running.";
    return err.message;
  }
  return "The server could not be reached: " + String(err && err.message ? err.message : err);
}

/* -------------------------------------------------------- markdown renderer */

const HTML_ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** Turns every HTML-significant character into a harmless entity. */
function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch]);
}

const CODE_MARK = "\u0001";

/**
 * Adds inline tags to text that is ALREADY escaped. Never call this with raw input.
 * Code spans are lifted out first so that a `*` inside one is not read as emphasis.
 */
function inlineMarkdown(escaped) {
  const spans = [];
  let s = escaped.replace(/`([^`]+)`/g, (_m, code) => {
    spans.push(code);
    return CODE_MARK + (spans.length - 1) + CODE_MARK;
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/(^|[^\w])__([^_]+)__/g, "$1<strong>$2</strong>");
  s = s.replace(/(^|[^*\w])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  s = s.replace(/(^|[\s(])_([^_\n]+)_/g, "$1<em>$2</em>");
  s = s.replace(new RegExp(CODE_MARK + "(\\d+)" + CODE_MARK, "g"), (_m, i) => {
    return "<code>" + spans[Number(i)] + "</code>";
  });
  return s;
}

/**
 * A small markdown renderer: headings, bold, italic, inline code, fenced code, lists,
 * paragraphs and horizontal rules. Nothing else.
 *
 * SECURITY — the reason the escape comes first, and why it must stay first:
 * the narrative is written by a model that was fed a forensic timeline, so every string in
 * it is attacker-controlled — file paths, command lines, registry values, user agents. The
 * WHOLE document is escaped to plain text BEFORE any formatting is applied. Formatting
 * after escaping can only add tags this file wrote itself. Formatting before escaping would
 * let an `<img src=x onerror=...>` sitting in a file path execute inside this page.
 */
function renderMarkdown(source) {
  const escaped = escapeHtml(source);
  const lines = escaped.split(/\r?\n/);
  const out = [];
  let listTag = "";
  let para = [];

  const closeList = () => {
    if (listTag !== "") {
      out.push("</" + listTag + ">");
      listTag = "";
    }
  };
  const closePara = () => {
    if (para.length > 0) {
      out.push("<p>" + inlineMarkdown(para.join(" ")) + "</p>");
      para = [];
    }
  };
  const openList = (tag) => {
    if (listTag !== tag) {
      closeList();
      out.push("<" + tag + ">");
      listTag = tag;
    }
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];

    if (/^\s*(```|~~~)/.test(line)) {
      closePara();
      closeList();
      const fence = line.trim().slice(0, 3);
      const block = [];
      i += 1;
      while (i < lines.length && !lines[i].trim().startsWith(fence)) {
        block.push(lines[i]);
        i += 1;
      }
      out.push("<pre><code>" + block.join("\n") + "</code></pre>");
      continue;
    }

    if (line.trim() === "") {
      closePara();
      closeList();
      continue;
    }

    if (/^\s*([-*_])\s*\1\s*\1[\s*_-]*$/.test(line)) {
      closePara();
      closeList();
      out.push("<hr />");
      continue;
    }

    const heading = /^\s*(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      closePara();
      closeList();
      const level = heading[1].length;
      out.push("<h" + level + ">" + inlineMarkdown(heading[2].trim()) + "</h" + level + ">");
      continue;
    }

    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    if (bullet) {
      closePara();
      openList("ul");
      out.push("<li>" + inlineMarkdown(bullet[1]) + "</li>");
      continue;
    }

    const ordered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (ordered) {
      closePara();
      openList("ol");
      out.push("<li>" + inlineMarkdown(ordered[1]) + "</li>");
      continue;
    }

    closeList();
    para.push(line.trim());
  }

  closePara();
  closeList();
  return out.join("\n");
}

/* --------------------------------------------------------------- page state */

const ui = {
  server: null,
  browsePath: "",
  rowOffset: 0,
  rowTotal: 0,
  sort: "malicious",
  /** The ceiling sent with the last judge POST, so a stop at the ceiling can be named. */
  lastCeiling: null,
  firstQuestionsHash: null,
  questionsOnDisk: "",
  narrativePath: "",
  liveStream: false,
};

/* --------------------------------------------------------- status and theme */

function setStatus(text) {
  setText("status-line", text);
}

function setConnection(kind, label) {
  const el = byId("conn-state");
  if (!el) return;
  el.dataset.state = kind;
  el.className = "conn conn-" + kind;
  setText("conn-text", label);
}

function applyTheme(theme) {
  const root = document.documentElement;
  if (theme === "dark" || theme === "light") root.dataset.theme = theme;
  else delete root.dataset.theme;
  const btn = byId("theme-toggle");
  if (btn) btn.setAttribute("aria-pressed", String(theme === "dark"));
}

function initTheme() {
  let saved = null;
  try {
    saved = window.localStorage.getItem("winnow-theme");
  } catch {
    saved = null;
  }
  applyTheme(saved);
  on(byId("theme-toggle"), "click", () => {
    const dark = document.documentElement.dataset.theme === "dark";
    const next = dark ? "light" : "dark";
    applyTheme(next);
    try {
      window.localStorage.setItem("winnow-theme", next);
    } catch {
      /* a private window can refuse storage; the theme still applies for this page. */
    }
  });
}

/* ------------------------------------------------------- 1. timeline picker */

async function loadBrowse(path) {
  const target = byId("browse-error");
  clearError(target);
  try {
    const params = new URLSearchParams();
    if (path) params.set("path", path);
    const res = await fetch(`/api/browse?${params.toString()}`);
    const result = await readJson(res);
    renderBrowse(result);
  } catch (err) {
    showError(target, explain(err));
  }
}

function renderBrowse(result) {
  if (!result) return;
  ui.browsePath = result.path || "";
  setText("browse-path", ui.browsePath || "—");

  const list = byId("browse-list");
  if (!list) return;
  list.replaceChildren();

  const add = (kind, name, sizeText, onPick) => {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";

    const k = document.createElement("span");
    k.className = "kind";
    k.textContent = kind;

    const n = document.createElement("span");
    n.className = "name";
    n.textContent = name;

    const s = document.createElement("span");
    s.className = "size";
    s.textContent = sizeText;

    btn.append(k, n, s);
    btn.addEventListener("click", onPick);
    li.appendChild(btn);
    list.appendChild(li);
  };

  if (typeof result.parent === "string" && result.parent !== "") {
    add("↑", "..", "", () => loadBrowse(result.parent));
  }

  for (const dir of result.dirs || []) {
    add("dir", dir, "", () => loadBrowse(joinPath(ui.browsePath, dir)));
  }

  for (const file of result.files || []) {
    add("csv", file.name, bytes(file.bytes), () => startScan(joinPath(ui.browsePath, file.name)));
  }

  if ((result.dirs || []).length === 0 && (result.files || []).length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "No subdirectories and no CSV files here.";
    list.appendChild(li);
  }
}

function joinPath(dir, name) {
  if (!dir) return name;
  const sep = dir.includes("\\") && !dir.includes("/") ? "\\" : "/";
  return dir.endsWith(sep) ? dir + name : dir + sep + name;
}

async function startScan(path) {
  const target = byId("path-error");
  clearError(target);
  if (!path) {
    showError(target, "Type an absolute path to a CSV file first.");
    return;
  }
  try {
    const res = await fetch("/api/scan", postJson({ file: path }));
    await readJson(res);
    setStatus("Scanning " + baseName(path) + "…");
  } catch (err) {
    showError(target, explain(err));
  }
}

function wireTimelinePanel() {
  on(byId("path-go"), "click", () => {
    const value = byId("path-input").value.trim();
    clearError(byId("path-error"));
    loadBrowse(value);
  });
  on(byId("path-scan"), "click", () => startScan(byId("path-input").value.trim()));
  on(byId("path-input"), "keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      startScan(byId("path-input").value.trim());
    }
  });
}

/* ---------------------------------------------------------------- 2. scan */

function renderScan(server) {
  const empty = byId("scan-empty");
  const body = byId("scan-body");
  const scan = server && server.scan;
  if (!scan) {
    if (empty) empty.hidden = false;
    if (body) body.hidden = true;
    return;
  }
  if (empty) empty.hidden = true;
  if (body) body.hidden = false;

  setText("scan-file", server.file || "—");
  setText("scan-db", server.dbPath || "—");
  setText("scan-cost", usd(scan.estimatedCostUsd));
  setText("scan-time", duration(scan.estimatedSeconds) + " of model calls");
  setText("scan-rows", num(scan.totalRows));
  setText("scan-flavor", scan.flavor || "—");
  setText("scan-range", shortTs(scan.earliest) + "  →  " + shortTs(scan.latest));
  setText("scan-distinct", num(scan.distinctKeys));

  const dupe =
    scan.totalRows > 0 ? (1 - scan.distinctKeys / scan.totalRows) * 100 : 0;
  setText(
    "scan-dupe",
    num(scan.totalRows - scan.distinctKeys) + " rows (" + dupe.toFixed(1) + "%)",
  );
  setText("scan-undecided", num(scan.undecidedKeys));
  setText("scan-unparsed", num(scan.unparsedTimestamps));
}

/* ----------------------------------------------------------- 3a. questions */

async function loadQuestions() {
  const feedback = byId("questions-feedback");
  try {
    const res = await fetch("/api/questions");
    const result = await readJson(res);
    if (!result) return;
    ui.questionsOnDisk = result.json || "";
    byId("questions-text").value = ui.questionsOnDisk;
    setQuestionsHash(result.hash);
    if (feedback) {
      feedback.textContent = "";
      feedback.className = "inline-feedback";
    }
  } catch (err) {
    if (feedback) {
      feedback.textContent = explain(err);
      feedback.className = "inline-feedback";
    }
  }
}

function setQuestionsHash(hash) {
  if (typeof hash !== "string" || hash === "") return;
  const short = hash.slice(0, 12);
  setText("questions-hash", short);
  setText("questions-hash-2", short);
  if (ui.firstQuestionsHash === null) {
    ui.firstQuestionsHash = hash;
  } else if (ui.firstQuestionsHash !== hash) {
    const warn = byId("hash-warning");
    if (warn) warn.hidden = false;
  }
}

async function saveQuestions() {
  const feedback = byId("questions-feedback");
  const text = byId("questions-text").value;
  if (feedback) {
    feedback.textContent = "Saving…";
    feedback.className = "inline-feedback ok";
  }
  try {
    const res = await fetch("/api/questions", { ...postJson({ json: text }), method: "PUT" });
    const result = await readJson(res);
    ui.questionsOnDisk = text;
    if (result && result.hash) setQuestionsHash(result.hash);
    if (feedback) {
      feedback.textContent =
        "Saved. Every verdict judged under the previous hash no longer applies.";
      feedback.className = "inline-feedback ok";
    }
    await refreshState();
  } catch (err) {
    if (feedback) {
      // A 400 is the server's JSON or schema complaint. It belongs next to the textarea.
      feedback.textContent = "Not saved — " + explain(err);
      feedback.className = "inline-feedback";
    }
  }
}

/* ---------------------------------------------------------------- 3b. rows */

function severityClass(level) {
  const key = String(level || "").toLowerCase();
  if (key.startsWith("crit")) return "sev sev-critical";
  if (key.startsWith("high")) return "sev sev-high";
  if (key.startsWith("med")) return "sev sev-medium";
  if (key.startsWith("low")) return "sev sev-low";
  if (key.startsWith("info")) return "sev sev-informational";
  return "sev sev-none";
}

function cell(className, text, title) {
  const td = document.createElement("td");
  td.className = className;
  td.textContent = text;
  if (title) td.title = title;
  return td;
}

function verdictRow(row) {
  const tr = document.createElement("tr");
  const judged = typeof row.malicious === "number";
  const failed = typeof row.error === "string" && row.error !== "";

  const scoreCell = cell(
    "num score " +
      (!judged ? "score-cold" : row.malicious >= 0.6 ? "score-hot" : row.malicious >= 0.35 ? "score-warm" : "score-cold"),
    judged ? row.malicious.toFixed(2) : "—",
  );
  tr.appendChild(scoreCell);

  // unjudged and error are different facts. One was never asked; the other was asked and
  // the call failed. Never collapse them into a single "no verdict".
  const stateCell = document.createElement("td");
  if (failed) {
    stateCell.className = "state state-error";
    stateCell.textContent = "error";
    stateCell.title = row.error;
  } else if (!judged) {
    stateCell.className = "state state-unjudged";
    stateCell.textContent = "unjudged";
    stateCell.title = "This entry was never sent to the model.";
  } else {
    stateCell.className = "state state-ok";
    stateCell.textContent = "judged";
  }
  tr.appendChild(stateCell);

  tr.appendChild(cell("cat", row.category || "—"));

  const sevText =
    typeof row.severity === "number"
      ? (row.severityLevel || "") + " (" + row.severity.toFixed(1) + ")"
      : row.severityLevel || "—";
  tr.appendChild(cell(severityClass(row.severityLevel), sevText.trim()));

  const analyst = document.createElement("td");
  analyst.className =
    "num" + (typeof row.needsAnalyst === "number" && row.needsAnalyst >= 0.6 ? " analyst-yes" : "");
  analyst.textContent = typeof row.needsAnalyst === "number" ? row.needsAnalyst.toFixed(2) : "—";
  tr.appendChild(analyst);

  tr.appendChild(cell("num", num(row.occurrences)));
  tr.appendChild(cell("ts", shortTs(row.firstSeenTs)));
  tr.appendChild(cell("src", row.source || "—", row.timestampDesc || ""));

  const entry = cell("entry", readableEntry(row.text), row.keyHash);
  tr.appendChild(entry);

  return tr;
}

/** The decision key joins its parts with a unit separator. Show it as a readable line. */
function readableEntry(text) {
  return String(text == null ? "" : text).split("\u001F").join("  ·  ");
}

async function loadRows() {
  const target = byId("rows-error");
  clearError(target);
  const limit = Math.max(1, Number(byId("rows-limit").value) || 100);
  const params = new URLSearchParams();
  const q = byId("rows-q").value.trim();
  if (q !== "") params.set("q", q);
  const min = byId("rows-min").value.trim();
  if (min !== "") params.set("min", min);
  const category = byId("rows-category").value;
  if (category !== "") params.set("category", category);
  params.set("sort", ui.sort);
  params.set("limit", String(limit));
  params.set("offset", String(ui.rowOffset));
  if (byId("rows-undecided").checked) params.set("includeUndecided", "1");

  try {
    const res = await fetch(`/api/rows?${params.toString()}`);
    const page = await readJson(res);
    const rows = (page && page.rows) || [];
    ui.rowTotal = (page && page.total) || 0;

    const body = byId("rows-body");
    body.replaceChildren();
    for (const row of rows) body.appendChild(verdictRow(row));

    const from = rows.length === 0 ? 0 : ui.rowOffset + 1;
    const to = ui.rowOffset + rows.length;
    setText(
      "rows-summary",
      rows.length === 0
        ? "No entries match."
        : num(from) + "–" + num(to) + " of " + num(ui.rowTotal) + " matching entries",
    );
    byId("rows-prev").disabled = ui.rowOffset <= 0;
    byId("rows-next").disabled = to >= ui.rowTotal;
  } catch (err) {
    showError(target, explain(err));
  }
}

async function loadStats() {
  const holder = byId("stats-dist");
  if (!holder) return;
  try {
    const res = await fetch("/api/stats");
    const stats = await readJson(res);
    const distribution = (stats && stats.distribution) || {};
    const pairs = Object.entries(distribution).sort((a, b) => b[1] - a[1]);
    holder.replaceChildren();

    if (pairs.length === 0) {
      const p = document.createElement("p");
      p.className = "panel-note";
      p.textContent = "No verdicts yet.";
      holder.appendChild(p);
      return;
    }

    const top = pairs[0][1] || 1;
    for (const [name, count] of pairs) {
      const row = document.createElement("div");
      row.className = "dist-row";

      const label = document.createElement("span");
      label.textContent = name;

      const bar = document.createElement("div");
      bar.className = "dist-bar";
      const fill = document.createElement("div");
      fill.className = "dist-fill";
      fill.style.width = Math.max(2, (count / top) * 100) + "%";
      bar.appendChild(fill);

      const n = document.createElement("span");
      n.className = "dist-n";
      n.textContent = num(count);

      row.append(label, bar, n);
      holder.appendChild(row);
    }
    fillCategories(pairs.map((p) => p[0]));
  } catch {
    /* Stats are a convenience. A failure here must not blank the verdict table. */
  }
}

function fillCategories(names) {
  const select = byId("rows-category");
  if (!select) return;
  const known = new Set(Array.from(select.options).map((o) => o.value));
  for (const name of names) {
    if (known.has(name)) continue;
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    select.appendChild(option);
  }
}

function wireCalibratePanel() {
  on(byId("sample-run"), "click", async () => {
    const target = byId("sample-error");
    clearError(target);
    const limit = Math.max(1, Number(byId("sample-n").value) || 500);
    try {
      const res = await fetch("/api/judge", postJson({ limit, random: true }));
      await readJson(res);
      setStatus("Judging a random sample of " + num(limit) + " entries…");
    } catch (err) {
      showError(target, explain(err));
    }
  });

  on(byId("questions-save"), "click", saveQuestions);
  on(byId("questions-reload"), "click", loadQuestions);

  const reload = () => {
    ui.rowOffset = 0;
    loadRows();
  };
  on(byId("rows-refresh"), "click", reload);
  on(byId("rows-q"), "change", reload);
  on(byId("rows-min"), "change", reload);
  on(byId("rows-category"), "change", reload);
  on(byId("rows-limit"), "change", reload);
  on(byId("rows-undecided"), "change", reload);
  on(byId("rows-sort"), "change", () => {
    ui.sort = byId("rows-sort").value;
    markSort();
    reload();
  });

  for (const th of document.querySelectorAll(".th-sort")) {
    th.addEventListener("click", () => {
      ui.sort = th.dataset.sort;
      byId("rows-sort").value = ui.sort;
      markSort();
      reload();
    });
  }

  on(byId("rows-prev"), "click", () => {
    const limit = Math.max(1, Number(byId("rows-limit").value) || 100);
    ui.rowOffset = Math.max(0, ui.rowOffset - limit);
    loadRows();
  });
  on(byId("rows-next"), "click", () => {
    const limit = Math.max(1, Number(byId("rows-limit").value) || 100);
    ui.rowOffset += limit;
    loadRows();
  });

  markSort();
}

function markSort() {
  for (const th of document.querySelectorAll(".th-sort")) {
    const active = th.dataset.sort === ui.sort;
    // aria-sort belongs on the column header, not on the button inside it.
    if (active) th.dataset.active = "1";
    else delete th.dataset.active;
    if (th.parentElement) th.parentElement.setAttribute("aria-sort", active ? "descending" : "none");
  }
}

/* ----------------------------------------------------------------- 4. run */

function renderJob(job, counts) {
  const bar = byId("progress");
  const fill = byId("progress-fill");
  const label = byId("progress-label");
  if (!bar || !fill || !label) return;

  bar.classList.remove("indeterminate", "done", "failed");

  if (!job) {
    label.textContent = "Idle — nothing has been started yet.";
    fill.style.width = "0%";
    bar.setAttribute("aria-valuetext", "idle");
    bar.removeAttribute("aria-valuenow");
    setJobButtons(false);
    return;
  }

  const running = job.state === "running";
  setJobButtons(running);

  if (typeof job.progress === "number" && Number.isFinite(job.progress)) {
    const pct = Math.max(0, Math.min(100, Math.round(job.progress * 100)));
    fill.style.width = pct + "%";
    bar.setAttribute("aria-valuenow", String(pct));
    bar.setAttribute("aria-valuetext", pct + "% complete");
  } else if (running) {
    fill.style.width = "30%";
    bar.classList.add("indeterminate");
    bar.removeAttribute("aria-valuenow");
    bar.setAttribute("aria-valuetext", "working, total not yet known");
  } else {
    fill.style.width = job.state === "done" ? "100%" : "0%";
    bar.setAttribute("aria-valuenow", job.state === "done" ? "100" : "0");
    bar.setAttribute("aria-valuetext", job.state);
  }

  if (job.state === "done") bar.classList.add("done");
  if (job.state === "error" || job.state === "cancelled") bar.classList.add("failed");

  const line = job.kind + " · " + job.state + (job.message ? " · " + job.message : "");
  label.textContent = line;
  setStatus(line + (job.error ? " · " + job.error : ""));

  setText("job-cost", usd(typeof job.costUsd === "number" ? job.costUsd : 0));
  setText("job-errors", num(typeof job.errors === "number" ? job.errors : 0));
  setText("job-decided", counts ? num(counts.decided) + " / " + num(counts.total) : "—");
  setText("job-malicious", counts ? num(counts.malicious) : "—");

  renderCeilingNote(job, counts);
}

function setJobButtons(running) {
  for (const id of ["judge-start", "sample-run", "export-run", "narrate-run", "path-scan"]) {
    const el = byId(id);
    if (el) el.disabled = running;
  }
  const cancel = byId("judge-cancel");
  if (cancel) cancel.disabled = !running;
}

/**
 * A judge pass that stopped at the cost ceiling has state "done", which reads as finished.
 * It is not finished. Say so in words, with the number of entries still unjudged.
 */
function renderCeilingNote(job, counts) {
  const note = byId("ceiling-note");
  if (!note) return;
  if (!job || job.kind !== "judge" || job.state === "running") {
    note.hidden = true;
    return;
  }

  const stoppedOnCost = /cost ceiling/i.test(job.message || "");
  const left = counts ? Math.max(0, counts.total - counts.decided) : 0;

  if (stoppedOnCost) {
    note.textContent =
      "Stopped at the cost ceiling" +
      (ui.lastCeiling ? " of " + usd(ui.lastCeiling) : "") +
      ". This pass is NOT complete" +
      (left > 0 ? " — " + num(left) + " distinct entries still have no verdict." : ".") +
      " Raise the ceiling and start again to continue; nothing already judged is re-judged.";
    note.hidden = false;
    return;
  }

  if (job.state === "cancelled") {
    note.textContent =
      "Cancelled." +
      (left > 0 ? " " + num(left) + " distinct entries still have no verdict." : "") +
      " Verdicts already written are kept.";
    note.hidden = false;
    return;
  }

  if (job.state === "done" && left > 0) {
    note.textContent =
      "The pass finished, but " + num(left) + " distinct entries still have no verdict.";
    note.hidden = false;
    return;
  }

  note.hidden = true;
}

function wireRunPanel() {
  on(byId("judge-start"), "click", async () => {
    const target = byId("judge-error");
    clearError(target);
    const workers = Math.max(1, Number(byId("judge-workers").value) || 16);
    const rareFirst = byId("judge-rare").checked;
    const raw = byId("judge-maxcost").value.trim();
    const maxCostUsd = raw === "" ? undefined : Number(raw);
    if (raw !== "" && !Number.isFinite(maxCostUsd)) {
      showError(target, "The cost ceiling must be a number, or empty for no ceiling.");
      return;
    }
    ui.lastCeiling = maxCostUsd === undefined ? null : maxCostUsd;

    const payload = { workers, rareFirst };
    if (maxCostUsd !== undefined) payload.maxCostUsd = maxCostUsd;
    try {
      const res = await fetch("/api/judge", postJson(payload));
      await readJson(res);
      setStatus("Judge pass started with " + workers + " workers.");
    } catch (err) {
      showError(target, explain(err));
    }
  });

  on(byId("judge-cancel"), "click", async () => {
    const target = byId("judge-error");
    clearError(target);
    try {
      const res = await fetch("/api/cancel", postJson({}));
      await readJson(res);
      setStatus("Cancel requested. Verdicts already written are kept.");
    } catch (err) {
      showError(target, explain(err));
    }
  });

  on(byId("thresholds-save"), "click", saveThresholds);

  on(byId("export-run"), "click", async () => {
    const target = byId("export-error");
    clearError(target);
    try {
      await saveThresholds();
      const res = await fetch("/api/export", postJson({}));
      await readJson(res);
      setStatus("Export started.");
    } catch (err) {
      showError(target, explain(err));
    }
  });
}

async function saveThresholds() {
  const target = byId("export-error");
  const payload = {
    malicious: Number(byId("th-malicious").value),
    needsAnalyst: Number(byId("th-needs").value),
    confident: Number(byId("th-confident").value),
  };
  try {
    const res = await fetch("/api/thresholds", postJson(payload));
    await readJson(res);
    clearError(target);
  } catch (err) {
    showError(target, explain(err));
    throw err;
  }
}

function renderThresholds(thresholds) {
  if (!thresholds) return;
  const set = (id, value) => {
    const el = byId(id);
    if (el && document.activeElement !== el && typeof value === "number") el.value = String(value);
  };
  set("th-malicious", thresholds.malicious);
  set("th-needs", thresholds.needsAnalyst);
  set("th-confident", thresholds.confident);
}

function renderArtifacts(artifacts) {
  const list = byId("artifact-links");
  if (!list) return;
  list.replaceChildren();

  const add = (label, path) => {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = `/api/download?path=${encodeURIComponent(path)}`;
    a.textContent = label + " — " + baseName(path);
    a.title = path;
    a.setAttribute("download", "");
    li.appendChild(a);
    list.appendChild(li);
  };

  const any = artifacts && (artifacts.maliciousCsv || artifacts.manifest);
  if (!any) {
    const li = document.createElement("li");
    li.className = "none";
    li.textContent = "Nothing exported yet.";
    list.appendChild(li);
    return;
  }
  if (artifacts.maliciousCsv) add("malicious CSV", artifacts.maliciousCsv);
  if (artifacts.manifest) add("manifest", artifacts.manifest);
}

/* ----------------------------------------------------------- 5. narrative */

function renderNarrativeList(paths) {
  const list = byId("narrative-list");
  if (!list) return;
  list.replaceChildren();

  if (!paths || paths.length === 0) {
    const li = document.createElement("li");
    li.className = "none";
    li.textContent = "No narrative written yet.";
    list.appendChild(li);
    return;
  }

  for (const path of paths) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = baseName(path);
    btn.title = path;
    btn.addEventListener("click", () => loadNarrative(path));
    li.appendChild(btn);

    const dl = document.createElement("a");
    dl.href = `/api/download?path=${encodeURIComponent(path)}`;
    dl.textContent = " (download)";
    dl.setAttribute("download", "");
    li.appendChild(dl);

    list.appendChild(li);
  }

  if (ui.narrativePath === "") loadNarrative(paths[paths.length - 1]);
}

async function loadNarrative(path) {
  const target = byId("narrate-error");
  clearError(target);
  try {
    const res = await fetch(`/api/narrative?path=${encodeURIComponent(path)}`);
    if (!res.ok) throw new ApiError((await bodyText(res)) || "HTTP " + res.status, res.status);
    const markdown = await res.text();
    ui.narrativePath = path;
    // The only innerHTML in this file. renderMarkdown escapes the whole document before it
    // adds a single tag; see the comment on renderMarkdown.
    byId("narrative-view").innerHTML = renderMarkdown(markdown);
  } catch (err) {
    showError(target, explain(err));
  }
}

function wireNarrativePanel() {
  on(byId("narrate-run"), "click", async () => {
    const target = byId("narrate-error");
    clearError(target);
    const payload = {
      narrator: byId("narrator").value,
      groupBy: byId("narrate-group").checked ? "host" : "none",
    };
    const model = byId("narrate-model").value.trim();
    if (model !== "") payload.model = model;
    try {
      const res = await fetch("/api/narrate", postJson(payload));
      await readJson(res);
      ui.narrativePath = "";
      setStatus("Narrating with " + payload.narrator + "…");
    } catch (err) {
      showError(target, explain(err));
    }
  });
}

/* ---------------------------------------------------------------- state */

function renderState(server) {
  if (!server) return;
  ui.server = server;

  renderScan(server);
  renderThresholds(server.thresholds);
  renderArtifacts(server.artifacts);
  renderNarrativeList(server.artifacts ? server.artifacts.narratives : []);
  renderJob(server.job, server.counts);
  setQuestionsHash(server.questionsHash);

  if (server.file) {
    const input = byId("path-input");
    if (input && input.value.trim() === "") input.value = server.file;
  }
  if (!server.job) {
    setStatus(server.file ? "Ready — " + baseName(server.file) : "No timeline loaded.");
  }
}

async function refreshState() {
  try {
    const res = await fetch("/api/state");
    const server = await readJson(res);
    renderState(server);
    if (server && server.file) {
      await loadRows();
      await loadStats();
    }
  } catch (err) {
    setStatus(explain(err));
  }
}

/* ------------------------------------------------------------ live stream */

let refreshTimer = null;

/** Coalesces the refreshes a burst of events would otherwise cause. */
function scheduleRefresh() {
  if (refreshTimer !== null) return;
  refreshTimer = window.setTimeout(() => {
    refreshTimer = null;
    refreshState();
  }, 400);
}

function openStream() {
  if (typeof window.EventSource !== "function") {
    // No EventSource. This is the ONLY case that polls.
    setConnection("poll", "polling");
    window.setInterval(refreshState, 3000);
    return;
  }

  const stream = new EventSource("/events");
  let lastJobState = "";

  stream.addEventListener("open", () => {
    ui.liveStream = true;
    setConnection("live", "live");
  });

  stream.addEventListener("message", (ev) => {
    let event = null;
    try {
      event = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (!event || typeof event.type !== "string") return;

    if (event.type === "job") {
      const job = event.job;
      renderJob(job, ui.server ? ui.server.counts : null);
      // A job that just left "running" changed the rows, the artifacts and the counts.
      if (job && job.state !== "running" && job.state !== lastJobState) scheduleRefresh();
      if (job) lastJobState = job.state;
      return;
    }
    if (event.type === "state") {
      renderState(event.state);
      if (event.state && event.state.file) {
        loadRows();
        loadStats();
      }
      return;
    }
    if (event.type === "log" && typeof event.line === "string") {
      setStatus(event.line);
    }
  });

  stream.addEventListener("error", () => {
    // EventSource retries on its own. Say so, so a stalled page is not read as a hung job.
    ui.liveStream = false;
    setConnection("retry", "reconnecting…");
  });
}

/* ------------------------------------------------------------------- boot */

function boot() {
  initTheme();
  wireTimelinePanel();
  wireCalibratePanel();
  wireRunPanel();
  wireNarrativePanel();
  openStream();
  loadQuestions();
  loadBrowse("");
  refreshState();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", boot);
} else {
  boot();
}
