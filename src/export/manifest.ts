// The run manifest: what was judged, by which model, against which questions, at what cost.
// It ships next to the malicious CSV so a second analyst can reproduce, or challenge, the run.
//
// REDACTION RULE — the manifest must NEVER contain an API key, an environment dump, or a file
// system path outside the case working directory. It is written to disk, attached to reports
// and handed to third parties, so nothing here reads `process.env` and the source file is
// recorded by NAME only. Adding a field that carries a credential, a raw environment or an
// absolute path breaks that rule; keep the new field to a name, a hash or a count.

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";
import { pipeline } from "node:stream/promises";
import type { Thresholds } from "../types.js";

export interface ToolInfo {
  readonly name: string;
  readonly version: string;
}

/**
 * The manifest, flat on purpose: it is read by a person in a text editor as often as by a
 * program, and one level of keys reads better in a report appendix than a tree does.
 */
export interface RunManifest {
  readonly tool: string;
  readonly version: string;
  /** The Jev model id the run judged with. */
  readonly jevModel: string;
  /** The full questions text, so a later run can be compared clause by clause. */
  readonly questionsText: string;
  /** sha256 of that text — the same hash that salts every decision key. */
  readonly questionsHash: string;
  readonly thresholds: Thresholds;
  /** The source file NAME only. Never the path that led to it — see the redaction rule above. */
  readonly sourceFile: string;
  readonly sourceBytes: number;
  readonly sourceSha256: string;
  readonly totalRows: number;
  readonly distinctKeys: number;
  readonly decidedKeys: number;
  readonly erroredKeys: number;
  /** How many distinct keys landed in each verdict category. */
  readonly distribution: Readonly<Record<string, number>>;
  /** Rows written to the malicious CSV. */
  readonly rowsWritten: number;
  readonly workers: number;
  /** Wall-clock start and end, ISO-8601 UTC. */
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly costUsd: number;
}

/** Everything the caller measured. `sourcePath` is reduced to its basename on the way in. */
export interface ManifestInputs {
  readonly toolName: string;
  readonly toolVersion: string;
  readonly model: string;
  readonly questionsText: string;
  readonly questionsHash: string;
  readonly thresholds: Thresholds;
  readonly sourcePath: string;
  readonly sourceBytes: number;
  readonly sourceSha256: string;
  readonly totalRows: number;
  readonly distinctKeys: number;
  readonly decidedKeys: number;
  readonly erroredKeys: number;
  readonly verdictsByCategory: Readonly<Record<string, number>>;
  readonly rowsWritten: number;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly totalCostUsd: number;
  readonly workers: number;
}

/** Assemble the manifest. Pure — it reads no environment and touches no disk. */
export function buildManifest(i: ManifestInputs): RunManifest {
  return {
    tool: i.toolName,
    version: i.toolVersion,
    jevModel: i.model,
    questionsText: i.questionsText,
    questionsHash: i.questionsHash,
    thresholds: i.thresholds,
    sourceFile: basename(i.sourcePath),
    sourceBytes: i.sourceBytes,
    sourceSha256: i.sourceSha256,
    totalRows: i.totalRows,
    distinctKeys: i.distinctKeys,
    decidedKeys: i.decidedKeys,
    erroredKeys: i.erroredKeys,
    distribution: { ...i.verdictsByCategory },
    rowsWritten: i.rowsWritten,
    workers: i.workers,
    startedAt: i.startedAt,
    finishedAt: i.finishedAt,
    costUsd: i.totalCostUsd,
  };
}

/** Write the manifest as pretty-printed JSON. */
export async function writeManifest(path: string, m: RunManifest): Promise<void> {
  // The basename is applied again here, so a caller that assembles the object by hand still
  // cannot write a path out of the case directory. See the redaction rule at the top.
  const safe: RunManifest = { ...m, sourceFile: basename(m.sourceFile) };
  await writeFile(path, `${JSON.stringify(safe, null, 2)}\n`, "utf8");
}

const PACKAGE_JSON_URL = new URL("../../package.json", import.meta.url);

/** The tool's own name and version, from package.json. */
export async function readToolInfo(packageJsonPath?: string): Promise<ToolInfo> {
  const source = packageJsonPath ?? PACKAGE_JSON_URL;
  const parsed: unknown = JSON.parse(await readFile(source, "utf8"));
  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("package.json is not an object");
  }
  const { name, version } = parsed as { name?: unknown; version?: unknown };
  if (typeof name !== "string" || typeof version !== "string") {
    throw new Error("package.json has no string name and version");
  }
  return { name, version };
}

/**
 * sha256 of a file, streamed. The source timeline can be multiple gigabytes, so the bytes
 * never all sit in memory at once.
 */
export async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  await pipeline(createReadStream(path), hash);
  return hash.digest("hex");
}
