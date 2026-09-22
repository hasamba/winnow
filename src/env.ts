// Environment loading. Keys are read from a file so a long run does not depend on an export
// that was only ever typed into one shell.
//
// Precedence, highest first:
//   1. a real environment variable, so CI and a one-off override always win
//   2. ./.env next to the working directory
//   3. the .env beside this project, so `winnow` works from any directory
//
// The Jev key keeps its own separate home at ~/.config/typesafe/openrouter.env, outside every
// git repo. This file never moves it and never copies it into the project.

import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** The project root, resolved from this module, so it works from src/ and from dist/. */
export function projectRoot(): string {
  return dirname(dirname(fileURLToPath(import.meta.url)));
}

/**
 * Load .env files if present. A real environment variable always wins, because
 * `process.loadEnvFile` does not overwrite one that is already set.
 */
export function loadEnvFiles(cwd: string = process.cwd()): string[] {
  const loaded: string[] = [];
  for (const path of [join(cwd, ".env"), join(projectRoot(), ".env")]) {
    if (!existsSync(path) || loaded.includes(path)) continue;
    try {
      process.loadEnvFile(path);
      loaded.push(path);
    } catch {
      // A malformed .env must not stop a run that may not need any key at all. The command
      // that needs a key raises its own error, naming the variable and where to put it.
    }
  }
  return loaded;
}
