// The file picker: the server lists its own directories so the analyst can point at a
// timeline. A browser cannot hand over a real path — a file input yields a sandboxed File
// object, not "/cases/wkstn01/timeline.csv" — and the timeline is measured in gigabytes, so
// uploading it is not an option either. The server opens the file itself, which means the
// server has to be the one that finds it.
//
// THIS LISTING IS DELIBERATELY UNRESTRICTED. There is no root jail: it will list any
// directory this process can read, all the way up to /. That is safe for exactly one reason —
// the server binds to BIND_HOST (127.0.0.1) and answers nothing but this machine, and anything
// on this machine already reads those directories directly, without asking. That is what
// BIND_HOST is FOR. Bind this server to 0.0.0.0 and this one function turns into a remote
// filesystem browser for the whole disk, with no credential in front of it.

import { readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { BrowseResult } from "./contract.js";

/** The dialects this tool reads. Anything else is noise in a picker. */
const TIMELINE_FILE = /\.(csv|tsv)$/i;

/**
 * List the subdirectories and timeline files at `path`, defaulting to the user's home.
 *
 * `home` is a parameter rather than a call to homedir() at the point of use so a test can
 * pin it; nothing else should pass it.
 */
export function browse(path: string | undefined, home?: string): BrowseResult {
  const base = home ?? homedir();
  const target = path === undefined || path.trim() === "" ? base : resolve(path);

  const dirs: string[] = [];
  const files: { name: string; bytes: number }[] = [];

  for (const entry of readdirSync(target)) {
    // A dotfile is configuration, not evidence, and a dot-directory is somebody's cache.
    if (entry.startsWith(".")) continue;
    let stats;
    try {
      // statSync, not the dirent: a symlink to a directory should list as a directory, and a
      // broken symlink or an unreadable entry should drop out here rather than take the whole
      // listing down. One bad entry must never hide the other nine hundred.
      stats = statSync(join(target, entry));
    } catch {
      continue;
    }
    if (stats.isDirectory()) dirs.push(entry);
    else if (stats.isFile() && TIMELINE_FILE.test(entry)) files.push({ name: entry, bytes: stats.size });
  }

  dirs.sort(byNameCi);
  files.sort((a, b) => byNameCi(a.name, b.name));

  const parent = dirname(target);
  return {
    path: target,
    // dirname() of a filesystem root is that root, which is how "we are at the top" reads.
    ...(parent === target ? {} : { parent }),
    dirs,
    files,
  };
}

/**
 * Case-insensitive, then case-sensitive to break the tie. Not localeCompare: the order has to
 * be the same on every machine that reads the same case, and a locale-aware collation is not.
 */
function byNameCi(a: string, b: string): number {
  const la = a.toLowerCase();
  const lb = b.toLowerCase();
  if (la !== lb) return la < lb ? -1 : 1;
  if (a === b) return 0;
  return a < b ? -1 : 1;
}
