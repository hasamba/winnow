import { afterEach, beforeEach, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse } from "node:path";
import { browse } from "../src/server/browse.js";

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "winnow-browse-"));
  mkdirSync(join(dir, "alpha"));
  mkdirSync(join(dir, "Beta"));
  mkdirSync(join(dir, ".hidden"));
  writeFileSync(join(dir, "one.csv"), "a,b\n1,2\n");
  writeFileSync(join(dir, "Two.tsv"), "a\tb\n");
  writeFileSync(join(dir, "three.txt"), "not a timeline");
  writeFileSync(join(dir, ".secret.csv"), "hidden");
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

it("lists directories then CSV and TSV files, case-insensitively", () => {
  const result = browse(dir);
  expect(result.path).toBe(dir);
  expect(result.dirs).toEqual(["alpha", "Beta"]);
  expect(result.files).toEqual([
    { name: "one.csv", bytes: 8 },
    { name: "Two.tsv", bytes: 4 },
  ]);
});

it("hides dotfiles and dot-directories", () => {
  const result = browse(dir);
  expect(result.dirs).not.toContain(".hidden");
  expect(result.files.map((f) => f.name)).not.toContain(".secret.csv");
});

it("includes the parent, except at the filesystem root", () => {
  expect(browse(dir).parent).toBe(dirname(dir));
  const root = parse(dir).root;
  expect(browse(root).parent).toBeUndefined();
});

it("skips an entry that cannot be stat'd rather than failing the listing", () => {
  symlinkSync(join(dir, "no-such-target.csv"), join(dir, "broken.csv"));
  const result = browse(dir);
  expect(result.files.map((f) => f.name)).toEqual(["one.csv", "Two.tsv"]);
});

it("defaults to the home directory when no path is given", () => {
  expect(browse(undefined, dir).path).toBe(dir);
  expect(browse("", dir).path).toBe(dir);
});
