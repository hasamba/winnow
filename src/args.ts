// Argument parsing. Deliberately hand-rolled: one dependency in this tool is enough, and
// the flag set is small and stable.

export interface ParsedArgs {
  readonly command: string;
  readonly file: string;
  readonly flags: Readonly<Record<string, string | boolean>>;
}

const KNOWN_COMMANDS = ["scan", "sample", "judge", "export", "narrate", "run", "help"] as const;
export type Command = (typeof KNOWN_COMMANDS)[number];

export function isCommand(v: string): v is Command {
  return (KNOWN_COMMANDS as readonly string[]).includes(v);
}

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const flags: Record<string, string | boolean> = {};
  const positional: string[] = [];

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === undefined) continue;
    if (!token.startsWith("--")) {
      positional.push(token);
      continue;
    }
    const body = token.slice(2);
    const eq = body.indexOf("=");
    if (eq !== -1) {
      flags[body.slice(0, eq)] = body.slice(eq + 1);
      continue;
    }
    const next = argv[i + 1];
    if (next !== undefined && !next.startsWith("--")) {
      flags[body] = next;
      i += 1;
    } else {
      flags[body] = true;
    }
  }

  return { command: positional[0] ?? "help", file: positional[1] ?? "", flags };
}

export function flagNumber(
  flags: Readonly<Record<string, string | boolean>>,
  name: string,
  fallback: number,
): number {
  const raw = flags[name];
  if (raw === undefined || typeof raw === "boolean") return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) {
    throw new Error(`--${name} expects a number, got "${raw}"`);
  }
  return parsed;
}

export function flagString(
  flags: Readonly<Record<string, string | boolean>>,
  name: string,
): string | undefined {
  const raw = flags[name];
  return typeof raw === "string" ? raw : undefined;
}

export function flagBool(
  flags: Readonly<Record<string, string | boolean>>,
  name: string,
): boolean {
  return flags[name] === true || flags[name] === "true";
}

export const USAGE = `winnow — separate the grain from the chaff in a Plaso supertimeline.

  winnow scan    <timeline.csv>    Count rows and distinct entries, estimate cost. Free, offline.
  winnow sample  <timeline.csv>    Judge a small random sample to check the questions. Cents.
  winnow judge   <timeline.csv>    Ask Jev about every distinct entry. Resumable.
  winnow export  <timeline.csv>    Write the malicious CSV and the run manifest.
  winnow narrate <malicious.csv>   Have a second model write what happened.
  winnow run     <timeline.csv>    scan, judge, export and narrate in one go.

Common flags
  --db <path>            Decision cache location (default: <timeline>.winnow.sqlite)
  --questions <path>     Question set (default: the bundled questions.json)
  --workers <n>          Parallel Jev calls (default: 16)
  --rare-first           Judge the least-repeated entries first
  --max-cost <usd>       Stop the run once this much has been spent
  --yes                  Do not stop to confirm the cost
  --threshold <0-1>      Malicious cut for inclusion (default: 0.35)
  --needs-analyst <0-1>  Keep-for-a-human cut (default: 0.6)
  --out <path>           Output file

sample flags
  --n <count>            Sample size (default: 500)

narrate flags
  --narrator <name>      openrouter | claude-api | claude-cli | codex-cli
  --model <id>           Model for that narrator
  --group-by host        One narrative per host
`;
