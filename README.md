# timeline-triage

Grade a Plaso supertimeline row by row with a cheap decision model, then have a stronger
model write what happened.

A supertimeline is too big to read and too noisy to grade by hand. This tool keeps every
row and gives every row a verdict. It never drops a row on suspicion: the only rows it
collapses are ones whose text is character-for-character identical.

## How it works

1. **Scan** reads the file and counts the distinct entries. Free and offline.
2. **Sample** judges a few hundred of them so you can check the questions before spending.
3. **Judge** asks Jev about every distinct entry, in parallel, and saves each verdict as it
   lands.
4. **Export** writes a CSV of the malicious rows — every original column untouched, six
   verdict columns appended.
5. **Narrate** hands that CSV to Claude, Codex or an OpenRouter model, which writes the
   incident account.

## Install

```bash
cd /home/hasamba/Projects/timeline-triage
npm install
npm run build
```

Jev needs an OpenRouter key. It is read from `OPENROUTER_API_KEY`, or from
`~/.config/typesafe/openrouter.env`. It is never copied into this repository, never
printed, and never written into any output file.

## Use

Start with a scan. It costs nothing and tells you what the job will cost.

```bash
npx tsx src/cli.ts scan /path/to/timeline.csv
```

```
2,412,880 rows · l2tcsv · 2026-03-02T00:11:04Z → 2026-03-11T18:42:57Z
  318,445 distinct entries (86.8% duplicate)
  318,445 still to judge
  Estimate: $9.55 · 33 min
```

Then calibrate. This is the step that matters most — it costs about two cents and it is
where a badly worded question gets caught, instead of after a ten-dollar run.

```bash
npx tsx src/cli.ts sample /path/to/timeline.csv --n 500
```

Read the verdicts it prints. If they do not look like an analyst's, edit `questions.json`
and sample again. Changing a question invalidates the old verdicts automatically, so you
cannot accidentally mix two question sets in one run.

Then the real pass, the export, and the narrative:

```bash
npx tsx src/cli.ts judge   /path/to/timeline.csv --workers 16 --max-cost 25
npx tsx src/cli.ts export  /path/to/timeline.csv
npx tsx src/cli.ts narrate /path/to/timeline.csv.malicious.csv --narrator claude-api
```

Or all of it at once:

```bash
npx tsx src/cli.ts run /path/to/timeline.csv --narrator claude-api --yes
```

`triage help` lists every flag.

## What you get

`<timeline>.malicious.csv` — every original column in its original order, then:

| Column | Meaning |
|---|---|
| `jev_malicious` | 0 to 1. How strongly the model reads this as attacker activity. |
| `jev_confidence` | `confident`, `uncertain`, `error` or `unjudged`. |
| `jev_category` | execution, persistence, credential access, and so on. |
| `jev_severity` | A level and a number, e.g. `High (3.4)`. |
| `jev_needs_analyst` | 0 to 1. Whether a person should read this one personally. |
| `jev_dupe_count` | How many times this exact entry appears in the timeline. |

`<timeline>.run.json` — the manifest: the model, the questions and their hash, the
thresholds, the source file's checksum, the counts and the cost. It is what lets a verdict
be reproduced or challenged months later.

## Things worth knowing

**A row is judged alone.** Supertimeline neighbours are usually unrelated noise rather than
the next step in a sequence, so context windows were left out on purpose. The cost is that
a download, an execution and a persistence entry that each look ordinary on their own can
all slip through. The `jev_needs_analyst` score partly covers this, and the narrating model
sees the whole surviving set at once.

**Nothing is dropped for looking benign.** Only exact duplicates collapse. A row the tool
failed to judge is still written to the malicious CSV, flagged `unjudged` — silently losing
a row it could not grade is the one thing this tool must not do.

**The malicious cut is 0.35, not 0.5.** In triage a missed attacker row costs more than a
noisy one. Change it with `--threshold`.

**Interrupting is safe.** Every verdict is written the moment it arrives. Ctrl-C and rerun
the same command; it continues where it stopped and re-judges nothing.

**A flagged row is a lead, not a finding.**

## Later

The parser, the CSV safety escaping and the four narrator providers are shaped after DFIR
Companion's own, so this folds back into that project as an importer plus an analysis pass
once the triage accuracy is proven.
