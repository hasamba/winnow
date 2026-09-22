// Terminal output helpers. The numbers this tool prints decide whether someone spends ten
// dollars, so they are formatted to be read at a glance rather than parsed.

export function num(n: number): string {
  return n.toLocaleString("en-US");
}

export function usd(n: number): string {
  if (n === 0) return "$0.00";
  if (n < 0.01) return `$${n.toFixed(5)}`;
  return `$${n.toFixed(2)}`;
}

export function duration(seconds: number): string {
  if (seconds < 90) return `${Math.round(seconds)}s`;
  const minutes = seconds / 60;
  if (minutes < 90) return `${Math.round(minutes)} min`;
  const hours = minutes / 60;
  if (hours < 48) return `${hours.toFixed(1)} hours`;
  return `${(hours / 24).toFixed(1)} days`;
}

export function percent(part: number, whole: number): string {
  if (whole === 0) return "0%";
  return `${((part / whole) * 100).toFixed(1)}%`;
}

export function bytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/** A single rewritten progress line, so a long run does not scroll the terminal away. */
export function progressLine(text: string): void {
  if (process.stderr.isTTY) {
    process.stderr.write(`\r\x1b[2K${text}`);
  }
}

export function endProgress(): void {
  if (process.stderr.isTTY) process.stderr.write("\n");
}
