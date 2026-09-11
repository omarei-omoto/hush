/**
 * Streaming redactor.
 *
 * Anything that could carry a secret value back to a human, a log file, or a
 * model context goes through this first. It handles the case that matters in
 * practice: a value split across two stdout chunks.
 */

const MIN_REDACTABLE = 5;

/** Values this short or this common are not worth masking — masking them is noise. */
const SKIP_VALUES = new Set(["true", "false", "null", "undefined", "0", "1", "localhost"]);

export class Redactor {
  /** Longest secret we track, so we know how much tail to hold back. */
  private maxLen = 0;
  /** value -> label used in the replacement. */
  private readonly targets: [string, string][] = [];
  private carry = "";

  constructor(secrets: Record<string, string> = {}) {
    for (const [key, value] of Object.entries(secrets)) this.add(key, value);
  }

  add(key: string, value: string): void {
    if (!value || value.length < MIN_REDACTABLE) return;
    if (SKIP_VALUES.has(value.toLowerCase())) return;
    this.targets.push([value, `[redacted:${key}]`]);
    this.maxLen = Math.max(this.maxLen, value.length);
    // Longest first, so a value that contains another is masked whole.
    this.targets.sort((a, b) => b[0].length - a[0].length);
  }

  get size(): number {
    return this.targets.length;
  }

  private mask(s: string): string {
    let out = s;
    for (const [value, label] of this.targets) out = out.split(value).join(label);
    return out;
  }

  /**
   * Feed a chunk; get back the safe-to-emit prefix.
   *
   * Only the tail that could still be *completing* a match is held back. The
   * previous version always carried `maxLen - 1` bytes, so one long secret in
   * the vault (a private key, say) made every subsequent write rescan a
   * multi-kilobyte buffer: 50k log lines with a 3KB secret cost ten seconds of
   * pure CPU, and `hush run -- npm test` looked like it had hung.
   *
   * Now the carry is the longest suffix of the buffer that is a proper prefix
   * of some secret — almost always nothing, so the buffer does not grow and
   * each chunk is scanned once.
   */
  push(chunk: string): string {
    if (this.targets.length === 0) return chunk;
    const buf = this.carry + chunk;

    // Earliest position from which a partial match could still be alive.
    const tailStart = Math.max(0, buf.length - (this.maxLen - 1));
    let cut = buf.length;

    for (const [value] of this.targets) {
      // Single-character indexOf is native and fast; most passes find nothing.
      let p = buf.indexOf(value[0], tailStart);
      while (p !== -1 && p < cut) {
        const remaining = buf.length - p;
        // A *complete* match is handled by mask(); only an incomplete tail is held.
        if (remaining < value.length && value.startsWith(buf.slice(p))) {
          cut = p;
          break;
        }
        p = buf.indexOf(value[0], p + 1);
      }
    }

    // A *complete* match can still straddle that cut, when a secret's own tail
    // happens to begin another secret — "…5432/app" ends with the "p" that
    // starts "postgres://…". Emitting up to the cut would then print the whole
    // value verbatim, so walk the cut past any complete match it lands inside.
    // Cheap now: the buffer is chunk-sized unless a partial match is in flight.
    for (let moved = true; moved; ) {
      moved = false;
      for (const [value] of this.targets) {
        let idx = buf.indexOf(value);
        while (idx !== -1 && idx < cut) {
          if (idx + value.length > cut) {
            cut = idx + value.length;
            moved = true;
          }
          idx = buf.indexOf(value, idx + 1);
        }
      }
    }

    this.carry = buf.slice(cut);
    return this.mask(buf.slice(0, cut));
  }

  /** Flush whatever is still held back. Call once at end of stream. */
  flush(): string {
    const rest = this.carry;
    this.carry = "";
    return this.mask(rest);
  }

  /** One-shot convenience for strings you already hold whole. */
  redact(s: string): string {
    return this.mask(s);
  }
}

/**
 * Show enough of a value to recognise it, never enough to use it.
 *
 * This is what `hush_describe_secret` hands an agent, so the bound matters: the
 * old rule revealed a fixed five characters above a length of eight, which for a
 * ten-character token was half the secret. Nothing is revealed below twenty
 * characters, and above it the five shown are at most a quarter of the value —
 * the prefix identifies the key type (`sk_live_` vs `sk_test_`) and the suffix
 * matches what a provider dashboard displays.
 */
const PREVIEW_MIN_LENGTH = 20;

export function preview(value: string): string {
  const n = value.length;
  if (n === 0) return "(empty)";
  if (n < PREVIEW_MIN_LENGTH) return `${"•".repeat(Math.min(n, 12))} (${n} chars)`;
  return `${value.slice(0, 3)}…${value.slice(-2)} (${n} chars)`;
}
