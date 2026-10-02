/**
 * One of `hush scan --transcripts`' scanning threads. It is handed the byte
 * strings to look for once, then asks for work one piece at a time (a file, or a range of a large one) until the main
 * thread says there are none left — a queue rather than a fixed share, so one
 * 2 GB database does not leave every other thread idle.
 */
import { parentPort, workerData } from "node:worker_threads";
import { Matcher } from "./transcripts.ts";

const port = parentPort!;
const matcher = new Matcher((workerData.needles as Uint8Array[]).map((n) => Buffer.from(n)));
port.on("message", (item: { path: string; start: number; end: number } | null) => {
  if (item === null) return port.close();
  const hits = matcher.scanFile(item.path, undefined, item.start, item.end);
  port.postMessage({ needles: [...hits.needles], tokens: [...hits.tokens] });
});
port.postMessage({ ready: true });
