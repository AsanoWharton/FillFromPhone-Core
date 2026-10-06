import { createHash, randomBytes } from "node:crypto";
import { performance } from "node:perf_hooks";
import { SessionStore } from "../dist/store.js";

const samples = [];
const store = new SessionStore(20_000);
for (let index = 0; index < 10_000; index += 1) {
  const id = randomBytes(32).toString("base64url");
  const read = randomBytes(32).toString("base64url");
  const write = randomBytes(32).toString("base64url");
  const readHash = createHash("sha256").update(Buffer.from(read, "base64url")).digest("base64url");
  const writeHash = createHash("sha256").update(Buffer.from(write, "base64url")).digest("base64url");
  const start = performance.now();
  store.reserve(id, Date.now() + 60_000, writeHash, readHash);
  store.subscribe(id, read, () => {});
  const claim = store.claim(id, write);
  store.put(id, write, claim, { v: 5, phonePublicKey: randomBytes(65).toString("base64url"), nonce: randomBytes(12).toString("base64url"), ciphertext: randomBytes(64).toString("base64url") });
  samples.push(performance.now() - start);
}
samples.sort((a, b) => a - b);
const percentile = (value) => samples[Math.floor((samples.length - 1) * value)];
process.stdout.write(JSON.stringify({ operations: samples.length, milliseconds: { p50: percentile(.5), p95: percentile(.95), p99: percentile(.99) } }, null, 2) + "\n");
store.close();
