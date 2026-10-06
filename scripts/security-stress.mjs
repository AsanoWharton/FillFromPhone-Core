import { createHash, randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import { performance } from "node:perf_hooks";

const target = process.env.TARGET_BASE;
if (!target) throw new Error("set TARGET_BASE to a loopback or isolated test endpoint");
const parsedTarget = new URL(target);
if (!["127.0.0.1", "localhost", "::1"].includes(parsedTarget.hostname) && process.env.ALLOW_NON_LOOPBACK !== "true") {
  throw new Error("refusing non-loopback stress target without ALLOW_NON_LOOPBACK=true");
}
const total = boundedInteger("TOTAL", 500, 1, 20_000);
const concurrency = boundedInteger("CONCURRENCY", 25, 1, 200);
const host = process.env.REQUEST_HOST ?? "fillfromphone.com";
const samples = [];
const failures = [];
let cursor = 0;

function boundedInteger(name, fallback, minimum, maximum) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) throw new Error(`invalid ${name}`);
  return value;
}

const token = (bytes = 32) => randomBytes(bytes).toString("base64url");
const hash = (value) => createHash("sha256").update(Buffer.from(value, "base64url")).digest("base64url");
const percentile = (values, fraction) => values[Math.floor((values.length - 1) * fraction)] ?? 0;

async function request(path, init, clientNumber) {
  const syntheticClient = `198.18.${Math.floor(clientNumber / 254) % 254}.${clientNumber % 254 + 1}`;
  const destination = new URL(path, parsedTarget);
  const body = init?.body ?? "";
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(destination, {
      method: init?.method ?? "GET",
      headers: {
        Host: host,
        "CF-Connecting-IP": syntheticClient,
        ...init?.headers,
        ...(body ? { "Content-Length": Buffer.byteLength(body) } : {})
      }
    }, (incoming) => {
      const chunks = [];
      incoming.on("data", (chunk) => chunks.push(chunk));
      incoming.on("end", () => {
        const responseBody = Buffer.concat(chunks).toString("utf8");
        resolve({
          status: incoming.statusCode ?? 0,
          json: async () => JSON.parse(responseBody),
          text: async () => responseBody
        });
      });
    });
    outgoing.once("error", reject);
    if (body) outgoing.write(body);
    outgoing.end();
  });
}

async function flow(index) {
  const started = performance.now();
  const id = token(32);
  const readToken = token();
  const writeToken = token();
  const reserve = await request("/v1/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id,
      expiresAt: Date.now() + 120_000,
      writeTokenHash: hash(writeToken),
      readTokenHash: hash(readToken)
    })
  }, index);
  if (reserve.status !== 201) throw new Error(`reserve:${reserve.status}`);
  const reservation = await reserve.json();
  if (!(["B", "G"].includes(reservation.slot)) || reservation.status !== "reserved") throw new Error("reserve:invalid_body");
  const path = `/v1/${reservation.slot}/session/${id}`;
  const claim = await request(`${path}/claim`, {
    method: "POST",
    headers: { "X-Write-Token": writeToken }
  }, index);
  if (claim.status !== 201) throw new Error(`claim:${claim.status}`);
  const claimReceipt = await claim.json();
  if (claimReceipt.status !== "claimed" || !/^[A-Za-z0-9_-]{43}$/u.test(claimReceipt.claimToken ?? "")) throw new Error("claim:invalid_body");
  const duplicateClaim = await request(`${path}/claim`, {
    method: "POST",
    headers: { "X-Write-Token": writeToken }
  }, index);
  if (duplicateClaim.status !== 409) throw new Error(`duplicate_claim:${duplicateClaim.status}`);
  const envelope = {
    v: 5,
    phonePublicKey: token(65),
    nonce: token(12),
    ciphertext: token(64)
  };
  const submit = await request(`${path}/payload`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Write-Token": writeToken, "X-Claim-Token": claimReceipt.claimToken },
    body: JSON.stringify(envelope)
  }, index);
  if (submit.status !== 202 || (await submit.json()).status !== "accepted") throw new Error(`submit:${submit.status}`);
  const consume = await request(`${path}/events`, { headers: { "X-Read-Token": readToken } }, index);
  if (consume.status !== 200 || !(await consume.text()).includes(envelope.ciphertext)) throw new Error(`consume:${consume.status}`);
  const replay = await request(`${path}/payload`, {
    method: "PUT",
    headers: { "Content-Type": "application/json", "X-Write-Token": writeToken, "X-Claim-Token": claimReceipt.claimToken },
    body: JSON.stringify(envelope)
  }, index);
  if (replay.status !== 409) throw new Error(`replay:${replay.status}`);
  samples.push(performance.now() - started);
}

async function worker() {
  while (true) {
    const index = cursor;
    cursor += 1;
    if (index >= total) return;
    try {
      await flow(index);
    } catch (error) {
      failures.push({ index, error: error instanceof Error ? error.message : "unknown" });
    }
  }
}

const runStarted = performance.now();
await Promise.all(Array.from({ length: concurrency }, () => worker()));
samples.sort((a, b) => a - b);
const elapsed = performance.now() - runStarted;
const evidence = {
  status: failures.length === 0 ? "pass" : "fail",
  target: parsedTarget.origin,
  transactions: total,
  concurrency,
  failures: failures.slice(0, 20),
  elapsedMilliseconds: elapsed,
  transactionsPerSecond: total / (elapsed / 1_000),
  transactionMilliseconds: {
    p50: percentile(samples, 0.5),
    p95: percentile(samples, 0.95),
    p99: percentile(samples, 0.99),
    maximum: samples.at(-1) ?? 0
  }
};
process.stdout.write(`${JSON.stringify(evidence, null, 2)}\n`);
if (failures.length) process.exitCode = 1;
