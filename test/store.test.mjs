import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import test from "node:test";
import { SessionStore, StoreError } from "../dist/store.js";

const token = () => randomBytes(32).toString("base64url");
const sessionId = () => randomBytes(32).toString("base64url");
const hash = (value) => createHash("sha256").update(Buffer.from(value, "base64url")).digest("base64url");
const envelope = { v: 5, phonePublicKey: randomBytes(65).toString("base64url"), nonce: randomBytes(12).toString("base64url"), ciphertext: randomBytes(48).toString("base64url") };

test("a mailbox delivers once and retains a consumed tombstone", async () => {
  let now = 1_000;
  const store = new SessionStore(10, () => now);
  const id = sessionId();
  const read = token();
  const write = token();
  store.reserve(id, now + 120_000, hash(write), hash(read));

  const deliveries = [];
  store.subscribe(id, read, (delivery) => deliveries.push(delivery));
  const claim = store.claim(id, write);
  assert.deepEqual(deliveries, [{ type: "claimed" }]);
  assert.throws(() => store.claim(id, write), (error) => error instanceof StoreError && error.code === "already_claimed");
  assert.equal(store.put(id, write, claim, envelope), "delivered");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(deliveries, [{ type: "claimed" }, { type: "payload", envelope }]);
  assert.throws(() => store.put(id, write, claim, envelope), (error) => error instanceof StoreError && error.code === "already_used");
  assert.throws(() => store.subscribe(id, read, () => {}), (error) => error instanceof StoreError && error.code === "already_used");

  now += 120_001;
  store.cleanup();
  assert.equal(store.size, 0);
  store.close();
});

test("capabilities are required and expiry fails closed", () => {
  let now = 5_000;
  const store = new SessionStore(10, () => now);
  const id = sessionId();
  const read = token();
  const write = token();
  store.reserve(id, now + 10_000, hash(write), hash(read));
  assert.throws(() => store.claim(id, token()), (error) => error instanceof StoreError && error.status === 403);
  now += 10_001;
  assert.throws(() => store.subscribe(id, read, () => {}), (error) => error instanceof StoreError && error.status === 410);
  store.close();
});

test("a payload accepted before subscription is reported and later consumed", async () => {
  const now = 8_000;
  const store = new SessionStore(10, () => now);
  const id = sessionId();
  const read = token();
  const write = token();
  store.reserve(id, now + 120_000, hash(write), hash(read));
  const claim = store.claim(id, write);
  assert.equal(store.put(id, write, claim, envelope), "accepted");
  const delivered = new Promise((resolve) => store.subscribe(id, read, resolve));
  assert.deepEqual(await delivered, { type: "payload", envelope });
  store.close();
});

test("a subscriber joining after the first scan sees the claim before delivery", async () => {
  const now = 12_000;
  const store = new SessionStore(10, () => now);
  const id = sessionId();
  const read = token();
  const write = token();
  store.reserve(id, now + 120_000, hash(write), hash(read));
  const claim = store.claim(id, write);
  const deliveries = [];
  store.subscribe(id, read, (delivery) => deliveries.push(delivery));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(deliveries, [{ type: "claimed" }]);
  assert.equal(store.put(id, write, claim, envelope), "delivered");
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(deliveries, [{ type: "claimed" }, { type: "payload", envelope }]);
  store.close();
});
