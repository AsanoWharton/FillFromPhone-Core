import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { once } from "node:events";
import { access, readFile } from "node:fs/promises";
import { request as httpRequest } from "node:http";
import test from "node:test";
import { createApp } from "../dist/server.js";

const token = (bytes = 32) => randomBytes(bytes).toString("base64url");
const hash = (value) => createHash("sha256").update(Buffer.from(value, "base64url")).digest("base64url");

function rawRequest(origin, path, { method = "GET", headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const request = httpRequest(new URL(path, origin), { method, headers }, (response) => {
      response.resume();
      response.once("end", () => resolve({ status: response.statusCode, headers: response.headers }));
    });
    request.once("error", reject);
    request.end();
  });
}

async function runningApp(context) {
  const app = createApp({
    host: "127.0.0.1",
    port: 8787,
    publicOrigin: "https://fillfromphone.com",
    trustProxy: false,
    maxActiveSessions: 100,
    slotId: "B"
  });
  app.listen(0, "127.0.0.1");
  await once(app, "listening");
  context.after(() => app.close());
  const address = app.address();
  assert(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

test("relay assigns a slot, enforces first claim, and rejects replay", async (context) => {
  const origin = await runningApp(context);
  const id = token();
  const readToken = token();
  const writeToken = token();
  const reservation = {
    id,
    expiresAt: Date.now() + 60_000,
    readTokenHash: hash(readToken),
    writeTokenHash: hash(writeToken)
  };

  const reserve = await fetch(`${origin}/v1/session`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(reservation)
  });
  assert.equal(reserve.status, 201);
  assert.deepEqual(await reserve.json(), { status: "reserved", slot: "B" });

  const stream = await fetch(`${origin}/v1/B/session/${id}/events`, {
    headers: { "x-read-token": readToken }
  });
  assert.equal(stream.status, 200);

  const claim = await fetch(`${origin}/v1/B/session/${id}/claim`, {
    method: "POST",
    headers: { "x-write-token": writeToken }
  });
  assert.equal(claim.status, 201);
  const { claimToken } = await claim.json();
  assert.match(claimToken, /^[A-Za-z0-9_-]{43}$/u);

  const duplicate = await fetch(`${origin}/v1/B/session/${id}/claim`, {
    method: "POST",
    headers: { "x-write-token": writeToken }
  });
  assert.equal(duplicate.status, 409);

  const envelope = {
    v: 5,
    phonePublicKey: token(65),
    nonce: token(12),
    ciphertext: token(48)
  };
  const delivery = await fetch(`${origin}/v1/B/session/${id}/payload`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-write-token": writeToken,
      "x-claim-token": claimToken
    },
    body: JSON.stringify(envelope)
  });
  assert.equal(delivery.status, 202);
  assert.deepEqual(await delivery.json(), { status: "delivered" });
  assert.match(await stream.text(), /event: payload/u);

  const replay = await fetch(`${origin}/v1/B/session/${id}/payload`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-write-token": writeToken,
      "x-claim-token": claimToken
    },
    body: JSON.stringify(envelope)
  });
  assert.equal(replay.status, 409);
});

test("public boundary exposes only relay, health, and mobile-entry surfaces", async (context) => {
  const origin = await runningApp(context);
  const id = token();
  const page = await fetch(`${origin}/t/${id}`);
  assert.equal(page.status, 200);
  assert.match(page.headers.get("content-security-policy") ?? "", /default-src 'none'/u);
  assert.match(page.headers.get("cache-control") ?? "", /no-transform/u);
  assert.match(await page.text(), /id="password-value" type="password"/u);
  assert.equal((await fetch(`${origin}/`)).status, 404);
  assert.equal((await fetch(`${origin}/test`)).status, 404);
  assert.equal((await fetch(`${origin}/f`)).status, 404);

  const denied = await fetch(`${origin}/v1/session`, {
    method: "OPTIONS",
    headers: { origin: "https://example.invalid", "access-control-request-method": "POST" }
  });
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.get("access-control-allow-origin"), null);
});

test("relay schemas reject metadata and plaintext fields", async (context) => {
  const origin = await runningApp(context);
  const response = await fetch(`${origin}/v1/session`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      id: token(),
      expiresAt: Date.now() + 60_000,
      readTokenHash: hash(token()),
      writeTokenHash: hash(token()),
      fieldKind: "password"
    })
  });
  assert.equal(response.status, 400);
});

test("public phone entry links to support and publishes the security contact", async () => {
  const mobile = await readFile(new URL("../dist/public/mobile.html", import.meta.url), "utf8");
  const headerStyles = await readFile(new URL("../dist/public/assets/header.css", import.meta.url), "utf8");
  const mobileStyles = await readFile(new URL("../dist/public/assets/styles.css", import.meta.url), "utf8");
  const securityPolicy = await readFile(new URL("../dist/public/security.txt", import.meta.url), "utf8");
  assert.match(headerStyles, /\.site-wordmark \{[^}]*font-family: "Sora", "Space Grotesk", sans-serif;[^}]*font-size-adjust: from-font/u);
  assert.match(mobileStyles, /--accent: #003c71/u);
  assert.match(mobileStyles, /font-family: "Space Grotesk", "Segoe UI", sans-serif/u);
  for (const fontName of ["space-grotesk-400.woff2", "space-grotesk-500.woff2", "space-grotesk-700.woff2", "sora-700.woff2"]) {
    await access(new URL(`../dist/public/assets/${fontName}`, import.meta.url));
  }
  assert.match(mobile, /class="site-wordmark" href="\/"/u);
  assert.match(mobile, /href="\/support">Support<\/a>/u);
  assert.match(mobile, /name="fillfromphone-credential-context-version" content="1"/u);
  assert.match(mobile, /data-ffp-context-version="1"/u);
  assert.match(mobile, /\/assets\/eye\.svg\?v=003c71/u);
  assert.match(mobile, /\/assets\/eye-slash\.svg\?v=003c71/u);
  assert.match(mobile, /<nav aria-label="Legal"><a href="\/privacy">Privacy<\/a><a href="\/privacy#terms">Terms of Service<\/a><\/nav>/u);
  assert.match(mobile, /<p class="footer-copy"><span>&copy; 2026 <a href="https:\/\/fillfromphone\.com">FillFromPhone\.com<\/a>\.<\/span><span>Powered by <a href="https:\/\/asanowharton\.com">Asano Wharton, LLC<\/a>\.<\/span><span>All rights reserved\.<\/span><\/p>/u);
  assert.doesNotMatch(mobile, /site-menu|menu-icon|>Menu</u);
  assert.doesNotMatch(mobile, /href="\/(?:security|cryptography|licenses)"/u);
  const supportRule = headerStyles.match(/\.site-support \{([^}]*)\}/u)?.[1] ?? "";
  assert.doesNotMatch(supportRule, /border|background|min-height/u);
  assert.match(headerStyles, /\.site-support:hover, \.site-support\[aria-current="page"\] \{[^}]*text-decoration: underline/u);
  assert.match(securityPolicy, /^Contact: mailto:contact@asanowharton\.com$/mu);
});

test("development hostname is isolated to its fixed extension identity", async (context) => {
  const developmentId = "b".repeat(32);
  const developmentOrigin = "https://development.example.test";
  const app = createApp({
    host: "127.0.0.1",
    port: 0,
    publicOrigin: "https://fillfromphone.com",
    developmentOrigin,
    developmentExtensionIds: new Set([developmentId]),
    trustProxy: true,
    maxActiveSessions: 10,
    allowedExtensionIds: new Set()
  });
  app.listen(0, "127.0.0.1");
  await once(app, "listening");
  context.after(() => app.close());
  const address = app.address();
  assert(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;
  const host = new URL(developmentOrigin).host;

  const allowed = await rawRequest(origin, "/v1/session", {
    method: "OPTIONS",
    headers: { host, origin: `chrome-extension://${developmentId}` }
  });
  assert.equal(allowed.status, 204);
  assert.equal(allowed.headers["access-control-allow-origin"], `chrome-extension://${developmentId}`);

  const wrongExtension = await rawRequest(origin, "/v1/session", {
    method: "OPTIONS",
    headers: { host, origin: `chrome-extension://${"a".repeat(32)}` }
  });
  assert.equal(wrongExtension.status, 403);

  const crossedWebsiteOrigin = await rawRequest(origin, "/v1/session", {
    method: "OPTIONS",
    headers: { host, origin: "https://fillfromphone.com" }
  });
  assert.equal(crossedWebsiteOrigin.status, 403);

  const developmentPage = await rawRequest(origin, `/t/${token()}`, { headers: { host } });
  assert.equal(developmentPage.status, 200);
  assert.equal(developmentPage.headers["x-robots-tag"], "noindex, nofollow, noarchive");

  const unknownHost = await rawRequest(origin, "/api/health/ready", { headers: { host: "unknown.example" } });
  assert.equal(unknownHost.status, 421);
});
