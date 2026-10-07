import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";
import { createApp } from "../dist/server.js";

async function runningApp(context) {
  const app = createApp({
    host: "127.0.0.1",
    port: 0,
    publicOrigin: "http://127.0.0.1",
    trustProxy: false,
    maxActiveSessions: 20,
    slotId: "B"
  });
  app.listen(0, "127.0.0.1");
  await once(app, "listening");
  context.after(() => app.close());
  const address = app.address();
  assert.ok(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;
  return { origin, config: app };
}

test("document delivery is nonce-bound and isolated", async (context) => {
  const { origin } = await runningApp(context);
  const response = await fetch(`${origin}/t/${"A".repeat(43)}`);
  assert.equal(response.status, 200);
  const csp = response.headers.get("content-security-policy") ?? "";
  assert.match(csp, /script-src 'nonce-[A-Za-z0-9_-]+' 'strict-dynamic'/u);
  assert.match(csp, /require-trusted-types-for 'script'/u);
  assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  assert.match(response.headers.get("vary") ?? "", /Sec-Fetch-Site/u);
  assert.match(await response.text(), /<script nonce="[A-Za-z0-9_-]+"/u);
});

test("cross-site API requests and unsupported methods fail before capability processing", async (context) => {
  const { origin } = await runningApp(context);
  const crossSite = await fetch(`${origin}/v1/session`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "sec-fetch-site": "cross-site",
      "sec-fetch-dest": "empty"
    },
    body: "{}"
  });
  assert.equal(crossSite.status, 403);
  assert.deepEqual(await crossSite.json(), { error: "cross_site_forbidden" });

  const unsupported = await fetch(`${origin}/v1/session`, { method: "PATCH" });
  assert.equal(unsupported.status, 405);
  assert.equal(unsupported.headers.get("allow"), "GET, HEAD, POST, PUT, DELETE, OPTIONS");
});
