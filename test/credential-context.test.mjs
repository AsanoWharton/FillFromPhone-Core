import assert from "node:assert/strict";
import test from "node:test";
import { credentialProviderContext } from "../src/mobile/credential-context.ts";

test("password context is minimal, advisory, and requires user mediation", () => {
  const context = credentialProviderContext("https://accounts.example.com", "password");
  assert.deepEqual(context, {
    version: 1,
    purpose: "select-existing-credential",
    claimedOrigin: "https://accounts.example.com",
    credentialKind: "password",
    authority: "advisory",
    mediation: "required"
  });
  assert.deepEqual(Object.keys(context).sort(), ["authority", "claimedOrigin", "credentialKind", "mediation", "purpose", "version"]);
  assert.equal(Object.isFrozen(context), true);
});

test("context is absent for non-password fields and rejects unsafe origins", () => {
  assert.equal(credentialProviderContext("https://accounts.example.com", "short-text"), undefined);
  assert.equal(credentialProviderContext("https://accounts.example.com", "long-text"), undefined);
  assert.equal(credentialProviderContext("http://localhost:8080", "password"), undefined);
  assert.throws(() => credentialProviderContext("http://accounts.example.com", "password"), /invalid credential context origin/u);
  assert.throws(() => credentialProviderContext("https://accounts.example.com/login", "password"), /invalid credential context origin/u);
});
