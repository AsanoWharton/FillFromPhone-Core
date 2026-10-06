# Fill from Phone Core

This is the primary technical repository for Fill from Phone. It contains the memory-only relay, the phone data-entry endpoint, the protocol boundary, and the tests that enforce single-use delivery. The product connects one phone browser to one explicitly selected browser field without an account, a paired device, clipboard synchronization, or a durable credential store.

The Chrome receiver is maintained in `FillFromPhone-Extension`. Marketing, privacy, and support pages are maintained in `FillFromPhone-Site`. Those separations keep the security-critical data path small enough to inspect directly.

## Security properties implemented here

- Relay request schemas exclude plaintext, destination origin, field classification, desktop public key, and QR challenge.
- A fresh 256-bit non-authorizing transaction identifier and independent read/write capabilities are used for every transfer.
- The first scanner atomically exchanges the write capability for a separate 256-bit claim capability; subsequent claims fail.
- Only a correctly claimed mailbox accepts an encrypted envelope, and consumption leaves a short-lived tombstone that rejects replay.
- Payload state is held in process memory and expires after 120 seconds. No account, recovery path, or durable payload database exists.
- The phone performs ephemeral P-256 ECDH, HKDF-SHA-256, and AES-256-GCM in its browser. The relay has no decryption path.
- The mobile endpoint has a restrictive CSP, no analytics, no cookies, no storage API, and no remote scripts.

These are narrow, testable code properties—not a claim that a browser, runtime, deployment, or organization is FIPS validated, FedRAMP authorized, or otherwise certified.

## Verify locally

Node.js 24 or later is required.

```bash
npm ci
npm run check
npm audit --audit-level=high
```

For an isolated local run:

```bash
PUBLIC_ORIGIN=http://127.0.0.1:8787 npm start
```

The relay listens on `127.0.0.1:8787` by default. Environment names and non-secret example values are documented in `.env.example`. No production topology, host identity, credential, tunnel identifier, or deployment record is included in this repository.

## Repository status

The source is publicly reviewable but proprietary. Public access does not grant permission to copy, modify, redistribute, sublicense, create derivative works, or use the product commercially. See `PROPRIETARY-NOTICE.md`.
