# Protocol version 5

The browser extension creates a fresh 256-bit transaction identifier, 256-bit read capability, 256-bit write capability, 128-bit challenge, and ephemeral P-256 ECDH key pair for each transfer. The private key is non-extractable. The relay reservation receives only the identifier, expiry, and SHA-256 hashes of the two capabilities.

The QR contains a URL of this form:

```text
https://fillfromphone.com/t/43_CHARACTER_ID#BASE64URL_BOOTSTRAP
```

The fragment carries protocol version, routing slot, identifier, desktop public key, challenge, expiry, destination origin, write capability, and field class. URL fragments are not sent in HTTP requests. The phone checks that the path identifier matches the fragment and removes both from browser history after parsing.

## Key schedule

Both endpoints compute P-256 ECDH. The 32-byte shared secret becomes HKDF input keying material.

```text
aad  = UTF8(JSON.stringify([5, slot, id, challenge, expiresAt, origin, fieldKind]))
salt = SHA-256(aad)
key  = HKDF-SHA-256(shared_secret, salt, "fill-from-phone/aes-gcm/v5")
```

The phone encrypts UTF-8 plaintext with AES-256-GCM, a fresh 96-bit nonce, and the authenticated additional data above. The relay envelope contains only `v`, `phonePublicKey`, `nonce`, and `ciphertext`. Exact-key schema checks reject added metadata.

## One-time lifecycle

1. The extension reserves a mailbox for at most 120 seconds.
2. It opens an authenticated server-sent event stream with the read capability.
3. The first phone atomically changes `reserved` to `claimed` and receives a new claim capability.
4. Upload requires both the write and claim capabilities.
5. Delivery changes the mailbox to `consumed`, releases the envelope and capability hashes, and retains only an expiry tombstone.
6. Duplicate claims, wrong capabilities, wrong routing slots, and replay are rejected.

The route identifier is lookup metadata, not authorization. A complete QR is a short-lived bearer invitation: an observer can race the intended scanner and cause denial of service or chosen-text injection, although the relay still cannot decrypt a legitimate payload. Preventing that race requires an identity or confirmation ceremony, which this accountless protocol intentionally does not claim.

## Limits

- Transaction lifetime: 120 seconds.
- Maximum UTF-8 plaintext: 65,536 bytes.
- Maximum encoded ciphertext: 90,000 characters.
- One subscriber, one successful claim, one submission, and one delivery per transaction.
- No automatic form submission.
