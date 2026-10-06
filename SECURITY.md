# Security policy and boundary

The phone browser and Chrome extension are encryption endpoints. The relay and network are treated as untrusted for content confidentiality. TLS remains mandatory for code integrity and metadata protection, while application-layer encryption prevents the relay from reading transferred text.

The defensible property is relay opacity: accepted request schemas and runtime data flow do not provide the relay with the endpoint private keys, complete authenticated context, or plaintext needed to derive the content key. This is not a formal zero-knowledge proof protocol. Compromised endpoints, hostile destination pages, keyloggers, screen capture, and maliciously replaced mobile code are outside this guarantee.

Browser strings, garbage collection, rendering internals, and operating-system memory also prevent a claim of physical erasure. The implementation clears visible controls, overwrites mutable byte buffers where practical, releases references, and intentionally persists no transferred plaintext.

Report vulnerabilities without real credentials, keys, capability tokens, complete QR payloads, or transferred values. Use synthetic data and the contact published in `src/security.txt`.
