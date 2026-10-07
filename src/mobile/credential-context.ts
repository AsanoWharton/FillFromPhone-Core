export type CredentialContextFieldKind = "short-text" | "long-text" | "password";

export interface CredentialProviderContext {
  version: 1;
  purpose: "select-existing-credential";
  claimedOrigin: string;
  credentialKind: "password";
  authority: "advisory";
  mediation: "required";
}

// This context is a user-facing search hint, never proof that the claimed origin
// owns the transfer or authority for a provider to release a credential.
export function credentialProviderContext(
  claimedOrigin: string,
  fieldKind: CredentialContextFieldKind
): Readonly<CredentialProviderContext> | undefined {
  if (fieldKind !== "password") return undefined;
  const parsed = new URL(claimedOrigin);
  const localDevelopment = parsed.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
  if (localDevelopment) return undefined;
  if (parsed.origin !== claimedOrigin || parsed.protocol !== "https:") throw new Error("invalid credential context origin");
  return Object.freeze({
    version: 1,
    purpose: "select-existing-credential",
    claimedOrigin,
    credentialKind: "password",
    authority: "advisory",
    mediation: "required"
  });
}
