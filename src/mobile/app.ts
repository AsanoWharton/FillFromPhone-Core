import { credentialProviderContext } from "./credential-context.js";

const MAX_PLAINTEXT_BYTES = 65_536;
const INFO_V5 = new TextEncoder().encode("fill-from-phone/aes-gcm/v5");
type FieldKind = "short-text" | "long-text" | "password";
const CREDENTIAL_CONTEXT_META_NAME = "fillfromphone-credential-context";

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

interface Bootstrap {
  v: 5;
  slot: "B" | "G";
  id: string;
  publicKey: string;
  challenge: string;
  expiresAt: number;
  origin: string;
  writeToken: string;
  fieldKind: FieldKind;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function base64UrlToBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new Error("invalid bootstrap");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function validToken(value: unknown, length: number): value is string {
  return typeof value === "string" && value.length === length && /^[A-Za-z0-9_-]+$/u.test(value);
}

function parseBootstrap(): Bootstrap {
  const encoded = location.hash.slice(1);
  const route = location.pathname;
  history.replaceState(null, "", "/");
  if (!encoded || encoded.length > 2_048) throw new Error("missing bootstrap");
  const raw = new TextDecoder("utf-8", { fatal: true }).decode(base64UrlToBytes(encoded));
  const value = JSON.parse(raw) as Partial<Bootstrap>;
  if (
    value.v !== 5 || (value.slot !== "B" && value.slot !== "G") || !validToken(value.id, 43) || !validToken(value.publicKey, 87) ||
    !validToken(value.challenge, 22) || !validToken(value.writeToken, 43) ||
    !Number.isSafeInteger(value.expiresAt) || (value.expiresAt as number) <= Date.now() ||
    (value.expiresAt as number) > Date.now() + 120_000 || typeof value.origin !== "string" ||
    value.fieldKind !== "short-text" && value.fieldKind !== "long-text" && value.fieldKind !== "password"
  ) throw new Error("invalid bootstrap");
  const origin = new URL(value.origin);
  const localDevelopment = origin.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(origin.hostname);
  if (origin.origin !== value.origin || (origin.protocol !== "https:" && !localDevelopment)) throw new Error("invalid origin");
  if (route !== `/t/${value.id}`) throw new Error("invalid transfer route");
  return value as Bootstrap;
}

function aadFor(bootstrap: Bootstrap): Uint8Array {
  const context: Array<string | number> = [bootstrap.v, bootstrap.slot, bootstrap.id, bootstrap.challenge, bootstrap.expiresAt, bootstrap.origin];
  context.push(bootstrap.fieldKind);
  return new TextEncoder().encode(JSON.stringify(context));
}

async function encrypt(bootstrap: Bootstrap, plaintext: Uint8Array): Promise<Record<string, string | number>> {
  const algorithm = { name: "ECDH", namedCurve: "P-256" };
  const desktopPublicKey = await crypto.subtle.importKey("raw", arrayBuffer(base64UrlToBytes(bootstrap.publicKey)), algorithm, false, []);
  const phoneKeys = await crypto.subtle.generateKey(algorithm, false, ["deriveBits"]) as CryptoKeyPair;
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: algorithm.name, public: desktopPublicKey }, phoneKeys.privateKey, 256));
  const aad = aadFor(bootstrap);
  const salt = await crypto.subtle.digest("SHA-256", arrayBuffer(aad));
  const hkdfKey = await crypto.subtle.importKey("raw", arrayBuffer(shared), "HKDF", false, ["deriveKey"]);
  shared.fill(0);
  const encryptionKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info: arrayBuffer(INFO_V5) },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: arrayBuffer(nonce), additionalData: arrayBuffer(aad) }, encryptionKey, arrayBuffer(plaintext)));
  const phonePublicKey = new Uint8Array(await crypto.subtle.exportKey("raw", phoneKeys.publicKey));
  const envelope = { v: bootstrap.v, phonePublicKey: bytesToBase64Url(phonePublicKey), nonce: bytesToBase64Url(nonce), ciphertext: bytesToBase64Url(ciphertext) };
  phonePublicKey.fill(0);
  nonce.fill(0);
  ciphertext.fill(0);
  return envelope;
}

function showResult(title: string, copy: string): void {
  clearCredentialProviderContext();
  document.querySelector<HTMLElement>("#loading")!.hidden = true;
  document.querySelector<HTMLElement>("#send-panel")!.hidden = true;
  document.querySelector<HTMLElement>("#result")!.hidden = false;
  document.querySelector<HTMLElement>("#result-title")!.textContent = title;
  document.querySelector<HTMLElement>("#result-copy")!.textContent = copy;
}

function clearCredentialProviderContext(): void {
  document.querySelector<HTMLMetaElement>(`meta[name="${CREDENTIAL_CONTEXT_META_NAME}"]`)?.remove();
  const input = document.querySelector<HTMLInputElement>("#password-value");
  if (!input) return;
  delete input.dataset.ffpClaimedOrigin;
  delete input.dataset.ffpCredentialKind;
  delete input.dataset.ffpAuthority;
  delete input.dataset.ffpMediation;
}

function publishCredentialProviderContext(bootstrap: Bootstrap, input: HTMLInputElement): void {
  clearCredentialProviderContext();
  const context = credentialProviderContext(bootstrap.origin, bootstrap.fieldKind);
  if (!context) return;
  const metadata = document.createElement("meta");
  metadata.name = CREDENTIAL_CONTEXT_META_NAME;
  metadata.content = JSON.stringify(context);
  document.head.append(metadata);
  input.dataset.ffpClaimedOrigin = context.claimedOrigin;
  input.dataset.ffpCredentialKind = context.credentialKind;
  input.dataset.ffpAuthority = context.authority;
  input.dataset.ffpMediation = context.mediation;
}

function closeAndClear(): void {
  clearCredentialProviderContext();
  document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input, textarea").forEach((control) => { control.value = ""; });
  history.replaceState(null, "", "/");
  window.close();
  window.setTimeout(() => location.replace("about:blank"), 100);
}

document.querySelector<HTMLButtonElement>("#close-page")!.addEventListener("click", closeAndClear);

async function start(): Promise<void> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Cryptography is unavailable");
  const bootstrap = parseBootstrap();
  const claimResponse = await fetch(`/v1/${bootstrap.slot}/session/${bootstrap.id}/claim`, {
    method: "POST",
    cache: "no-store",
    credentials: "omit",
    referrerPolicy: "no-referrer",
    headers: { "X-Write-Token": bootstrap.writeToken }
  });
  if (claimResponse.status === 409) {
    showResult("Already scanned", "This one-time QR code was already claimed. Start a new transfer from the computer.");
    return;
  }
  if (claimResponse.status !== 201) throw new Error("claim rejected");
  const claimReceipt = await claimResponse.json() as { status?: string; claimToken?: string };
  if (claimReceipt.status !== "claimed" || !validToken(claimReceipt.claimToken, 43)) throw new Error("invalid claim receipt");
  const claimToken = claimReceipt.claimToken;
  const panel = document.querySelector<HTMLElement>("#send-panel")!;
  const shortInput = document.querySelector<HTMLInputElement>("#short-value")!;
  const longTextarea = document.querySelector<HTMLTextAreaElement>("#long-value")!;
  const passwordInput = document.querySelector<HTMLInputElement>("#password-value")!;
  const passwordControl = document.querySelector<HTMLElement>("#password-control")!;
  const visibilityButton = document.querySelector<HTMLButtonElement>("#password-visibility")!;
  const visibilityLabel = document.querySelector<HTMLElement>("#password-visibility-label")!;
  const showIcon = document.querySelector<HTMLImageElement>("#password-visibility-show-icon")!;
  const hideIcon = document.querySelector<HTMLImageElement>("#password-visibility-hide-icon")!;
  const button = document.querySelector<HTMLButtonElement>("#send")!;
  const passwordMode = bootstrap.fieldKind === "password";
  const longTextMode = bootstrap.fieldKind === "long-text";
  const valueControl: HTMLTextAreaElement | HTMLInputElement = passwordMode ? passwordInput : longTextMode ? longTextarea : shortInput;
  publishCredentialProviderContext(bootstrap, passwordInput);
  document.querySelector<HTMLElement>("#destination")!.textContent = new URL(bootstrap.origin).host;
  document.querySelector<HTMLElement>("#transfer-kind")!.textContent = passwordMode ? "Password transfer" : longTextMode ? "Long text transfer" : "Short text transfer";
  document.querySelector<HTMLLabelElement>("#value-label")!.htmlFor = passwordMode ? "password-value" : longTextMode ? "long-value" : "short-value";
  document.querySelector<HTMLLabelElement>("#value-label")!.textContent = passwordMode ? "Choose or enter a password" : longTextMode ? "Enter or paste long text" : "Enter or paste short text";
  document.querySelector<HTMLElement>("#password-guidance")!.hidden = !passwordMode;
  document.querySelector<HTMLElement>("#assurance")!.textContent = passwordMode
    ? "Masked, encrypted end-to-end, and cleared immediately by Fill from Phone. Your browser or password manager controls its own storage."
    : "Encrypted end-to-end. Nothing is saved by Fill from Phone.";
  shortInput.hidden = passwordMode || longTextMode;
  longTextarea.hidden = !longTextMode;
  passwordControl.hidden = !passwordMode;
  document.querySelector<HTMLElement>("#loading")!.hidden = true;
  panel.hidden = false;
  valueControl.focus();

  let remaskTimer: number | undefined;
  const remask = (): void => {
    if (!passwordMode) return;
    if (remaskTimer !== undefined) window.clearTimeout(remaskTimer);
    passwordInput.type = "password";
    visibilityButton.setAttribute("aria-pressed", "false");
    visibilityButton.setAttribute("aria-label", "Show password");
    visibilityLabel.textContent = "Show";
    showIcon.hidden = false;
    hideIcon.hidden = true;
  };
  visibilityButton.addEventListener("click", () => {
    if (passwordInput.type === "password") {
      passwordInput.type = "text";
      visibilityButton.setAttribute("aria-pressed", "true");
      visibilityButton.setAttribute("aria-label", "Hide password");
      visibilityLabel.textContent = "Hide";
      showIcon.hidden = true;
      hideIcon.hidden = false;
      remaskTimer = window.setTimeout(remask, 10_000);
    } else {
      remask();
    }
    passwordInput.focus();
  });
  window.addEventListener("blur", remask);
  document.addEventListener("visibilitychange", () => { if (document.hidden) remask(); });

  const expirationTimer = window.setTimeout(() => showResult("Expired", "Start a new transfer from the computer."), Math.max(0, bootstrap.expiresAt - Date.now()));
  button.addEventListener("click", async () => {
    if (Date.now() >= bootstrap.expiresAt) return showResult("Expired", "Start a new transfer from the computer.");
    button.disabled = true;
    const plaintext = new TextEncoder().encode(valueControl.value);
    valueControl.value = "";
    remask();
    if (plaintext.length === 0 || plaintext.length > MAX_PLAINTEXT_BYTES) {
      plaintext.fill(0);
      button.disabled = false;
      return showResult("Not sent", plaintext.length === 0 ? "Enter text and try again." : "The text is too large for one transfer.");
    }
    try {
      const envelope = await encrypt(bootstrap, plaintext);
      plaintext.fill(0);
      const response = await fetch(`/v1/${bootstrap.slot}/session/${bootstrap.id}/payload`, {
        method: "PUT",
        cache: "no-store",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: { "Content-Type": "application/json", "X-Write-Token": bootstrap.writeToken, "X-Claim-Token": claimToken },
        body: JSON.stringify(envelope)
      });
      if (!response.ok) throw new Error("relay rejected payload");
      const receipt = await response.json() as { status?: string };
      window.clearTimeout(expirationTimer);
      showResult(
        "Transfer complete",
        receipt.status === "delivered"
          ? "The relay reports that its one-time envelope was delivered and removed from the active mailbox."
          : "The encrypted envelope was accepted for one-time delivery and will be removed after delivery or expiration."
      );
      document.querySelector<HTMLElement>("#destruction-receipt")!.hidden = false;
    } catch {
      plaintext.fill(0);
      showResult("Not sent", "The transfer failed. Start a new transfer from the computer.");
    }
  }, { once: true });
}

start().catch(() => showResult("Cannot open transfer", "Start a new transfer from the computer and scan its QR code."));
