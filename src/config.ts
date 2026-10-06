/** Runtime configuration is deliberately small; the service has no application secrets. */
export interface Config {
  host: string;
  port: number;
  publicOrigin: string;
  trustProxy: boolean;
  maxActiveSessions: number;
  requireFips?: boolean;
  allowedExtensionIds?: ReadonlySet<string>;
  /** One-character deployment slot discriminator embedded into every assigned session ID. */
  slotId?: "B" | "G";
}

function integer(name: string, fallback: number, min: number, max: number): number {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`invalid ${name}`);
  }
  return value;
}

function boolean(name: string, fallback: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`invalid ${name}`);
}

export function loadConfig(): Config {
  const publicOrigin = process.env.PUBLIC_ORIGIN ?? "https://fillfromphone.com";
  const parsed = new URL(publicOrigin);
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    throw new Error("invalid PUBLIC_ORIGIN");
  }
  if (parsed.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) {
    throw new Error("PUBLIC_ORIGIN must use HTTPS outside localhost");
  }
  const extensionIds = (process.env.ALLOWED_EXTENSION_IDS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (extensionIds.some((value) => !/^[a-p]{32}$/.test(value))) throw new Error("invalid ALLOWED_EXTENSION_IDS");
  const slotId = process.env.SLOT_ID;
  if (slotId !== undefined && slotId !== "B" && slotId !== "G") throw new Error("invalid SLOT_ID");
  return {
    host: process.env.HOST ?? "127.0.0.1",
    port: integer("PORT", 8787, 1, 65535),
    publicOrigin: parsed.origin,
    trustProxy: boolean("TRUST_PROXY", false),
    maxActiveSessions: integer("MAX_ACTIVE_SESSIONS", 10_000, 1, 100_000),
    requireFips: boolean("REQUIRE_FIPS", false),
    allowedExtensionIds: new Set(extensionIds),
    ...(slotId === undefined ? {} : { slotId })
  };
}
