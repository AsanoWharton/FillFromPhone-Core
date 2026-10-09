import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { getFips, randomBytes } from "node:crypto";
import { realpathSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { fileURLToPath } from "node:url";
import { loadConfig, type Config } from "./config.js";
import { SessionStore, StoreError, type Envelope } from "./store.js";

const JSON_LIMIT = 96_000;
const SESSION_PATH = /^\/v1\/([BG])\/session\/([A-Za-z0-9_-]{43})(?:\/(claim|payload|events))?$/;
const TRANSFER_PATH = /^\/t\/[A-Za-z0-9_-]{43}$/;

class RateLimiter {
  readonly #buckets = new Map<string, { start: number; count: number }>();
  allow(key: string, limit: number): boolean {
    const now = Date.now();
    if (this.#buckets.size > 10_000) {
      for (const [candidate, bucket] of this.#buckets) {
        if (now - bucket.start >= 60_000) this.#buckets.delete(candidate);
      }
    }
    if (this.#buckets.size >= 20_000 && !this.#buckets.has(key)) key = "overflow";
    const bucket = this.#buckets.get(key);
    if (!bucket || now - bucket.start >= 60_000) {
      this.#buckets.set(key, { start: now, count: 1 });
      return true;
    }
    bucket.count += 1;
    return bucket.count <= limit;
  }
}

function securityHeaders(res: ServerResponse): void {
  res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'none'; script-src-attr 'none'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; worker-src 'none'; manifest-src 'none'; media-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "accelerometer=(), browsing-topics=(), camera=(), display-capture=(), fullscreen=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), publickey-credentials-create=(), publickey-credentials-get=(), usb=(), clipboard-read=(self), clipboard-write=(self)");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
  res.setHeader("Origin-Agent-Cluster", "?1");
  res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  // no-transform prevents CDN security products from injecting script into the cryptographic endpoint.
  res.setHeader("Cache-Control", "no-store, no-transform, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Vary", "Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site");
}

function documentCsp(nonce: string): string {
  return `default-src 'none'; script-src 'nonce-${nonce}' 'strict-dynamic'; script-src-attr 'none'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; worker-src 'none'; manifest-src 'none'; media-src 'none'; require-trusted-types-for 'script'; trusted-types 'none'`;
}

function sendHtml(res: ServerResponse, method: string, source: Buffer): void {
  const nonce = randomBytes(18).toString("base64url");
  const body = Buffer.from(source.toString("utf8").replace(/<script(?=\s|>)/gu, `<script nonce="${nonce}"`), "utf8");
  res.setHeader("Content-Security-Policy", documentCsp(nonce));
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": body.length });
  res.end(method === "HEAD" ? undefined : body);
}

function appendVary(res: ServerResponse, value: string): void {
  const current = String(res.getHeader("Vary") ?? "").split(",").map((item) => item.trim()).filter(Boolean);
  if (!current.some((item) => item.toLowerCase() === value.toLowerCase())) current.push(value);
  res.setHeader("Vary", current.join(", "));
}

function requestServiceOrigin(req: IncomingMessage, config: Config): string | undefined {
  const host = req.headers.host?.toLowerCase();
  if (!host) return undefined;
  if (host === new URL(config.publicOrigin).host) return config.publicOrigin;
  if (config.developmentOrigin && host === new URL(config.developmentOrigin).host) return config.developmentOrigin;
  return undefined;
}

function isAllowedOrigin(origin: string, serviceOrigin: string, config: Config): boolean {
  if (origin === serviceOrigin) return true;
  const match = /^chrome-extension:\/\/([a-p]{32})$/.exec(origin);
  if (!match) return false;
  if (serviceOrigin === config.developmentOrigin) return config.developmentExtensionIds?.has(match[1] as string) ?? false;
  return !config.allowedExtensionIds?.size || config.allowedExtensionIds.has(match[1] as string);
}

function cors(req: IncomingMessage, res: ServerResponse, serviceOrigin: string, config: Config): boolean {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (!isAllowedOrigin(origin, serviceOrigin, config)) return false;
  res.setHeader("Access-Control-Allow-Origin", origin);
  appendVary(res, "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST, PUT, GET, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Read-Token, X-Write-Token, X-Claim-Token");
  res.setHeader("Access-Control-Max-Age", "600");
  return true;
}

function fetchMetadataAllowed(req: IncomingMessage, path: string, serviceOrigin: string, config: Config): boolean {
  if (!path.startsWith("/v1/")) return true;
  const origin = req.headers.origin;
  if (origin && isAllowedOrigin(origin, serviceOrigin, config)) return true;
  const site = req.headers["sec-fetch-site"];
  if (site === undefined) return true;
  if (site !== "same-origin") return false;
  const destination = req.headers["sec-fetch-dest"];
  return destination === undefined || destination === "empty";
}

function clientKey(req: IncomingMessage, config: Config): string {
  if (config.trustProxy) {
    const cloudflare = req.headers["cf-connecting-ip"];
    if (typeof cloudflare === "string" && isIP(cloudflare.trim())) return cloudflare.trim();
    const forwarded = req.headers["x-forwarded-for"];
    const candidate = typeof forwarded === "string" ? forwarded.split(",", 1)[0]?.trim() : undefined;
    if (candidate && isIP(candidate)) return candidate;
  }
  return req.socket.remoteAddress ?? "unknown";
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const contentType = req.headers["content-type"]?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") throw new StoreError(415, "unsupported_media_type");
  const declared = Number(req.headers["content-length"] ?? 0);
  if (declared > JSON_LIMIT) throw new StoreError(413, "body_too_large");
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of req) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > JSON_LIMIT) throw new StoreError(413, "body_too_large");
    chunks.push(bytes);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new StoreError(400, "invalid_json");
  }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new StoreError(400, "invalid_request");
  return value as Record<string, unknown>;
}

function requiredString(value: unknown, max: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > max) throw new StoreError(400, "invalid_request");
  return value;
}

function requireExactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (actual.length !== required.length || actual.some((key, index) => key !== required[index])) {
    throw new StoreError(400, "invalid_request");
  }
}

function parseEnvelope(value: unknown): Envelope {
  const body = object(value);
  requireExactKeys(body, ["v", "phonePublicKey", "nonce", "ciphertext"]);
  if (body.v !== 5) throw new StoreError(400, "invalid_payload");
  const phonePublicKey = requiredString(body.phonePublicKey, 87);
  const nonce = requiredString(body.nonce, 16);
  const ciphertext = requiredString(body.ciphertext, 90_000);
  if (!/^[A-Za-z0-9_-]{87}$/.test(phonePublicKey) || !/^[A-Za-z0-9_-]{16}$/.test(nonce) || !/^[A-Za-z0-9_-]+$/.test(ciphertext)) {
    throw new StoreError(400, "invalid_payload");
  }
  return { v: body.v, phonePublicKey, nonce, ciphertext };
}

function json(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  const encoded = JSON.stringify(body);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Content-Length": Buffer.byteLength(encoded) });
  res.end(encoded);
}

function token(req: IncomingMessage, name: "x-read-token" | "x-write-token" | "x-claim-token"): string {
  const value = req.headers[name];
  if (typeof value !== "string") throw new StoreError(403, "forbidden");
  return value;
}

function enforceRateLimit(limiter: RateLimiter, res: ServerResponse, key: string, scope: string, limit: number): void {
  if (limiter.allow(`${key}:${scope}`, limit)) return;
  res.setHeader("Retry-After", "60");
  throw new StoreError(429, "rate_limited");
}

export function createApp(config: Config = loadConfig()): ReturnType<typeof createServer> {
  if (config.requireFips && getFips() !== 1) throw new Error("FIPS mode is required but the active Node.js cryptographic module is not in FIPS mode");
  const store = new SessionStore(config.maxActiveSessions);
  const limiter = new RateLimiter();
  const publicRoot = fileURLToPath(new URL("./public/", import.meta.url));

  const server = createServer(async (req, res) => {
    securityHeaders(res);
    const method = req.method ?? "GET";
    let path: string;
    try {
      path = new URL(req.url ?? "/", "http://service.invalid").pathname;
    } catch {
      return json(res, 400, { error: "invalid_request" });
    }
    if (!["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"].includes(method)) {
      res.setHeader("Allow", "GET, HEAD, POST, PUT, DELETE, OPTIONS");
      return json(res, 405, { error: "method_not_allowed" });
    }
    if (req.headers.expect !== undefined) return json(res, 417, { error: "expectation_failed" });
    const requestedServiceOrigin = requestServiceOrigin(req, config);
    if (config.trustProxy && !requestedServiceOrigin) {
      return json(res, 421, { error: "misdirected_request" });
    }
    const serviceOrigin = requestedServiceOrigin ?? config.publicOrigin;
    if (serviceOrigin === config.developmentOrigin) {
      res.setHeader("X-Robots-Tag", "noindex, nofollow, noarchive");
    }
    const key = clientKey(req, config);
    if (!limiter.allow(`${key}:all`, 900)) {
      res.setHeader("Retry-After", "60");
      return json(res, 429, { error: "rate_limited" });
    }
    if (req.method === "OPTIONS" && !limiter.allow(`${key}:preflight`, 300)) {
      res.setHeader("Retry-After", "60");
      return json(res, 429, { error: "rate_limited" });
    }
    if (!fetchMetadataAllowed(req, path, serviceOrigin, config)) return json(res, 403, { error: "cross_site_forbidden" });
    if (!cors(req, res, serviceOrigin, config)) return json(res, 403, { error: "origin_forbidden" });
    if (req.method === "OPTIONS") return res.writeHead(204).end();

    try {
      if (method === "GET" && path === "/api/health/live") return json(res, 200, { status: "ok" });
      if (method === "GET" && path === "/api/health/ready") return json(res, 200, { status: "ready" });

      if (method === "POST" && path === "/v1/session") {
        enforceRateLimit(limiter, res, key, "reserve", 20);
        const body = object(await readJson(req));
        requireExactKeys(body, ["id", "expiresAt", "writeTokenHash", "readTokenHash"]);
        const id = requiredString(body.id, 43);
        store.reserve(
          id,
          Number(body.expiresAt),
          requiredString(body.writeTokenHash, 43),
          requiredString(body.readTokenHash, 43)
        );
        return json(res, 201, { status: "reserved", slot: config.slotId ?? "B" });
      }

      const match = SESSION_PATH.exec(path);
      if (match) {
        const requestedSlot = match[1] as "B" | "G";
        if (config.slotId && requestedSlot !== config.slotId) throw new StoreError(421, "misdirected_request");
        const id = match[2] as string;
        const action = match[3];
        if (method === "POST" && action === "claim") {
          enforceRateLimit(limiter, res, key, "claim", 90);
          if (req.headers["transfer-encoding"] || Number(req.headers["content-length"] ?? 0) !== 0) {
            throw new StoreError(400, "invalid_request");
          }
          const claimToken = store.claim(id, token(req, "x-write-token"));
          return json(res, 201, { status: "claimed", claimToken });
        }
        if (method === "PUT" && action === "payload") {
          enforceRateLimit(limiter, res, key, "payload", 90);
          const status = store.put(id, token(req, "x-write-token"), token(req, "x-claim-token"), parseEnvelope(await readJson(req)));
          return json(res, 202, { status });
        }
        if (method === "GET" && action === "events") {
          enforceRateLimit(limiter, res, key, "events", 120);
          const unsubscribe = store.subscribe(id, token(req, "x-read-token"), (delivery) => {
            if (delivery.type === "claimed") res.write("event: claimed\ndata: {}\n\n");
            else if (delivery.type === "payload") res.end(`event: payload\ndata: ${JSON.stringify(delivery.envelope)}\n\n`);
            else res.end("event: expired\ndata: {}\n\n");
          });
          res.writeHead(200, {
            "Content-Type": "text/event-stream; charset=utf-8",
            "Cache-Control": "no-store, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
          });
          res.write(": connected\n\n");
          req.on("close", unsubscribe);
          return;
        }
        if (method === "DELETE" && action === undefined) {
          enforceRateLimit(limiter, res, key, "cancel", 90);
          store.cancel(id, token(req, "x-read-token"));
          return res.writeHead(204).end();
        }
      }

      if ((method === "GET" || method === "HEAD") && TRANSFER_PATH.test(path)) {
        const body = await readFile(`${publicRoot}mobile.html`);
        return sendHtml(res, method, body);
      }
      if ((method === "GET" || method === "HEAD") && path === "/assets/app.js") {
        const body = await readFile(`${publicRoot}assets/app.js`);
        res.writeHead(200, { "Content-Type": "text/javascript; charset=utf-8", "Content-Length": body.length });
        return res.end(method === "HEAD" ? undefined : body);
      }
      if ((method === "GET" || method === "HEAD") && path === "/assets/styles.css") {
        const body = await readFile(`${publicRoot}assets/styles.css`);
        res.writeHead(200, { "Content-Type": "text/css; charset=utf-8", "Content-Length": body.length });
        return res.end(method === "HEAD" ? undefined : body);
      }
      if ((method === "GET" || method === "HEAD") && path === "/assets/header.css") {
        const body = await readFile(`${publicRoot}assets/header.css`);
        res.writeHead(200, { "Content-Type": "text/css; charset=utf-8", "Content-Length": body.length });
        return res.end(method === "HEAD" ? undefined : body);
      }
      const fontRoutes: Record<string, string> = {
        "/assets/space-grotesk-400.woff2": "space-grotesk-400.woff2",
        "/assets/space-grotesk-500.woff2": "space-grotesk-500.woff2",
        "/assets/space-grotesk-700.woff2": "space-grotesk-700.woff2",
        "/assets/sora-700.woff2": "sora-700.woff2"
      };
      if ((method === "GET" || method === "HEAD") && fontRoutes[path]) {
        const body = await readFile(`${publicRoot}assets/${fontRoutes[path]}`);
        res.writeHead(200, { "Content-Type": "font/woff2", "Content-Length": body.length, "Cache-Control": "public, max-age=31536000, immutable" });
        return res.end(method === "HEAD" ? undefined : body);
      }
      const svgRoutes: Record<string, string> = { "/assets/eye.svg": "eye.svg", "/assets/eye-slash.svg": "eye-slash.svg" };
      if ((method === "GET" || method === "HEAD") && svgRoutes[path]) {
        const body = await readFile(`${publicRoot}assets/${svgRoutes[path]}`);
        res.writeHead(200, { "Content-Type": "image/svg+xml", "Content-Length": body.length, "Cache-Control": "public, max-age=31536000, immutable" });
        return res.end(method === "HEAD" ? undefined : body);
      }
      if ((method === "GET" || method === "HEAD") && path === "/favicon.png") {
        const body = await readFile(`${publicRoot}favicon.png`);
        res.writeHead(200, { "Content-Type": "image/png", "Content-Length": body.length, "Cache-Control": "public, max-age=31536000, immutable" });
        return res.end(method === "HEAD" ? undefined : body);
      }
      if ((method === "GET" || method === "HEAD") && path === "/.well-known/security.txt") {
        const body = await readFile(`${publicRoot}security.txt`);
        res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8", "Content-Length": body.length });
        return res.end(method === "HEAD" ? undefined : body);
      }
      return json(res, 404, { error: "not_found" });
    } catch (error) {
      if (res.headersSent) return res.end();
      if (error instanceof StoreError) return json(res, error.status, { error: error.code });
      return json(res, 500, { error: "internal_error" });
    }
  });

  server.on("close", () => store.close());
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxHeadersCount = 32;
  server.maxRequestsPerSocket = 100;
  return server;
}

if (process.argv[1] && realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])) {
  const config = loadConfig();
  const server = createApp(config);
  server.listen(config.port, config.host, () => {
    // Startup metadata contains no transaction or user data.
    process.stdout.write(`remote-fill listening on ${config.host}:${config.port}\n`);
  });
  const shutdown = (): void => {
    server.close(() => process.exit(0));
  };
  process.once("SIGTERM", shutdown);
  process.once("SIGINT", shutdown);
}
