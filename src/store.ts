import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export const SESSION_TTL_MS = 120_000;
export const TOKEN_BYTES = 32;
export const SESSION_ID_BYTES = 32;

export interface Envelope {
  v: 5;
  phonePublicKey: string;
  nonce: string;
  ciphertext: string;
}

export type Delivery = { type: "claimed" } | { type: "payload"; envelope: Envelope } | { type: "expired" };
export type DeliveryListener = (delivery: Delivery) => void;

interface Session {
  expiresAt: number;
  writeTokenHash: Buffer;
  readTokenHash: Buffer;
  state: "reserved" | "claimed" | "ready" | "consumed";
  claimTokenHash?: Buffer;
  envelope?: Envelope;
  listener?: DeliveryListener;
}

export class StoreError extends Error {
  constructor(public readonly status: number, public readonly code: string) {
    super(code);
  }
}

function decodeHash(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new StoreError(400, "invalid_session");
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== 32) throw new StoreError(400, "invalid_session");
  return decoded;
}

function presentedHash(token: string): Buffer {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new StoreError(403, "forbidden");
  return createHash("sha256").update(Buffer.from(token, "base64url")).digest();
}

function authorized(expected: Buffer, token: string): boolean {
  const actual = presentedHash(token);
  return timingSafeEqual(expected, actual);
}

/** Memory-only single-use mailbox store. Consumed tombstones remain until expiry. */
export class SessionStore {
  readonly #sessions = new Map<string, Session>();
  readonly #timer: NodeJS.Timeout;

  constructor(private readonly maxActive: number, private readonly now: () => number = Date.now) {
    this.#timer = setInterval(() => this.cleanup(), 1_000);
    this.#timer.unref();
  }

  get size(): number {
    return this.#sessions.size;
  }

  close(): void {
    clearInterval(this.#timer);
    for (const session of this.#sessions.values()) session.listener?.({ type: "expired" });
    this.#sessions.clear();
  }

  reserve(id: string, expiresAt: number, writeTokenHash: string, readTokenHash: string): void {
    const current = this.now();
    if (!/^[A-Za-z0-9_-]{43}$/.test(id)) throw new StoreError(400, "invalid_session");
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= current || expiresAt > current + SESSION_TTL_MS) {
      throw new StoreError(400, "invalid_expiration");
    }
    if (this.#sessions.has(id)) throw new StoreError(409, "session_exists");
    if (this.#sessions.size >= this.maxActive) throw new StoreError(503, "capacity_reached");
    this.#sessions.set(id, {
      expiresAt,
      writeTokenHash: decodeHash(writeTokenHash),
      readTokenHash: decodeHash(readTokenHash),
      state: "reserved"
    });
  }

  claim(id: string, token: string): string {
    const session = this.getLive(id);
    if (!authorized(session.writeTokenHash, token)) throw new StoreError(403, "forbidden");
    if (session.state !== "reserved") throw new StoreError(409, "already_claimed");
    const claimToken = randomBytes(TOKEN_BYTES).toString("base64url");
    session.claimTokenHash = presentedHash(claimToken);
    session.state = "claimed";
    session.listener?.({ type: "claimed" });
    return claimToken;
  }

  put(id: string, token: string, claimToken: string, envelope: Envelope): "delivered" | "accepted" {
    const session = this.getLive(id);
    if (!authorized(session.writeTokenHash, token)) throw new StoreError(403, "forbidden");
    if (session.state === "reserved") throw new StoreError(409, "not_claimed");
    if (session.state !== "claimed" || !session.claimTokenHash) throw new StoreError(409, "already_used");
    if (!authorized(session.claimTokenHash, claimToken)) throw new StoreError(403, "forbidden");
    session.state = "ready";
    delete session.claimTokenHash;
    session.envelope = envelope;
    if (session.listener) {
      this.deliver(session);
      return "delivered";
    }
    return "accepted";
  }

  subscribe(id: string, token: string, listener: DeliveryListener): () => void {
    const session = this.getLive(id);
    if (!authorized(session.readTokenHash, token)) throw new StoreError(403, "forbidden");
    if (session.state === "consumed") throw new StoreError(409, "already_used");
    if (session.listener) throw new StoreError(409, "subscriber_exists");
    session.listener = listener;
    if (session.state === "claimed") queueMicrotask(() => listener({ type: "claimed" }));
    else if (session.state === "ready") this.deliver(session);
    return () => {
      if (session.listener === listener) delete session.listener;
    };
  }

  cancel(id: string, token: string): void {
    const session = this.getLive(id);
    if (!authorized(session.readTokenHash, token)) throw new StoreError(403, "forbidden");
    session.listener?.({ type: "expired" });
    this.#sessions.delete(id);
  }

  cleanup(): void {
    const current = this.now();
    for (const [id, session] of this.#sessions) {
      if (session.expiresAt <= current) {
        session.listener?.({ type: "expired" });
        this.#sessions.delete(id);
      }
    }
  }

  private getLive(id: string): Session {
    const session = this.#sessions.get(id);
    if (!session) throw new StoreError(404, "not_found");
    if (session.expiresAt <= this.now()) {
      session.listener?.({ type: "expired" });
      this.#sessions.delete(id);
      throw new StoreError(410, "expired");
    }
    return session;
  }

  private deliver(session: Session): void {
    const listener = session.listener;
    const envelope = session.envelope;
    if (!listener || !envelope) return;
    session.state = "consumed";
    delete session.listener;
    delete session.envelope;
    queueMicrotask(() => listener({ type: "payload", envelope }));
  }
}
