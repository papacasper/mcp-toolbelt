// Card-paid API keys for MCP Toolbelt (Polar subscriptions).
// Shared by the toolbelt (auth + metering) and the Polar webhook handler
// (/opt/audit-fulfillment/mcp-subscriptions.ts) — both import this file.
//
// Data minimisation (GDPR): we store ONLY the SHA-256 hash of each key (never
// the raw key), a short non-secret prefix for support lookups, the buyer's
// email + Polar customer/subscription IDs (needed to disable on cancel), the
// plan, and usage counters. No IPs, no request contents.
import { Database } from "bun:sqlite";
import { createHash, randomBytes } from "crypto";
import { chmodSync, existsSync } from "fs";

export const APIKEYS_DB_PATH =
  process.env.APIKEYS_DB_PATH ?? "/var/www/papacasper.com/mcp/apikeys.db";

export const PLANS: Record<string, { name: string; credits: number; priceUsd: number }> = {
  starter: { name: "Starter", credits: 2000, priceUsd: 9 },
  pro: { name: "Pro", credits: 10000, priceUsd: 29 },
  test: { name: "Test", credits: 20, priceUsd: 0 },
};

// Polar product IDs -> plan
export const PRODUCT_PLANS: Record<string, string> = {
  "5d63e6ba-afd2-411e-976a-84355911210a": "starter",
  "a7f9d1e7-90a2-4065-83a3-6fd22be0dddb": "pro",
};

export const CHECKOUT_LINKS = {
  starter: "https://buy.polar.sh/polar_cl_ohAX5VD8UYJGDHAjfP8Y5jowuK2nRQu0jb2XU3c9PBm",
  pro: "https://buy.polar.sh/polar_cl_NSE3CdNGwKv97h1v4Koj5mQqMt0ow8CR8oJdR19py6p",
};

// Retention: key records for ended subscriptions are deleted this many days after revocation.
export const RETENTION_DAYS = 30;

let _db: Database | null = null;
export function db(): Database {
  if (_db) return _db;
  const fresh = !existsSync(APIKEYS_DB_PATH);
  const d = new Database(APIKEYS_DB_PATH, { create: true });
  if (fresh) {
    try { chmodSync(APIKEYS_DB_PATH, 0o600); } catch {}
  }
  d.exec("PRAGMA journal_mode = WAL;");
  d.exec("PRAGMA busy_timeout = 5000;");
  d.exec(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      email TEXT,
      plan TEXT NOT NULL,
      monthly_credits INTEGER NOT NULL,
      used_credits INTEGER NOT NULL DEFAULT 0,
      total_calls INTEGER NOT NULL DEFAULT 0,
      period_start INTEGER NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      polar_subscription_id TEXT UNIQUE,
      polar_customer_id TEXT,
      cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      disabled_at INTEGER
    );
  `);
  d.exec("CREATE INDEX IF NOT EXISTS idx_api_keys_email ON api_keys (email)");
  _db = d;
  return d;
}

export function hashKey(key: string): string {
  return createHash("sha256").update(key, "utf8").digest("hex");
}

export function generateKey(): string {
  return "mcptb_" + randomBytes(24).toString("base64url");
}

// Credits per call = x402 price in cents ($0.01 = 1 credit, $0.25 = 25 credits).
export function creditsForPrice(price: string | undefined): number {
  const n = Number(String(price ?? "$0.01").replace(/[^0-9.]/g, ""));
  if (!Number.isFinite(n) || n <= 0) return 1;
  return Math.max(1, Math.round(n * 100));
}

function addMonth(ts: number): number {
  const d = new Date(ts);
  const day = d.getUTCDate();
  d.setUTCMonth(d.getUTCMonth() + 1);
  if (d.getUTCDate() < day) d.setUTCDate(0); // clamp e.g. Jan 31 -> Feb 28
  return d.getTime();
}

export interface KeyRow {
  id: number; key_prefix: string; email: string | null; plan: string;
  monthly_credits: number; used_credits: number; total_calls: number;
  period_start: number; status: string; polar_subscription_id: string | null;
  cancel_at_period_end: number; created_at: number; disabled_at: number | null;
}

// Roll the usage period forward (monthly, anchored on the key's start date).
function rollPeriod(row: KeyRow): KeyRow {
  let start = row.period_start;
  const now = Date.now();
  if (addMonth(start) > now) return row;
  while (addMonth(start) <= now) start = addMonth(start);
  db().query("UPDATE api_keys SET used_credits = 0, period_start = ?, updated_at = ? WHERE id = ?")
    .run(start, now, row.id);
  return { ...row, used_credits: 0, period_start: start };
}

export function periodResetsAt(row: KeyRow): number { return addMonth(row.period_start); }

export function lookupKey(rawKey: string): KeyRow | null {
  if (!rawKey || !rawKey.startsWith("mcptb_") || rawKey.length > 200) return null;
  const row = db().query<KeyRow, [string]>("SELECT * FROM api_keys WHERE key_hash = ?").get(hashKey(rawKey));
  if (!row) return null;
  return row.status === "active" ? rollPeriod(row) : row;
}

export type ChargeResult =
  | { ok: true; row: KeyRow; credits: number; remaining: number }
  | { ok: false; reason: "invalid" | "disabled" | "over_quota"; row?: KeyRow; credits: number };

// Atomically reserve credits for one call. Returns ok=false if the key is unknown,
// disabled, or would exceed its monthly quota.
export function chargeKey(rawKey: string, credits: number): ChargeResult {
  const row = lookupKey(rawKey);
  if (!row) return { ok: false, reason: "invalid", credits };
  if (row.status !== "active") return { ok: false, reason: "disabled", row, credits };
  const res = db().query(
    `UPDATE api_keys SET used_credits = used_credits + ?1, total_calls = total_calls + 1, updated_at = ?2
     WHERE id = ?3 AND status = 'active' AND used_credits + ?1 <= monthly_credits`
  ).run(credits, Date.now(), row.id);
  if (res.changes !== 1) return { ok: false, reason: "over_quota", row, credits };
  const used = row.used_credits + credits;
  return { ok: true, row: { ...row, used_credits: used }, credits, remaining: row.monthly_credits - used };
}

// Give credits back when the tool itself failed (customer is not charged for our errors).
export function refundKey(id: number, credits: number) {
  db().query("UPDATE api_keys SET used_credits = MAX(0, used_credits - ?), updated_at = ? WHERE id = ?")
    .run(credits, Date.now(), id);
}

export function mintKey(opts: {
  plan: string; email?: string | null; subscriptionId?: string | null; customerId?: string | null;
}): { key: string; row: KeyRow } {
  const plan = PLANS[opts.plan];
  if (!plan) throw new Error(`unknown plan ${opts.plan}`);
  const key = generateKey();
  const now = Date.now();
  db().query(
    `INSERT INTO api_keys (key_hash, key_prefix, email, plan, monthly_credits, period_start, status,
       polar_subscription_id, polar_customer_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)`
  ).run(hashKey(key), key.slice(0, 12), opts.email ?? null, opts.plan, plan.credits, now,
        opts.subscriptionId ?? null, opts.customerId ?? null, now, now);
  const row = db().query<KeyRow, [string]>("SELECT * FROM api_keys WHERE key_hash = ?").get(hashKey(key))!;
  return { key, row };
}

export function getBySubscription(subId: string): KeyRow | null {
  return db().query<KeyRow, [string]>("SELECT * FROM api_keys WHERE polar_subscription_id = ?").get(subId) ?? null;
}

// Replace the key for an existing record (lost key). Old key stops working immediately.
export function rotateKey(id: number): string {
  const key = generateKey();
  db().query("UPDATE api_keys SET key_hash = ?, key_prefix = ?, updated_at = ? WHERE id = ?")
    .run(hashKey(key), key.slice(0, 12), Date.now(), id);
  return key;
}

export function setStatus(id: number, status: "active" | "disabled") {
  const now = Date.now();
  db().query("UPDATE api_keys SET status = ?, disabled_at = ?, updated_at = ? WHERE id = ?")
    .run(status, status === "disabled" ? now : null, now, id);
}

export function setPlan(id: number, planKey: string) {
  const plan = PLANS[planKey];
  if (!plan) return;
  db().query("UPDATE api_keys SET plan = ?, monthly_credits = ?, updated_at = ? WHERE id = ?")
    .run(planKey, plan.credits, Date.now(), id);
}

export function setCancelFlag(id: number, flag: boolean) {
  db().query("UPDATE api_keys SET cancel_at_period_end = ?, updated_at = ? WHERE id = ?")
    .run(flag ? 1 : 0, Date.now(), id);
}

// GDPR erasure: delete every record for an email (or a single id). Returns rows removed.
export function deleteByEmail(email: string): number {
  return db().query("DELETE FROM api_keys WHERE lower(email) = lower(?)").run(email).changes;
}
export function deleteById(id: number): number {
  return db().query("DELETE FROM api_keys WHERE id = ?").run(id).changes;
}

// Retention: drop disabled records older than RETENTION_DAYS.
export function purgeExpired(): number {
  const cutoff = Date.now() - RETENTION_DAYS * 86400_000;
  return db().query("DELETE FROM api_keys WHERE status = 'disabled' AND disabled_at IS NOT NULL AND disabled_at < ?")
    .run(cutoff).changes;
}

export function listKeys(): KeyRow[] {
  return db().query<KeyRow, []>("SELECT * FROM api_keys ORDER BY id").all().map((r) => (r.status === "active" ? rollPeriod(r) : r));
}
