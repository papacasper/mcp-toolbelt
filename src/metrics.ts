import { Database } from "bun:sqlite";
import { dirname, resolve } from "path";
import { mkdirSync } from "fs";

const DB_PATH = process.env.METRICS_DB_PATH || resolve(process.cwd(), "metrics.db");
mkdirSync(dirname(DB_PATH), { recursive: true });

export const db = new Database(DB_PATH);
db.exec(`
  CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    tool TEXT NOT NULL,
    transport TEXT NOT NULL,
    success INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    error TEXT,
    payer TEXT,
    tx_hash TEXT,
    network TEXT
  );
`);
db.exec("CREATE INDEX IF NOT EXISTS idx_calls_ts ON calls (ts)");

export const START_TIME = Date.now();

export interface LogCallInput {
  tool: string;
  transport: "pay" | "rpc";
  success: boolean;
  durationMs: number;
  error?: string;
  payer?: string;
  txHash?: string;
  network?: string;
}

export function logCall(input: LogCallInput) {
  db.query(
    `INSERT INTO calls (ts, tool, transport, success, duration_ms, error, payer, tx_hash, network)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    Date.now(),
    input.tool,
    input.transport,
    input.success ? 1 : 0,
    input.durationMs,
    input.error ?? null,
    input.payer ?? null,
    input.txHash ?? null,
    input.network ?? null
  );
}

// Best-effort decode of the x402-hono X-PAYMENT-RESPONSE header (base64 JSON
// settlement payload: { success, transaction, network, payer }).
export function decodePaymentResponseHeader(header: string | null | undefined) {
  if (!header) return null;
  try {
    const json = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    return {
      txHash: json.transaction as string | undefined,
      network: json.network as string | undefined,
      payer: json.payer as string | undefined,
    };
  } catch {
    return null;
  }
}

export function getStats() {
  const totalCalls = db.query<{ n: number }, []>("SELECT COUNT(*) as n FROM calls").get()?.n ?? 0;
  const totalErrors =
    db.query<{ n: number }, []>("SELECT COUNT(*) as n FROM calls WHERE success = 0").get()?.n ?? 0;

  const callsByTool = db
    .query<{ tool: string; n: number; errors: number; avg_ms: number }, []>(
      `SELECT tool, COUNT(*) as n, SUM(CASE WHEN success = 0 THEN 1 ELSE 0 END) as errors, AVG(duration_ms) as avg_ms
       FROM calls GROUP BY tool ORDER BY n DESC`
    )
    .all();

  const callsByTransport = db
    .query<{ transport: string; n: number }, []>(
      "SELECT transport, COUNT(*) as n FROM calls GROUP BY transport"
    )
    .all();

  const last24h =
    db
      .query<{ n: number }, [number]>("SELECT COUNT(*) as n FROM calls WHERE ts > ?")
      .get(Date.now() - 24 * 60 * 60 * 1000)?.n ?? 0;

  const payments = db
    .query<{ n: number; last_ts: number | null }, []>(
      "SELECT COUNT(*) as n, MAX(ts) as last_ts FROM calls WHERE transport = 'pay' AND success = 1"
    )
    .get();

  const recentCalls = db
    .query<
      {
        ts: number;
        tool: string;
        transport: string;
        success: number;
        duration_ms: number;
        error: string | null;
        payer: string | null;
        tx_hash: string | null;
        network: string | null;
      },
      []
    >("SELECT ts, tool, transport, success, duration_ms, error, payer, tx_hash, network FROM calls ORDER BY ts DESC LIMIT 50")
    .all();

  const recentPayments = db
    .query<
      { ts: number; tool: string; payer: string | null; tx_hash: string | null; network: string | null },
      []
    >(
      `SELECT ts, tool, payer, tx_hash, network FROM calls
       WHERE transport = 'pay' AND success = 1 ORDER BY ts DESC LIMIT 50`
    )
    .all();

  return {
    uptimeMs: Date.now() - START_TIME,
    startedAt: START_TIME,
    totalCalls,
    totalErrors,
    last24h,
    callsByTool,
    callsByTransport,
    payments: { count: payments?.n ?? 0, lastTs: payments?.last_ts ?? null },
    recentCalls,
    recentPayments,
  };
}
