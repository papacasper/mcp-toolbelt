import { Hono } from "hono";
import { paymentMiddleware } from "x402-hono";
import { tools } from "./tools";
import { logCall, decodePaymentResponseHeader, getStats } from "./metrics";
import { dashboardHtml } from "./dashboard";

const PORT = Number(process.env.PORT ?? 3457);
const API_KEY = process.env.MCP_API_KEY ?? "";
const X402_PAY_TO = process.env.X402_PAY_TO ?? "";
const X402_PRICE = process.env.X402_PRICE ?? "$0.0001";
const X402_NETWORK = process.env.X402_NETWORK ?? "base";
const X402_FACILITATOR_URL = process.env.X402_FACILITATOR_URL ?? "https://facilitator.mogami.tech";

const app = new Hono();

app.get("/health", (c) => c.json({ ok: true, service: "mcp-toolbelt" }));

function requireApiKey(c: any): Response | null {
  if (!API_KEY) return null;
  const provided = c.req.header("x-api-key") ?? c.req.query("key") ?? "";
  if (provided !== API_KEY) return c.json({ error: "unauthorized" }, 401);
  return null;
}

app.get("/dashboard", (c) => c.html(dashboardHtml));

app.get("/dashboard-data", (c) => {
  const unauthorized = requireApiKey(c);
  if (unauthorized) return unauthorized;
  return c.json(getStats());
});

// Payment-gated REST entrypoint — one route per tool, priced via x402.
// Separate from the JSON-RPC endpoint below since x402-hono gates by HTTP path,
// and MCP's tools/list vs tools/call distinction lives inside a single JSON-RPC body.
if (X402_PAY_TO) {
  app.use(
    "/pay/*",
    paymentMiddleware(
      X402_PAY_TO as `0x${string}`,
      {
        "/pay/*": {
          price: X402_PRICE,
          network: X402_NETWORK as any,
        },
      },
      { url: X402_FACILITATOR_URL }
    )
  );

  app.post("/pay/:tool", async (c) => {
    const name = c.req.param("tool");
    if (!name || !(name in tools)) {
      return c.json({ error: `Unknown tool: ${name}` }, 404);
    }
    let args: any = {};
    try {
      args = await c.req.json();
    } catch {
      // no body is fine for tools with no required args
    }
    const started = Date.now();
    try {
      const output = await (tools as any)[name].run(args);
      const payment = decodePaymentResponseHeader(c.res.headers.get("X-PAYMENT-RESPONSE"));
      logCall({
        tool: name,
        transport: "pay",
        success: true,
        durationMs: Date.now() - started,
        payer: payment?.payer,
        txHash: payment?.txHash,
        network: payment?.network,
      });
      return c.json(output);
    } catch (err: any) {
      logCall({
        tool: name,
        transport: "pay",
        success: false,
        durationMs: Date.now() - started,
        error: err?.message ?? String(err),
      });
      return c.json({ error: err?.message ?? String(err) }, 502);
    }
  });
}

function toolList() {
  return Object.entries(tools).map(([name, def]) => ({
    name,
    description: def.description,
    inputSchema: def.inputSchema,
  }));
}

function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

function rpcResult(id: unknown, result: unknown) {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

app.post("/", async (c) => {
  // Simple API-key gate — interim access control until x402 pay-per-call is wired in.
  if (API_KEY) {
    const provided = c.req.header("x-api-key") ?? "";
    if (provided !== API_KEY) {
      return c.json({ error: "unauthorized" }, 401);
    }
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json(rpcError(null, -32700, "Parse error"), 400);
  }

  const { id, method, params } = body ?? {};

  try {
    switch (method) {
      case "initialize":
        return c.json(
          rpcResult(id, {
            protocolVersion: "2024-11-05",
            capabilities: { tools: {} },
            serverInfo: { name: "mcp-toolbelt", version: "1.0.0" },
          })
        );

      case "notifications/initialized":
        return c.body(null, 204);

      case "tools/list":
        return c.json(rpcResult(id, { tools: toolList() }));

      case "tools/call": {
        const name = params?.name as string | undefined;
        const args = params?.arguments ?? {};
        if (!name || !(name in tools)) {
          return c.json(rpcError(id, -32602, `Unknown tool: ${name}`), 400);
        }
        const started = Date.now();
        try {
          const output = await (tools as any)[name].run(args);
          logCall({ tool: name, transport: "rpc", success: true, durationMs: Date.now() - started });
          return c.json(
            rpcResult(id, {
              content: [{ type: "text", text: JSON.stringify(output, null, 2) }],
              isError: false,
            })
          );
        } catch (err: any) {
          logCall({
            tool: name,
            transport: "rpc",
            success: false,
            durationMs: Date.now() - started,
            error: err?.message ?? String(err),
          });
          return c.json(
            rpcResult(id, {
              content: [{ type: "text", text: `Error: ${err?.message ?? String(err)}` }],
              isError: true,
            })
          );
        }
      }

      default:
        return c.json(rpcError(id, -32601, `Method not found: ${method}`), 404);
    }
  } catch (err: any) {
    return c.json(rpcError(id, -32603, `Internal error: ${err?.message ?? String(err)}`), 500);
  }
});

console.log(`mcp-toolbelt listening on 127.0.0.1:${PORT}`);

export default {
  port: PORT,
  hostname: "127.0.0.1",
  fetch: app.fetch,
};
