import { Hono } from "hono";
import { paymentMiddlewareFromConfig } from "@x402/hono";
import { HTTPFacilitatorClient } from "@x402/core/http";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { declareDiscoveryExtension } from "@x402/extensions/bazaar";
import { tools } from "./tools";
import { logCall, decodePaymentResponseHeader, getStats, paymentResponseHeaderFrom, settlementMetricsMiddleware } from "./metrics";
import { dashboardHtml } from "./dashboard";
import { installFetchGuard } from "./tools/ssrf-guard";
import { readStoredFile } from "./tools/files";
import { chargeKey, refundKey, creditsForPrice, periodResetsAt, CHECKOUT_LINKS } from "./apikeys";

installFetchGuard();

const PORT = Number(process.env.PORT ?? 3457);
const API_KEY = process.env.MCP_API_KEY ?? "";
const X402_PAY_TO = process.env.X402_PAY_TO ?? "";
const X402_PRICE = process.env.X402_PRICE ?? "$0.01";
const X402_NETWORK = process.env.X402_NETWORK ?? "eip155:8453";
const X402_FACILITATOR_URL = process.env.X402_FACILITATOR_URL ?? "https://facilitator.xpay.sh";
const X402_PUBLIC_BASE_URL = process.env.X402_PUBLIC_BASE_URL ?? "https://papacasper.com/mcp";

const app = new Hono();

app.get("/health", (c) => c.json({ ok: true, service: "mcp-toolbelt" }));

app.get("/", (c) => c.html("<!doctype html><html><head><title>MCP Toolbelt</title></head><body><h1>MCP Toolbelt</h1><p>This is an MCP server endpoint. It speaks MCP over Streamable HTTP, so connect an MCP client to https://papacasper.com/mcp. Opening this URL in a browser does not show a tool list.</p><p>Tools available: " + Object.keys(tools).length + ". Calls are pay-per-call via x402 (USDC on Base), or use a card-paid API key (Authorization: Bearer &lt;key&gt;) from https://papacasper.com/mcp-docs#api-key. tools/list is open for discovery.</p></body></html>"));

function requireApiKey(c: any): Response | null {
  if (!API_KEY) return null;
  const provided = c.req.header("x-api-key") ?? c.req.query("key") ?? "";
  if (provided !== API_KEY) return c.json({ error: "unauthorized" }, 401);
  return null;
}

app.get("/dashboard", (c) => c.html(dashboardHtml));

// Short-lived binary outputs (screenshots, PDFs, resized images). Unguessable names, 1-hour TTL.
app.get("/files/:name", (c) => {
  const file = readStoredFile(c.req.param("name"));
  if (!file) return c.json({ error: "not found or expired" }, 404);
  return new Response(file.body, {
    headers: {
      "content-type": file.contentType,
      "cache-control": "private, max-age=3600",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src none; img-src self; style-src unsafe-inline; sandbox",
      "content-disposition": "inline",
    },
  });
});

function toolPricing() {
  return Object.fromEntries(
    Object.entries(tools).map(([name, def]) => [name, (def as any).price ?? X402_PRICE])
  );
}

app.get("/dashboard-data", (c) => {
  const unauthorized = requireApiKey(c);
  if (unauthorized) return unauthorized;
  return c.json({ ...getStats(), pricing: toolPricing() });
});

// Payment-gated REST entrypoint — one route per tool, priced via x402.
// Separate from the JSON-RPC endpoint below since the x402 middleware gates by HTTP path,
// and MCP's tools/list vs tools/call distinction lives inside a single JSON-RPC body.
// Example argument values for x402 Bazaar discovery metadata: each /pay/* route
// declares how to call it (a real, minimal example built from the tool's schema),
// so facilitators that run a discovery index can catalog the tool after settlement.
function exampleValue(prop: string, schema: any): unknown {
  if (Array.isArray(schema?.enum) && schema.enum.length) return schema.enum[0];
  const byName: Record<string, unknown> = {
    domain: "example.com", hostname: "example.com", host: "example.com",
    url: "https://example.com", email: "user@example.com",
    ip: "192.0.2.1", address: "192.0.2.1",
    package: "express", repo: "papacasper/mcp-toolbelt", repository: "papacasper/mcp-toolbelt",
    username: "example", query: "example.com", target: "example.com", server: "example.com",
  };
  if (prop in byName) return byName[prop];
  switch (schema?.type) {
    case "number": case "integer": return 1;
    case "boolean": return true;
    case "array": return [exampleValue(prop, schema?.items ?? {})];
    case "object": return {};
    default: return "example.com";
  }
}
function exampleInput(def: any): Record<string, unknown> {
  const schema = def?.inputSchema ?? {};
  const props = schema.properties ?? {};
  const required: string[] = schema.required ?? [];
  const out: Record<string, unknown> = {};
  for (const key of required) out[key] = exampleValue(key, props[key] ?? {});
  if (Object.keys(out).length === 0) {
    const first = Object.keys(props)[0];
    if (first) out[first] = exampleValue(first, props[first]);
  }
  return out;
}

// ---- Card-paid API keys (Polar subscription) ------------------------------------------
// A customer key (mcptb_…) sent as `Authorization: Bearer <key>` or `x-api-key: <key>`
// bypasses x402 while it has monthly credits left. No key -> x402 exactly as before.
// Invalid / disabled / over-quota key -> the normal x402 402 response plus an `apiKey` note.
function customerKeyFrom(c: any): string | null {
  const auth = c.req.header("authorization") ?? "";
  const m = auth.match(/^Bearer\s+(mcptb_[A-Za-z0-9_-]+)\s*$/i);
  if (m) return m[1];
  const x = c.req.header("x-api-key") ?? "";
  return x.startsWith("mcptb_") ? x.trim() : null;
}

function keyFailureNote(reason: string, row?: any, needed?: number) {
  const upgrade = CHECKOUT_LINKS.pro;
  const messages: Record<string, string> = {
    invalid: "API key not recognised. Falling back to x402 pay-per-call.",
    disabled: "API key is disabled (subscription ended). Falling back to x402 pay-per-call. Resubscribe: " + CHECKOUT_LINKS.starter,
    over_quota: `Not enough monthly API credits left for this call (needs ${needed ?? "?"}, ${row ? Math.max(0, row.monthly_credits - row.used_credits) : "?"} of ${row?.monthly_credits ?? "?"} left); credits reset ${row ? new Date(periodResetsAt(row)).toISOString() : "next period"}. Falling back to x402 pay-per-call. Upgrade to Pro (10,000 credits/mo): ${upgrade}`,
  };
  return { error: reason, message: messages[reason] ?? reason, plans: CHECKOUT_LINKS, docs: "https://papacasper.com/mcp-docs#api-key" };
}

async function runWithKey(c: any, key: string, name: string, args: any) {
  const credits = creditsForPrice((tools as any)[name]?.price ?? X402_PRICE);
  const charge = chargeKey(key, credits);
  if (!charge.ok) return { ok: false as const, note: keyFailureNote(charge.reason, charge.row, credits) };
  const started = Date.now();
  c.header("X-API-Credits-Remaining", String(charge.remaining));
  c.header("X-API-Credits-Charged", String(credits));
  try {
    const output = await (tools as any)[name].run(args);
    logCall({ tool: name, transport: "key" as any, success: true, durationMs: Date.now() - started });
    return { ok: true as const, output };
  } catch (err: any) {
    refundKey(charge.row.id, credits);
    c.header("X-API-Credits-Remaining", String(charge.remaining + credits));
    logCall({ tool: name, transport: "key" as any, success: false, durationMs: Date.now() - started, error: err?.message ?? String(err) });
    return { ok: true as const, error: err?.message ?? String(err) };
  }
}

if (X402_PAY_TO) {
  const perToolRoutes = Object.fromEntries(
    Object.entries(tools).map(([name, def]) => [
      `/pay/${name}`,
      {
        accepts: {
          scheme: "exact",
          payTo: X402_PAY_TO,
          price: (def as any).price ?? X402_PRICE,
          network: X402_NETWORK as any,
        },
        resource: `${X402_PUBLIC_BASE_URL}/pay/${name}`,
        description: (def as any).description ?? "",
        mimeType: "application/json",
        extensions: declareDiscoveryExtension({
          method: "POST",
          bodyType: "json",
          input: exampleInput(def),
          inputSchema: (def as any).inputSchema,
        }),
      },
    ])
  );

  // Outermost /pay/* middleware: runs after the x402 middleware below has settled the payment,
  // then fills the settlement details (payer, tx hash, network) into the metrics row that the
  // route handler wrote. Reading the header inside the handler is too early, since settlement
  // only happens after the handler returns.
  app.use("/pay/*", settlementMetricsMiddleware);

  // Customer API key on the REST routes: serve directly (no x402) when the key has credits.
  app.use("/pay/*", async (c, next) => {
    const key = customerKeyFrom(c);
    if (!key || c.req.method !== "POST") return next();
    const name = c.req.path.replace(/^.*\/pay\//, "");
    if (!name || !(name in tools)) return next();
    let args: any = {};
    try { args = await c.req.raw.clone().json(); } catch {}
    const r = await runWithKey(c, key, name, args);
    if (!r.ok) {
      c.header("X-API-Key-Status", r.note.error);
      await next();
      if (c.res.status === 402) {
        try {
          const body = await c.res.clone().json();
          const headers = new Headers(c.res.headers);
          c.res = new Response(JSON.stringify({ ...body, apiKey: r.note }), { status: 402, headers });
        } catch {}
      }
      return;
    }
    if ("error" in r && r.error) return c.json({ error: r.error }, 502);
    return c.json(r.output);
  });

  app.use(
    "/pay/*",
    paymentMiddlewareFromConfig(
      {
        ...perToolRoutes,
        "/pay/*": {
          accepts: {
            scheme: "exact",
            payTo: X402_PAY_TO,
            price: X402_PRICE,
            network: X402_NETWORK as any,
          },
        },
      },
      new HTTPFacilitatorClient({ url: X402_FACILITATOR_URL }),
      [{ network: X402_NETWORK as any, server: new ExactEvmScheme() }]
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
      // Payer / tx hash / network are filled in after settlement by the outer /pay/* middleware.
      const rowId = logCall({ tool: name, transport: "pay", success: true, durationMs: Date.now() - started });
      (c as any).set("metricsRowId", rowId);
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
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return c.json(rpcError(null, -32700, "Parse error"), 400);
  }

  const { id, method, params } = body ?? {};

  // API-key gate only on tools/call — initialize/tools/list stay open so directories
  // and agents can discover tools without a key before deciding to pay per call.
  if (method === "tools/call") {
    const provided = c.req.header("x-api-key") ?? "";
    let apiKeyNote: any = null;
    const customerKey = API_KEY && provided === API_KEY ? null : customerKeyFrom(c);
    if (customerKey) {
      const name = params?.name as string | undefined;
      if (!name || !(name in tools)) {
        return c.json(rpcError(id, -32602, `Unknown tool: ${name}`), 400);
      }
      const r = await runWithKey(c, customerKey, name, params?.arguments ?? {});
      if (r.ok) {
        if ("error" in r && r.error) {
          return c.json(rpcResult(id, { content: [{ type: "text", text: `Error: ${r.error}` }], isError: true }));
        }
        return c.json(rpcResult(id, { content: [{ type: "text", text: JSON.stringify((r as any).output, null, 2) }], isError: false }));
      }
      apiKeyNote = r.note; // fall through to x402 below
      c.header("X-API-Key-Status", r.note.error);
    }
    if (!(API_KEY && provided === API_KEY)) {
      // No valid free-access key — fall through to x402 pay-per-call instead of a flat 401,
      // so standard MCP clients (Smithery, Glama, Claude Desktop) can actually pay for tools/call.
      const name = params?.name as string | undefined;
      if (!name || !(name in tools)) {
        return c.json(rpcError(id, -32602, `Unknown tool: ${name}`), 400);
      }
      if (!X402_PAY_TO) {
        return c.json({ error: "unauthorized" }, 401);
      }
      const payHeaders = new Headers(c.req.raw.headers);
      payHeaders.set("content-type", "application/json");
      if (customerKey) { payHeaders.delete("authorization"); payHeaders.delete("x-api-key"); } // already tried above
      const payResponse = await app.request(`/pay/${name}`, {
        method: "POST",
        headers: payHeaders,
        body: JSON.stringify(params?.arguments ?? {}),
      });
      // Settlement header from the inner /pay route (x402 v2 name PAYMENT-RESPONSE; v1 X-PAYMENT-RESPONSE).
      // The metrics row for this call is written and settled inside that inner request.
      const paymentResponseHeader = paymentResponseHeaderFrom(payResponse.headers);
      if (paymentResponseHeader) {
        c.header("PAYMENT-RESPONSE", paymentResponseHeader);
        c.header("X-PAYMENT-RESPONSE", paymentResponseHeader);
      }
      if (payResponse.status === 402) {
        const paymentRequiredHeader = payResponse.headers.get("payment-required");
        if (paymentRequiredHeader) c.header("payment-required", paymentRequiredHeader);
        const challenge = await payResponse.json().catch(() => ({}));
        return c.json(apiKeyNote ? { ...challenge, apiKey: apiKeyNote } : challenge, 402);
      }
      const output = await payResponse.json();
      if (!payResponse.ok) {
        return c.json(rpcResult(id, { content: [{ type: "text", text: `Error: ${output?.error ?? "payment failed"}` }], isError: true }));
      }
      return c.json(rpcResult(id, { content: [{ type: "text", text: JSON.stringify(output, null, 2) }], isError: false }));
    }
  }

  try {
    switch (method) {
      case "initialize":
        return c.json(
          rpcResult(id, {
            protocolVersion: "2024-11-05",
            capabilities: { tools: {} },
            serverInfo: { name: "mcp-toolbelt", version: "1.4.0" },
            instructions: `${Object.keys(tools).length} DNS, SEO, SSL, security, WHOIS, mail, screenshot/PDF, validation, conversion, and archive tools.`+" tools/list is free. tools/call is paid either per call via x402 (USDC on Base, no account) or with a card-paid API key sent as `Authorization: Bearer mcptb_...` or `x-api-key`: Starter $9/mo 2,000 credits https://buy.polar.sh/polar_cl_ohAX5VD8UYJGDHAjfP8Y5jowuK2nRQu0jb2XU3c9PBm ; Pro $29/mo 10,000 credits https://buy.polar.sh/polar_cl_NSE3CdNGwKv97h1v4Koj5mQqMt0ow8CR8oJdR19py6p ; docs https://papacasper.com/mcp-docs#api-key",
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
