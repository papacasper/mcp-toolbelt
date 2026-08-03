#!/usr/bin/env bun
// Generates x402 discovery documents (openapi.json + .well-known/x402) from the live tool
// registry and writes them into the Astro site's public/ dir, since x402scan probes the
// domain root, not /mcp/. Re-run and redeploy the site whenever a tool is added, removed,
// or repriced.
import { tools } from "../src/tools";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const PUBLIC_BASE_URL = "https://papacasper.com/mcp";
const SITE_PUBLIC_DIR = join(import.meta.dir, "..", "..", "site", "public");

const toolEntries = Object.entries(tools) as Array<[string, any]>;

const paths: Record<string, any> = {};
for (const [name, def] of toolEntries) {
  const price = String(def.price ?? "$0.0001").replace(/^\$/, "");
  paths[`/pay/${name}`] = {
    post: {
      summary: def.description ?? name,
      operationId: name,
      "x-payment-info": {
        protocols: [{ x402: {} }],
        price: { mode: "fixed", currency: "USD", amount: price },
      },
      requestBody: def.inputSchema
        ? { required: true, content: { "application/json": { schema: def.inputSchema } } }
        : undefined,
      responses: {
        "200": {
          description: "Tool result",
          content: { "application/json": { schema: { type: "object" } } },
        },
        "402": { description: "Payment required" },
      },
    },
  };
}

const openapi = {
  openapi: "3.1.0",
  info: {
    title: "mcp-toolbelt",
    version: "1.0.0",
    description: "Pay-per-call web, SEO, DNS, and network tools via the x402 protocol.",
    "x-guidance":
      "POST JSON to /pay/<tool-name> with the tool's input fields as the request body. " +
      "Each tool is priced individually via x402 (see x-payment-info per operation). " +
      "Call GET /openapi.json for the full list of tools, their input schemas, and prices.",
    contact: { email: "contact@papacasper.com" },
  },
  servers: [{ url: PUBLIC_BASE_URL }],
  paths,
};

const wellKnown = {
  version: 1,
  resources: toolEntries.map(([name]) => `${PUBLIC_BASE_URL}/pay/${name}`),
};

mkdirSync(SITE_PUBLIC_DIR, { recursive: true });
mkdirSync(join(SITE_PUBLIC_DIR, ".well-known"), { recursive: true });

writeFileSync(join(SITE_PUBLIC_DIR, "openapi.json"), JSON.stringify(openapi, null, 2) + "\n");
writeFileSync(join(SITE_PUBLIC_DIR, ".well-known", "x402"), JSON.stringify(wellKnown, null, 2) + "\n");

console.log(`Wrote openapi.json (${toolEntries.length} paths) and .well-known/x402 to ${SITE_PUBLIC_DIR}`);
