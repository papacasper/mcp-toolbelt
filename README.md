# mcp-toolbelt

Public x402 pay-per-call MCP server behind `https://papacasper.com/mcp/`.

## Discovery documents

`scripts/gen-discovery.ts` generates `openapi.json` and `.well-known/x402` from the live tool
registry (`src/tools`) and writes them into `../site/public/`, since discovery crawlers probe the
domain root (`papacasper.com/openapi.json`), not `/mcp/`. Re-run it and redeploy the site
(`~/dev/papacasper/site`, `./scripts/deploy.sh`) whenever a tool is added, removed, or repriced:

```
bun run scripts/gen-discovery.ts
```

## x402 protocol

Payments run on x402 v2 via `@x402/hono`, facilitated by `https://facilitator.xpay.sh`
(zero fees, gas-sponsored, no API key) on Base mainnet (`eip155:8453`). Configured through
`X402_FACILITATOR_URL` and `X402_NETWORK` env vars.
