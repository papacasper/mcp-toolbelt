# mcp-toolbelt

Public MCP server behind `https://papacasper.com/mcp/` (Streamable HTTP). 37 DNS, SEO, SSL,
security, WHOIS, mail, AI-readiness, rendering, validation, and conversion tools for AI agents. `initialize` and `tools/list` are open; `tools/call`
is paid one of two ways:

[![MCP Toolbelt - Listed on Claude AI Directory](https://www.claudeai.directory/badge/mcp-toolbelt)](https://www.claudeai.directory/launches/mcp-toolbelt)

## Payment options

1. **x402 pay-per-call** - USDC on Base, no account or API key needed. An unpaid call returns
   HTTP 402 with the x402 payment requirements.
2. **Card-paid API key** (via Polar) - send `Authorization: Bearer mcptb_...` (or `x-api-key: mcptb_...`).
   Each call uses its normal price in credits (cheap tools 1 credit, `domain_report` 25).
   - Starter: $9/month, 2,000 credits - https://buy.polar.sh/polar_cl_ohAX5VD8UYJGDHAjfP8Y5jowuK2nRQu0jb2XU3c9PBm
   - Pro: $29/month, 10,000 credits - https://buy.polar.sh/polar_cl_NSE3CdNGwKv97h1v4Koj5mQqMt0ow8CR8oJdR19py6p

   The key is emailed right after checkout. When a key runs out of credits or its subscription
   ends, calls fall back to x402. Docs: https://papacasper.com/mcp-docs#api-key

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

## Binary outputs (screenshots, PDFs, images)

`website_screenshot`, `html_to_pdf`, and `image_resize` write their output to `.files/` (gitignored)
and return a short-lived URL, `https://papacasper.com/mcp/files/<random>.<ext>`, valid for 1 hour,
plus byte size and SHA-256. Pass `includeBase64: true` to get the bytes inline (capped at 3 MB).
Rendering uses `chrome-headless-shell` (installed with `bunx @puppeteer/browsers install
chrome-headless-shell@stable --path ~/.cache/puppeteer`, or set `CHROME_PATH`), max 2 concurrent
renders, and every browser request is checked against the same private-address guard as `fetch`.
