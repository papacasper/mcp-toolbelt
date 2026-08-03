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
