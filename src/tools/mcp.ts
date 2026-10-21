// Probe and quality-grade a remote MCP server the way a careful client would:
// handshake, tool inventory, and schema/description quality analysis.
async function mcpRequest(
  url: string,
  body: unknown,
  sessionId: string | null,
  timeoutMs = 15000
): Promise<{ status: number; json: any; sessionId: string | null; contentType: string | null }> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
    "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;

  const res = await fetch(url, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const newSession = res.headers.get("mcp-session-id");
  const contentType = res.headers.get("content-type");
  const text = await res.text();

  // Streamable HTTP servers may answer with SSE: take the JSON payload of the
  // data: lines and find the one matching our request.
  let json: any = null;
  if (contentType?.includes("text/event-stream")) {
    const payloads = text
      .split("\n")
      .filter((l) => l.startsWith("data:"))
      .map((l) => {
        try {
          return JSON.parse(l.slice(5).trim());
        } catch {
          return null;
        }
      })
      .filter(Boolean);
    json = payloads.find((p: any) => p && (p.result !== undefined || p.error !== undefined)) ?? payloads[0] ?? null;
  } else if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  return { status: res.status, json, sessionId: newSession ?? sessionId, contentType };
}

export const tools = {
  mcp_server_probe: {
    price: "$0.10",
    description:
      "Probe a remote MCP server end-to-end: performs the initialize handshake, captures server info and protocol version, lists its tools, and grades tool-quality the way directories like Glama do — description coverage and depth, input-schema completeness, and naming consistency — with a 0-100 score, letter grade, and per-tool detail. Use it to vet an MCP server before connecting an agent (or paying per call) to it.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The MCP server endpoint URL, e.g. https://example.com/mcp" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        throw new Error(`Invalid URL: ${url}`);
      }
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error("URL must be http:// or https://");
      }

      const init = await mcpRequest(url, {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-03-26",
          capabilities: {},
          clientInfo: { name: "mcp-toolbelt-probe", version: "1.0" },
        },
      }, null).catch((e: any) => ({ status: 0, json: null, sessionId: null, contentType: null, error: e?.message ?? String(e) }) as any);

      if ((init as any).error || !init.json) {
        return {
          url,
          reachable: false,
          stage: "initialize",
          httpStatus: init.status || null,
          error: (init as any).error ?? "No JSON-RPC response to initialize",
          hint: init.status === 401 || init.status === 403
            ? "Server requires authentication — probe cannot proceed without credentials"
            : init.status === 402
              ? "Server requires payment before the handshake"
              : "Check the URL is a Streamable HTTP MCP endpoint",
        };
      }
      if (init.json.error) {
        return {
          url,
          reachable: false,
          stage: "initialize",
          httpStatus: init.status,
          error: `JSON-RPC error ${init.json.error.code}: ${init.json.error.message}`,
        };
      }

      const result = init.json.result ?? {};
      const serverInfo = result.serverInfo ?? null;
      const protocolVersion = result.protocolVersion ?? null;
      const sessionId = init.sessionId;

      // Best-effort initialized notification (required by strict servers before tools/list).
      if (sessionId) {
        await mcpRequest(url, { jsonrpc: "2.0", method: "notifications/initialized" }, sessionId, 8000).catch(() => null);
      }

      const list = await mcpRequest(url, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, sessionId)
        .catch((e: any) => ({ status: 0, json: null, sessionId, contentType: null, error: e?.message ?? String(e) }) as any);

      if (!list.json || list.json.error || !Array.isArray(list.json.result?.tools)) {
        return {
          url,
          reachable: true,
          stage: "tools/list",
          httpStatus: list.status || null,
          serverInfo,
          protocolVersion,
          error: (list as any).error ?? list.json?.error?.message ?? "tools/list did not return a tools array",
        };
      }

      const rawTools: any[] = list.json.result.tools;
      const analyzed = rawTools.map((t) => {
        const schema = t.inputSchema ?? {};
        const props = schema.properties && typeof schema.properties === "object" ? Object.keys(schema.properties) : [];
        return {
          name: String(t.name ?? ""),
          descriptionChars: typeof t.description === "string" ? t.description.trim().length : 0,
          hasDescription: typeof t.description === "string" && t.description.trim().length > 0,
          hasSchema: !!t.inputSchema,
          paramCount: props.length,
          requiredCount: Array.isArray(schema.required) ? schema.required.length : 0,
        };
      });

      const total = analyzed.length;
      const described = analyzed.filter((t) => t.hasDescription).length;
      const avgDescChars = total ? Math.round(analyzed.reduce((s, t) => s + t.descriptionChars, 0) / total) : 0;
      const withSchema = analyzed.filter((t) => t.hasSchema).length;
      const snakeCase = analyzed.filter((t) => /^[a-z][a-z0-9]*(_[a-z0-9]+)*$/.test(t.name)).length;
      const namePrefixes = analyzed.map((t) => t.name.split("_")[0]);
      const consistentSuffix = total ? Math.max(...Object.values(
        analyzed.reduce((acc: Record<string, number>, t) => {
          const suffix = t.name.split("_").pop() ?? "";
          acc[suffix] = (acc[suffix] ?? 0) + 1;
          return acc;
        }, {})
      )) / total : 0;

      const pctDescribed = total ? described / total : 0;
      const pctSchema = total ? withSchema / total : 0;
      const pctSnake = total ? snakeCase / total : 0;
      const descDepth = Math.min(1, avgDescChars / 200); // 200+ avg chars = full marks

      const score = Math.round(30 * pctDescribed + 20 * descDepth + 25 * pctSchema + 15 * pctSnake + 10 * consistentSuffix);
      const grade = score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";

      const issues: string[] = [];
      if (total === 0) issues.push("Server lists zero tools");
      if (described < total) issues.push(`${total - described} of ${total} tools have no description — agents cannot tell when to call them`);
      if (avgDescChars > 0 && avgDescChars < 80) issues.push(`Average description is short (${avgDescChars} chars) — thin descriptions score poorly on directory quality rubrics`);
      const noParams = analyzed.filter((t) => t.hasSchema && t.paramCount === 0 && t.requiredCount === 0).length;
      if (noParams) issues.push(`${noParams} tool(s) expose an empty input schema despite the tool presumably taking input`);
      if (pctSnake < 1) issues.push(`${total - snakeCase} tool name(s) are not snake_case — mixed naming reads as inconsistent to directory scorers`);
      const dupes = analyzed.map((t) => t.name).filter((n, i, a) => a.indexOf(n) !== i);
      if (dupes.length) issues.push(`Duplicate tool names: ${[...new Set(dupes)].join(", ")}`);
      if (!protocolVersion) issues.push("Server did not report a protocol version in initialize");

      return {
        url,
        reachable: true,
        serverInfo,
        protocolVersion,
        toolCount: total,
        quality: {
          score,
          grade,
          pctDescribed: Math.round(pctDescribed * 100),
          avgDescriptionChars: avgDescChars,
          pctWithSchema: Math.round(pctSchema * 100),
          pctSnakeCaseNames: Math.round(pctSnake * 100),
        },
        tools: analyzed,
        issues,
      };
    },
  },
};

export type ToolName = keyof typeof tools;
