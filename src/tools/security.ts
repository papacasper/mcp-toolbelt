const SAFE_BROWSING_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY ?? "";

async function safeBrowsingLookup(url: string) {
  if (!SAFE_BROWSING_KEY) {
    throw new Error(
      "GOOGLE_SAFE_BROWSING_API_KEY is not configured on the server. Get a free key at https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com"
    );
  }
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_KEY}`;
  const body = {
    client: { clientId: "mcp-toolbelt", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`Safe Browsing API error: ${res.status} ${res.statusText}`);
  const data = (await res.json()) as { matches?: Array<{ threatType: string; platformType: string }> };
  const matches = data.matches ?? [];
  return {
    url,
    flagged: matches.length > 0,
    threats: matches.map((m) => ({ threatType: m.threatType, platformType: m.platformType })),
  };
}

const SSL_LABS_API = "https://api.ssllabs.com/api/v3";

async function pollSslLabs(host: string, maxWaitMs = 90000): Promise<any> {
  const start = Date.now();
  let url = `${SSL_LABS_API}/analyze?host=${encodeURIComponent(host)}&all=done&fromCache=on&maxAge=24`;
  while (Date.now() - start < maxWaitMs) {
    const res = await fetch(url, { headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" } });
    if (!res.ok) throw new Error(`SSL Labs API error: ${res.status} ${res.statusText}`);
    const data: any = await res.json();
    if (data.status === "READY" || data.status === "ERROR") return data;
    url = `${SSL_LABS_API}/analyze?host=${encodeURIComponent(host)}&all=done`;
    await new Promise((r) => setTimeout(r, 8000));
  }
  throw new Error(`SSL Labs assessment for ${host} did not finish within ${Math.round(maxWaitMs / 1000)}s — SSL Labs scans can take 1-2 minutes on a cold cache. Try again shortly; results are cached for 24h.`);
}

export const tools = {
  safe_browsing_check: {
    price: "$0.001",
    description:
      "Check a URL against Google Safe Browsing's malware/phishing/unwanted-software/PUA blocklists. Requires GOOGLE_SAFE_BROWSING_API_KEY to be configured server-side (free Google Cloud API key).",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to check" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      return safeBrowsingLookup(url);
    },
  },

  ssl_labs_grade: {
    price: "$0.01",
    description:
      "Full SSL Labs-style TLS assessment: overall letter grade, protocol support (TLS 1.0-1.3), cipher strength, certificate chain issues, and known vulnerabilities (Heartbleed, POODLE, etc.) for each endpoint. Slower than ssl_cert_check (can take up to ~90s on a cold cache; SSL Labs caches results for 24h server-side).",
    inputSchema: {
      type: "object",
      properties: {
        hostname: { type: "string", description: "Hostname to assess, e.g. example.com (no scheme/path)" },
      },
      required: ["hostname"],
    },
    async run({ hostname }: { hostname: string }) {
      const cleanHost = hostname.replace(/^https?:\/\//, "").split("/")[0];
      const data = await pollSslLabs(cleanHost);
      if (data.status === "ERROR") {
        return { hostname: cleanHost, status: "ERROR", statusMessage: data.statusMessage ?? "Unknown error" };
      }
      const endpoints = (data.endpoints ?? []).map((ep: any) => ({
        ipAddress: ep.ipAddress,
        grade: ep.grade ?? null,
        hasWarnings: !!ep.hasWarnings,
        isExceptional: !!ep.isExceptional,
        progress: ep.progress,
        statusMessage: ep.statusMessage,
        protocols: (ep.details?.protocols ?? []).map((p: any) => `${p.name} ${p.version}`),
        vulnBeast: ep.details?.vulnBeast,
        heartbleed: ep.details?.heartbleed,
        poodle: ep.details?.poodle,
        poodleTls: ep.details?.poodleTls,
        freak: ep.details?.freak,
        logjam: ep.details?.logjam,
        drownVulnerable: ep.details?.drownVulnerable,
      }));
      return {
        hostname: cleanHost,
        status: data.status,
        endpoints,
      };
    },
  },
};

export type ToolName = keyof typeof tools;
