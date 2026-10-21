import { mapWithConcurrency } from "./shared";

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
  let lastData: any = null;
  while (Date.now() - start < maxWaitMs) {
    const res = await fetch(url, { headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" } });
    if (!res.ok) throw new Error(`SSL Labs API error: ${res.status} ${res.statusText}`);
    const data: any = await res.json();
    lastData = data;
    if (data.status === "READY" || data.status === "ERROR") return data;
    url = `${SSL_LABS_API}/analyze?host=${encodeURIComponent(host)}&all=done`;
    await new Promise((r) => setTimeout(r, 8000));
  }
  // Do not throw away a paid call because SSL Labs is slow on a cold cache:
  // return the latest in-progress state and tell the caller to re-check.
  if (lastData) {
    return {
      ...lastData,
      note: `SSL Labs assessment still ${String(lastData.status ?? "running").toLowerCase()} after ${Math.round(maxWaitMs / 1000)}s (cold cache scans take 1-2 minutes). Call again in about a minute for the completed grade; SSL Labs caches finished results for 24h.`,
    };
  }
  throw new Error(`SSL Labs did not return any assessment data for ${host}.`);
}

export const tools = {
  safe_browsing_check: {
    price: "$0.05",
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
    price: "$0.10",
    description:
      "Full SSL Labs-style TLS assessment: overall letter grade, protocol support (TLS 1.0-1.3), cipher strength, certificate chain issues, and known vulnerabilities (Heartbleed, POODLE, etc.) for each endpoint. Use this for a deep grade; use ssl_cert_check instead for a fast expiry/issuer check. Slower (can take up to ~90s on a cold cache; SSL Labs caches results for 24h server-side).",
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
        ...(data.note ? { note: data.note } : {}),
      };
    },
  },
  exposed_files_check: {
    price: "$0.05",
    description:
      "Probe a site for publicly exposed sensitive files attackers scan for: /.env and variants, /.git/config and /.git/HEAD, /.svn/entries, docker-compose files, /.aws/credentials, /.ssh/id_rsa, database dumps (backup.sql, db.sql, dump.sql), backup archives, phpinfo pages, .DS_Store, and similar. Reports ONLY reachability metadata (path, status, content type, size) — file contents are never returned or stored. A random-nonexistent-path baseline filters out SPA/catch-all false positives. For auditing your own sites' exposure.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Any URL on the site to probe (origin is derived from it)" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const origin = new URL(url).origin;

      const PATHS = [
        "/.env", "/.env.local", "/.env.production", "/.env.bak", "/.env.save",
        "/.git/config", "/.git/HEAD", "/.svn/entries",
        "/docker-compose.yml", "/docker-compose.yaml",
        "/.aws/credentials", "/.ssh/id_rsa",
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
        "/phpinfo.php", "/info.php",
        "/.DS_Store", "/wp-config.php.bak", "/config.php.bak", "/.npmrc", "/server-status",
      ];

      async function probe(path: string) {
        try {
          const res = await fetch(`${origin}${path}`, {
            headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
            redirect: "manual",
            signal: AbortSignal.timeout(10000),
          });
          let bytes = 0;
          if (res.body) {
            const reader = (res.body as any).getReader?.();
            if (reader) {
              try {
                while (bytes <= 65536) {
                  const { done, value } = await reader.read();
                  if (done) break;
                  bytes += value?.length ?? 0;
                }
              } catch {}
              try { await reader.cancel(); } catch {}
            } else {
              bytes = (await res.arrayBuffer()).byteLength;
            }
          }
          return {
            path,
            status: res.status,
            contentType: res.headers.get("content-type"),
            bytes,
            signature: `${res.status}|${res.headers.get("content-type") ?? ""}|${bytes}`,
          };
        } catch (e: any) {
          return { path, status: 0, contentType: null, bytes: 0, signature: `0||0`, error: e?.message ?? String(e) };
        }
      }

      const baselinePath = `/.toolbelt-nonexistent-${Math.random().toString(36).slice(2, 10)}`;
      const baseline = await probe(baselinePath);
      const results = await mapWithConcurrency(PATHS, 6, probe);

      const exposed = results
        .filter((r) => r.status === 200 && r.signature !== baseline.signature)
        .map((r) => ({ path: r.path, status: r.status, contentType: r.contentType, bytesApprox: r.bytes }));
      const inconclusive = results
        .filter((r) => r.status === 200 && r.signature === baseline.signature)
        .map((r) => r.path);

      return {
        origin,
        pathsProbed: PATHS.length,
        exposedCount: exposed.length,
        exposed,
        inconclusiveCount: inconclusive.length,
        inconclusivePaths: inconclusive,
        baselineStatus: baseline.status,
        note: "Only reachability metadata is reported; file contents are never returned. Paths matching the site's catch-all/SPA fallback signature are listed as inconclusive rather than exposed.",
        risk: exposed.length ? "HIGH - sensitive file(s) publicly reachable" : "No exposed sensitive files detected",
      };
    },
  },

};

export type ToolName = keyof typeof tools;
