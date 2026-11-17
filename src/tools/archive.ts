// archived_page_lookup: find the Internet Archive Wayback Machine snapshot of a URL nearest a date.
// Uses the public CDX API (closest-match sort), falling back to the availability API.
const UA = { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" };

function toWaybackTimestamp(date?: string): string {
  if (!date) return new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
  const t = String(date).trim();
  if (/^\d{4}(\d{2}){0,5}$/.test(t)) return t.padEnd(14, "0").slice(0, 14).replace(/^(\d{4})00/, "$101").replace(/^(\d{6})00/, "$101");
  const d = new Date(t);
  if (Number.isNaN(d.getTime())) throw new Error("date must be ISO (2015-01-01 or 2015-01-01T12:00:00Z) or a Wayback timestamp (20150101)");
  return d.toISOString().replace(/[-:T]/g, "").slice(0, 14);
}

function tsToIso(ts: string): string {
  const p = ts.padEnd(14, "0");
  return `${p.slice(0, 4)}-${p.slice(4, 6)}-${p.slice(6, 8)}T${p.slice(8, 10)}:${p.slice(10, 12)}:${p.slice(12, 14)}Z`;
}

function cleanTarget(url: string): string {
  const raw = String(url ?? "").trim();
  if (!raw) throw new Error("url is required");
  if (raw.length > 2000) throw new Error("url is too long");
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  const u = new URL(withScheme);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http(s) URLs can be looked up");
  return raw.replace(/^https?:\/\//i, "");
}

async function getJson(url: string, timeoutMs = 20_000): Promise<any> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { headers: UA, signal: controller.signal });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    return text.trim() ? JSON.parse(text) : [];
  } catch (e: any) {
    throw new Error(e?.name === "AbortError" ? "timeout" : e?.message ?? String(e));
  } finally {
    clearTimeout(timer);
  }
}

async function lookup(args: { url: string; date?: string; onlySuccessful?: boolean; alternatives?: number }) {
  const target = cleanTarget(args.url);
  const ts = toWaybackTimestamp(args.date);
  const onlyOk = args.onlySuccessful ?? true;
  const alternatives = Math.min(10, Math.max(0, Math.round(Number(args.alternatives ?? 4))));
  const targetMs = Date.parse(tsToIso(ts));

  const params = new URLSearchParams({
    url: target,
    output: "json",
    closest: ts,
    sort: "closest",
    limit: String(alternatives + 1),
    fl: "timestamp,original,statuscode,mimetype,digest,length",
  });
  if (onlyOk) params.append("filter", "statuscode:200");
  let rows: any[] | null = null;
  let cdxError: string | null = null;
  try {
    const data = await getJson(`https://web.archive.org/cdx/search/cdx?${params}`);
    rows = Array.isArray(data) ? data.slice(1) : [];
  } catch (e: any) {
    cdxError = e?.message ?? String(e);
  }

  const shape = (r: { timestamp: string; original: string; statuscode?: string | null; mimetype?: string | null; digest?: string | null; length?: string | null }) => {
    const iso = tsToIso(r.timestamp);
    return {
      timestamp: r.timestamp,
      capturedAt: iso,
      daysFromRequested: Math.round(((Date.parse(iso) - targetMs) / 86_400_000) * 10) / 10,
      snapshotUrl: `https://web.archive.org/web/${r.timestamp}/${r.original}`,
      rawContentUrl: `https://web.archive.org/web/${r.timestamp}id_/${r.original}`,
      originalUrl: r.original,
      httpStatus: r.statuscode && r.statuscode !== "-" ? Number(r.statuscode) : null,
      mimeType: r.mimetype ?? null,
      contentDigest: r.digest ?? null,
      archivedBytes: r.length ? Number(r.length) : null,
    };
  };

  if (rows) {
    const snaps = rows.map((r: string[]) => shape({ timestamp: r[0], original: r[1], statuscode: r[2], mimetype: r[3], digest: r[4], length: r[5] }));
    return {
      url: target,
      requestedDate: tsToIso(ts),
      found: snaps.length > 0,
      closest: snaps[0] ?? null,
      alternatives: snaps.slice(1),
      filter: onlyOk ? "HTTP 200 captures only" : "all captures (incl. redirects/errors)",
      source: "wayback-cdx",
      note: snaps.length ? null : "The Wayback Machine has no matching capture of this URL",
    };
  }

  // Fallback: availability API (closest only).
  try {
    const avail = await getJson(`https://archive.org/wayback/available?${new URLSearchParams({ url: target, timestamp: ts })}`);
    const c = avail?.archived_snapshots?.closest;
    const closest = c?.timestamp
      ? shape({ timestamp: c.timestamp, original: String(c.url).replace(/^https?:\/\/web\.archive\.org\/web\/\d+\//, ""), statuscode: c.status ?? null })
      : null;
    return {
      url: target,
      requestedDate: tsToIso(ts),
      found: !!closest,
      closest,
      alternatives: [],
      filter: "availability API (closest capture, any status)",
      source: "wayback-availability",
      note: `CDX index unavailable (${cdxError}); used the availability API instead`,
    };
  } catch (e: any) {
    throw new Error(`Wayback Machine is unreachable right now (CDX: ${cdxError}; availability: ${e?.message ?? e}). Retry later.`);
  }
}

export const tools = {
  archived_page_lookup: {
    price: "$0.01",
    description:
      "Find the Internet Archive Wayback Machine snapshot of a URL closest to a given date (default: now): capture time, how many days off it is, the viewable snapshot URL, a raw-content URL (original bytes, no Wayback toolbar), HTTP status, MIME type and content digest, plus a few next-closest captures. Defaults to successful (HTTP 200) captures only. Uses the public CDX index with an availability-API fallback. Good for seeing what a page said on a past date or proving when content changed.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Page or domain to look up, e.g. example.com or https://example.com/pricing" },
        date: { type: "string", description: "Target date: ISO (2015-01-01 or 2015-01-01T12:00:00Z) or Wayback timestamp (20150101). Default now" },
        onlySuccessful: { type: "boolean", description: "Only consider HTTP 200 captures (default true)" },
        alternatives: { type: "number", description: "How many next-closest captures to include, 0-10 (default 4)" },
      },
      required: ["url"],
    },
    async run(args: any) {
      return lookup(args);
    },
  },
};

export type ToolName = keyof typeof tools;
