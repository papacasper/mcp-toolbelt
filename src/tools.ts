import { connect as tlsConnect } from "node:tls";
import { connect as netConnect } from "node:net";
import { promises as dns } from "node:dns";

function whoisQuery(server: string, query: string, timeoutMs = 6000): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: server, port: 43, timeout: timeoutMs });
    let data = "";
    socket.on("connect", () => socket.write(query + "\r\n"));
    socket.on("data", (chunk) => (data += chunk.toString("utf8")));
    socket.on("end", () => resolve(data));
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`WHOIS query to ${server} timed out`));
    });
    socket.on("error", reject);
  });
}

function extractWhoisField(raw: string, labels: string[]): string | null {
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    for (const label of labels) {
      if (line.toLowerCase().startsWith(label.toLowerCase())) {
        const value = line.slice(line.indexOf(":") + 1).trim();
        if (value) return value;
      }
    }
  }
  return null;
}

async function lookupDomainWhois(domain: string): Promise<{
  registrar: string | null;
  createdDate: string | null;
  expiryDate: string | null;
  daysRemaining: number | null;
  expired: boolean | null;
  whoisServer: string | null;
}> {
  const ianaRaw = await whoisQuery("whois.iana.org", domain);
  const referral = extractWhoisField(ianaRaw, ["refer", "whois"]);
  const server = referral || "whois.iana.org";

  let raw = ianaRaw;
  if (referral && referral !== "whois.iana.org") {
    try {
      raw = await whoisQuery(referral, domain);
    } catch {
      // fall back to the IANA response if the registry's own whois is unreachable
    }
  }

  const expiryRaw = extractWhoisField(raw, [
    "Registry Expiry Date",
    "Registrar Registration Expiration Date",
    "Expiration Date",
    "Expiry Date",
    "paid-till",
  ]);
  const createdRaw = extractWhoisField(raw, ["Creation Date", "Created On", "Domain Registration Date", "created"]);
  const registrar = extractWhoisField(raw, ["Registrar:", "Registrar Name", "sponsoring registrar"]);

  const expiryDate = expiryRaw ? new Date(expiryRaw) : null;
  const daysRemaining =
    expiryDate && !Number.isNaN(expiryDate.getTime())
      ? Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
      : null;

  return {
    registrar,
    createdDate: createdRaw ? new Date(createdRaw).toISOString().slice(0, 10) : null,
    expiryDate: expiryDate && !Number.isNaN(expiryDate.getTime()) ? expiryDate.toISOString().slice(0, 10) : null,
    daysRemaining,
    expired: daysRemaining === null ? null : daysRemaining < 0,
    whoisServer: server,
  };
}

async function lookupDnsHealth(domain: string) {
  async function safe<T>(fn: () => Promise<T>): Promise<T | null> {
    try {
      return await fn();
    } catch {
      return null;
    }
  }

  const [ns, a, aaaa, mx, txt, dmarcTxt, dkimTxt] = await Promise.all([
    safe(() => dns.resolveNs(domain)),
    safe(() => dns.resolve4(domain)),
    safe(() => dns.resolve6(domain)),
    safe(() => dns.resolveMx(domain)),
    safe(() => dns.resolveTxt(domain)),
    safe(() => dns.resolveTxt(`_dmarc.${domain}`)),
    safe(() => dns.resolveTxt(`default._domainkey.${domain}`)),
  ]);

  const flatten = (records: string[][] | null) => records?.map((r) => r.join("")) ?? [];
  const txtFlat = flatten(txt);
  const spf = txtFlat.find((t) => t.toLowerCase().startsWith("v=spf1")) ?? null;
  const dmarc = flatten(dmarcTxt).find((t) => t.toLowerCase().startsWith("v=dmarc1")) ?? null;
  const dkim = flatten(dkimTxt)[0] ?? null;

  return {
    nameservers: ns ?? [],
    a: a ?? [],
    aaaa: aaaa ?? [],
    mx: (mx ?? []).sort((x, y) => x.priority - y.priority).map((m) => `${m.priority} ${m.exchange}`),
    spf,
    dmarc,
    dkimSelectorChecked: "default",
    dkim,
    issues: [
      !ns?.length && "No nameservers found",
      !mx?.length && "No MX records found",
      !spf && "No SPF record found",
      !dmarc && "No DMARC record found",
    ].filter(Boolean) as string[],
  };
}

function checkCertExpiry(hostname: string, port: number, timeoutMs = 8000): Promise<{
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  expired: boolean;
}> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect(
      { host: hostname, port, servername: hostname, timeout: timeoutMs },
      () => {
        try {
          const cert = socket.getPeerCertificate();
          socket.end();
          if (!cert || !cert.valid_to) {
            reject(new Error("No certificate presented"));
            return;
          }
          const validTo = new Date(cert.valid_to);
          const daysRemaining = Math.ceil((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
          resolve({
            subject: cert.subject?.CN ?? hostname,
            issuer: cert.issuer?.CN ?? "unknown",
            validFrom: new Date(cert.valid_from).toISOString(),
            validTo: validTo.toISOString(),
            daysRemaining,
            expired: daysRemaining < 0,
          });
        } catch (e) {
          reject(e);
        }
      }
    );
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error(`Connection to ${hostname}:${port} timed out`));
    });
    socket.on("error", reject);
  });
}

function stripHtml(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|h[1-6]|li|tr)>/gi, "\n")
    .replace(/<li>/gi, "- ")
    .replace(/<[^>]+>/g, "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function extractTag(html: string, tag: string): string | null {
  const m = html.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return m ? m[1].trim() : null;
}

function extractMeta(html: string, name: string): string | null {
  const m = html.match(
    new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']*)["']`, "i")
  ) || html.match(
    new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+name=["']${name}["']`, "i")
  );
  return m ? m[1].trim() : null;
}

async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
  return await res.text();
}

interface HeaderCheck {
  header: string;
  present: boolean;
  value: string | null;
  severity: "info" | "warn" | "fail";
  issue: string | null;
}

function auditSecurityHeaders(headers: Headers, isHttps: boolean): { checks: HeaderCheck[]; score: number } {
  const get = (name: string) => headers.get(name);
  const checks: HeaderCheck[] = [];

  const hsts = get("strict-transport-security");
  checks.push({
    header: "Strict-Transport-Security",
    present: !!hsts,
    value: hsts,
    severity: isHttps && !hsts ? "fail" : "info",
    issue: isHttps && !hsts ? "Missing HSTS — allows protocol downgrade attacks" : null,
  });

  const csp = get("content-security-policy");
  checks.push({
    header: "Content-Security-Policy",
    present: !!csp,
    value: csp,
    severity: csp ? "info" : "warn",
    issue: csp ? null : "Missing CSP — no defense-in-depth against XSS/injection",
  });

  const xfo = get("x-frame-options");
  const cspFrameAncestors = csp?.toLowerCase().includes("frame-ancestors") ?? false;
  checks.push({
    header: "X-Frame-Options",
    present: !!xfo,
    value: xfo,
    severity: xfo || cspFrameAncestors ? "info" : "warn",
    issue: xfo || cspFrameAncestors ? null : "Missing X-Frame-Options/CSP frame-ancestors — clickjacking risk",
  });

  const xcto = get("x-content-type-options");
  checks.push({
    header: "X-Content-Type-Options",
    present: !!xcto,
    value: xcto,
    severity: xcto?.toLowerCase() === "nosniff" ? "info" : "warn",
    issue: xcto?.toLowerCase() === "nosniff" ? null : "Missing or invalid X-Content-Type-Options — MIME sniffing risk",
  });

  const refPolicy = get("referrer-policy");
  checks.push({
    header: "Referrer-Policy",
    present: !!refPolicy,
    value: refPolicy,
    severity: refPolicy ? "info" : "warn",
    issue: refPolicy ? null : "Missing Referrer-Policy — full URLs may leak to third parties on outbound links",
  });

  const permsPolicy = get("permissions-policy");
  checks.push({
    header: "Permissions-Policy",
    present: !!permsPolicy,
    value: permsPolicy,
    severity: "info",
    issue: null,
  });

  const xssProtection = get("x-xss-protection");
  checks.push({
    header: "X-XSS-Protection",
    present: !!xssProtection,
    value: xssProtection,
    severity: "info",
    issue: null,
  });

  const failCount = checks.filter((c) => c.severity === "fail").length;
  const warnCount = checks.filter((c) => c.severity === "warn").length;
  const score = Math.max(0, 100 - failCount * 25 - warnCount * 10);

  return { checks, score };
}

function extractLinks(html: string, baseUrl: string): string[] {
  const links = new Set<string>();
  const re = /<a\s[^>]*href=["']([^"'#][^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      const resolved = new URL(m[1], baseUrl);
      if (resolved.protocol === "http:" || resolved.protocol === "https:") {
        resolved.hash = "";
        links.add(resolved.toString());
      }
    } catch {
      // skip unparseable hrefs (mailto:, javascript:, malformed, etc.)
    }
  }
  return [...links];
}

async function checkLinkStatus(url: string, timeoutMs = 8000): Promise<{ status: number | null; ok: boolean; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let res = await fetch(url, { method: "HEAD", redirect: "follow", signal: controller.signal });
    if (res.status === 405 || res.status === 501) {
      res = await fetch(url, { method: "GET", redirect: "follow", signal: controller.signal });
    }
    return { status: res.status, ok: res.ok };
  } catch (e: any) {
    return { status: null, ok: false, error: e?.name === "AbortError" ? "timeout" : (e?.message ?? String(e)) };
  } finally {
    clearTimeout(timer);
  }
}

async function mapWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await fn(items[i]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

async function crawlBrokenLinks(
  startUrl: string,
  maxPages: number,
  checkExternal: boolean
) {
  const start = new URL(startUrl);
  const origin = start.origin;

  const visited = new Set<string>();
  const queue: string[] = [start.toString()];
  const linkSources = new Map<string, Set<string>>();

  while (queue.length && visited.size < maxPages) {
    const page = queue.shift()!;
    if (visited.has(page)) continue;
    visited.add(page);

    let html: string;
    try {
      html = await fetchText(page);
    } catch {
      continue;
    }

    for (const link of extractLinks(html, page)) {
      if (!linkSources.has(link)) linkSources.set(link, new Set());
      linkSources.get(link)!.add(page);

      const linkUrl = new URL(link);
      const sameOrigin = linkUrl.origin === origin;
      if (sameOrigin && !visited.has(link) && !queue.includes(link) && visited.size + queue.length < maxPages) {
        queue.push(link);
      }
    }
  }

  const allLinks = [...linkSources.keys()].filter((link) => checkExternal || new URL(link).origin === origin);
  const capped = allLinks.slice(0, 200);

  const statuses = await mapWithConcurrency(capped, 8, (link) => checkLinkStatus(link));

  const broken = capped
    .map((link, i) => ({ url: link, ...statuses[i], foundOn: [...(linkSources.get(link) ?? [])] }))
    .filter((r) => !r.ok);

  return {
    pagesCrawled: visited.size,
    linksChecked: capped.length,
    linksTruncated: allLinks.length > capped.length,
    brokenCount: broken.length,
    brokenLinks: broken,
  };
}

const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443, 27017];

function checkPort(host: string, port: number, timeoutMs = 2500): Promise<{ port: number; state: "open" | "closed" | "filtered" }> {
  return new Promise((resolve) => {
    const socket = netConnect({ host, port, timeout: timeoutMs });
    const finish = (state: "open" | "closed" | "filtered") => {
      socket.destroy();
      resolve({ port, state });
    };
    socket.on("connect", () => finish("open"));
    socket.on("timeout", () => finish("filtered"));
    socket.on("error", (err: any) => finish(err?.code === "ECONNREFUSED" ? "closed" : "filtered"));
  });
}

async function scanPorts(host: string, ports: number[], timeoutMs = 2500) {
  const results = await mapWithConcurrency(ports, 20, (port) => checkPort(host, port, timeoutMs));
  results.sort((a, b) => a.port - b.port);
  return {
    host,
    portsScanned: results.length,
    open: results.filter((r) => r.state === "open").map((r) => r.port),
    closed: results.filter((r) => r.state === "closed").map((r) => r.port),
    filtered: results.filter((r) => r.state === "filtered").map((r) => r.port),
    results,
  };
}

export const tools = {
  url_to_markdown: {
    price: "$0.0001",
    description: "Fetch a URL and return its main text content as clean, readable plain text/markdown-ish output. Strips scripts, styles, and HTML tags.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to fetch" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const html = await fetchText(url);
      const title = extractTag(html, "title") ?? "";
      const body = stripHtml(html);
      const truncated = body.length > 20000 ? body.slice(0, 20000) + "\n\n[truncated]" : body;
      return { title, content: truncated, sourceUrl: url };
    },
  },

  seo_audit: {
    price: "$0.0002",
    description: "Fetch a URL and run a basic SEO audit: title, meta description, H1 count, word count, and robots.txt/sitemap.xml presence.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to audit" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const html = await fetchText(url);
      const title = extractTag(html, "title");
      const description = extractMeta(html, "description");
      const h1Matches = html.match(/<h1[\s>]/gi) || [];
      const wordCount = stripHtml(html).split(/\s+/).filter(Boolean).length;

      const origin = new URL(url).origin;
      const [robotsOk, sitemapOk] = await Promise.all([
        fetch(`${origin}/robots.txt`).then((r) => r.ok).catch(() => false),
        fetch(`${origin}/sitemap.xml`).then((r) => r.ok).catch(() => false),
      ]);

      const issues: string[] = [];
      if (!title) issues.push("Missing <title> tag");
      else if (title.length > 60) issues.push("Title longer than 60 characters");
      if (!description) issues.push("Missing meta description");
      else if (description.length > 160) issues.push("Meta description longer than 160 characters");
      if (h1Matches.length === 0) issues.push("No <h1> found");
      if (h1Matches.length > 1) issues.push(`Multiple <h1> tags found (${h1Matches.length})`);
      if (!robotsOk) issues.push("No robots.txt found");
      if (!sitemapOk) issues.push("No sitemap.xml found");

      return {
        url,
        title,
        description,
        h1Count: h1Matches.length,
        wordCount,
        hasRobotsTxt: robotsOk,
        hasSitemapXml: sitemapOk,
        issues,
        score: Math.max(0, 100 - issues.length * 12),
      };
    },
  },

  check_robots_sitemap: {
    price: "$0.0001",
    description: "Check whether a site has a valid robots.txt and sitemap.xml, and return their raw contents (truncated).",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Any URL on the site to check (origin is derived from it)" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const origin = new URL(url).origin;
      async function safeFetch(path: string) {
        try {
          const res = await fetch(`${origin}${path}`);
          if (!res.ok) return { found: false, status: res.status };
          const text = await res.text();
          return { found: true, status: res.status, content: text.slice(0, 3000) };
        } catch (e) {
          return { found: false, error: String(e) };
        }
      }
      const [robots, sitemap] = await Promise.all([
        safeFetch("/robots.txt"),
        safeFetch("/sitemap.xml"),
      ]);
      return { origin, robots, sitemap };
    },
  },

  ssl_cert_check: {
    price: "$0.0002",
    description: "Connect to a host over TLS and report its certificate's expiry date, days remaining, issuer, and subject.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: { type: "string", description: "Hostname to check, e.g. papacasper.com (no scheme/path)" },
        port: { type: "number", description: "TLS port to connect to (default 443)" },
      },
      required: ["hostname"],
    },
    async run({ hostname, port }: { hostname: string; port?: number }) {
      const cleanHost = hostname.replace(/^https?:\/\//, "").split("/")[0];
      const result = await checkCertExpiry(cleanHost, port ?? 443);
      return { hostname: cleanHost, port: port ?? 443, ...result };
    },
  },

  domain_health_check: {
    price: "$0.0005",
    description:
      "Check a domain's registration expiry (via WHOIS) and DNS health: nameservers, A/AAAA, MX, SPF, and DMARC records. Flags common misconfigurations.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Bare domain to check, e.g. example.com (no scheme/path)" },
      },
      required: ["domain"],
    },
    async run({ domain }: { domain: string }) {
      const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
      const [whois, dnsHealth] = await Promise.all([
        lookupDomainWhois(cleanDomain).catch((e) => ({ error: e?.message ?? String(e) })),
        lookupDnsHealth(cleanDomain),
      ]);
      return { domain: cleanDomain, whois, dns: dnsHealth };
    },
  },

  broken_link_check: {
    price: "$0.001",
    description:
      "Crawl a site starting from a URL (same-origin pages only, bounded by maxPages) and check every linked URL for broken status codes. Returns broken links with the page(s) they were found on. Note: some external sites (e.g. social platforms) block automated HEAD/GET requests and may show up as false positives.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Starting URL to crawl" },
        maxPages: { type: "number", description: "Max same-origin pages to crawl (default 20, capped at 50)" },
        checkExternal: { type: "boolean", description: "Also check links pointing off-site (default true; crawling never follows off-site links)" },
      },
      required: ["url"],
    },
    async run({ url, maxPages, checkExternal }: { url: string; maxPages?: number; checkExternal?: boolean }) {
      const cappedMaxPages = Math.max(1, Math.min(maxPages ?? 20, 50));
      return crawlBrokenLinks(url, cappedMaxPages, checkExternal ?? true);
    },
  },

  check_open_ports: {
    price: "$0.0003",
    description:
      "TCP-connect scan a host for open ports. Defaults to a list of ~20 common service ports (SSH, HTTP/S, mail, DBs, etc.) if none are given. For checking your own infrastructure's exposure — capped at 100 ports per call.",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string", description: "Hostname or IP to scan (no scheme)" },
        ports: {
          type: "array",
          items: { type: "number" },
          description: "Specific ports to check. Defaults to a common-ports list. Max 100 ports per call.",
        },
      },
      required: ["host"],
    },
    async run({ host, ports }: { host: string; ports?: number[] }) {
      const cleanHost = host.replace(/^https?:\/\//, "").split("/")[0];
      const list = (ports?.length ? ports : COMMON_PORTS)
        .filter((p) => Number.isInteger(p) && p > 0 && p <= 65535)
        .slice(0, 100);
      return scanPorts(cleanHost, list);
    },
  },

  security_headers_audit: {
    price: "$0.0002",
    description:
      "Fetch a URL and audit its response for security-relevant HTTP headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy). Flags missing/misconfigured headers with a score.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to audit" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const res = await fetch(url, {
        headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
        redirect: "follow",
      });
      const { checks, score } = auditSecurityHeaders(res.headers, new URL(res.url).protocol === "https:");
      return {
        url: res.url,
        status: res.status,
        score,
        checks,
      };
    },
  },
};

export type ToolName = keyof typeof tools;
