import { fetchText, extractTag, stripHtml } from "./shared";

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

async function traceRedirectChain(startUrl: string, maxHops = 10) {
  const hops: Array<{ url: string; status: number; location: string | null }> = [];
  const seen = new Set<string>();
  let current = startUrl;

  while (hops.length < maxHops) {
    if (seen.has(current)) {
      hops.push({ url: current, status: 0, location: null });
      return {
        startUrl,
        hops,
        finalUrl: current,
        redirectCount: hops.length - 1,
        issues: ["Redirect loop detected — a URL was visited twice"],
      };
    }
    seen.add(current);

    let res: Response;
    try {
      res = await fetch(current, {
        method: "HEAD",
        redirect: "manual",
        headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
      });
    } catch (e: any) {
      hops.push({ url: current, status: 0, location: null });
      return {
        startUrl,
        hops,
        finalUrl: current,
        redirectCount: hops.length - 1,
        issues: [`Request failed: ${e?.message ?? String(e)}`],
      };
    }

    const isRedirect = res.status >= 300 && res.status < 400;
    const location = isRedirect ? res.headers.get("location") : null;
    hops.push({ url: current, status: res.status, location });

    if (!isRedirect || !location) break;
    current = new URL(location, current).toString();
  }

  const issues: string[] = [];
  if (hops.length >= maxHops && hops[hops.length - 1].location) {
    issues.push(`Hit the ${maxHops}-hop limit without resolving — possible redirect chain that's too long`);
  }
  for (let i = 0; i < hops.length - 1; i++) {
    if (hops[i].url.startsWith("https://") && hops[i + 1]?.url.startsWith("http://")) {
      issues.push(`Downgrades from HTTPS to HTTP between hop ${i + 1} and ${i + 2}`);
    }
  }
  if (hops.length > 3) issues.push(`${hops.length - 1} redirects — consider shortening the chain for SEO/performance`);

  return {
    startUrl,
    hops,
    finalUrl: hops[hops.length - 1]?.url ?? startUrl,
    redirectCount: Math.max(0, hops.length - 1),
    issues,
  };
}

async function checkPagePerformance(url: string) {
  const started = performance.now();
  const res = await fetch(url, {
    headers: {
      "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)",
      "Accept-Encoding": "gzip, br",
    },
    redirect: "follow",
  });
  const ttfbMs = Math.round(performance.now() - started);

  const body = await res.arrayBuffer();
  const totalMs = Math.round(performance.now() - started);
  const bodyBytes = body.byteLength;

  const contentEncoding = res.headers.get("content-encoding");
  const cacheControl = res.headers.get("cache-control");
  const contentLength = res.headers.get("content-length");

  const issues: string[] = [];
  if (!contentEncoding) issues.push("No compression (gzip/br) — response is sent uncompressed");
  if (!cacheControl) issues.push("No Cache-Control header — browsers/CDNs can't cache the response");
  if (bodyBytes > 2_000_000) issues.push(`Large response body (${(bodyBytes / 1_000_000).toFixed(1)}MB) — consider reducing payload size`);
  if (ttfbMs > 800) issues.push(`Slow time-to-first-byte (${ttfbMs}ms) — server response is slow`);

  return {
    url: res.url,
    status: res.status,
    ttfbMs,
    totalMs,
    bodyBytes,
    contentLengthHeader: contentLength ? Number(contentLength) : null,
    contentEncoding,
    cacheControl,
    issues,
  };
}

const PROBE_ORIGIN = "https://example.org";

function auditCors(headers: Headers, probeOrigin: string) {
  const allowOrigin = headers.get("access-control-allow-origin");
  const allowCreds = headers.get("access-control-allow-credentials");
  const allowMethods = headers.get("access-control-allow-methods");
  const allowHeaders = headers.get("access-control-allow-headers");

  const issues: string[] = [];
  const reflectsOrigin = allowOrigin === probeOrigin;
  if (allowOrigin === "*" && allowCreds?.toLowerCase() === "true") {
    issues.push("Access-Control-Allow-Origin: * combined with Allow-Credentials: true — invalid/dangerous combination");
  }
  if (reflectsOrigin) {
    issues.push(`Reflects arbitrary Origin header back (echoed "${probeOrigin}") — effectively allows any origin`);
  }

  return {
    allowOrigin,
    allowCredentials: allowCreds,
    allowMethods,
    allowHeaders,
    reflectsArbitraryOrigin: reflectsOrigin,
    wildcard: allowOrigin === "*",
    issues,
  };
}

function extractJsonLd(html: string): unknown[] {
  const blocks: unknown[] = [];
  const re = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      blocks.push(JSON.parse(m[1].trim()));
    } catch {
      // skip malformed JSON-LD blocks
    }
  }
  return blocks;
}

function extractOpenGraph(html: string): Record<string, string> {
  const og: Record<string, string> = {};
  const re = /<meta[^>]+property=["']og:([^"']+)["'][^>]+content=["']([^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) og[m[1]] = m[2];
  return og;
}

async function extractBySelector(html: string, selector: string, attr?: string): Promise<string[]> {
  if (attr) {
    const values: string[] = [];
    const rewriter = new HTMLRewriter().on(selector, {
      element(el) {
        const v = el.getAttribute(attr);
        if (v !== null) values.push(v);
      },
    });
    await rewriter.transform(new Response(html)).text();
    return values;
  }
  const values: string[] = [];
  const rewriter = new HTMLRewriter().on(selector, {
    element() {
      values.push("");
    },
    text(t) {
      if (values.length === 0) values.push("");
      values[values.length - 1] += t.text;
    },
  });
  await rewriter.transform(new Response(html)).text();
  return values.map((v) => v.replace(/\s+/g, " ").trim()).filter(Boolean);
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

  redirect_chain_check: {
    price: "$0.0002",
    description:
      "Follow a URL through every HTTP redirect hop and report the full chain, final destination, and issues like redirect loops, too many hops, or HTTPS-to-HTTP downgrades.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The starting URL to trace" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      return traceRedirectChain(url);
    },
  },

  page_performance_check: {
    price: "$0.0002",
    description:
      "Fetch a URL and measure time-to-first-byte, total fetch time, and response size. Flags missing compression, missing Cache-Control, oversized payloads, and slow TTFB.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to measure" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      return checkPagePerformance(url);
    },
  },

  cors_policy_check: {
    price: "$0.0002",
    description:
      "Send a probe request with a foreign Origin header to a URL and report its CORS response headers. Flags wildcard-origin + credentials combinations and arbitrary-origin reflection, both common CORS misconfigurations.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to probe" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const res = await fetch(url, {
        method: "GET",
        headers: {
          "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)",
          Origin: PROBE_ORIGIN,
        },
        redirect: "follow",
      });
      return { url: res.url, status: res.status, probeOrigin: PROBE_ORIGIN, cors: auditCors(res.headers, PROBE_ORIGIN) };
    },
  },

  structured_data_extract: {
    price: "$0.0003",
    description:
      "Fetch a URL and extract structured data deterministically: JSON-LD blocks, OpenGraph/meta tags, and optional caller-supplied CSS-selector fields (e.g. { price: '.product-price', title: 'h1' }). No LLM involved — pure HTML parsing via CSS selectors, so results are exact matches only, not summarized or inferred.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to extract from" },
        selectors: {
          type: "object",
          description:
            "Optional map of field name -> CSS selector (e.g. { price: '.product-price', headline: 'h1' }). Each field returns an array of matched, whitespace-normalized text values in document order.",
          additionalProperties: { type: "string" },
        },
        attr: {
          type: "string",
          description:
            "Optional HTML attribute to extract instead of text content (e.g. 'href', 'src', 'content'). Applies to all selector fields in this call.",
        },
      },
      required: ["url"],
    },
    async run({ url, selectors, attr }: { url: string; selectors?: Record<string, string>; attr?: string }) {
      const res = await fetch(url, {
        headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
        redirect: "follow",
      });
      if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
      const html = await res.text();

      const fields: Record<string, string[]> = {};
      if (selectors) {
        for (const [field, selector] of Object.entries(selectors)) {
          fields[field] = await extractBySelector(html, selector, attr);
        }
      }

      return {
        url: res.url,
        status: res.status,
        title: extractTag(html, "title"),
        jsonLd: extractJsonLd(html),
        openGraph: extractOpenGraph(html),
        fields,
      };
    },
  },

  tech_stack_fingerprint: {
    price: "$0.0002",
    description:
      "Fetch a URL and fingerprint its likely tech stack from response headers (server, x-powered-by, x-generator) and HTML markers (generator meta tag, framework/CMS-specific script or class patterns). Best-effort — not exhaustive, no additional paths are probed.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to fingerprint" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const res = await fetch(url, {
        headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
        redirect: "follow",
      });
      const html = await res.text();

      const headerHints: Record<string, string> = {};
      for (const h of ["server", "x-powered-by", "x-generator", "x-drupal-cache", "x-varnish"]) {
        const v = res.headers.get(h);
        if (v) headerHints[h] = v;
      }

      const generatorMeta = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']*)["']/i)?.[1] ?? null;

      const markers: Array<{ label: string; pattern: RegExp }> = [
        { label: "WordPress", pattern: /wp-content|wp-includes|\/wp-json\// },
        { label: "Next.js", pattern: /__NEXT_DATA__|_next\/static/ },
        { label: "React", pattern: /data-reactroot|react-dom/ },
        { label: "Vue", pattern: /data-v-app|__VUE__/ },
        { label: "Shopify", pattern: /cdn\.shopify\.com|Shopify\.theme/ },
        { label: "Squarespace", pattern: /squarespace-cdn|static1\.squarespace/ },
        { label: "Wix", pattern: /wix\.com|wixstatic\.com/ },
        { label: "Webflow", pattern: /webflow\.com|data-wf-site/ },
        { label: "Ghost", pattern: /ghost-url|content\/images\/\d{4}\// },
        { label: "Laravel", pattern: /laravel_session|XSRF-TOKEN/ },
        { label: "Django", pattern: /csrfmiddlewaretoken/ },
        { label: "Astro", pattern: /astro-island|data-astro-cid/ },
      ];
      const htmlMatches = markers.filter((m) => m.pattern.test(html)).map((m) => m.label);

      return {
        url: res.url,
        status: res.status,
        headerHints,
        generatorMeta,
        htmlMatches,
        note: "Best-effort fingerprinting from public headers/markup only.",
      };
    },
  },
};

export type ToolName = keyof typeof tools;
