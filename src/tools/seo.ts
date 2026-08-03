import { fetchText, extractTag, extractMeta, stripHtml, extractLinks, checkLinkStatus, mapWithConcurrency } from "./shared";

async function headExists(url: string): Promise<{ found: boolean; status: number | null; contentType: string | null }> {
  try {
    const res = await fetch(url, { method: "HEAD", redirect: "follow" });
    return { found: res.ok, status: res.status, contentType: res.headers.get("content-type") };
  } catch {
    return { found: false, status: null, contentType: null };
  }
}

const JSON_LD_REQUIRED_FIELDS: Record<string, string[]> = {
  Article: ["headline", "datePublished"],
  NewsArticle: ["headline", "datePublished"],
  BlogPosting: ["headline", "datePublished"],
  Product: ["name"],
  Organization: ["name"],
  BreadcrumbList: ["itemListElement"],
  WebSite: ["name", "url"],
  LocalBusiness: ["name", "address"],
  Person: ["name"],
  FAQPage: ["mainEntity"],
};

function validateJsonLdBlock(block: any, index: number) {
  const errors: string[] = [];
  const types = Array.isArray(block?.["@type"]) ? block["@type"] : [block?.["@type"]].filter(Boolean);

  if (!block?.["@context"]) errors.push("Missing @context");
  else if (!String(block["@context"]).includes("schema.org")) errors.push("@context does not reference schema.org");
  if (!types.length) errors.push("Missing @type");

  for (const type of types) {
    const required = JSON_LD_REQUIRED_FIELDS[type];
    if (!required) continue;
    for (const field of required) {
      if (block[field] === undefined || block[field] === null || block[field] === "") {
        errors.push(`@type "${type}" is missing required field "${field}"`);
      }
    }
  }

  return { index, types, valid: errors.length === 0, errors };
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

export const tools = {
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

  favicon_manifest_check: {
    price: "$0.0001",
    description:
      "Check a site for favicon, apple-touch-icon, web app manifest, and theme-color presence — a quick completeness check for browser/OS chrome and PWA metadata.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Any URL on the site to check (origin is derived from it)" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const origin = new URL(url).origin;
      const html = await fetchText(url).catch(() => "");

      const iconHref = html.match(/<link[^>]+rel=["'](?:shortcut icon|icon)["'][^>]+href=["']([^"']+)["']/i)?.[1]
        ?? html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:shortcut icon|icon)["']/i)?.[1]
        ?? null;
      const appleTouchHref = html.match(/<link[^>]+rel=["']apple-touch-icon["'][^>]+href=["']([^"']+)["']/i)?.[1]
        ?? html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["']apple-touch-icon["']/i)?.[1]
        ?? null;
      const manifestHref = html.match(/<link[^>]+rel=["']manifest["'][^>]+href=["']([^"']+)["']/i)?.[1]
        ?? html.match(/<link[^>]+href=["']([^"']+)["'][^>]+rel=["']manifest["']/i)?.[1]
        ?? null;
      const themeColor = extractMeta(html, "theme-color");

      const [favicon, appleTouchIcon, manifest, defaultFaviconIco] = await Promise.all([
        iconHref ? headExists(new URL(iconHref, url).toString()) : Promise.resolve({ found: false, status: null, contentType: null }),
        appleTouchHref ? headExists(new URL(appleTouchHref, url).toString()) : Promise.resolve({ found: false, status: null, contentType: null }),
        manifestHref ? headExists(new URL(manifestHref, url).toString()) : Promise.resolve({ found: false, status: null, contentType: null }),
        headExists(`${origin}/favicon.ico`),
      ]);

      const effectiveFavicon = favicon.found ? favicon : defaultFaviconIco;

      const issues: string[] = [];
      if (!effectiveFavicon.found) issues.push("No favicon found (neither a <link rel=icon> nor /favicon.ico)");
      if (!appleTouchIcon.found) issues.push("No apple-touch-icon found — iOS home-screen bookmarks will use a low-quality fallback");
      if (!manifest.found) issues.push("No web app manifest found — site won't be installable as a PWA");
      if (!themeColor) issues.push("No theme-color meta tag — browser chrome won't match site branding on mobile");

      return {
        url,
        favicon: effectiveFavicon,
        appleTouchIcon,
        manifest,
        themeColor,
        issues,
      };
    },
  },

  json_ld_schema_validator: {
    price: "$0.0002",
    description:
      "Fetch a URL, extract every JSON-LD (<script type=\"application/ld+json\">) block, and validate basic structure — @context/@type presence plus required fields for common schema.org types (Article, Product, Organization, WebSite, LocalBusiness, BreadcrumbList, FAQPage). Reports per-block errors rather than failing the whole call on one bad block.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to check" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const html = await fetchText(url);
      const blocks = [...html.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)];

      const results = blocks.map((m, i) => {
        try {
          const parsed = JSON.parse(m[1].trim());
          const items = Array.isArray(parsed) ? parsed : (parsed["@graph"] ?? [parsed]);
          return items.map((item: any, j: number) => validateJsonLdBlock(item, blocks.length > 1 ? i : j));
        } catch (e: any) {
          return [{ index: i, types: [], valid: false, errors: [`Invalid JSON: ${e?.message ?? String(e)}`] }];
        }
      }).flat();

      return {
        url,
        blocksFound: blocks.length,
        entriesValidated: results.length,
        validCount: results.filter((r) => r.valid).length,
        invalidCount: results.filter((r) => !r.valid).length,
        results,
      };
    },
  },
};

export type ToolName = keyof typeof tools;
