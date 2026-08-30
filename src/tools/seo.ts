import { fetchText, extractTag, extractMeta, stripHtml, extractLinks, checkLinkStatus, mapWithConcurrency } from "./shared";

function extractOgTag(html: string, property: string): string | null {
  const m =
    html.match(new RegExp(`<meta[^>]+property=["']${property}["'][^>]+content=["']([^"']*)["']`, "i")) ||
    html.match(new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+property=["']${property}["']`, "i")) ||
    html.match(new RegExp(`<meta[^>]+name=["']${property}["'][^>]+content=["']([^"']*)["']`, "i")) ||
    html.match(new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+name=["']${property}["']`, "i"));
  return m ? m[1].trim() : null;
}

function extractAnchors(html: string, baseUrl: string): Array<{ text: string; absoluteHref: string }> {
  const anchors: Array<{ text: string; absoluteHref: string }> = [];
  const re = /<a\s[^>]*href=["']([^"'#][^"']*)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html))) {
    try {
      const resolved = new URL(m[1], baseUrl);
      if (resolved.protocol !== "http:" && resolved.protocol !== "https:") continue;
      resolved.hash = "";
      anchors.push({ text: stripHtml(m[2]), absoluteHref: resolved.toString() });
    } catch {
      // skip unparseable hrefs
    }
  }
  return anchors;
}

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

function extractSitemapLocs(xml: string): string[] {
  return [...xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1].trim());
}

function isSitemapIndex(xml: string): boolean {
  return /<sitemapindex[\s>]/i.test(xml);
}

async function fetchSitemapXml(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
  return await res.text();
}

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

const AI_CRAWLER_AGENTS = [
  "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-Web", "anthropic-ai",
  "CCBot", "PerplexityBot", "Google-Extended", "Applebot-Extended", "Bytespider", "Amazonbot",
];

function parseRobotsDirectives(robotsTxt: string): Map<string, { disallow: string[]; allow: string[] }> {
  const groups = new Map<string, { disallow: string[]; allow: string[] }>();
  let currentAgents: string[] = [];
  let groupOpen = false;

  for (const rawLine of robotsTxt.split("\n")) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const [key, ...rest] = line.split(":");
    const value = rest.join(":").trim();
    const directive = key.trim().toLowerCase();

    if (directive === "user-agent") {
      if (!groupOpen) currentAgents = [value];
      else currentAgents.push(value);
      groupOpen = true;
      if (!groups.has(value)) groups.set(value, { disallow: [], allow: [] });
    } else if (directive === "disallow" && currentAgents.length) {
      groupOpen = false;
      for (const agent of currentAgents) groups.get(agent)!.disallow.push(value);
    } else if (directive === "allow" && currentAgents.length) {
      groupOpen = false;
      for (const agent of currentAgents) groups.get(agent)!.allow.push(value);
    } else {
      groupOpen = false;
    }
  }

  return groups;
}

export const tools = {
  ai_crawler_policy_check: {
    price: "$0.0003",
    description:
      "Check a site's robots.txt for explicit directives targeting known AI crawlers (GPTBot, ClaudeBot, CCBot, PerplexityBot, Google-Extended, Bytespider, Amazonbot, and others used for LLM training or AI search/answer products), and check for an llms.txt file. Useful for publishers deciding whether their content policy toward AI crawlers matches their intent, or for auditing a competitor's stance.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Any URL on the site to check (origin is derived from it)" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const origin = new URL(url).origin;

      const robotsRes = await fetch(`${origin}/robots.txt`).catch(() => null);
      const robotsTxt = robotsRes?.ok ? await robotsRes.text() : null;

      const llmsRes = await fetch(`${origin}/llms.txt`).catch(() => null);
      const hasLlmsTxt = !!llmsRes?.ok;

      if (!robotsTxt) {
        return {
          origin,
          hasRobotsTxt: false,
          hasLlmsTxt,
          agents: AI_CRAWLER_AGENTS.map((agent) => ({ agent, mentioned: false, blocked: null })),
          wildcardDisallowsAll: null,
          issues: ["No robots.txt found — AI crawlers will default to their own policy (usually: crawl everything)"],
        };
      }

      const groups = parseRobotsDirectives(robotsTxt);
      const wildcard = groups.get("*");
      const wildcardDisallowsAll = wildcard?.disallow.some((d) => d === "/") ?? false;

      const agents = AI_CRAWLER_AGENTS.map((agent) => {
        const match = [...groups.keys()].find((g) => g.toLowerCase() === agent.toLowerCase());
        if (!match) {
          return { agent, mentioned: false, blocked: wildcardDisallowsAll ? true : null };
        }
        const rules = groups.get(match)!;
        const blocked = rules.disallow.some((d) => d === "/") && !rules.allow.some((a) => a === "/");
        return { agent, mentioned: true, blocked };
      });

      const unmentioned = agents.filter((a) => !a.mentioned).map((a) => a.agent);
      const issues: string[] = [];
      if (unmentioned.length && !wildcardDisallowsAll) {
        issues.push(`No explicit rule for: ${unmentioned.join(", ")} — these will crawl under the wildcard (*) or default-allow policy`);
      }
      if (!hasLlmsTxt) {
        issues.push("No llms.txt found — an emerging (non-standardized) convention some sites use to give AI systems a curated summary of their content");
      }

      return {
        origin,
        hasRobotsTxt: true,
        hasLlmsTxt,
        wildcardDisallowsAll,
        agents,
        issues,
      };
    },
  },

  seo_audit: {
    price: "$0.0003",
    description:
      "Fetch a URL and run an SEO audit: title/meta description length, canonical tag, Open Graph + Twitter Card tags, html lang attribute, viewport meta, heading structure, image alt-text coverage, internal/external link counts and generic-anchor-text detection, robots meta (noindex/nofollow), structured data (JSON-LD) presence, and robots.txt/sitemap.xml presence.",
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
      const h2Matches = html.match(/<h2[\s>]/gi) || [];
      const h3Matches = html.match(/<h3[\s>]/gi) || [];
      const wordCount = stripHtml(html).split(/\s+/).filter(Boolean).length;

      const canonicalMatch = html.match(/<link[^>]+rel=["']canonical["'][^>]+href=["']([^"']*)["']/i);
      const canonical = canonicalMatch ? canonicalMatch[1].trim() : null;

      const langMatch = html.match(/<html[^>]+lang=["']([^"']*)["']/i);
      const lang = langMatch ? langMatch[1].trim() : null;

      const hasViewport = /<meta[^>]+name=["']viewport["']/i.test(html);

      const ogTitle = extractOgTag(html, "og:title");
      const ogDescription = extractOgTag(html, "og:description");
      const ogImage = extractOgTag(html, "og:image");
      const twitterCard = extractOgTag(html, "twitter:card");

      const robotsMeta = extractMeta(html, "robots");
      const isNoindex = !!robotsMeta && /noindex/i.test(robotsMeta);
      const isNofollow = !!robotsMeta && /nofollow/i.test(robotsMeta);

      const imgTags = html.match(/<img\b[^>]*>/gi) || [];
      const imgsMissingAlt = imgTags.filter((tag) => !/\balt=["'][^"']*["']/i.test(tag)).length;

      const structuredDataBlocks = (html.match(/<script[^>]+type=["']application\/ld\+json["']/gi) || []).length;

      let httpNote: string | null = null;
      try {
        if (new URL(url).protocol === "http:") httpNote = "URL uses http:// instead of https://";
      } catch {}

      const origin = new URL(url).origin;
      const anchors = extractAnchors(html, url);
      const internalLinks = anchors.filter((a) => a.absoluteHref.startsWith(origin));
      const externalLinks = anchors.filter((a) => !a.absoluteHref.startsWith(origin));
      const genericAnchorPattern = /^(click here|here|read more|learn more|link|this page|more)$/i;
      const genericAnchorCount = anchors.filter((a) => genericAnchorPattern.test(a.text.trim())).length;

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
      if (h2Matches.length === 0 && h3Matches.length > 0) issues.push("Has <h3> tags but no <h2> — skipped heading level");
      if (!robotsOk) issues.push("No robots.txt found");
      if (!sitemapOk) issues.push("No sitemap.xml found");
      if (!canonical) issues.push("Missing canonical tag");
      if (!lang) issues.push("Missing lang attribute on <html>");
      if (!hasViewport) issues.push("Missing viewport meta tag");
      if (!ogTitle) issues.push("Missing og:title");
      if (!ogDescription) issues.push("Missing og:description");
      if (!ogImage) issues.push("Missing og:image");
      if (!twitterCard) issues.push("Missing twitter:card");
      if (isNoindex) issues.push("Page has robots noindex — will not be indexed");
      if (isNofollow) issues.push("Page has robots nofollow — outbound links will not pass authority");
      if (imgsMissingAlt > 0) issues.push(`${imgsMissingAlt} of ${imgTags.length} <img> tags missing alt text`);
      if (structuredDataBlocks === 0) issues.push("No structured data (JSON-LD) found");
      if (genericAnchorCount > 0) issues.push(`${genericAnchorCount} links use generic anchor text (e.g. "click here")`);
      if (httpNote) issues.push(httpNote);

      return {
        url,
        title,
        description,
        canonical,
        lang,
        hasViewport,
        openGraph: { title: ogTitle, description: ogDescription, image: ogImage, twitterCard },
        headings: { h1: h1Matches.length, h2: h2Matches.length, h3: h3Matches.length },
        wordCount,
        images: { total: imgTags.length, missingAlt: imgsMissingAlt },
        links: { internal: internalLinks.length, external: externalLinks.length, genericAnchorText: genericAnchorCount },
        robotsMeta: { noindex: isNoindex, nofollow: isNofollow },
        structuredDataBlocks,
        hasRobotsTxt: robotsOk,
        hasSitemapXml: sitemapOk,
        issues,
        score: Math.max(0, 100 - issues.length * 6),
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

  sitemap_url_validator: {
    price: "$0.0005",
    description:
      "Parse a site's sitemap.xml (following one level of sitemap-index nesting) and check the HTTP status of every listed URL. Concurrency-limited, capped at 200 URLs checked per call. Reports broken/redirecting URLs found in the sitemap.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "URL of the sitemap.xml to validate (or any page URL — /sitemap.xml on that origin is used)" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const sitemapUrl = url.endsWith(".xml") ? url : `${new URL(url).origin}/sitemap.xml`;
      const rootXml = await fetchSitemapXml(sitemapUrl);

      let locs: string[];
      let sitemapsFollowed = 1;
      if (isSitemapIndex(rootXml)) {
        const childSitemaps = extractSitemapLocs(rootXml).slice(0, 20);
        const childXmls = await mapWithConcurrency(childSitemaps, 5, (u) => fetchSitemapXml(u).catch(() => ""));
        locs = childXmls.flatMap((xml) => (xml ? extractSitemapLocs(xml) : []));
        sitemapsFollowed += childSitemaps.length;
      } else {
        locs = extractSitemapLocs(rootXml);
      }

      const uniqueLocs = [...new Set(locs)];
      const capped = uniqueLocs.slice(0, 200);
      const statuses = await mapWithConcurrency(capped, 8, (u) => checkLinkStatus(u));

      const broken = capped
        .map((u, i) => ({ url: u, ...statuses[i] }))
        .filter((r) => !r.ok);

      return {
        sitemapUrl,
        sitemapsFollowed,
        urlsFound: uniqueLocs.length,
        urlsChecked: capped.length,
        urlsTruncated: uniqueLocs.length > capped.length,
        brokenCount: broken.length,
        brokenUrls: broken,
      };
    },
  },
};

export type ToolName = keyof typeof tools;
