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
  seo_audit: {
    price: "$0.05",
    description:
      "Fetch a URL and run a full on-page SEO audit: title/meta description length, canonical tag, Open Graph + Twitter Card tags, html lang attribute, viewport meta, heading structure, image alt-text coverage, internal/external link counts and generic-anchor-text detection, robots meta (noindex/nofollow), structured data (JSON-LD) presence, robots.txt/sitemap.xml presence, and site chrome (favicon, apple-touch-icon, web app manifest, theme-color). Whole-page audit — for raw extracted data only use structured_data_extract, for the platform/framework use tech_stack_fingerprint.",
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

      // Site chrome (favicon / apple-touch-icon / manifest / theme-color) — folded in from the
      // former standalone favicon_manifest_check.
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
      const emptyHead = { found: false, status: null, contentType: null };
      const [faviconLinked, appleTouchIcon, manifestFound, defaultFaviconIco] = await Promise.all([
        iconHref ? headExists(new URL(iconHref, url).toString()) : Promise.resolve(emptyHead),
        appleTouchHref ? headExists(new URL(appleTouchHref, url).toString()) : Promise.resolve(emptyHead),
        manifestHref ? headExists(new URL(manifestHref, url).toString()) : Promise.resolve(emptyHead),
        headExists(`${origin}/favicon.ico`),
      ]);
      const siteChrome = {
        favicon: faviconLinked.found ? faviconLinked : defaultFaviconIco,
        appleTouchIcon,
        manifest: manifestFound,
        themeColor,
      };

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
      if (!siteChrome.favicon.found) issues.push("No favicon found (neither a <link rel=icon> nor /favicon.ico)");
      if (!siteChrome.appleTouchIcon.found) issues.push("No apple-touch-icon found — iOS home-screen bookmarks will use a low-quality fallback");
      if (!siteChrome.manifest.found) issues.push("No web app manifest found — site won't be installable as a PWA");
      if (!siteChrome.themeColor) issues.push("No theme-color meta tag — browser chrome won't match site branding on mobile");

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
        siteChrome,
        issues,
        score: Math.max(0, 100 - issues.length * 6),
      };
    },
  },

  check_robots_sitemap: {
    price: "$0.01",
    description: "Check a site's robots.txt and sitemap.xml in one call: raw contents (truncated), sitemap presence, an AI-crawler policy analysis (explicit rules for GPTBot, ClaudeBot, CCBot, PerplexityBot, Google-Extended, Bytespider, Amazonbot and other AI crawlers, vs wildcard/default), and llms.txt presence. For a scored, whole-site AI-readiness report use ai_readiness_audit instead.",
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
      const [robots, sitemap, llmsTxt] = await Promise.all([
        safeFetch("/robots.txt"),
        safeFetch("/sitemap.xml"),
        safeFetch("/llms.txt"),
      ]);

      let aiCrawlerPolicy: any = null;
      if ((robots as any).found && (robots as any).content) {
        const groups = parseRobotsDirectives((robots as any).content);
        const wildcard = groups.get("*");
        const wildcardDisallowsAll = wildcard?.disallow.some((d) => d === "/") ?? false;
        const agents = AI_CRAWLER_AGENTS.map((agent) => {
          const match = [...groups.keys()].find((g) => g.toLowerCase() === agent.toLowerCase());
          if (!match) return { agent, mentioned: false, blocked: wildcardDisallowsAll ? true : null };
          const rules = groups.get(match)!;
          const blocked = rules.disallow.some((d) => d === "/") && !rules.allow.some((a) => a === "/");
          return { agent, mentioned: true, blocked };
        });
        aiCrawlerPolicy = { wildcardDisallowsAll, agents };
      }

      return { origin, robots, sitemap, llmsTxt: { found: llmsTxt.found }, aiCrawlerPolicy };
    },
  },

  broken_link_check: {
    price: "$0.10",
    description:
      "Find broken links two ways. Default (crawl mode): crawl a site starting from a URL (same-origin pages only, bounded by maxPages) and check every linked URL for broken status codes, returning each broken link with the page(s) it was found on. Sitemap mode (viaSitemap: true): parse the site's sitemap.xml (following one level of sitemap-index nesting) and check the status of every URL listed in it instead. Note: some external sites (e.g. social platforms) block automated HEAD/GET requests and may show up as false positives.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Starting URL to crawl — or, in sitemap mode, the sitemap.xml URL or any page URL on the site" },
        maxPages: { type: "number", description: "Max same-origin pages to crawl in crawl mode (default 20, capped at 50)" },
        checkExternal: { type: "boolean", description: "Crawl mode only: also check links pointing off-site (default true; crawling never follows off-site links)" },
        viaSitemap: { type: "boolean", description: "Check the URLs listed in the site's sitemap.xml instead of crawling pages (default false)" },
      },
      required: ["url"],
    },
    async run({ url, maxPages, checkExternal, viaSitemap }: { url: string; maxPages?: number; checkExternal?: boolean; viaSitemap?: boolean }) {
      if (viaSitemap) {
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
          mode: "sitemap",
          sitemapUrl,
          sitemapsFollowed,
          urlsFound: uniqueLocs.length,
          urlsChecked: capped.length,
          urlsTruncated: uniqueLocs.length > capped.length,
          brokenCount: broken.length,
          brokenUrls: broken,
        };
      }
      const cappedMaxPages = Math.max(1, Math.min(maxPages ?? 20, 50));
      return { mode: "crawl", ...(await crawlBrokenLinks(url, cappedMaxPages, checkExternal ?? true)) };
    },
  },

  ai_readiness_audit: {
    price: "$0.25",
    description:
      "Score how ready a website is for AI agents and LLM-driven discovery, 0-100 with a letter grade: robots.txt presence, explicit AI-crawler policy (GPTBot, ClaudeBot, CCBot, PerplexityBot, and 8 more), llms.txt presence and structure, structured data (JSON-LD) and Open Graph basics, agent/payment discovery files (/.well-known/x402, /openapi.json), sitemap presence, and title/meta basics. The bundle to run before/after making a site agent-friendly — for raw robots/sitemap contents only, use check_robots_sitemap; for classic search SEO only, use seo_audit.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Any URL on the site to audit (origin is derived from it)" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      const origin = new URL(url).origin;

      const [robotsInfo, html, llmsText, x402Ok, openapiOk] = await Promise.all([
        tools.check_robots_sitemap.run({ url }).catch(() => null),
        fetchText(url).catch(() => ""),
        fetch(`${origin}/llms.txt`).then(async (r) => (r.ok ? await r.text() : null)).catch(() => null),
        fetch(`${origin}/.well-known/x402`).then((r) => r.ok).catch(() => false),
        fetch(`${origin}/openapi.json`).then((r) => r.ok).catch(() => false),
      ]);

      const hasRobots = !!(robotsInfo as any)?.robots?.found;
      const hasSitemap = !!(robotsInfo as any)?.sitemap?.found;
      const policy = (robotsInfo as any)?.aiCrawlerPolicy ?? null;
      const mentioned = policy ? policy.agents.filter((a: any) => a.mentioned).length : 0;
      const totalAgents = AI_CRAWLER_AGENTS.length;

      const llmsPresent = llmsText !== null;
      const llmsHasHeading = !!llmsText && /^#\s/m.test(llmsText);
      const llmsHasLinks = !!llmsText && /\[[^\]]+\]\([^)]+\)/.test(llmsText);
      const llmsSizeable = !!llmsText && llmsText.trim().length > 200;

      const hasJsonLd = /<script[^>]+type=["']application\/ld\+json["']/i.test(html);
      const hasOg = /<meta[^>]+property=["']og:/i.test(html);
      const hasTitle = !!extractTag(html, "title");
      const hasDescription = !!extractMeta(html, "description");

      const components = {
        robotsTxt: { present: hasRobots, points: hasRobots ? 10 : 0, max: 10 },
        aiCrawlerPolicy: {
          explicitAgents: mentioned,
          ofAgents: totalAgents,
          wildcardDisallowsAll: policy?.wildcardDisallowsAll ?? null,
          points: Math.round((mentioned / totalAgents) * 15),
          max: 15,
        },
        llmsTxt: {
          present: llmsPresent,
          hasHeading: llmsHasHeading,
          hasLinks: llmsHasLinks,
          sizeable: llmsSizeable,
          points: (llmsPresent ? 13 : 0) + (llmsHasHeading ? 4 : 0) + (llmsHasLinks ? 4 : 0) + (llmsSizeable ? 4 : 0),
          max: 25,
        },
        structuredData: { jsonLd: hasJsonLd, openGraph: hasOg, points: (hasJsonLd ? 10 : 0) + (hasOg ? 5 : 0), max: 15 },
        agentDiscovery: { x402: x402Ok, openapiJson: openapiOk, points: (x402Ok ? 10 : 0) + (openapiOk ? 5 : 0), max: 15 },
        sitemap: { present: hasSitemap, points: hasSitemap ? 10 : 0, max: 10 },
        pageBasics: { title: hasTitle, metaDescription: hasDescription, points: (hasTitle ? 5 : 0) + (hasDescription ? 5 : 0), max: 10 },
      };

      const score = Object.values(components).reduce((sum, c: any) => sum + c.points, 0);
      const grade = score >= 85 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : score >= 40 ? "D" : "F";

      const issues: string[] = [];
      if (!hasRobots) issues.push("No robots.txt — AI crawlers default to crawling everything; add one with explicit AI-crawler rules");
      else if (mentioned === 0 && !policy?.wildcardDisallowsAll) issues.push("robots.txt states no explicit policy for any known AI crawler — your stance toward AI training/search crawlers is implicit, not chosen");
      else if (mentioned < totalAgents) issues.push(`Explicit AI-crawler rules cover ${mentioned} of ${totalAgents} known crawlers`);
      if (!llmsPresent) issues.push("No llms.txt — the emerging convention for giving AI systems a curated summary of your content");
      else {
        if (!llmsHasHeading) issues.push("llms.txt has no Markdown heading structure");
        if (!llmsHasLinks) issues.push("llms.txt contains no Markdown links to key pages");
        if (!llmsSizeable) issues.push("llms.txt is very short (<200 chars) — likely a stub");
      }
      if (!hasJsonLd) issues.push("No JSON-LD structured data — agents extract facts less reliably from raw HTML");
      if (!hasOg) issues.push("No Open Graph tags — link previews in AI/chat surfaces will be poor");
      if (!x402Ok && !openapiOk) issues.push("No machine-readable API/payment discovery (/.well-known/x402 or /openapi.json) — agents cannot find paid/programmatic access");
      if (!hasSitemap) issues.push("No sitemap.xml — crawlers and agents must discover pages by following links");
      if (!hasTitle) issues.push("Homepage is missing a <title>");
      if (!hasDescription) issues.push("Homepage is missing a meta description");

      return { url, origin, score, grade, components, issues };
    },
  },
};

export type ToolName = keyof typeof tools;
