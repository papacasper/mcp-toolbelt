import { fetchText, extractTag, extractMeta, stripHtml, extractLinks, checkLinkStatus, mapWithConcurrency } from "./shared";

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
};

export type ToolName = keyof typeof tools;
