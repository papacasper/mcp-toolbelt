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

export const tools = {
  url_to_markdown: {
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
};

export type ToolName = keyof typeof tools;
