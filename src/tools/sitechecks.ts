// Site-chrome and AI-crawler policy checks, used standalone and by the Website Watchdog scanner.
// Deterministic HTML/robots.txt/JSON parsing only, no AI. Issues are emitted as
// { severity, issue } objects so Watchdog's report parser picks them up (info = no score impact).
import { readCapped } from "./files";

const UA = "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)";
type Issue = { severity: "warning" | "info"; issue: string };

function normalizePageUrl(input: string): URL {
  const raw = String(input ?? "").trim();
  if (!raw) throw new Error("url is required");
  const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http(s) URLs are supported");
  return u;
}

async function get(url: string, opts: { method?: string; maxBytes?: number; timeoutMs?: number; accept?: string } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 10_000);
  try {
    const res = await fetch(url, {
      method: opts.method ?? "GET",
      redirect: "follow",
      headers: { "User-Agent": UA, accept: opts.accept ?? "*/*" },
      signal: controller.signal,
    });
    let body: string | null = null;
    if ((opts.method ?? "GET") === "GET" && opts.maxBytes) {
      body = new TextDecoder("utf-8").decode(await readCapped(res, opts.maxBytes).catch(() => new Uint8Array()));
    } else {
      try { await res.body?.cancel(); } catch {}
    }
    return { ok: res.ok, status: res.status, contentType: res.headers.get("content-type"), finalUrl: res.url || url, headers: res.headers, body, error: null as string | null };
  } catch (e: any) {
    return { ok: false, status: null as number | null, contentType: null as string | null, finalUrl: url, headers: null as Headers | null, body: null as string | null, error: e?.name === "AbortError" ? "timeout" : (e?.message ?? String(e)) };
  } finally {
    clearTimeout(timer);
  }
}

/** HEAD first (cheap), GET fallback when a server refuses HEAD. */
async function probe(url: string) {
  let r = await get(url, { method: "HEAD" });
  if (!r.ok && (r.status === 405 || r.status === 501 || r.status === 403 || r.status === null)) r = await get(url, { method: "GET", maxBytes: 1 });
  return { url, status: r.status, ok: r.ok, contentType: r.contentType, ...(r.error ? { error: r.error } : {}) };
}

function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return m ? (m[1] ?? m[2] ?? m[3] ?? "").trim() : null;
}

function linkTags(html: string): Array<{ rel: string; href: string; sizes: string | null; type: string | null }> {
  const head = html.slice(0, 300_000);
  const out: Array<{ rel: string; href: string; sizes: string | null; type: string | null }> = [];
  for (const m of head.matchAll(/<link\b[^>]*>/gi)) {
    const rel = attr(m[0], "rel");
    const href = attr(m[0], "href");
    if (rel && href) out.push({ rel: rel.toLowerCase().replace(/\s+/g, " "), href, sizes: attr(m[0], "sizes"), type: attr(m[0], "type") });
  }
  return out;
}

function metaContent(html: string, name: string): string | null {
  for (const m of html.slice(0, 300_000).matchAll(/<meta\b[^>]*>/gi)) {
    const n = attr(m[0], "name") ?? attr(m[0], "property");
    if (n && n.toLowerCase() === name.toLowerCase()) return attr(m[0], "content");
  }
  return null;
}

// ---- favicon_manifest_check ------------------------------------------------------------------
async function faviconManifestCheck(input: string) {
  const page = normalizePageUrl(input);
  const pageRes = await get(page.toString(), { maxBytes: 2 * 1024 * 1024, accept: "text/html,*/*;q=0.8", timeoutMs: 15_000 });
  if (pageRes.status === null) throw new Error(`Could not fetch ${page}: ${pageRes.error}`);
  const html = pageRes.body ?? "";
  const base = pageRes.finalUrl;
  const origin = new URL(base).origin;
  const resolve = (href: string) => { try { return new URL(href, base).toString(); } catch { return null; } };

  const links = linkTags(html);
  const iconLinks = links.filter((l) => /(^| )(icon|shortcut icon|mask-icon)( |$)/.test(l.rel) && !/apple-touch-icon/.test(l.rel));
  const appleLinks = links.filter((l) => /apple-touch-icon/.test(l.rel));
  const manifestLink = links.find((l) => /(^| )manifest( |$)/.test(l.rel));

  const [favicons, appleTouchIcons, faviconIco] = await Promise.all([
    Promise.all(iconLinks.slice(0, 10).map(async (l) => ({ rel: l.rel, href: l.href, sizes: l.sizes, type: l.type, ...(await probe(resolve(l.href) ?? l.href)) }))),
    Promise.all(appleLinks.slice(0, 5).map(async (l) => ({ rel: l.rel, href: l.href, sizes: l.sizes, ...(await probe(resolve(l.href) ?? l.href)) }))),
    probe(`${origin}/favicon.ico`),
  ]);

  let manifest: any = { linked: false, url: null, status: null, ok: false };
  if (manifestLink) {
    const murl = resolve(manifestLink.href);
    const mr = murl ? await get(murl, { maxBytes: 512 * 1024, accept: "application/manifest+json,application/json,*/*;q=0.5" }) : null;
    manifest = { linked: true, href: manifestLink.href, url: murl, status: mr?.status ?? null, ok: !!mr?.ok, contentType: mr?.contentType ?? null, valid: false };
    if (mr?.ok && mr.body) {
      try {
        const j = JSON.parse(mr.body);
        const icons = Array.isArray(j.icons) ? j.icons : [];
        const checked = await Promise.all(icons.slice(0, 12).map(async (ic: any) => {
          const src = typeof ic?.src === "string" ? ic.src : "";
          const abs = src ? (() => { try { return new URL(src, murl!).toString(); } catch { return null; } })() : null;
          const p = abs ? await probe(abs) : { status: null, ok: false };
          return { src, sizes: ic?.sizes ?? null, type: ic?.type ?? null, purpose: ic?.purpose ?? null, status: p.status, ok: p.ok };
        }));
        const sizes = new Set(icons.flatMap((ic: any) => String(ic?.sizes ?? "").toLowerCase().split(/\s+/)));
        manifest = {
          ...manifest,
          valid: true,
          name: j.name ?? null,
          short_name: j.short_name ?? null,
          description: typeof j.description === "string" ? j.description.slice(0, 300) : null,
          start_url: j.start_url ?? null,
          scope: j.scope ?? null,
          display: j.display ?? null,
          theme_color: j.theme_color ?? null,
          background_color: j.background_color ?? null,
          iconCount: icons.length,
          has192: sizes.has("192x192"),
          has512: sizes.has("512x512"),
          hasMaskable: icons.some((ic: any) => /maskable/.test(String(ic?.purpose ?? ""))),
          icons: checked,
        };
      } catch (e: any) {
        manifest.parseError = `Manifest is not valid JSON: ${e?.message ?? e}`;
      }
    }
  }

  const themeColor = metaContent(html, "theme-color");
  const workingLinked = favicons.find((f) => f.ok);
  const favicon = workingLinked
    ? { found: true, source: "link", url: workingLinked.url, status: workingLinked.status, contentType: workingLinked.contentType }
    : faviconIco.ok
      ? { found: true, source: "/favicon.ico", url: faviconIco.url, status: faviconIco.status, contentType: faviconIco.contentType }
      : { found: false, source: null, url: null, status: faviconIco.status, contentType: null };

  const issues: Issue[] = [];
  if (!favicon.found) issues.push({ severity: "warning", issue: "No working favicon (no <link rel=icon> that loads, and /favicon.ico is missing)" });
  for (const f of favicons) if (!f.ok) issues.push({ severity: "warning", issue: `Linked icon ${f.href} returns ${f.status ?? "an error"}` });
  if (!appleTouchIcons.length) issues.push({ severity: "info", issue: "No apple-touch-icon link; iOS home-screen bookmarks use a screenshot or generic icon" });
  for (const a of appleTouchIcons) if (!a.ok) issues.push({ severity: "warning", issue: `apple-touch-icon ${a.href} returns ${a.status ?? "an error"}` });
  if (!manifest.linked) issues.push({ severity: "info", issue: "No web app manifest linked; the site can't be installed as a PWA" });
  else if (!manifest.ok) issues.push({ severity: "warning", issue: `Linked manifest ${manifest.href} returns ${manifest.status ?? "an error"}` });
  else if (!manifest.valid) issues.push({ severity: "warning", issue: "Linked manifest is not valid JSON" });
  else {
    if (!manifest.name && !manifest.short_name) issues.push({ severity: "info", issue: "Manifest has no name or short_name" });
    if (!manifest.has192 || !manifest.has512) issues.push({ severity: "info", issue: "Manifest should include 192x192 and 512x512 icons for installability" });
    for (const ic of manifest.icons ?? []) if (!ic.ok) issues.push({ severity: "warning", issue: `Manifest icon ${ic.src} returns ${ic.status ?? "an error"}` });
  }
  if (!themeColor) issues.push({ severity: "info", issue: "No theme-color meta tag; mobile browser chrome won't match the site's branding" });

  return {
    url: page.toString(),
    finalUrl: base,
    pageStatus: pageRes.status,
    favicon,
    faviconIco: { url: faviconIco.url, status: faviconIco.status, ok: faviconIco.ok, contentType: faviconIco.contentType },
    linkedIcons: favicons,
    appleTouchIcons,
    manifest,
    themeColor,
    issues,
    summary: { warnings: issues.filter((i) => i.severity === "warning").length, info: issues.filter((i) => i.severity === "info").length },
  };
}

// ---- ai_crawler_policy_check -----------------------------------------------------------------
const AI_BOTS: Array<{ agent: string; operator: string; purpose: string }> = [
  { agent: "GPTBot", operator: "OpenAI", purpose: "model training" },
  { agent: "ChatGPT-User", operator: "OpenAI", purpose: "live fetches for ChatGPT users" },
  { agent: "OAI-SearchBot", operator: "OpenAI", purpose: "ChatGPT search index" },
  { agent: "ClaudeBot", operator: "Anthropic", purpose: "model training" },
  { agent: "Claude-User", operator: "Anthropic", purpose: "live fetches for Claude users" },
  { agent: "Claude-SearchBot", operator: "Anthropic", purpose: "Claude search index" },
  { agent: "Claude-Web", operator: "Anthropic", purpose: "legacy agent" },
  { agent: "anthropic-ai", operator: "Anthropic", purpose: "legacy agent" },
  { agent: "Google-Extended", operator: "Google", purpose: "Gemini training/grounding (robots token only)" },
  { agent: "GoogleOther", operator: "Google", purpose: "research and one-off crawls" },
  { agent: "Applebot-Extended", operator: "Apple", purpose: "Apple Intelligence training (robots token only)" },
  { agent: "PerplexityBot", operator: "Perplexity", purpose: "search index" },
  { agent: "Perplexity-User", operator: "Perplexity", purpose: "live fetches for users" },
  { agent: "CCBot", operator: "Common Crawl", purpose: "open dataset used for training" },
  { agent: "Bytespider", operator: "ByteDance", purpose: "model training" },
  { agent: "Meta-ExternalAgent", operator: "Meta", purpose: "model training" },
  { agent: "Meta-ExternalFetcher", operator: "Meta", purpose: "live fetches for users" },
  { agent: "FacebookBot", operator: "Meta", purpose: "speech/language model training" },
  { agent: "Amazonbot", operator: "Amazon", purpose: "Alexa/AI answers" },
  { agent: "cohere-ai", operator: "Cohere", purpose: "model training" },
  { agent: "cohere-training-data-crawler", operator: "Cohere", purpose: "model training" },
  { agent: "Diffbot", operator: "Diffbot", purpose: "knowledge graph / training data" },
  { agent: "YouBot", operator: "You.com", purpose: "search index" },
  { agent: "DuckAssistBot", operator: "DuckDuckGo", purpose: "AI answers" },
  { agent: "MistralAI-User", operator: "Mistral", purpose: "live fetches for users" },
  { agent: "AI2Bot", operator: "Allen Institute", purpose: "model training" },
  { agent: "Timpibot", operator: "Timpi", purpose: "search index / training" },
  { agent: "ImagesiftBot", operator: "ImageSift", purpose: "image dataset" },
  { agent: "omgili", operator: "Webz.io", purpose: "dataset" },
];

type Group = { agents: string[]; rules: Array<{ allow: boolean; path: string }> };

/** RFC 9309 robots.txt parse into groups (consecutive user-agent lines share the following rules). */
function parseRobots(txt: string): { groups: Group[]; sitemaps: string[] } {
  const groups: Group[] = [];
  const sitemaps: string[] = [];
  let cur: Group | null = null;
  let lastWasAgent = false;
  for (const rawLine of txt.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === "user-agent") {
      if (!cur || !lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(value.toLowerCase());
      lastWasAgent = true;
    } else if (key === "allow" || key === "disallow") {
      lastWasAgent = false;
      if (!cur) continue;
      if (key === "disallow" && value === "") continue; // empty Disallow = allow everything
      cur.rules.push({ allow: key === "allow", path: value });
    } else {
      lastWasAgent = false;
      if (key === "sitemap") sitemaps.push(value);
    }
  }
  return { groups, sitemaps };
}

function ruleMatches(pattern: string, path: string): boolean {
  const anchored = pattern.endsWith("$");
  const body = anchored ? pattern.slice(0, -1) : pattern;
  const re = new RegExp("^" + body.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + (anchored ? "$" : ""));
  return re.test(path);
}

/** Longest-match rule wins; on a tie Allow wins (RFC 9309 / Google behaviour). */
function isAllowed(rules: Group["rules"], path: string): boolean {
  let best: { allow: boolean; len: number } | null = null;
  for (const r of rules) {
    if (!r.path || !ruleMatches(r.path, path)) continue;
    const len = r.path.replace(/\$$/, "").length;
    if (!best || len > best.len || (len === best.len && r.allow)) best = { allow: r.allow, len };
  }
  return best ? best.allow : true;
}

function evaluateBot(groups: Group[], agent: string, testPaths: string[]) {
  const a = agent.toLowerCase();
  const specific = groups.filter((g) => g.agents.includes(a));
  const wildcard = groups.filter((g) => g.agents.includes("*"));
  const chosen = specific.length ? specific : wildcard;
  const matchedGroup = specific.length ? agent : wildcard.length ? "*" : null;
  const rules = chosen.flatMap((g) => g.rules);
  const rootAllowed = isAllowed(rules, "/");
  const pathResults = testPaths.map((p) => ({ path: p, allowed: isAllowed(rules, p) }));
  const disallows = rules.filter((r) => !r.allow).map((r) => r.path);
  const status = !rootAllowed ? "blocked" : disallows.length ? "partially_blocked" : "allowed";
  return { matchedGroup, explicit: specific.length > 0, status, rootAllowed, paths: pathResults, disallowRules: disallows.slice(0, 20) };
}

async function aiCrawlerPolicyCheck(input: string, paths?: string[]) {
  const page = normalizePageUrl(input);
  const origin = page.origin;
  const testPaths = [...new Set(["/", page.pathname || "/", ...(Array.isArray(paths) ? paths.filter((p) => typeof p === "string" && p.startsWith("/")).slice(0, 10) : [])])];

  const [robotsRes, pageRes, llmsRes, llmsFullRes] = await Promise.all([
    get(`${origin}/robots.txt`, { maxBytes: 512 * 1024, accept: "text/plain,*/*" }),
    get(page.toString(), { maxBytes: 2 * 1024 * 1024, accept: "text/html,*/*;q=0.8", timeoutMs: 15_000 }),
    get(`${origin}/llms.txt`, { maxBytes: 256 * 1024, accept: "text/plain,text/markdown,*/*" }),
    probe(`${origin}/llms-full.txt`),
  ]);

  const robotsFound = !!robotsRes.ok && !/text\/html/i.test(robotsRes.contentType ?? "");
  // RFC 9309: 4xx = no restrictions; 5xx/unreachable = assume full disallow.
  const robotsUnreachable = robotsRes.status === null || (robotsRes.status >= 500);
  const parsed = robotsFound ? parseRobots(robotsRes.body ?? "") : { groups: [], sitemaps: [] };

  const bots = AI_BOTS.map((b) => {
    if (robotsUnreachable) return { ...b, matchedGroup: null, explicit: false, status: "blocked", rootAllowed: false, paths: testPaths.map((p) => ({ path: p, allowed: false })), disallowRules: [], note: "robots.txt unreachable/5xx: compliant crawlers treat the site as fully disallowed" };
    return { ...b, ...evaluateBot(parsed.groups, b.agent, testPaths) };
  });

  const html = pageRes.body ?? "";
  const metaRobots = [metaContent(html, "robots"), ...AI_BOTS.map((b) => metaContent(html, b.agent))].filter(Boolean).join(", ") || null;
  const xRobots = pageRes.headers?.get("x-robots-tag") ?? null;
  const hintText = `${metaRobots ?? ""} ${xRobots ?? ""}`.toLowerCase();
  const noaiHints = {
    metaRobots,
    xRobotsTag: xRobots,
    noai: /\bnoai\b/.test(hintText),
    noimageai: /\bnoimageai\b/.test(hintText),
    noindex: /\bnoindex\b/.test(hintText),
  };

  const llmsBody = llmsRes.ok && !/text\/html/i.test(llmsRes.contentType ?? "") ? llmsRes.body ?? "" : "";
  const llmsTxt = {
    found: !!llmsBody,
    status: llmsRes.status,
    bytes: llmsBody ? Buffer.byteLength(llmsBody) : 0,
    hasTitle: /^\s*#\s+\S/.test(llmsBody),
    linkCount: (llmsBody.match(/\]\(https?:\/\/[^)]+\)/g) ?? []).length,
    llmsFullTxt: { found: llmsFullRes.ok, status: llmsFullRes.status },
  };

  const blocked = bots.filter((b) => b.status === "blocked").map((b) => b.agent);
  const allowed = bots.filter((b) => b.status === "allowed").map((b) => b.agent);
  const partial = bots.filter((b) => b.status === "partially_blocked").map((b) => b.agent);
  const explicit = bots.filter((b) => b.explicit).map((b) => b.agent);

  const issues: Issue[] = [];
  if (robotsUnreachable) issues.push({ severity: "warning", issue: `robots.txt returned ${robotsRes.status ?? "no response"}; compliant crawlers (AI and search) treat the whole site as disallowed until it loads` });
  else if (!robotsFound) issues.push({ severity: "info", issue: "No robots.txt, so every AI crawler is allowed by default" });
  else if (!explicit.length) issues.push({ severity: "info", issue: "robots.txt has no AI-crawler-specific rules; AI crawlers follow the * group" });
  if (!llmsTxt.found) issues.push({ severity: "info", issue: "No /llms.txt file to guide AI agents to key content" });
  if (noaiHints.noai && allowed.length) issues.push({ severity: "info", issue: "Page sends a noai hint but robots.txt still allows some AI crawlers; only some crawlers honour noai" });

  return {
    url: page.toString(),
    origin,
    robotsTxt: { found: robotsFound, status: robotsRes.status, bytes: robotsRes.body ? Buffer.byteLength(robotsRes.body) : 0, groups: parsed.groups.length, sitemaps: parsed.sitemaps.slice(0, 10) },
    testedPaths: testPaths,
    summary: { botsChecked: bots.length, allowed: allowed.length, blocked: blocked.length, partiallyBlocked: partial.length, explicitRules: explicit.length, blockedBots: blocked, allowedBots: allowed, partiallyBlockedBots: partial },
    bots,
    noaiHints,
    llmsTxt,
    issues,
  };
}

export const tools = {
  favicon_manifest_check: {
    price: "$0.01",
    description:
      "Check a site's browser/OS chrome and PWA metadata: every <link rel=icon> favicon plus /favicon.ico, apple-touch-icon(s), and the web app manifest (fetched and parsed: name, short_name, start_url, display, theme_color, background_color, icons with sizes/purpose), each with its HTTP status, plus the theme-color meta tag. Flags broken icon links and missing 192/512 manifest icons. Deterministic HTML/JSON parsing, no AI. For a whole-page SEO audit (which includes a lighter version of this) use seo_audit.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Page to check, usually the homepage, e.g. https://example.com" },
      },
      required: ["url"],
    },
    async run({ url }: { url: string }) {
      return faviconManifestCheck(url);
    },
  },

  ai_crawler_policy_check: {
    price: "$0.01",
    description:
      "Report, per AI crawler, whether a site allows or blocks it: parses robots.txt with RFC 9309 rules (most-specific user-agent group, longest-match Allow/Disallow, * and $ wildcards) for 29 AI agents including GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, Claude-Web, anthropic-ai, Google-Extended, PerplexityBot, CCBot, Bytespider, Applebot-Extended, Meta-ExternalAgent, Amazonbot and cohere-ai. Also reads the page's meta robots / X-Robots-Tag noai and noimageai hints and checks /llms.txt (and /llms-full.txt). Optional extra paths to test. Deterministic parsing, no AI. For a scored AI-readiness report use ai_readiness_audit; for raw robots/sitemap contents use check_robots_sitemap.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Any URL on the site (origin is derived from it); its path is also tested" },
        paths: { type: "array", items: { type: "string" }, description: "Optional extra paths to test per bot, e.g. ['/blog/', '/api/'] (max 10)" },
      },
      required: ["url"],
    },
    async run({ url, paths }: { url: string; paths?: string[] }) {
      return aiCrawlerPolicyCheck(url, paths);
    },
  },
};

export type ToolName = keyof typeof tools;
