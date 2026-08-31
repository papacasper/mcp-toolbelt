import { connect as netConnect } from "node:net";
import { assertPublicHost } from "./ssrf-guard";

export async function whoisQuery(server: string, query: string, timeoutMs = 6000): Promise<string> {
  await assertPublicHost(server);
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

export function extractWhoisField(raw: string, labels: string[]): string | null {
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

export function stripHtml(html: string): string {
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

export function extractTag(html: string, tag: string): string | null {
  const m = html.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return m ? m[1].trim() : null;
}

export function extractMeta(html: string, name: string): string | null {
  const m = html.match(
    new RegExp(`<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']*)["']`, "i")
  ) || html.match(
    new RegExp(`<meta[^>]+content=["']([^"']*)["'][^>]+name=["']${name}["']`, "i")
  );
  return m ? m[1].trim() : null;
}

export async function fetchText(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
    redirect: "follow",
  });
  if (!res.ok) throw new Error(`Fetch failed: ${res.status} ${res.statusText}`);
  return await res.text();
}

export function extractLinks(html: string, baseUrl: string): string[] {
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

export async function checkLinkStatus(url: string, timeoutMs = 8000): Promise<{ status: number | null; ok: boolean; error?: string }> {
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

export async function mapWithConcurrency<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
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
