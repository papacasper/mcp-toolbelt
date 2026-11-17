// Headless-browser rendering tools: website_screenshot and html_to_pdf.
// Deterministic rendering only (no AI). Every request the page makes (navigation, redirects,
// subresources) is checked with assertPublicHost, so a public URL can't make the browser reach
// the host's own network or cloud metadata. WebSockets, downloads, and service workers are blocked.
import puppeteer, { type Browser, type Page } from "puppeteer-core";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { assertPublicHost } from "./ssrf-guard";
import { storeFile } from "./files";

const NAV_TIMEOUT_MS = 25_000;
const TOTAL_TIMEOUT_MS = 45_000;
const MAX_CONCURRENT = 2;
const MAX_QUEUE = 6;
const MAX_FULLPAGE_HEIGHT = 10_000;
const MAX_HTML_BYTES = 2 * 1024 * 1024;
const MAX_OUTPUT_BYTES = 20 * 1024 * 1024;

function findChrome(): string {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const base = join(process.env.HOME ?? "/home/ubuntu", ".cache", "puppeteer", "chrome-headless-shell");
  try {
    const versions = readdirSync(base).filter((d) => d.startsWith("linux-")).sort().reverse();
    for (const v of versions) {
      const p = join(base, v, "chrome-headless-shell-linux64", "chrome-headless-shell");
      if (existsSync(p)) return p;
    }
  } catch {}
  throw new Error("Headless browser is not installed on this server");
}

// Simple semaphore so a burst of calls can't exhaust server memory.
let active = 0;
const waiters: Array<() => void> = [];
async function acquire() {
  if (active < MAX_CONCURRENT) { active++; return; }
  if (waiters.length >= MAX_QUEUE) throw new Error("Renderer is busy, retry in a few seconds");
  await new Promise<void>((resolve) => waiters.push(resolve));
  active++;
}
function release() {
  active--;
  const next = waiters.shift();
  if (next) next();
}

function normalizeUrl(input: string): string {
  const raw = String(input ?? "").trim();
  if (!raw) throw new Error("url is required");
  const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http(s) URLs are supported");
  return u.toString();
}

function clampInt(v: unknown, def: number, min: number, max: number): number {
  const n = Number(v);
  if (v === undefined || v === null || !Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, Math.round(n)));
}

async function guardPage(page: Page, blocked: string[]) {
  const hostOk = new Map<string, boolean>();
  await page.setRequestInterception(true);
  await page.setBypassServiceWorker(true);
  const cdp = await page.createCDPSession();
  await cdp.send("Network.enable");
  await cdp.send("Network.setBlockedURLs", { urls: ["ws://*", "wss://*", "ftp://*", "file://*"] });
  await cdp.send("Browser.setDownloadBehavior", { behavior: "deny" }).catch(() => {});
  page.on("dialog", (d) => d.dismiss().catch(() => {}));
  page.on("request", async (req) => {
    try {
      const u = new URL(req.url());
      if (u.protocol === "data:" || u.protocol === "blob:" || u.protocol === "about:") return req.continue();
      if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error(`blocked scheme ${u.protocol}`);
      const host = u.hostname;
      let ok = hostOk.get(host);
      if (ok === undefined) {
        ok = await assertPublicHost(host).then(() => true, () => false);
        hostOk.set(host, ok);
      }
      if (!ok) throw new Error(`blocked private host ${host}`);
      return req.continue();
    } catch (e: any) {
      if (blocked.length < 20) blocked.push(`${req.url().slice(0, 200)} (${e?.message ?? "blocked"})`);
      return req.abort("blockedbyclient").catch(() => {});
    }
  });
}

async function withBrowser<T>(fn: (browser: Browser) => Promise<T>): Promise<T> {
  await acquire();
  let browser: Browser | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    browser = await puppeteer.launch({
      executablePath: findChrome(),
      headless: true,
      args: [
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--no-first-run",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-default-apps",
        "--mute-audio",
        "--hide-scrollbars",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--js-flags=--max-old-space-size=256",
      ],
      timeout: 15_000,
    });
    const b = browser;
    return await Promise.race([
      fn(b),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Rendering timed out after ${TOTAL_TIMEOUT_MS / 1000}s`)), TOTAL_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
    if (browser) {
      const proc = browser.process();
      await browser.close().catch(() => {});
      try { proc?.kill("SIGKILL"); } catch {}
    }
    release();
  }
}

async function navigate(page: Page, url: string, waitUntil: string, delayMs: number) {
  await assertPublicHost(new URL(url).hostname);
  const res = await page.goto(url, { waitUntil: waitUntil as any, timeout: NAV_TIMEOUT_MS });
  if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
  return {
    finalUrl: page.url(),
    httpStatus: res?.status() ?? null,
    title: (await page.title().catch(() => "")) || null,
  };
}

const WAIT_UNTIL = ["load", "domcontentloaded", "networkidle0", "networkidle2"];

export const tools = {
  website_screenshot: {
    price: "$0.05",
    description:
      "Render a URL in a real headless Chromium browser and capture a PNG screenshot — either the viewport or the full scrolling page (capped at 10,000px tall). Options: viewport width/height, device scale factor (retina), wait condition, and extra delay for late-loading content. Returns a short-lived download URL (valid 1 hour) plus pixel dimensions, byte size and SHA-256; set includeBase64 for the PNG inline (up to 3 MB). Private/internal addresses are blocked. Pure rendering, no AI. For load-time numbers use page_performance_check or pagespeed_insights instead.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Page to capture, e.g. https://example.com (https:// is assumed if no scheme)" },
        fullPage: { type: "boolean", description: "Capture the full scrolling page instead of just the viewport (default false; capped at 10,000px tall)" },
        width: { type: "number", description: "Viewport width in CSS pixels, 320-1920 (default 1280)" },
        height: { type: "number", description: "Viewport height in CSS pixels, 240-2160 (default 800)" },
        deviceScaleFactor: { type: "number", description: "Device pixel ratio, 1-2 (default 1; 2 = retina)" },
        waitUntil: { type: "string", enum: WAIT_UNTIL, description: "When navigation counts as finished (default load)" },
        delayMs: { type: "number", description: "Extra wait after load before capturing, 0-5000 ms (default 0)" },
        includeBase64: { type: "boolean", description: "Also return the PNG as base64 in the response (default false; omitted if over 3 MB)" },
      },
      required: ["url"],
    },
    async run(args: { url: string; fullPage?: boolean; width?: number; height?: number; deviceScaleFactor?: number; waitUntil?: string; delayMs?: number; includeBase64?: boolean }) {
      const url = normalizeUrl(args.url);
      const width = clampInt(args.width, 1280, 320, 1920);
      const height = clampInt(args.height, 800, 240, 2160);
      const dpr = Math.min(2, Math.max(1, Number(args.deviceScaleFactor) || 1));
      const waitUntil = WAIT_UNTIL.includes(args.waitUntil ?? "") ? args.waitUntil! : "load";
      const delayMs = clampInt(args.delayMs, 0, 0, 5000);
      const blocked: string[] = [];
      return withBrowser(async (browser) => {
        const page = await browser.newPage();
        await guardPage(page, blocked);
        await page.setViewport({ width, height, deviceScaleFactor: dpr });
        const nav = await navigate(page, url, waitUntil, delayMs);
        let captureHeight = height;
        let truncated = false;
        if (args.fullPage) {
          const docHeight = await page.evaluate(() => Math.max(
            document.documentElement?.scrollHeight ?? 0,
            document.body?.scrollHeight ?? 0,
          )).catch(() => height);
          captureHeight = Math.max(height, Math.min(docHeight, MAX_FULLPAGE_HEIGHT));
          truncated = docHeight > MAX_FULLPAGE_HEIGHT;
        }
        const png = await page.screenshot({
          type: "png",
          clip: { x: 0, y: 0, width, height: captureHeight },
          captureBeyondViewport: !!args.fullPage,
        });
        if (png.byteLength > MAX_OUTPUT_BYTES) throw new Error(`Screenshot is ${png.byteLength} bytes, over the ${MAX_OUTPUT_BYTES}-byte limit; try a smaller size or fullPage=false`);
        return {
          ...nav,
          requestedUrl: url,
          mode: args.fullPage ? "fullPage" : "viewport",
          viewport: { width, height, deviceScaleFactor: dpr },
          image: {
            format: "png",
            width: Math.round(width * dpr),
            height: Math.round(captureHeight * dpr),
            truncatedAtMaxHeight: truncated,
            ...storeFile(png, "png", !!args.includeBase64),
          },
          blockedRequests: blocked,
        };
      });
    },
  },

  html_to_pdf: {
    price: "$0.05",
    description:
      "Render a URL or a raw HTML string to a PDF in headless Chromium (print-quality, selectable text). Options: paper format (A4, Letter, Legal, A3, A5, Tabloid), landscape, print backgrounds, margins, and scale. Returns a short-lived download URL (valid 1 hour) with byte size, page count and SHA-256; set includeBase64 for the PDF inline (up to 3 MB). Raw HTML up to 2 MB; any external resources it loads go through the same private-address block. Pure rendering, no AI.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Page to render (provide url OR html)" },
        html: { type: "string", description: "Raw HTML document to render instead of a URL (max 2 MB)" },
        format: { type: "string", enum: ["A4", "Letter", "Legal", "A3", "A5", "Tabloid"], description: "Paper size (default A4)" },
        landscape: { type: "boolean", description: "Landscape orientation (default false)" },
        printBackground: { type: "boolean", description: "Include CSS backgrounds and colors (default true)" },
        margin: { type: "string", description: "CSS margin applied to all sides, e.g. '1cm', '0.5in', '10mm' (default '1cm')" },
        scale: { type: "number", description: "Render scale, 0.1-2 (default 1)" },
        waitUntil: { type: "string", enum: WAIT_UNTIL, description: "When loading counts as finished (default load)" },
        includeBase64: { type: "boolean", description: "Also return the PDF as base64 in the response (default false; omitted if over 3 MB)" },
      },
    },
    async run(args: { url?: string; html?: string; format?: string; landscape?: boolean; printBackground?: boolean; margin?: string; scale?: number; waitUntil?: string; includeBase64?: boolean }) {
      if (!args.url && !args.html) throw new Error("Provide either url or html");
      if (args.url && args.html) throw new Error("Provide url OR html, not both");
      if (args.html && Buffer.byteLength(args.html, "utf8") > MAX_HTML_BYTES) throw new Error(`html is over the ${MAX_HTML_BYTES}-byte limit`);
      const url = args.url ? normalizeUrl(args.url) : null;
      const format = ["A4", "Letter", "Legal", "A3", "A5", "Tabloid"].includes(args.format ?? "") ? args.format! : "A4";
      const margin = typeof args.margin === "string" && /^\d+(\.\d+)?(px|in|cm|mm)$/.test(args.margin.trim()) ? args.margin.trim() : "1cm";
      const scale = Math.min(2, Math.max(0.1, Number(args.scale) || 1));
      const waitUntil = WAIT_UNTIL.includes(args.waitUntil ?? "") ? args.waitUntil! : "load";
      const blocked: string[] = [];
      return withBrowser(async (browser) => {
        const page = await browser.newPage();
        await guardPage(page, blocked);
        let nav: Record<string, unknown> = { source: "html" };
        if (url) {
          nav = { source: "url", requestedUrl: url, ...(await navigate(page, url, waitUntil, 0)) };
        } else {
          await page.setContent(args.html!, { waitUntil: waitUntil as any, timeout: NAV_TIMEOUT_MS });
          nav.title = (await page.title().catch(() => "")) || null;
        }
        const pdf = await page.pdf({
          format: format as any,
          landscape: !!args.landscape,
          printBackground: args.printBackground ?? true,
          margin: { top: margin, right: margin, bottom: margin, left: margin },
          scale,
          timeout: NAV_TIMEOUT_MS,
        });
        if (pdf.byteLength > MAX_OUTPUT_BYTES) throw new Error(`PDF is ${pdf.byteLength} bytes, over the ${MAX_OUTPUT_BYTES}-byte limit`);
        const pageCount = (Buffer.from(pdf).toString("latin1").match(/\/Type\s*\/Page(?!s)/g) ?? []).length || null;
        return {
          ...nav,
          pdf: {
            format,
            landscape: !!args.landscape,
            margin,
            scale,
            pageCount,
            ...storeFile(pdf, "pdf", !!args.includeBase64),
          },
          blockedRequests: blocked,
        };
      });
    },
  },
};

export type ToolName = keyof typeof tools;
