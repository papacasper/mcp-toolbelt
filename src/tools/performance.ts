const PSI_KEY = process.env.GOOGLE_PAGESPEED_API_KEY ?? "";
const PSI_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed";

async function fetchPageSpeed(url: string, strategy: "mobile" | "desktop") {
  const params = new URLSearchParams({ url, strategy, category: "PERFORMANCE" });
  if (PSI_KEY) params.set("key", PSI_KEY);
  const res = await fetch(`${PSI_ENDPOINT}?${params}`, {
    headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`PageSpeed Insights API error: ${res.status} ${res.statusText}${body ? ` — ${body.slice(0, 300)}` : ""}`);
  }
  const data: any = await res.json();
  const lighthouse = data.lighthouseResult;
  const audits = lighthouse?.audits ?? {};
  const crux = data.loadingExperience?.metrics ?? {};

  const metric = (id: string) => ({
    score: audits[id]?.score ?? null,
    displayValue: audits[id]?.displayValue ?? null,
    numericValue: audits[id]?.numericValue ?? null,
  });

  const cruxMetric = (id: string) => {
    const m = crux[id];
    if (!m) return null;
    return { percentile: m.percentile, category: m.category };
  };

  return {
    url,
    strategy,
    performanceScore: lighthouse?.categories?.performance?.score != null
      ? Math.round(lighthouse.categories.performance.score * 100)
      : null,
    labMetrics: {
      firstContentfulPaint: metric("first-contentful-paint"),
      largestContentfulPaint: metric("largest-contentful-paint"),
      totalBlockingTime: metric("total-blocking-time"),
      cumulativeLayoutShift: metric("cumulative-layout-shift"),
      speedIndex: metric("speed-index"),
      interactive: metric("interactive"),
    },
    fieldData: {
      note: crux && Object.keys(crux).length
        ? "Real-user Chrome UX Report data for the last 28 days, where available."
        : "No field data available for this URL (insufficient real-user traffic in Chrome UX Report).",
      largestContentfulPaint: cruxMetric("LARGEST_CONTENTFUL_PAINT_MS"),
      interactionToNextPaint: cruxMetric("INTERACTION_TO_NEXT_PAINT"),
      cumulativeLayoutShift: cruxMetric("CUMULATIVE_LAYOUT_SHIFT_SCORE"),
    },
  };
}

export const tools = {
  pagespeed_insights: {
    price: "$0.01",
    description:
      "Run Google's real PageSpeed Insights (Lighthouse + Chrome UX Report) against a URL: performance score, Core Web Vitals (LCP, CLS, INP/TBT), and real-user field data where available. Authoritative version of a local timing check — hits Google's own infrastructure. Works without an API key at low volume; set GOOGLE_PAGESPEED_API_KEY server-side for higher throughput.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "The URL to test" },
        strategy: { type: "string", enum: ["mobile", "desktop"], description: "Device strategy (default mobile)" },
      },
      required: ["url"],
    },
    async run({ url, strategy }: { url: string; strategy?: "mobile" | "desktop" }) {
      return fetchPageSpeed(url, strategy ?? "mobile");
    },
  },
};

export type ToolName = keyof typeof tools;
