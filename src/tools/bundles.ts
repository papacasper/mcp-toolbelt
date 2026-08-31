// Bundle tools chain multiple existing single-purpose tools into one paid call, one charge.
// Each sub-check runs independently via Promise.allSettled so one failure doesn't void the bundle.
import { tools as seoTools } from "./seo";
import { tools as dnsTools } from "./dns";

async function settled<T>(label: string, promise: Promise<T>) {
  try {
    return { ok: true as const, data: await promise };
  } catch (e: any) {
    return { ok: false as const, error: e?.message ?? String(e) };
  }
}

export const tools = {
  domain_report: {
    price: "$0.01",
    description:
      "Bundle: runs seo_audit, domain_health_check (WHOIS + DNS: nameservers, A/AAAA, MX, SPF, DMARC), and email_deliverability_check (DKIM, SPF lookup-count, DMARC strength, DNSBL) against a domain in one call, one charge. Cheaper than calling the three tools separately. Each sub-check reports independently, so a failure in one doesn't void the others.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Bare domain to report on, e.g. example.com (no scheme/path)" },
      },
      required: ["domain"],
    },
    async run({ domain }: { domain: string }) {
      const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
      const url = `https://${cleanDomain}`;

      const [seo, health, email] = await Promise.all([
        settled("seo_audit", seoTools.seo_audit.run({ url })),
        settled("domain_health_check", dnsTools.domain_health_check.run({ domain: cleanDomain })),
        settled("email_deliverability_check", dnsTools.email_deliverability_check.run({ domain: cleanDomain })),
      ]);

      return { domain: cleanDomain, seo, domainHealth: health, emailDeliverability: email };
    },
  },
};
