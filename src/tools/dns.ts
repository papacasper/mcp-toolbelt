import { promises as dns } from "node:dns";
import { whoisQuery, extractWhoisField } from "./shared";

async function lookupDomainWhois(domain: string): Promise<{
  registrar: string | null;
  createdDate: string | null;
  expiryDate: string | null;
  daysRemaining: number | null;
  expired: boolean | null;
  whoisServer: string | null;
}> {
  const ianaRaw = await whoisQuery("whois.iana.org", domain);
  const referral = extractWhoisField(ianaRaw, ["refer", "whois"]);
  const server = referral || "whois.iana.org";

  let raw = ianaRaw;
  if (referral && referral !== "whois.iana.org") {
    try {
      raw = await whoisQuery(referral, domain);
    } catch {
      // fall back to the IANA response if the registry's own whois is unreachable
    }
  }

  const expiryRaw = extractWhoisField(raw, [
    "Registry Expiry Date",
    "Registrar Registration Expiration Date",
    "Expiration Date",
    "Expiry Date",
    "paid-till",
  ]);
  const createdRaw = extractWhoisField(raw, ["Creation Date", "Created On", "Domain Registration Date", "created"]);
  const registrar = extractWhoisField(raw, ["Registrar:", "Registrar Name", "sponsoring registrar"]);

  const expiryDate = expiryRaw ? new Date(expiryRaw) : null;
  const daysRemaining =
    expiryDate && !Number.isNaN(expiryDate.getTime())
      ? Math.ceil((expiryDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
      : null;

  return {
    registrar,
    createdDate: createdRaw ? new Date(createdRaw).toISOString().slice(0, 10) : null,
    expiryDate: expiryDate && !Number.isNaN(expiryDate.getTime()) ? expiryDate.toISOString().slice(0, 10) : null,
    daysRemaining,
    expired: daysRemaining === null ? null : daysRemaining < 0,
    whoisServer: server,
  };
}

async function safe<T>(fn: () => Promise<T>): Promise<T | null> {
  try {
    return await fn();
  } catch {
    return null;
  }
}

async function lookupDnsHealth(domain: string) {
  const [ns, a, aaaa, mx, txt, dmarcTxt, dkimTxt] = await Promise.all([
    safe(() => dns.resolveNs(domain)),
    safe(() => dns.resolve4(domain)),
    safe(() => dns.resolve6(domain)),
    safe(() => dns.resolveMx(domain)),
    safe(() => dns.resolveTxt(domain)),
    safe(() => dns.resolveTxt(`_dmarc.${domain}`)),
    safe(() => dns.resolveTxt(`default._domainkey.${domain}`)),
  ]);

  const flatten = (records: string[][] | null) => records?.map((r) => r.join("")) ?? [];
  const txtFlat = flatten(txt);
  const spf = txtFlat.find((t) => t.toLowerCase().startsWith("v=spf1")) ?? null;
  const dmarc = flatten(dmarcTxt).find((t) => t.toLowerCase().startsWith("v=dmarc1")) ?? null;
  const dkim = flatten(dkimTxt)[0] ?? null;

  return {
    nameservers: ns ?? [],
    a: a ?? [],
    aaaa: aaaa ?? [],
    mx: (mx ?? []).sort((x, y) => x.priority - y.priority).map((m) => `${m.priority} ${m.exchange}`),
    spf,
    dmarc,
    dkimSelectorChecked: "default",
    dkim,
    issues: [
      !ns?.length && "No nameservers found",
      !mx?.length && "No MX records found",
      !spf && "No SPF record found",
      !dmarc && "No DMARC record found",
    ].filter(Boolean) as string[],
  };
}

export const tools = {
  domain_health_check: {
    price: "$0.0005",
    description:
      "Check a domain's registration expiry (via WHOIS) and DNS health: nameservers, A/AAAA, MX, SPF, and DMARC records. Flags common misconfigurations.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Bare domain to check, e.g. example.com (no scheme/path)" },
      },
      required: ["domain"],
    },
    async run({ domain }: { domain: string }) {
      const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
      const [whois, dnsHealth] = await Promise.all([
        lookupDomainWhois(cleanDomain).catch((e) => ({ error: e?.message ?? String(e) })),
        lookupDnsHealth(cleanDomain),
      ]);
      return { domain: cleanDomain, whois, dns: dnsHealth };
    },
  },
};

export type ToolName = keyof typeof tools;
