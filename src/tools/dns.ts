import { promises as dns, Resolver } from "node:dns";
import { whoisQuery, extractWhoisField, mapWithConcurrency } from "./shared";

const PUBLIC_RESOLVERS: Record<string, string> = {
  google: "8.8.8.8",
  cloudflare: "1.1.1.1",
  quad9: "9.9.9.9",
  opendns: "208.67.222.222",
};

type RecordType = "A" | "AAAA" | "MX" | "TXT" | "NS" | "CNAME";

function resolveWith(server: string, domain: string, type: RecordType): Promise<string[]> {
  return new Promise((resolve) => {
    const resolver = new Resolver();
    resolver.setServers([server]);
    resolver.setTimeout?.(5000);
    const cb = (err: any, records: any) => {
      if (err) return resolve([]);
      if (type === "MX") {
        resolve((records as any[]).sort((a, b) => a.priority - b.priority).map((r) => `${r.priority} ${r.exchange}`));
      } else if (type === "TXT") {
        resolve((records as string[][]).map((r) => r.join("")));
      } else {
        resolve(records as string[]);
      }
    };
    switch (type) {
      case "A": return resolver.resolve4(domain, cb);
      case "AAAA": return resolver.resolve6(domain, cb);
      case "MX": return resolver.resolveMx(domain, cb);
      case "TXT": return resolver.resolveTxt(domain, cb);
      case "NS": return resolver.resolveNs(domain, cb);
      case "CNAME": return resolver.resolveCname(domain, cb);
    }
  });
}

const TLD_WHOIS_SERVERS: Record<string, string> = {
  com: "whois.verisign-grs.com",
  net: "whois.verisign-grs.com",
  org: "whois.pir.org",
  io: "whois.identity.digital",
  info: "whois.identity.digital",
  co: "whois.nic.co",
  ai: "whois.nic.ai",
  app: "whois.nic.google",
  dev: "whois.nic.google",
  me: "whois.nic.me",
  tv: "whois.nic.tv",
  biz: "whois.nic.biz",
  us: "whois.nic.us",
  xyz: "whois.nic.xyz",
  site: "whois.nic.site",
  online: "whois.nic.online",
  tech: "whois.nic.tech",
};

const WHOIS_EXPIRY_LABELS = [
  "Registry Expiry Date",
  "Registrar Registration Expiration Date",
  "Expiration Date",
  "Expiry Date",
  "Renewal Date",
  "paid-till",
];
const WHOIS_CREATED_LABELS = ["Creation Date", "Created On", "Domain Registration Date", "Registered On", "created"];
const WHOIS_REGISTRAR_LABELS = ["Registrar:", "Registrar Name", "Sponsoring Registrar", "sponsoring registrar"];

async function registryWhois(domain: string): Promise<{ server: string; raw: string }> {
  // Query the TLD registry whois directly when known. whois.iana.org cannot be
  // relied on for a referral: for some domains (e.g. example.com) its response
  // is a stub with no "refer:" line at all, which used to leave registrar and
  // expiry permanently null.
  const tld = domain.split(".").pop()?.toLowerCase() ?? "";
  let server = TLD_WHOIS_SERVERS[tld];
  if (!server) {
    const ianaRaw = await whoisQuery("whois.iana.org", domain);
    server = extractWhoisField(ianaRaw, ["refer", "whois"]) || "whois.iana.org";
    if (server === "whois.iana.org") return { server, raw: ianaRaw };
  }
  let raw = await whoisQuery(server, domain);
  // Thin registries (e.g. Verisign for .com/.net) sometimes omit fields that
  // only the registrar record has; follow one more hop when expiry is missing.
  if (!extractWhoisField(raw, WHOIS_EXPIRY_LABELS)) {
    const registrarServer = extractWhoisField(raw, ["Registrar WHOIS Server"]);
    if (registrarServer && registrarServer.toLowerCase() !== server.toLowerCase()) {
      try {
        const registrarRaw = await whoisQuery(registrarServer, domain);
        if (extractWhoisField(registrarRaw, WHOIS_EXPIRY_LABELS)) {
          return { server: registrarServer, raw: registrarRaw };
        }
      } catch {
        // keep the registry response
      }
    }
  }
  return { server, raw };
}

async function lookupDomainWhois(domain: string): Promise<{
  registrar: string | null;
  createdDate: string | null;
  expiryDate: string | null;
  daysRemaining: number | null;
  expired: boolean | null;
  whoisServer: string | null;
  raw?: string;
}> {
  const { server, raw } = await registryWhois(domain);

  const expiryRaw = extractWhoisField(raw, WHOIS_EXPIRY_LABELS);
  const createdRaw = extractWhoisField(raw, WHOIS_CREATED_LABELS);
  const registrar = extractWhoisField(raw, WHOIS_REGISTRAR_LABELS);

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
    raw,
  };
}

function extractAllWhoisField(raw: string, labels: string[]): string[] {
  const out: string[] = [];
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    for (const label of labels) {
      if (line.toLowerCase().startsWith(label.toLowerCase())) {
        const value = line.slice(line.indexOf(":") + 1).trim();
        if (value && !out.includes(value)) out.push(value);
      }
    }
  }
  return out;
}

function reverseIpv4(ip: string): string {
  return ip.split(".").reverse().join(".");
}

export async function cymruAsnLookup(ip: string): Promise<{
  asn: string | null;
  prefix: string | null;
  countryCode: string | null;
  registry: string | null;
  asName: string | null;
}> {
  const origin = await dns.resolveTxt(`${reverseIpv4(ip)}.origin.asn.cymru.com`).catch(() => null);
  const originLine = origin?.[0]?.join("") ?? null;
  if (!originLine) return { asn: null, prefix: null, countryCode: null, registry: null, asName: null };

  const [asnRaw, prefix, countryCode, registry] = originLine.split("|").map((s) => s.trim());
  const asn = asnRaw?.split(" ")[0] ?? null;

  let asName: string | null = null;
  if (asn) {
    const nameTxt = await dns.resolveTxt(`AS${asn}.asn.cymru.com`).catch(() => null);
    const nameLine = nameTxt?.[0]?.join("") ?? null;
    asName = nameLine?.split("|").pop()?.trim() ?? null;
  }

  return { asn: asn ? `AS${asn}` : null, prefix: prefix ?? null, countryCode: countryCode ?? null, registry: registry ?? null, asName };
}

const DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1"];
const DNSBL_ZONES: Record<string, string> = {
  spamhausZen: "zen.spamhaus.org",
  spamcop: "bl.spamcop.net",
  barracuda: "b.barracudacentral.org",
};

async function probeDkimSelectors(domain: string): Promise<Array<{ selector: string; found: boolean; value: string | null }>> {
  const results = await Promise.all(
    DKIM_SELECTORS.map(async (selector) => {
      const txt = await dns.resolveTxt(`${selector}._domainkey.${domain}`).catch(() => null);
      const value = txt?.[0]?.join("") ?? null;
      return { selector, found: !!value, value };
    })
  );
  return results;
}

function countSpfLookups(spf: string): number {
  const mechanisms = spf.match(/\b(include|a|mx|ptr|exists|redirect)(:|=|\b)/gi) ?? [];
  return mechanisms.length;
}

async function reverseDns(ip: string): Promise<string[]> {
  // dns.reverse() (getnameinfo) silently returns [] on some systems even when a
  // PTR record exists; an explicit PTR query is reliable, so use that.
  const ptrName = `${reverseIpv4(ip)}.in-addr.arpa`;
  return withTimeout(dns.resolvePtr(ptrName), 4000).catch(() => []);
}

function isDnsblErrorCode(codes: string[]): boolean {
  // Spamhaus (and others) return 127.255.255.x for query errors/rate-limiting, not real listings.
  return codes.every((c) => c.startsWith("127.255.255."));
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Object.assign(new Error("timeout"), { code: "ETIMEOUT" })), timeoutMs);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); }
    );
  });
}

async function dnsblLookup(
  ip: string,
  zone: string
): Promise<{ listed: boolean | null; codes: string[]; note: string | null }> {
  try {
    const codes = await withTimeout(dns.resolve4(`${reverseIpv4(ip)}.${zone}`), 2500);
    if (isDnsblErrorCode(codes)) {
      return {
        listed: null,
        codes,
        note: "The list operator refused this query (127.255.255.x = query sent via a public/blocked resolver), so listed status is unknown, not clean. A Spamhaus DQS key or a non-public resolver is required for a definitive answer.",
      };
    }
    return { listed: true, codes, note: null };
  } catch (e: any) {
    if (e?.code === "ENOTFOUND" || e?.code === "ENODATA") return { listed: false, codes: [], note: null };
    return { listed: null, codes: [], note: "DNSBL query failed or timed out; listed status unknown." };
  }
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

const COMMON_TLDS = ["com", "net", "org", "io", "co", "ai", "app", "dev"];
const KEYBOARD_ADJACENT: Record<string, string[]> = {
  q: ["w", "a"], w: ["q", "e", "s"], e: ["w", "r", "d"], r: ["e", "t", "f"], t: ["r", "y", "g"],
  y: ["t", "u", "h"], u: ["y", "i", "j"], i: ["u", "o", "k"], o: ["i", "p", "l"], p: ["o", "l"],
  a: ["q", "s", "z"], s: ["a", "d", "w"], d: ["s", "f", "e"], f: ["d", "g", "r"], g: ["f", "h", "t"],
  h: ["g", "j", "y"], j: ["h", "k", "u"], k: ["j", "l", "i"], l: ["k", "o"],
  z: ["a", "x"], x: ["z", "c"], c: ["x", "v"], v: ["c", "b"], b: ["v", "n"], n: ["b", "m"], m: ["n"],
};

function generateTypoVariants(label: string): Set<string> {
  const variants = new Set<string>();

  for (let i = 0; i < label.length; i++) {
    // omission
    variants.add(label.slice(0, i) + label.slice(i + 1));
    // doubling
    variants.add(label.slice(0, i) + label[i] + label[i] + label.slice(i + 1));
    // adjacent-key substitution
    for (const adj of KEYBOARD_ADJACENT[label[i]] ?? []) {
      variants.add(label.slice(0, i) + adj + label.slice(i + 1));
    }
    // adjacent transposition
    if (i < label.length - 1) {
      variants.add(label.slice(0, i) + label[i + 1] + label[i] + label.slice(i + 2));
    }
  }

  variants.delete(label);
  variants.delete("");
  return variants;
}

async function isDomainRegistered(domain: string): Promise<boolean | null> {
  try {
    const { raw } = await registryWhois(domain);
    if (/No match|NOT FOUND|No Data Found|no entries found|Domain not found|Status:\s*free|is available/i.test(raw)) {
      return false;
    }
    if (/Domain Name:|Creation Date:|Registrar:/i.test(raw)) return true;
    return null;
  } catch {
    return null;
  }
}

export const tools = {
  domain_health_check: {
    price: "$0.05",
    description:
      "Check a domain's registration expiry (via WHOIS) and DNS health: nameservers, A/AAAA, MX, SPF, and DMARC records. Flags common misconfigurations. WHOIS + DNS only — for the WHOIS record alone use whois_lookup; for deliverability detail (DKIM, DNSBL, PTR) use email_deliverability_check; for all of it plus SEO in one report use domain_report.",
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

  dns_propagation_check: {
    price: "$0.01",
    description:
      "Query a DNS record for a domain against several major public resolvers (Google, Cloudflare, Quad9, OpenDNS) in parallel and compare the answers. Flags mismatches, which usually mean propagation is still in progress after a DNS change.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Bare domain to query, e.g. example.com" },
        recordType: { type: "string", description: "Record type: A, AAAA, MX, TXT, NS, or CNAME (default A)" },
      },
      required: ["domain"],
    },
    async run({ domain, recordType }: { domain: string; recordType?: string }) {
      const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
      const type = ((recordType ?? "A").toUpperCase()) as RecordType;
      if (!["A", "AAAA", "MX", "TXT", "NS", "CNAME"].includes(type)) {
        throw new Error(`Unsupported recordType: ${recordType}. Use A, AAAA, MX, TXT, NS, or CNAME.`);
      }

      const entries = Object.entries(PUBLIC_RESOLVERS);
      const answers = await Promise.all(entries.map(([, server]) => resolveWith(server, cleanDomain, type)));

      const results = entries.map(([name, server], i) => ({
        resolver: name,
        server,
        answers: [...answers[i]].sort(),
      }));

      const signatures = new Set(results.map((r) => JSON.stringify(r.answers)));
      const propagated = signatures.size <= 1;

      return {
        domain: cleanDomain,
        recordType: type,
        propagated,
        results,
        issues: propagated ? [] : ["Resolvers disagree on the answer — DNS change may still be propagating, or resolvers are caching stale records"],
      };
    },
  },

  email_deliverability_check: {
    price: "$0.05",
    description:
      "Deep-dive email deliverability check for a domain: MX records + reverse-DNS (PTR) on each MX host, common DKIM selector probing, SPF lookup-count (RFC 7208 caps at 10), DMARC policy strength, and DNSBL blacklist lookups (Spamhaus Zen, SpamCop, Barracuda) on MX IPs. Note: public-resolver DNSBL queries are frequently rate-limited or blocked by Spamhaus, so a `listed: null` result means \"unknown\", not \"clean\" — treat null results as inconclusive, not as a clean bill of health.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Bare domain to check, e.g. example.com" },
      },
      required: ["domain"],
    },
    async run({ domain }: { domain: string }) {
      const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();

      const mx = await dns.resolveMx(cleanDomain).catch(() => []);
      const sortedMx = [...mx].sort((a, b) => a.priority - b.priority).slice(0, 5);

      const mxDetails = await Promise.all(
        sortedMx.map(async (m) => {
          const ips = (await dns.resolve4(m.exchange).catch(() => [] as string[])).slice(0, 2);
          const perIp = await Promise.all(
            ips.map(async (ip) => {
              const ptr = await reverseDns(ip);
              const dnsbl = await Promise.all(
                Object.entries(DNSBL_ZONES).map(async ([name, zone]) => [name, await dnsblLookup(ip, zone)] as const)
              );
              return { ip, ptr, dnsbl: Object.fromEntries(dnsbl) };
            })
          );
          return { priority: m.priority, exchange: m.exchange, ips: perIp };
        })
      );

      const txt = await dns.resolveTxt(cleanDomain).catch(() => []);
      const spf = txt.map((r) => r.join("")).find((t) => t.toLowerCase().startsWith("v=spf1")) ?? null;
      const spfLookupCount = spf ? countSpfLookups(spf) : null;

      const dmarcTxt = await dns.resolveTxt(`_dmarc.${cleanDomain}`).catch(() => []);
      const dmarc = dmarcTxt.map((r) => r.join("")).find((t) => t.toLowerCase().startsWith("v=dmarc1")) ?? null;
      const dmarcPolicy = dmarc?.match(/;\s*p=(\w+)/i)?.[1]?.toLowerCase() ?? null;

      const dkimSelectors = await probeDkimSelectors(cleanDomain);

      const issues: string[] = [];
      if (!sortedMx.length) issues.push("No MX records found");
      if (!spf) issues.push("No SPF record found");
      else if (spfLookupCount !== null && spfLookupCount > 10) issues.push(`SPF record has ${spfLookupCount} lookup-triggering mechanisms — exceeds the RFC 7208 limit of 10, which causes a PermError`);
      if (!dmarc) issues.push("No DMARC record found");
      else if (dmarcPolicy === "none") issues.push('DMARC policy is "none" — monitoring only, no enforcement against spoofing');
      if (!dkimSelectors.some((s) => s.found)) issues.push("No DKIM record found under any commonly-used selector (this doesn't rule out a custom selector)");
      for (const m of mxDetails) {
        for (const ip of m.ips) {
          if (!ip.ptr.length) issues.push(`MX host ${m.exchange} (${ip.ip}) has no reverse DNS (PTR) record — many receiving servers penalize this`);
          for (const [zone, result] of Object.entries(ip.dnsbl)) {
            if ((result as any).listed === true) issues.push(`MX host ${m.exchange} (${ip.ip}) is listed on ${zone}`);
          }
        }
      }

      return {
        domain: cleanDomain,
        mx: mxDetails,
        spf: { record: spf, lookupCount: spfLookupCount },
        dmarc: { record: dmarc, policy: dmarcPolicy },
        dkimSelectorsChecked: dkimSelectors,
        issues,
      };
    },
  },

  whois_lookup: {
    price: "$0.01",
    description:
      "Look up a domain's WHOIS registration record: registrar, creation and expiry dates, days remaining, name servers, and domain statuses, direct from the TLD registry. Registration data only — for DNS/mail health as well, use domain_health_check; for a combined report, use domain_report.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Bare domain to look up, e.g. example.com (no scheme/path)" },
      },
      required: ["domain"],
    },
    async run({ domain }: { domain: string }) {
      const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
      const { server, raw } = await registryWhois(cleanDomain);
      const registered = /Domain Name:|Creation Date:|Registrar:/i.test(raw)
        ? true
        : /No match|NOT FOUND|No Data Found|no entries found|Domain not found/i.test(raw)
          ? false
          : null;
      const whois = await lookupDomainWhois(cleanDomain).catch(() => null);
      return {
        domain: cleanDomain,
        registered,
        registrar: whois?.registrar ?? null,
        createdDate: whois?.createdDate ?? null,
        expiryDate: whois?.expiryDate ?? null,
        daysRemaining: whois?.daysRemaining ?? null,
        expired: whois?.expired ?? null,
        nameServers: extractAllWhoisField(raw, ["Name Server", "Nameserver", "nserver"]),
        statuses: extractAllWhoisField(raw, ["Domain Status", "status"]),
        whoisServer: server,
        raw: raw.slice(0, 2000),
      };
    },
  },

  domain_availability_check: {
    price: "$0.01",
    description:
      "Check whether a domain is registered, plus scan common typo-squat variants (adjacent-key substitution, letter omission/doubling, transposition) across popular TLDs (.com, .net, .org, .io, .co, .ai, .app, .dev) for brand-protection or domain-flipping research. WHOIS-based; capped at 40 variants checked per call for latency.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Bare domain to check, e.g. example.com" },
        checkSquats: { type: "boolean", description: "Also scan typo-squat variants (default true)" },
      },
      required: ["domain"],
    },
    async run({ domain, checkSquats }: { domain: string; checkSquats?: boolean }) {
      const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
      const parts = cleanDomain.split(".");
      const tld = parts.length > 1 ? parts.slice(1).join(".") : "com";
      const label = parts[0];

      const registered = await isDomainRegistered(cleanDomain);

      if (checkSquats === false) {
        return { domain: cleanDomain, registered, squats: null };
      }

      const variantLabels = [...generateTypoVariants(label)].slice(0, 20);
      const candidates: string[] = [];
      for (const v of variantLabels) candidates.push(`${v}.${tld}`);
      for (const t of COMMON_TLDS) {
        if (t !== tld) candidates.push(`${label}.${t}`);
      }
      const capped = candidates.slice(0, 40);

      const results = await mapWithConcurrency(capped, 6, async (d) => ({
        domain: d,
        registered: await isDomainRegistered(d),
      }));

      return {
        domain: cleanDomain,
        registered,
        squatsChecked: results.length,
        squatsRegistered: results.filter((r) => r.registered === true),
        squatsAvailable: results.filter((r) => r.registered === false),
        squatsUnknown: results.filter((r) => r.registered === null).map((r) => r.domain),
      };
    },
  },
  subdomain_discovery: {
    price: "$0.05",
    description:
      "Enumerate a domain's subdomains from public Certificate Transparency logs (crt.sh, with a Cert Spotter fallback): every hostname that has ever appeared on a certificate for the domain. Passive reconnaissance - no packets are sent to the target. Useful for attack-surface reviews, migration inventories, and finding forgotten test/staging hosts.",
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Bare domain to enumerate, e.g. example.com (no scheme/path)" },
      },
      required: ["domain"],
    },
    async run({ domain }: { domain: string }) {
      const cleanDomain = domain.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();

      const names = new Set<string>();
      let source: string | null = null;

      try {
        const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(cleanDomain)}&output=json`, {
          headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" },
          signal: AbortSignal.timeout(25000),
        });
        if (res.ok) {
          const data: any[] = await res.json();
          for (const entry of data) {
            for (const field of [entry.name_value, entry.common_name]) {
              if (!field) continue;
              for (const n of String(field).split("\n")) {
                const name = n.trim().toLowerCase().replace(/^\*\./, "");
                if (name.endsWith(cleanDomain)) names.add(name);
              }
            }
          }
          if (names.size) source = "crt.sh";
        }
      } catch {
        // fall through to the fallback source
      }

      if (!names.size) {
        const res = await fetch(
          `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(cleanDomain)}&include_subdomains=true&expand=dns_names`,
          { headers: { "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)" }, signal: AbortSignal.timeout(25000) }
        );
        if (!res.ok) throw new Error(`Certificate Transparency lookup failed (crt.sh unreachable, Cert Spotter returned ${res.status})`);
        const data: any[] = await res.json();
        for (const entry of data) {
          for (const n of entry.dns_names ?? []) {
            const name = String(n).toLowerCase().replace(/^\*\./, "");
            if (name.endsWith(cleanDomain)) names.add(name);
          }
        }
        source = "certspotter";
      }

      const subdomains = [...names].sort();
      return {
        domain: cleanDomain,
        source,
        totalFound: subdomains.length,
        subdomains: subdomains.slice(0, 500),
        truncated: subdomains.length > 500,
        note: "Names come from certificates issued historically; a listed subdomain may no longer resolve, and hosts without certificates are invisible here.",
      };
    },
  },

};

export type ToolName = keyof typeof tools;
