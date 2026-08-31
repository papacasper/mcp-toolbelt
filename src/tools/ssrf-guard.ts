import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true; // link-local + cloud metadata (169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  if (a >= 224) return true; // multicast/reserved
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === "::1" || lower === "::") return true;
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // fc00::/7 (ULA)
  if (/^fe[89ab]/.test(lower)) return true; // fe80::/10 (link-local)
  if (lower.startsWith("::ffff:")) {
    const v4 = lower.split(":").pop()!;
    if (isIP(v4) === 4) return isPrivateIPv4(v4);
  }
  return false;
}

/**
 * Resolves `hostname` and throws if it (or any resolved address) is loopback,
 * link-local, private-range, or otherwise internal. Prevents public tool calls
 * from being used to reach the host's own network or cloud metadata endpoints.
 * Only checks the initial hostname, not subsequent redirect hops.
 */
export async function assertPublicHost(hostname: string): Promise<void> {
  const clean = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (!clean) throw new Error("Empty hostname");

  if (clean === "localhost" || clean.endsWith(".localhost")) {
    throw new Error(`Refusing to connect to internal host: ${clean}`);
  }

  const family = isIP(clean);
  if (family) {
    const blocked = family === 4 ? isPrivateIPv4(clean) : isPrivateIPv6(clean);
    if (blocked) throw new Error(`Refusing to connect to private/internal address: ${clean}`);
    return;
  }

  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await lookup(clean, { all: true, verbatim: true });
  } catch {
    return; // let the real connection attempt surface the DNS error naturally
  }
  for (const { address, family: fam } of addresses) {
    const blocked = fam === 4 ? isPrivateIPv4(address) : isPrivateIPv6(address);
    if (blocked) {
      throw new Error(`Refusing to connect to ${clean}: resolves to private/internal address ${address}`);
    }
  }
}

/**
 * Monkey-patches globalThis.fetch so every tool's fetch() call is checked
 * against assertPublicHost before the real network request is made.
 * Centralizing here means new tools get the guard for free.
 */
export function installFetchGuard(): void {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: any, init?: any) => {
    const urlStr = typeof input === "string" ? input : input instanceof URL ? input.toString() : input?.url;
    if (urlStr) {
      const hostname = new URL(urlStr).hostname;
      await assertPublicHost(hostname);
    }
    return originalFetch(input, init);
  }) as typeof fetch;
}
