import { promises as dns } from "node:dns";

const EMAIL_RE = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// Small, well-known disposable-email domain sample. Not exhaustive — a false "not disposable"
// is expected for less common throwaway services; treat this as a signal, not a guarantee.
const DISPOSABLE_DOMAINS = new Set([
  "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com",
  "temp-mail.org", "throwawaymail.com", "yopmail.com", "getnada.com",
  "trashmail.com", "fakeinbox.com", "sharklasers.com", "dispostable.com",
  "maildrop.cc", "mintemail.com", "mytemp.email", "moakt.com",
]);

const ROLE_LOCAL_PARTS = new Set([
  "admin", "administrator", "info", "support", "sales", "contact", "help",
  "billing", "postmaster", "webmaster", "noreply", "no-reply", "abuse",
  "security", "root", "hostmaster", "marketing", "office",
]);

async function validateEmailAddress(email: string) {
  const trimmed = email.trim();
  const syntaxValid = EMAIL_RE.test(trimmed);
  const issues: string[] = [];

  if (!syntaxValid) {
    issues.push("Invalid email syntax");
    return { email: trimmed, syntaxValid: false, hasMx: null, isDisposable: null, isRoleAccount: null, issues };
  }

  const [localPart, domain] = trimmed.split("@");
  const domainLower = domain.toLowerCase();

  const isDisposable = DISPOSABLE_DOMAINS.has(domainLower);
  const isRoleAccount = ROLE_LOCAL_PARTS.has(localPart.toLowerCase());

  let hasMx = false;
  let mxHosts: string[] = [];
  try {
    const mx = await dns.resolveMx(domainLower);
    hasMx = mx.length > 0;
    mxHosts = mx.sort((a, b) => a.priority - b.priority).map((m) => m.exchange);
  } catch {
    // no MX — fall back to checking an A record, since some domains accept mail via bare A record
    try {
      await dns.resolve4(domainLower);
      hasMx = false;
      issues.push("No MX record — domain has an A record but no dedicated mail server configured (implicit MX, rarely used correctly)");
    } catch {
      issues.push("Domain does not resolve at all (no MX or A record) — mail cannot be delivered");
    }
  }

  if (isDisposable) issues.push("Domain is a known disposable/temporary email provider");
  if (isRoleAccount) issues.push("Local part looks like a role account (info@, admin@, etc.), not a personal inbox");

  return {
    email: trimmed,
    syntaxValid: true,
    domain: domainLower,
    hasMx,
    mxHosts,
    isDisposable,
    isRoleAccount,
    issues,
    deliverabilityRisk: !hasMx ? "high" : isDisposable ? "high" : isRoleAccount ? "medium" : "low",
  };
}

export const tools = {
  email_address_validate: {
    price: "$0.01",
    description:
      "Validate a single email address: RFC syntax check, MX record lookup on the domain, disposable/temporary-email-provider detection, and role-account detection (info@, admin@, etc.). Per-address check — different from email_deliverability_check, which audits a whole domain's sending reputation (SPF/DKIM/DMARC/PTR/DNSBL).",
    inputSchema: {
      type: "object",
      properties: {
        email: { type: "string", description: "Email address to validate" },
      },
      required: ["email"],
    },
    async run({ email }: { email: string }) {
      return validateEmailAddress(email);
    },
  },
};

export type ToolName = keyof typeof tools;
