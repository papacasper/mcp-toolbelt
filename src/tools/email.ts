import { promises as dns } from "node:dns";
import { connect as netConnect } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { assertPublicHost } from "./ssrf-guard";

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


interface SmtpLine { code: number; text: string; more: boolean }

function readSmtpLines(socket: any, timeoutMs = 10000): Promise<SmtpLine[]> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const lines: SmtpLine[] = [];
    const timer = setTimeout(() => { cleanup(); reject(new Error("Timed out waiting for SMTP response")); }, timeoutMs);
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      let idx: number;
      while ((idx = buffer.indexOf("\r\n")) >= 0) {
        const raw = buffer.slice(0, idx);
        buffer = buffer.slice(idx + 2);
        const m = raw.match(/^(\d{3})([ -])(.*)$/);
        if (!m) continue;
        const more = m[2] === "-";
        lines.push({ code: Number(m[1]), text: m[3], more });
        if (!more) { cleanup(); resolve(lines); return; }
      }
    };
    const onError = (e: any) => { cleanup(); reject(e); };
    const cleanup = () => {
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("error", onError);
    };
    socket.on("data", onData);
    socket.on("error", onError);
  });
}

async function probeSmtp(host: string, port: number) {
  const socket: any = netConnect({ host, port, timeout: 10000 });
  socket.setEncoding("utf8");
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("timeout", () => { socket.destroy(); reject(new Error(`Connection to ${host}:${port} timed out`)); });
    socket.once("error", reject);
  });

  try {
    const bannerLines = await readSmtpLines(socket);
    const banner = bannerLines.map((l) => l.text).join(" ").trim();

    socket.write(`EHLO toolbelt.papacasper.com\r\n`);
    const ehloLines = await readSmtpLines(socket);
    const capabilities = ehloLines.map((l) => l.text.trim()).filter(Boolean);
    const capsUpper = capabilities.map((c) => c.toUpperCase());
    const offersStarttls = capsUpper.some((c) => c.startsWith("STARTTLS"));
    const authLine = capabilities.find((c) => c.toUpperCase().startsWith("AUTH"));
    const authMechanisms = authLine ? authLine.split(/\s+/).slice(1) : [];
    const sizeLine = capabilities.find((c) => c.toUpperCase().startsWith("SIZE"));
    const maxSize = sizeLine ? Number(sizeLine.split(/\s+/)[1]) || null : null;

    let starttls: any = { offered: offersStarttls, upgraded: false };
    if (offersStarttls) {
      try {
        socket.write("STARTTLS\r\n");
        const tlsResp = await readSmtpLines(socket);
        if (tlsResp[0]?.code === 220) {
          const tlsSocket: any = tlsConnect({ socket, servername: host });
          await new Promise<void>((resolve, reject) => {
            tlsSocket.once("secureConnect", resolve);
            tlsSocket.once("error", reject);
            setTimeout(() => reject(new Error("STARTTLS upgrade timed out")), 10000);
          });
          const cert = tlsSocket.getPeerCertificate();
          starttls = {
            offered: true,
            upgraded: true,
            protocol: tlsSocket.getProtocol(),
            authorized: tlsSocket.authorized,
            cert: cert?.valid_to ? {
              subject: cert.subject?.CN ?? null,
              issuer: cert.issuer?.CN ?? null,
              validTo: new Date(cert.valid_to).toISOString(),
              daysRemaining: Math.ceil((new Date(cert.valid_to).getTime() - Date.now()) / (1000 * 60 * 60 * 24)),
            } : null,
          };
          try { tlsSocket.write("QUIT\r\n"); } catch {}
          tlsSocket.end();
        } else {
          starttls = { offered: true, upgraded: false, error: `Server refused STARTTLS (code ${tlsResp[0]?.code})` };
        }
      } catch (e: any) {
        starttls = { offered: true, upgraded: false, error: e?.message ?? String(e) };
      }
    }

    if (!starttls.upgraded) {
      try { socket.write("QUIT\r\n"); } catch {}
      socket.end();
    }

    const issues: string[] = [];
    if (!offersStarttls) issues.push("STARTTLS not offered — mail transport to this server is unencrypted");
    if (offersStarttls && !starttls.upgraded) issues.push("STARTTLS offered but the upgrade failed");
    if (starttls.cert && starttls.cert.daysRemaining < 30) issues.push(`Mail certificate expires in ${starttls.cert.daysRemaining} days`);
    if (authMechanisms.includes("LOGIN") && !offersStarttls) issues.push("AUTH LOGIN advertised without STARTTLS — credentials could cross the wire unencrypted");
    if (!banner) issues.push("No SMTP banner received");

    return {
      reachable: true,
      banner,
      capabilities,
      authMechanisms,
      maxMessageSize: maxSize,
      starttls,
      issues,
      note: "No mail was sent and no open-relay test was performed.",
    };
  } catch (e) {
    try { socket.destroy(); } catch {}
    throw e;
  }
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
  smtp_server_check: {
    price: "$0.05",
    description:
      "Live-probe a mail server over SMTP: connects to port 25 (or a given port), reads the banner, issues EHLO and lists advertised capabilities (STARTTLS, AUTH mechanisms, SIZE, 8BITMIME, PIPELINING), then upgrades via STARTTLS when offered and reports the TLS protocol and certificate (issuer, expiry). The server-side complement to email_deliverability_check (which reads DNS records only and never connects). No mail is sent and no relay attempt is made.",
    inputSchema: {
      type: "object",
      properties: {
        host: { type: "string", description: "Mail server hostname, e.g. mail.example.com — or a bare domain, in which case its lowest-priority-number MX host is probed" },
        port: { type: "number", description: "SMTP port (default 25)" },
      },
      required: ["host"],
    },
    async run({ host, port }: { host: string; port?: number }) {
      const cleanHost = host.replace(/^https?:\/\//, "").split("/")[0].toLowerCase();
      const smtpPort = port ?? 25;

      // Probe the given host first; if it refuses and it's a domain with MX records,
      // the catch below retries against its first MX host.
      const target = cleanHost;
      await assertPublicHost(target);

      const result = await probeSmtp(target, smtpPort).catch(async (e: any) => {
        // Fallback: if connecting to the given host failed and it's a domain with MX, try the first MX host.
        try {
          const mx = await dns.resolveMx(cleanHost);
          const first = mx.sort((a, b) => a.priority - b.priority)[0]?.exchange?.toLowerCase();
          if (first && first !== cleanHost) {
            await assertPublicHost(first);
            const via = await probeSmtp(first, smtpPort);
            return { ...via, requestedHost: cleanHost, probedViaMx: first };
          }
        } catch {}
        throw e;
      });

      return { host: target, port: smtpPort, ...result };
    },
  },

};

export type ToolName = keyof typeof tools;
