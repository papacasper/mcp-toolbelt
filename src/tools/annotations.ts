/** MCP tool titles and annotations for tools/list. Keep in sync with the live tool registry. */

export type ToolAnnotations = {
  title: string;
  readOnlyHint: boolean;
  destructiveHint: boolean;
  openWorldHint: boolean;
  idempotentHint: boolean;
};

type Meta = { title: string; annotations: ToolAnnotations };

function meta(
  title: string,
  opts: { readOnly?: boolean; destructive?: boolean; openWorld?: boolean; idempotent?: boolean } = {},
): Meta {
  const readOnly = opts.readOnly ?? true;
  const destructive = opts.destructive ?? false;
  const openWorld = opts.openWorld ?? true;
  const idempotent = opts.idempotent ?? true;
  return {
    title,
    annotations: {
      title,
      readOnlyHint: readOnly,
      destructiveHint: destructive,
      openWorldHint: openWorld,
      idempotentHint: idempotent,
    },
  };
}

// Writes a new short-lived file on this server; does not delete or overwrite caller data.
const writesTempFile = { readOnly: false, destructive: false, openWorld: true, idempotent: false };

export const toolMeta: Record<string, Meta> = {
  url_to_markdown: meta("URL to Markdown"),
  security_headers_audit: meta("Security Headers Audit"),
  redirect_chain_check: meta("Redirect Chain Check"),
  page_performance_check: meta("Page Performance Check"),
  structured_data_extract: meta("Structured Data Extract"),
  tech_stack_fingerprint: meta("Tech Stack Fingerprint"),
  seo_audit: meta("SEO Audit"),
  check_robots_sitemap: meta("Robots and Sitemap Check"),
  broken_link_check: meta("Broken Link Check"),
  ai_readiness_audit: meta("AI Readiness Audit"),
  domain_health_check: meta("Domain Health Check"),
  dns_propagation_check: meta("DNS Propagation Check"),
  email_deliverability_check: meta("Email Deliverability Check"),
  whois_lookup: meta("WHOIS Lookup"),
  domain_availability_check: meta("Domain Availability Check"),
  subdomain_discovery: meta("Subdomain Discovery"),
  ssl_cert_check: meta("SSL Certificate Check"),
  check_open_ports: meta("Check Open Ports"),
  websocket_endpoint_check: meta("WebSocket Endpoint Check"),
  domain_report: meta("Domain Report"),
  safe_browsing_check: meta("Safe Browsing Check"),
  ssl_labs_grade: meta("SSL Labs Grade"),
  exposed_files_check: meta("Exposed Files Check"),
  pagespeed_insights: meta("PageSpeed Insights"),
  package_vulnerability_check: meta("Package Vulnerability Check"),
  github_repo_health_check: meta("GitHub Repo Health Check"),
  email_address_validate: meta("Email Address Validate"),
  smtp_server_check: meta("SMTP Server Check"),
  mcp_server_probe: meta("MCP Server Probe"),
  website_screenshot: meta("Website Screenshot", writesTempFile),
  html_to_pdf: meta("HTML to PDF", writesTempFile),
  phone_validate: meta("Phone Validate", { openWorld: false }),
  vat_validate: meta("VAT Validate"),
  address_normalize: meta("Address Normalize", { openWorld: false }),
  image_resize: meta("Image Resize", writesTempFile),
  csv_to_json: meta("CSV to JSON"),
  archived_page_lookup: meta("Archived Page Lookup"),
  favicon_manifest_check: meta("Favicon and Manifest Check"),
  ai_crawler_policy_check: meta("AI Crawler Policy Check"),
};

export function assertToolMeta(tools: Record<string, unknown>): void {
  const missing = Object.keys(tools).filter((name) => !toolMeta[name]);
  const extra = Object.keys(toolMeta).filter((name) => !(name in tools));
  if (missing.length || extra.length) {
    throw new Error(
      `toolMeta is out of sync with the tool registry: missing=${missing.join(",") || "none"} extra=${extra.join(",") || "none"}`,
    );
  }
}
