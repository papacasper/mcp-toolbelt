const OSV_ENDPOINT = "https://api.osv.dev/v1/query";
const GITHUB_API = "https://api.github.com";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN ?? "";

const ECOSYSTEM_MAP: Record<string, string> = {
  npm: "npm",
  pypi: "PyPI",
  cargo: "crates.io",
  rubygems: "RubyGems",
  go: "Go",
  maven: "Maven",
  nuget: "NuGet",
  packagist: "Packagist",
};

async function checkPackageVulnerabilities(ecosystem: string, name: string, version?: string) {
  const osvEcosystem = ECOSYSTEM_MAP[ecosystem.toLowerCase()];
  if (!osvEcosystem) {
    throw new Error(`Unsupported ecosystem: ${ecosystem}. Supported: ${Object.keys(ECOSYSTEM_MAP).join(", ")}`);
  }

  const body: Record<string, unknown> = { package: { name, ecosystem: osvEcosystem } };
  if (version) body.version = version;

  const res = await fetch(OSV_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`OSV.dev API error: ${res.status} ${res.statusText}`);
  const data: any = await res.json();
  const vulns = data.vulns ?? [];

  return {
    ecosystem: osvEcosystem,
    package: name,
    version: version ?? null,
    vulnerabilityCount: vulns.length,
    vulnerabilities: vulns.map((v: any) => ({
      id: v.id,
      summary: v.summary ?? null,
      severity: v.severity?.[0]?.score ?? null,
      aliases: v.aliases ?? [],
      published: v.published ?? null,
      fixedIn: (v.affected ?? [])
        .flatMap((a: any) => a.ranges ?? [])
        .flatMap((r: any) => r.events ?? [])
        .filter((e: any) => e.fixed)
        .map((e: any) => e.fixed),
      references: (v.references ?? []).slice(0, 5).map((r: any) => r.url),
    })),
  };
}

async function githubRepoHealth(owner: string, repo: string) {
  const headers: Record<string, string> = {
    "User-Agent": "mcp-toolbelt/1.0 (+https://papacasper.com/mcp)",
    Accept: "application/vnd.github+json",
  };
  if (GITHUB_TOKEN) headers.Authorization = `Bearer ${GITHUB_TOKEN}`;

  const res = await fetch(`${GITHUB_API}/repos/${owner}/${repo}`, { headers });
  if (res.status === 404) throw new Error(`Repository not found: ${owner}/${repo}`);
  if (res.status === 403) throw new Error(`GitHub API rate-limited (unauthenticated limit is 60 req/hr). Set GITHUB_TOKEN server-side for higher limits.`);
  if (!res.ok) throw new Error(`GitHub API error: ${res.status} ${res.statusText}`);
  const data: any = await res.json();

  const lastPushDays = data.pushed_at
    ? Math.floor((Date.now() - new Date(data.pushed_at).getTime()) / (1000 * 60 * 60 * 24))
    : null;

  const issues: string[] = [];
  if (data.archived) issues.push("Repository is archived — no longer maintained");
  if (data.disabled) issues.push("Repository is disabled");
  if (!data.license) issues.push("No license detected — unclear terms for reuse");
  if (lastPushDays !== null && lastPushDays > 365) issues.push(`No commits in ${lastPushDays} days — likely abandoned`);
  if (data.open_issues_count > 0 && data.has_issues === false) issues.push("Issue tracker disabled");

  return {
    repo: `${owner}/${repo}`,
    description: data.description,
    stars: data.stargazers_count,
    forks: data.forks_count,
    openIssues: data.open_issues_count,
    watchers: data.subscribers_count ?? data.watchers_count,
    defaultBranch: data.default_branch,
    license: data.license?.spdx_id ?? null,
    archived: !!data.archived,
    disabled: !!data.disabled,
    createdAt: data.created_at,
    lastPushAt: data.pushed_at,
    daysSinceLastPush: lastPushDays,
    homepage: data.homepage || null,
    topics: data.topics ?? [],
    issues,
  };
}

export const tools = {
  package_vulnerability_check: {
    price: "$0.01",
    description:
      "Look up a package (optionally pinned to a version) against OSV.dev's aggregated vulnerability database (GitHub Advisories, PyPA, RustSec, Go vuln DB, etc.) for known CVEs/advisories. Supports npm, PyPI, crates.io, RubyGems, Go, Maven, NuGet, and Packagist ecosystems. Useful before adding a dependency.",
    inputSchema: {
      type: "object",
      properties: {
        ecosystem: { type: "string", enum: Object.keys(ECOSYSTEM_MAP), description: "Package ecosystem" },
        name: { type: "string", description: "Package name" },
        version: { type: "string", description: "Optional exact version to check; omit to check the package generally" },
      },
      required: ["ecosystem", "name"],
    },
    async run({ ecosystem, name, version }: { ecosystem: string; name: string; version?: string }) {
      return checkPackageVulnerabilities(ecosystem, name, version);
    },
  },

  github_repo_health_check: {
    price: "$0.01",
    description:
      "Check a GitHub repository's health signals: stars, forks, open issues, license, archived/disabled status, and days since last push. Flags likely-abandoned or unlicensed repos. Useful before depending on a repo.",
    inputSchema: {
      type: "object",
      properties: {
        owner: { type: "string", description: "Repository owner (user or org)" },
        repo: { type: "string", description: "Repository name" },
      },
      required: ["owner", "repo"],
    },
    async run({ owner, repo }: { owner: string; repo: string }) {
      return githubRepoHealth(owner, repo);
    },
  },
};

export type ToolName = keyof typeof tools;
