export const dashboardHtml = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>mcp-toolbelt dashboard</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 960px; margin: 40px auto; padding: 0 20px; }
  h1 { font-size: 1.3rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 20px 0; }
  .card { border: 1px solid #8884; border-radius: 10px; padding: 14px 16px; }
  .card .label { font-size: 0.8rem; opacity: 0.7; }
  .card .value { font-size: 1.5rem; font-weight: 600; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 8px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #8882; }
  th { opacity: 0.7; font-weight: 500; }
  .ok { color: #2a7; }
  .err { color: #c33; }
  section { margin-top: 32px; }
  code { background: #8882; padding: 1px 5px; border-radius: 4px; }
  #keyPrompt { display: flex; gap: 8px; margin: 20px 0; }
  #keyPrompt input { flex: 1; padding: 6px 10px; }
  #keyPrompt button { padding: 6px 14px; }
  .muted { opacity: 0.6; font-size: 0.85rem; }
</style>
</head>
<body>
  <h1>mcp-toolbelt dashboard</h1>
  <p class="muted">Live status, call metrics, and x402 payment activity for the papacasper.com MCP server.</p>

  <div id="keyPrompt">
    <input id="keyInput" type="password" placeholder="API key" />
    <button id="keyBtn">Load</button>
  </div>

  <div id="content" style="display:none">
    <div class="grid" id="summaryGrid"></div>

    <section>
      <h2>Calls by tool</h2>
      <table id="byToolTable"><thead><tr><th>Tool</th><th>Calls</th><th>Errors</th><th>Avg ms</th></tr></thead><tbody></tbody></table>
    </section>

    <section>
      <h2>Recent payments</h2>
      <table id="paymentsTable"><thead><tr><th>Time</th><th>Tool</th><th>Payer</th><th>Tx</th><th>Network</th></tr></thead><tbody></tbody></table>
    </section>

    <section>
      <h2>Recent calls</h2>
      <table id="callsTable"><thead><tr><th>Time</th><th>Tool</th><th>Transport</th><th>Status</th><th>ms</th></tr></thead><tbody></tbody></table>
    </section>
  </div>

<script>
  const keyInput = document.getElementById("keyInput");
  const keyBtn = document.getElementById("keyBtn");
  const content = document.getElementById("content");
  const keyPrompt = document.getElementById("keyPrompt");

  const stored = localStorage.getItem("mcp_dashboard_key");
  if (stored) { keyInput.value = stored; load(stored); }

  keyBtn.addEventListener("click", () => load(keyInput.value));
  keyInput.addEventListener("keydown", (e) => { if (e.key === "Enter") load(keyInput.value); });

  function fmtTs(ts) { return new Date(ts).toLocaleString(); }
  function fmtDuration(ms) {
    const s = Math.floor(ms / 1000);
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h + "h " + m + "m";
  }
  function short(str) { return str ? str.slice(0, 6) + "…" + str.slice(-4) : "—"; }

  async function load(key) {
    try {
      const res = await fetch("dashboard-data", { headers: key ? { "x-api-key": key } : {} });
      if (!res.ok) { alert("Unauthorized — check the API key."); return; }
      const data = await res.json();
      localStorage.setItem("mcp_dashboard_key", key);
      render(data);
      keyPrompt.style.display = "none";
      content.style.display = "block";
    } catch (e) {
      alert("Failed to load dashboard data: " + e.message);
    }
  }

  function render(d) {
    document.getElementById("summaryGrid").innerHTML = [
      ["Uptime", fmtDuration(d.uptimeMs)],
      ["Total calls", d.totalCalls],
      ["Calls (24h)", d.last24h],
      ["Errors", d.totalErrors],
      ["Payments", d.payments.count],
    ].map(([label, value]) => \`<div class="card"><div class="label">\${label}</div><div class="value">\${value}</div></div>\`).join("");

    document.querySelector("#byToolTable tbody").innerHTML = d.callsByTool.map(t =>
      \`<tr><td>\${t.tool}</td><td>\${t.n}</td><td>\${t.errors}</td><td>\${Math.round(t.avg_ms)}</td></tr>\`
    ).join("") || '<tr><td colspan="4" class="muted">No calls yet</td></tr>';

    document.querySelector("#paymentsTable tbody").innerHTML = d.recentPayments.map(p =>
      \`<tr><td>\${fmtTs(p.ts)}</td><td>\${p.tool}</td><td>\${short(p.payer)}</td><td>\${short(p.tx_hash)}</td><td>\${p.network || "—"}</td></tr>\`
    ).join("") || '<tr><td colspan="5" class="muted">No payments yet</td></tr>';

    document.querySelector("#callsTable tbody").innerHTML = d.recentCalls.map(c =>
      \`<tr><td>\${fmtTs(c.ts)}</td><td>\${c.tool}</td><td>\${c.transport}</td><td class="\${c.success ? 'ok' : 'err'}">\${c.success ? "ok" : "error"}</td><td>\${c.duration_ms}</td></tr>\`
    ).join("") || '<tr><td colspan="5" class="muted">No calls yet</td></tr>';
  }
</script>
</body>
</html>`;
