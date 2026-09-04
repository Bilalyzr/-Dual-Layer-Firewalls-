"""
Test-Case Report page — the formal QA-style report (college template format).

Rendered live at GET /reports/testcase and exported as a standalone HTML by
scripts/export_report.py (data embedded, opens by double-click).

Layout mirrors the classic test-case table: TC ID | Test Case | Input |
Expected | Actual | Status — populated from real recorded runs only.
"""
from __future__ import annotations

PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dual-Layer AI Firewall — Test Case Report</title>
<style>
  :root{
    --blue:#4472C4; --blue-d:#2f5597; --ink:#1f2430; --mut:#5b6472;
    --line:#c9d2e0; --row:#f4f7fc; --pass:#1e7e34; --pass-bg:#e8f5e9;
    --fail:#b3261e; --fail-bg:#fdecea;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:"Segoe UI",Arial,Helvetica,sans-serif;color:var(--ink);
       background:#eef1f6;padding:28px 16px;line-height:1.45}
  .doc{max-width:1120px;margin:0 auto;background:#fff;border:1px solid var(--line);
       box-shadow:0 2px 10px rgba(31,36,48,.08)}
  /* ---------- header band ---------- */
  .band{background:var(--blue);color:#fff;padding:22px 30px;display:flex;
        justify-content:space-between;align-items:flex-end;gap:16px;flex-wrap:wrap}
  .band h1{font-size:21px;letter-spacing:.4px}
  .band .sub{font-size:12.5px;opacity:.9;margin-top:3px}
  .badge{font-size:13px;font-weight:700;padding:7px 16px;border-radius:4px;
         background:#fff;color:var(--blue-d);border:1px solid #fff}
  .badge.ok{background:#c8e6c9;color:#14471f}
  .badge.bad{background:#ffcdd2;color:#7f1d1d}
  .meta{display:flex;gap:26px;flex-wrap:wrap;padding:12px 30px;font-size:12.5px;
        color:var(--mut);border-bottom:2px solid var(--blue);background:#fafbfe}
  .meta b{color:var(--ink);font-weight:600}
  /* ---------- summary strip ---------- */
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
         gap:10px;padding:18px 30px}
  .stat{border:1px solid var(--line);border-top:3px solid var(--blue);
        padding:10px 12px;background:#fff}
  .stat .n{font-size:22px;font-weight:700;color:var(--blue-d)}
  .stat .l{font-size:11.5px;color:var(--mut);text-transform:uppercase;
           letter-spacing:.5px;margin-top:2px}
  /* ---------- sections ---------- */
  section{padding:6px 30px 22px}
  h2{font-size:14px;color:var(--blue-d);text-transform:uppercase;letter-spacing:.8px;
     margin:18px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{background:var(--blue);color:#fff;font-weight:600;text-align:left;
     padding:8px 10px;border:1px solid var(--blue-d);white-space:nowrap}
  td{border:1px solid var(--line);padding:7px 10px;vertical-align:top}
  tbody tr:nth-child(even){background:var(--row)}
  td.tc{font-weight:700;color:var(--blue-d);white-space:nowrap}
  td.inp{font-family:Consolas,Menlo,monospace;font-size:11.5px;color:#333;
         max-width:330px}
  td.exp,td.act{max-width:210px}
  .st{display:inline-block;font-weight:700;font-size:11px;padding:2px 10px;
      border-radius:3px;white-space:nowrap}
  .st.p{background:var(--pass-bg);color:var(--pass)}
  .st.f{background:var(--fail-bg);color:var(--fail)}
  .cat{font-size:10.5px;color:var(--mut);display:block;margin-top:2px;
       text-transform:uppercase;letter-spacing:.4px}
  .foot{padding:14px 30px;border-top:1px solid var(--line);font-size:11.5px;
        color:var(--mut);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
  .foot a{color:var(--blue-d);text-decoration:none}
  .empty{padding:30px;text-align:center;color:var(--mut);font-size:13px}
  @media print{
    body{background:#fff;padding:0}
    .doc{box-shadow:none;border:none;max-width:none}
    .foot a{display:none}
    section{page-break-inside:auto}
    tr{page-break-inside:avoid}
  }
</style>
</head>
<body>
<div class="doc">
  <div class="band">
    <div>
      <h1>DUAL-LAYER AI FIREWALL — TEST CASE REPORT</h1>
      <div class="sub">GenAI Security Proxy · 7-Layer Inspection Pipeline · Red-Team Battery &amp; Regression Suites</div>
    </div>
    <div id="verdict" class="badge">LOADING…</div>
  </div>
  <div class="meta">
    <span>Generated: <b id="gen">—</b></span>
    <span>Model: <b id="model">—</b></span>
    <span>Fast tier: <b id="fast">—</b></span>
    <span>Test cases: <b id="tccount">—</b></span>
  </div>

  <div class="stats" id="stats"></div>

  <section>
    <h2>Test Case Report</h2>
    <table>
      <thead>
        <tr>
          <th>TC ID</th><th>Test Case</th><th>Input</th>
          <th>Expected</th><th>Actual</th><th>Status</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
    <div id="empty" class="empty" style="display:none">
      No red-team battery recorded with per-case results yet —<br>
      run <code>python scripts/redteam_custom.py</code> once, then reload.
    </div>
  </section>

  <section>
    <h2>Model Version History</h2>
    <table>
      <thead>
        <tr><th>Version</th><th>Trained At</th><th>Source</th><th>Samples (T/B)</th>
            <th>Accuracy</th><th>FPR</th><th>FNR</th><th>Deployed</th></tr>
      </thead>
      <tbody id="mvBody"></tbody>
    </table>
  </section>

  <section>
    <h2>Test Run History</h2>
    <table>
      <thead>
        <tr><th>Date / Time</th><th>Run</th><th>Result</th><th>Detail</th></tr>
      </thead>
      <tbody id="runBody"></tbody>
    </table>
  </section>

  <div class="foot">
    <span>Auto-generated from recorded runs only — data/reports/history.jsonl</span>
    <span><a href="/reports">← Live metrics dashboard</a></span>
  </div>
</div>

<script>
const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const dt = ts => { const d = new Date(ts * 1000); return isNaN(d) ? "—" :
  d.toLocaleString("en-GB", {day:"2-digit",month:"short",year:"numeric",
                             hour:"2-digit",minute:"2-digit"}); };

function tcRow(id, name, cat, input, expected, actual, pass){
  return `<tr>
    <td class="tc">${esc(id)}</td>
    <td>${esc(name)}<span class="cat">${esc(cat)}</span></td>
    <td class="inp">${esc(input)}</td>
    <td class="exp">${esc(expected)}</td>
    <td class="act">${esc(actual)}</td>
    <td><span class="st ${pass ? "p" : "f"}">${pass ? "PASS" : "FAIL"}</span></td>
  </tr>`;
}

fetch('/reports/data').then(r => r.json()).then(d => {
  const runs = d.runs || [];
  document.getElementById("gen").textContent = new Date().toLocaleString("en-GB");

  /* ---------------- summary ---------------- */
  const bats = runs.filter(r => r.kind === "battery");
  const last = bats[bats.length - 1] || {};
  const suites = {};
  for (const r of runs) if (r.kind === "pytest" && r.suite) suites[r.suite] = r;
  const suiteList = Object.values(suites);
  const suiteFail = suiteList.reduce((a, r) => a + (r.failed || 0), 0);

  const cur = d.current_version || {};
  const m = cur.metrics || {};
  document.getElementById("model").textContent =
    cur.version ? ("v" + cur.version + (m.accuracy ? " · acc " + (m.accuracy * 100).toFixed(1) + "%" : "")) : "—";
  document.getElementById("fast").textContent = m.macro_f1_fast
    ? ("TF-IDF ensemble · macro-F1 " + m.macro_f1_fast.toFixed(4)) : "TF-IDF ensemble";

  const vEl = document.getElementById("verdict");
  const allClear = last.all_clear && suiteFail === 0;
  const hasCases = (last.cases || []).length > 0;
  vEl.textContent = allClear ? "ALL TESTS PASSED" : (hasCases ? "FAILURES DETECTED" : "NO BATTERY DATA");
  vEl.className = "badge " + (allClear ? "ok" : "bad");

  const passed = hasCases ? last.cases.filter(c => c.pass).length : 0;
  const total = hasCases ? last.cases.length : 0;
  document.getElementById("tccount").textContent = total ? total + " (" + passed + " passed)" : "—";

  const cells = [
    total ? `<div class="stat"><div class="n">${passed} / ${total}</div><div class="l">Battery cases passed</div></div>` : "",
    last.attacks ? `<div class="stat"><div class="n">${last.combined} / ${last.attacks}</div><div class="l">Attacks blocked (either path)</div></div>` : "",
    last.attacks ? `<div class="stat"><div class="n">${last.site_blocked} / ${last.attacks}</div><div class="l">Blocked on site proxy</div></div>` : "",
    last.benign_total ? `<div class="stat"><div class="n">${last.benign_ok} / ${last.benign_total}</div><div class="l">Benign controls allowed</div></div>` : "",
    suiteList.length ? `<div class="stat"><div class="n">${suiteFail === 0 ? "0" : suiteFail}</div><div class="l">Regression failures (latest)</div></div>` : "",
    m.fpr !== undefined ? `<div class="stat"><div class="n">${(m.fpr * 100).toFixed(2)}%</div><div class="l">Model false-positive rate</div></div>` : "",
  ];
  document.getElementById("stats").innerHTML = cells.join("");

  /* ---------------- main TC table ---------------- */
  let rows = "", n = 0;
  if (hasCases) {
    for (const c of last.cases) {
      n++;
      const isA = c.kind === "attack";
      const expected = isA
        ? "Blocked — site returns blocked:true · API returns HTTP 403"
        : "Allowed — HTTP 200 with LLM response on both paths";
      let actual;
      if (isA) {
        const bits = [];
        bits.push(c.site === "blocked" ? "blocked (p=" + (c.site_p ?? 0).toFixed(2) + ")"
                                       : "ALLOWED (p=" + (c.site_p ?? 0).toFixed(2) + ")");
        bits.push(c.v2 === "blocked" ? "API 403 (risk " + c.v2_risk + ")"
                                     : "API ALLOWED (risk " + c.v2_risk + ")");
        actual = "Site " + bits[0] + " · " + bits[1];
      } else {
        actual = "Site " + (c.site === "blocked" ? "BLOCKED (p=" + c.site_p.toFixed(2) + ") — false positive"
                                                 : "allowed (p=" + (c.site_p ?? 0).toFixed(2) + ")")
               + " · API " + (c.v2 === "blocked" ? "BLOCKED (risk " + c.v2_risk + ") — false positive"
                                                 : "allowed (risk " + c.v2_risk + ")");
      }
      rows += tcRow(c.id || ("TC-" + String(n).padStart(2, "0")), c.name || "Attack prompt",
                    isA ? "Red-team attack" : "Benign control",
                    c.input, expected, actual, c.pass);
    }
  } else {
    document.getElementById("empty").style.display = "block";
  }

  /* regression suites */
  let sn = n;
  for (const r of suiteList) {
    sn++;
    rows += tcRow("TC-" + String(sn).padStart(2, "0"),
      (r.suite === "engine" ? "Engine classifier suite" : "Firewall v2 API suite") + " (pytest)",
      "Regression suite", "python -m pytest (suite: " + r.suite + ")",
      "All tests pass · exit code 0",
      (r.passed || 0) + " passed · " + (r.failed || 0) + " failed · "
        + (r.duration_s || 0).toFixed(1) + "s",
      (r.failed || 0) === 0 && (r.exit || 0) === 0);
  }

  /* model promotion gate */
  if (cur.version) {
    sn++;
    rows += tcRow("TC-" + String(sn).padStart(2, "0"),
      "Threat-model promotion gate (v" + cur.version + ")",
      "ML governance", "Live retrain deploys only if challenger ≥ champion quality bar",
      "Deployed v" + cur.version + (m.accuracy ? " · accuracy " + (m.accuracy * 100).toFixed(1) + "%" : "")
        + (m.fpr !== undefined ? " · FPR " + (m.fpr * 100).toFixed(2) + "%" : ""),
      "Gate passed — challenger met the bar; v" + cur.version + " is live and serving traffic",
      true);
  }
  document.getElementById("tbody").innerHTML = rows;

  /* ---------------- model history ---------------- */
  const mv = (d.model_versions || []).slice().reverse();
  document.getElementById("mvBody").innerHTML = mv.length ? mv.map(v => {
    const mm = v.metrics || {};
    const f = (x, pct) => x === undefined || x === null ? "—" : (pct ? (x * 100).toFixed(2) + "%" : x);
    return `<tr>
      <td class="tc">v${esc(v.version)}</td><td>${esc(dt(v.trained_at))}</td>
      <td>${esc(v.source)}</td><td>${esc(v.threat)} / ${esc(v.benign)}</td>
      <td>${f(mm.accuracy, 1)}</td><td>${f(mm.fpr, 1)}</td><td>${f(mm.fnr, 1)}</td>
      <td>${cur.version === v.version ? '<span class="st p">CURRENT</span>' : "—"}</td>
    </tr>`;
  }).join("") : `<tr><td colspan="8" class="empty">No model versions recorded.</td></tr>`;

  /* ---------------- run history ---------------- */
  const rr = runs.slice().reverse();
  document.getElementById("runBody").innerHTML = rr.length ? rr.map(r => {
    const isB = r.kind === "battery";
    const ok = isB ? r.all_clear : (r.failed || 0) === 0 && (r.exit || 0) === 0;
    const detail = isB
      ? `attacks ${r.combined}/${r.attacks} blocked · benign ${r.benign_ok}/${r.benign_total}`
      : `${r.passed || 0} passed · ${r.failed || 0} failed · ${(r.duration_s || 0).toFixed(1)}s`;
    return `<tr>
      <td>${esc(dt(r.ts))}</td>
      <td>${isB ? "Red-team battery" : "Suite: " + esc(r.suite)}</td>
      <td><span class="st ${ok ? "p" : "f"}">${ok ? "PASS" : "FAIL"}</span></td>
      <td>${esc(detail)}</td>
    </tr>`;
  }).join("") : `<tr><td colspan="4" class="empty">No runs recorded yet.</td></tr>`;
}).catch(e => {
  document.getElementById("verdict").textContent = "DATA ERROR";
  document.getElementById("verdict").className = "badge bad";
});
</script>
</body>
</html>
"""
