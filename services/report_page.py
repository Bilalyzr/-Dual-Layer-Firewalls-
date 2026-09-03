"""
Personal test-report dashboard — GET /reports on the firewall API.

Self-contained HTML + hand-rolled SVG charts (no CDN, works offline on flaky
networks). Visualizes:
  * every pytest suite run (pass/fail/duration history) — auto-recorded by
    the conftest hooks
  * every red-team battery run (site/v2 block counts, misses, false positives)
  * model accuracy / FP / FN trend from model_versions (live from the audit DB)
  * training-store class balance
"""
from __future__ import annotations

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Dual-Layer Firewall — Test Reports</title>
<style>
  :root { --bg:#0a0a13; --panel:#131422; --edge:rgba(148,136,255,.16);
          --text:#e8eaf2; --muted:#5d6478; --ok:#00ff9d; --bad:#ff3860;
          --warn:#ffcc33; --cyan:#00f0ff; --mono:Consolas,monospace; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:var(--bg); color:var(--text); font:14px/1.5 system-ui;
         padding:24px; }
  h1 { font-size:18px; letter-spacing:1px; }
  h1 b { color:var(--cyan); }
  .sub { color:var(--muted); font-size:11px; margin:4px 0 20px; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(430px,1fr));
          gap:16px; }
  .panel { background:var(--panel); border:1px solid var(--edge); border-radius:12px;
           padding:16px 18px; }
  .panel h2 { font:700 11px var(--mono); letter-spacing:1.5px; text-transform:uppercase;
              color:var(--cyan); margin-bottom:12px; }
  .kpi { display:flex; gap:18px; flex-wrap:wrap; margin-bottom:8px; }
  .kpi div { text-align:center; }
  .kpi .v { font:700 22px var(--mono); }
  .kpi .l { font:9px var(--mono); color:var(--muted); text-transform:uppercase;
            letter-spacing:1px; }
  table { width:100%; border-collapse:collapse; font:11px var(--mono); }
  th { text-align:left; color:var(--muted); font-size:9px; text-transform:uppercase;
       letter-spacing:1px; padding:4px 6px; border-bottom:1px solid var(--edge); }
  td { padding:4px 6px; border-bottom:1px solid rgba(148,136,255,.06); }
  .ok { color:var(--ok); } .bad { color:var(--bad); } .warn { color:var(--warn); }
  .muted { color:var(--muted); }
  svg text { font:9px var(--mono); fill:var(--muted); }
  .legend { display:flex; gap:14px; font:10px var(--mono); color:var(--muted);
            margin-top:6px; }
  .legend i { display:inline-block; width:9px; height:9px; border-radius:2px;
              margin-right:4px; vertical-align:-1px; }
</style>
</head>
<body>
<h1>DUAL-LAYER <b>AI FIREWALL</b> — TEST REPORTS</h1>
<div class="sub" id="sub">loading…</div>
<div class="grid">

  <div class="panel">
    <h2>Suite Runs (auto-recorded)</h2>
    <div class="kpi" id="suite-kpi"></div>
    <svg id="suite-chart" width="100%" height="150" viewBox="0 0 400 150"
         preserveAspectRatio="none"></svg>
    <div class="legend"><span><i style="background:var(--ok)"></i>passed</span>
      <span><i style="background:var(--bad)"></i>failed</span>
      <span><i style="background:var(--cyan)"></i>duration (s)</span></div>
    <table id="suite-table"></table>
  </div>

  <div class="panel">
    <h2>Red-Team Battery History</h2>
    <div class="kpi" id="bat-kpi"></div>
    <svg id="bat-chart" width="100%" height="150" viewBox="0 0 400 150"
         preserveAspectRatio="none"></svg>
    <div class="legend"><span><i style="background:var(--cyan)"></i>site blocked</span>
      <span><i style="background:#9d6bff"></i>v2 blocked</span>
      <span><i style="background:var(--bad)"></i>misses</span></div>
    <table id="bat-table"></table>
  </div>

  <div class="panel">
    <h2>Model Trend (holdout)</h2>
    <svg id="model-chart" width="100%" height="170" viewBox="0 0 400 170"
         preserveAspectRatio="none"></svg>
    <div class="legend"><span><i style="background:var(--ok)"></i>accuracy</span>
      <span><i style="background:var(--warn)"></i>false-positive rate</span>
      <span><i style="background:var(--bad)"></i>false-negative rate</span></div>
    <table id="model-table"></table>
  </div>

  <div class="panel">
    <h2>Training Store</h2>
    <div class="kpi" id="store-kpi"></div>
    <svg id="store-chart" width="100%" height="120" viewBox="0 0 400 120"></svg>
    <div class="sub" id="store-sub"></div>
  </div>

</div>
<script>
const $ = (id) => document.getElementById(id);
const fmtT = (ts) => new Date(ts * 1000).toLocaleString();
const esc = (s) => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

function linePath(pts) {
  return pts.map((p,i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
}
function drawSeries(svg, series, opts) {
  // series: [{color, pts:[y], width}] over N samples mapped to 0..400 x
  const N = opts.n, H = opts.h, pad = 8;
  const yv = (v) => H - pad - (v - (opts.min||0)) / ((opts.max||1) - (opts.min||0)) * (H - 2*pad);
  let out = '';
  if (opts.guideY != null)
    out += `<line x1="0" y1="${yv(opts.guideY)}" x2="400" y2="${yv(opts.guideY)}"
             stroke="rgba(255,56,96,.3)" stroke-width="0.5" stroke-dasharray="3 3"/>`;
  for (const s of series) {
    const pts = s.pts.map((v, i) => [N > 1 ? i/(N-1)*400 : 0, yv(v)]);
    out += `<polyline points="${pts.map(p=>p[0].toFixed(1)+','+p[1].toFixed(1)).join(' ')}"
              fill="none" stroke="${s.color}" stroke-width="${s.width||1.4}"/>`;
    if (s.dots !== false)
      out += pts.map(p => `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="1.6"
                    fill="${s.color}"/>`).join('');
  }
  svg.innerHTML = out;
}

fetch('/reports/data').then(r => r.json()).then(d => {
  $('sub').textContent = `${d.total_runs} recorded runs · latest ${d.latest_ts ?
    fmtT(d.latest_ts) : '—'} · data: data/reports/history.jsonl`;

  // ---- suites ----
  const suites = d.runs.filter(r => r.kind === 'pytest');
  const last = {};
  for (const r of suites) last[r.suite] = r;
  $('suite-kpi').innerHTML = Object.entries(last).map(([s, r]) => `
    <div><div class="v ${r.failed ? 'bad' : 'ok'}">${r.failed ? r.failed + ' FAIL' : 'PASS'}</div>
    <div class="l">${esc(s)} · ${r.passed}/${r.passed + r.failed}</div></div>`).join('') ||
    '<div class="muted">no suite runs recorded yet</div>';
  if (suites.length > 1) {
    const n = suites.length;
    drawSeries($('suite-chart'), [
      { color:'var(--ok)',  pts: suites.map(r => r.passed), dots:false },
      { color:'var(--bad)', pts: suites.map(r => r.failed + 0.4) },
      { color:'var(--cyan)', pts: suites.map(r => r.duration_s || 0), width:0.8, dots:false },
    ], { n, h:150, min:0, max: Math.max(...suites.map(r => r.passed), 60) });
  }
  $('suite-table').innerHTML = '<tr><th>when</th><th>suite</th><th>result</th><th>dur(s)</th></tr>' +
    suites.slice(-8).reverse().map(r => `<tr><td class="muted">${fmtT(r.ts)}</td>
      <td>${esc(r.suite)}</td>
      <td class="${r.failed ? 'bad' : 'ok'}">${r.passed}✓ ${r.failed ? r.failed + '✗' : ''}</td>
      <td>${r.duration_s ?? '—'}</td></tr>`).join('');

  // ---- batteries ----
  const bats = d.runs.filter(r => r.kind === 'battery');
  const lastB = bats[bats.length - 1];
  if (lastB) $('bat-kpi').innerHTML = `
    <div><div class="v ${lastB.all_clear ? 'ok' : 'warn'}">${lastB.all_clear ? 'ALL CLEAR' : 'GAPS'}</div>
    <div class="l">last battery</div></div>
    <div><div class="v">site ${lastB.site_blocked}/${lastB.attacks}</div><div class="l">path</div></div>
    <div><div class="v">v2 ${lastB.v2_blocked}/${lastB.attacks}</div><div class="l">path</div></div>
    <div><div class="v ${lastB.benign_ok === lastB.benign_total ? 'ok' : 'bad'}">
      ${lastB.benign_ok}/${lastB.benign_total}</div><div class="l">benign ok</div></div>`;
  else $('bat-kpi').innerHTML = '<div class="muted">no battery runs recorded yet</div>';
  if (bats.length > 1) drawSeries($('bat-chart'), [
    { color:'var(--cyan)', pts: bats.map(b => b.site_blocked) },
    { color:'#9d6bff',     pts: bats.map(b => b.v2_blocked) },
    { color:'var(--bad)',  pts: bats.map(b => b.attacks - b.combined) },
  ], { n: bats.length, h:150, min:0, max: Math.max(16, ...bats.map(b => b.attacks)), guideY: 16 });
  $('bat-table').innerHTML = '<tr><th>when</th><th>site</th><th>v2</th><th>benign</th><th>misses</th></tr>' +
    bats.slice(-8).reverse().map(b => `<tr><td class="muted">${fmtT(b.ts)}</td>
      <td>${b.site_blocked}/${b.attacks}</td><td>${b.v2_blocked}/${b.attacks}</td>
      <td class="${b.benign_ok === b.benign_total ? 'ok' : 'bad'}">${b.benign_ok}/${b.benign_total}</td>
      <td class="${(b.missed || []).length ? 'bad' : 'ok'}">${(b.missed || []).length}</td></tr>`).join('');

  // ---- model trend ----
  const mv = d.model_versions || [];
  if (mv.length > 1) drawSeries($('model-chart'), [
    { color:'var(--ok)',   pts: mv.map(m => (m.metrics || {}).accuracy ?? null).map(v => v == null ? 0 : v) },
    { color:'var(--warn)', pts: mv.map(m => (m.metrics || {}).false_positive_rate ?? 0) },
    { color:'var(--bad)',  pts: mv.map(m => (m.metrics || {}).false_negative_rate ?? 0) },
  ], { n: mv.length, h:170, min:0, max:1, guideY: 0.95 });
  $('model-table').innerHTML = '<tr><th>ver</th><th>acc</th><th>FP</th><th>FN</th><th>rows</th></tr>' +
    mv.slice(-8).reverse().map(m => {
      const x = m.metrics || {};
      return `<tr><td>v${m.version}</td>
        <td class="${(x.accuracy ?? 0) >= .9 ? 'ok' : 'warn'}">${x.accuracy ?? '—'}</td>
        <td>${x.false_positive_rate ?? '—'}</td><td>${x.false_negative_rate ?? '—'}</td>
        <td class="muted">${m.samples ?? '—'}</td></tr>`;
    }).join('');

  // ---- training store ----
  const s = d.store || {};
  $('store-kpi').innerHTML = `
    <div><div class="v">${s.total ?? '—'}</div><div class="l">samples</div></div>
    <div><div class="v bad">${s.threat ?? '—'}</div><div class="l">threat</div></div>
    <div><div class="v ok">${s.benign ?? '—'}</div><div class="l">benign</div></div>`;
  const tot = (s.threat || 0) + (s.benign || 0) || 1;
  const tw = 360 * (s.threat || 0) / tot;
  $('store-chart').innerHTML =
    `<circle cx="200" cy="60" r="40" fill="none" stroke="var(--bad)" stroke-width="16"
       stroke-dasharray="${tw} 360" transform="rotate(-90 200 60)"/>
     <circle cx="200" cy="60" r="40" fill="none" stroke="var(--ok)" stroke-width="16"
       stroke-dasharray="${360 - tw} 360" stroke-dashoffset="${-tw}" transform="rotate(-90 200 60)"/>
     <text x="200" y="64" text-anchor="middle" style="font-size:13px;fill:var(--text)">
       ${Math.round(100 * (s.threat || 0) / tot)}%</text>`;
  $('store-sub').textContent = `current model: v${(d.current_version || {}).version ?? '—'} · ` +
    `retrained ${s.last_retrain ? fmtT(s.last_retrain) : '—'}`;
}).catch(e => { $('sub').textContent = 'failed to load: ' + e; });
</script>
</body>
</html>
"""
