const POLL_MS = 3000;

let riskChart;
let historyChart;

function initChart() {
  const ctx = document.getElementById('riskChart').getContext('2d');
  riskChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Low', 'Medium', 'High'],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: ['#35C87B', '#F0A93B', '#FF4D5E'],
        borderWidth: 0,
      }]
    },
    options: {
      cutout: '68%',
      plugins: { legend: { display: false } },
      responsive: true,
    }
  });

  const hctx = document.getElementById('historyChart').getContext('2d');
  historyChart = new Chart(hctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [
        { label: 'Low', data: [], borderColor: '#35C87B', backgroundColor: 'rgba(53,200,123,0.08)', tension: 0.3, fill: true, pointRadius: 0 },
        { label: 'Medium', data: [], borderColor: '#F0A93B', backgroundColor: 'rgba(240,169,59,0.08)', tension: 0.3, fill: true, pointRadius: 0 },
        { label: 'High', data: [], borderColor: '#FF4D5E', backgroundColor: 'rgba(255,77,94,0.08)', tension: 0.3, fill: true, pointRadius: 0 },
      ]
    },
    options: {
      responsive: true,
      interaction: { mode: 'index', intersect: false },
      scales: {
        x: { ticks: { color: '#8A94A0', maxTicksLimit: 8 }, grid: { color: '#262C33' } },
        y: { beginAtZero: true, ticks: { color: '#8A94A0', precision: 0 }, grid: { color: '#262C33' } },
      },
      plugins: { legend: { labels: { color: '#8A94A0', boxWidth: 12 } } },
    }
  });
}

function updateClock() {
  const el = document.getElementById('clock');
  el.textContent = new Date().toLocaleTimeString();
}

async function fetchJSON(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} -> ${res.status}`);
  return res.json();
}

function setStatus(ok) {
  const dot = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  if (ok) {
    dot.style.background = 'var(--risk-low)';
    text.textContent = 'Monitoring active';
  } else {
    dot.style.background = 'var(--risk-high)';
    text.textContent = 'Connection lost';
  }
}

async function refreshSummary() {
  const s = await fetchJSON('/api/summary');
  document.getElementById('statTotalProcesses').textContent = s.total_running_processes;
  document.getElementById('statTracked').textContent = s.tracked_processes;
  document.getElementById('statAlerts').textContent = s.active_alerts;
  document.getElementById('statHighRisk').textContent = s.high_risk_count;

  const d = s.risk_distribution;
  riskChart.data.datasets[0].data = [d.Low || 0, d.Medium || 0, d.High || 0];
  riskChart.update();
}

async function refreshHistory() {
  const points = await fetchJSON('/api/history');
  if (!points.length) return;

  historyChart.data.labels = points.map(p => new Date(p.timestamp * 1000).toLocaleTimeString());
  historyChart.data.datasets[0].data = points.map(p => p.low_count);
  historyChart.data.datasets[1].data = points.map(p => p.medium_count);
  historyChart.data.datasets[2].data = points.map(p => p.high_count);
  historyChart.update();
}

async function refreshProcesses() {
  const rows = await fetchJSON('/api/processes');
  const tbody = document.getElementById('processTableBody');

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-row">No flagged processes yet - system looks quiet.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(r => `
    <tr>
      <td>${r.pid}</td>
      <td>${escapeHtml(r.process_name)}</td>
      <td>${r.risk_score}</td>
      <td><span class="badge badge--${r.threat_level}">${r.threat_level}</span></td>
      <td>${escapeHtml((r.reasons || '').split(';').join(', '))}</td>
      <td>${escapeHtml(r.virus_result)}</td>
      <td>${quarantineButtonHtml(r)}</td>
    </tr>
  `).join('');
}

function quarantineButtonHtml(r) {
  const trustBtn = `<button class="trust-btn" onclick="handleAddWhitelistFromRow('${escapeHtml(r.process_name).replace(/'/g, "\\'")}')">Trust</button>`;
  if (r.threat_level === 'Low') {
    return `<span class="quarantine-na">&mdash;</span> ${trustBtn}`;
  }
  const quarantineBtn = `<button class="quarantine-btn" onclick="handleQuarantine(${r.pid}, '${escapeHtml(r.process_name).replace(/'/g, "\\'")}')">Quarantine</button>`;
  return `${quarantineBtn} ${trustBtn}`;
}

async function handleQuarantine(pid, name) {
  try {
    const check = await fetchJSON(`/api/process/${pid}/quarantine_check`);
    if (!check.allowed) {
      alert(`Cannot quarantine "${name}" (pid ${pid}):\n\n${check.reason}`);
      return;
    }
  } catch (err) {
    alert('Could not verify process before quarantine. It may have already exited.');
    return;
  }

  const confirmed = confirm(
    `Quarantine (terminate) "${name}" (pid ${pid})?\n\n` +
    `This will attempt to close the process immediately. This action cannot be undone.`
  );
  if (!confirmed) return;

  try {
    const res = await fetch(`/api/process/${pid}/quarantine`, { method: 'POST' });
    const data = await res.json();
    alert(data.message);
    tick(); // refresh dashboard immediately
  } catch (err) {
    alert('Quarantine request failed. See console for details.');
    console.error(err);
  }
}

async function refreshWhitelist() {
  const items = await fetchJSON('/api/whitelist');
  const tbody = document.getElementById('whitelistTableBody');

  if (!items.length) {
    tbody.innerHTML = '<tr><td colspan="2" class="empty-row">No trusted apps added yet.</td></tr>';
    return;
  }

  tbody.innerHTML = items.map(w => `
    <tr>
      <td>${escapeHtml(w.process_name)}</td>
      <td><button class="untrust-btn" onclick="handleRemoveWhitelist('${escapeHtml(w.process_name).replace(/'/g, "\\'")}')">Remove</button></td>
    </tr>
  `).join('');
}

async function handleAddWhitelist() {
  const input = document.getElementById('whitelistInput');
  const name = input.value.trim();
  if (!name) return;
  await addToWhitelist(name);
  input.value = '';
}

async function handleAddWhitelistFromRow(name) {
  if (!confirm(`Mark "${name}" as trusted? It will stop being flagged/monitored for risk.`)) return;
  await addToWhitelist(name);
}

async function addToWhitelist(name) {
  try {
    const res = await fetch('/api/whitelist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ process_name: name }),
    });
    const data = await res.json();
    if (!data.success) alert(data.message);
    tick();
  } catch (err) {
    alert('Could not add to whitelist.');
    console.error(err);
  }
}

async function handleRemoveWhitelist(name) {
  try {
    await fetch(`/api/whitelist/${encodeURIComponent(name)}`, { method: 'DELETE' });
    tick();
  } catch (err) {
    alert('Could not remove from whitelist.');
    console.error(err);
  }
}

async function refreshWebsites() {
  const sites = await fetchJSON('/api/websites');
  const tbody = document.getElementById('websiteTableBody');

  if (!sites.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-row">No browser activity detected yet&hellip;</td></tr>';
    return;
  }

  tbody.innerHTML = sites.map(s => `
    <tr>
      <td>${escapeHtml(s.domain)}</td>
      <td><span class="badge badge--${s.risk_level}">${s.risk_level}</span></td>
      <td>${escapeHtml(s.process_name)}</td>
      <td>${escapeHtml(s.reason)}</td>
      <td>${s.visit_count}</td>
    </tr>
  `).join('');
}

const TYPE_LABEL = { process: 'PROC', file: 'FILE', network: 'NET', virus: 'VIRUS' };

async function refreshEvents() {
  const events = await fetchJSON('/api/events');
  const feed = document.getElementById('eventFeed');

  if (!events.length) {
    feed.innerHTML = '<div class="log-line log-line--muted">No events yet.</div>';
    return;
  }

  feed.innerHTML = events.map(e => {
    const t = new Date(e.timestamp * 1000).toLocaleTimeString();
    const tag = TYPE_LABEL[e.event_type] || e.event_type.toUpperCase();
    const proc = e.process_name ? `${escapeHtml(e.process_name)} (${e.pid ?? '-'})` : 'system';
    return `<div class="log-line log-line--${e.event_type}">[${t}] ${tag} ${proc} - ${escapeHtml(e.detail)}${e.risk_points ? ` (+${e.risk_points})` : ''}</div>`;
  }).join('');
}

async function refreshAlerts() {
  const alerts = await fetchJSON('/api/alerts');
  const feed = document.getElementById('alertFeed');

  if (!alerts.length) {
    feed.innerHTML = '<div class="alert-empty">No alerts yet. All clear.</div>';
    return;
  }

  feed.innerHTML = alerts.map(a => {
    const t = new Date(a.timestamp * 1000).toLocaleTimeString();
    return `
      <div class="alert-item">
        <span class="badge badge--${a.threat_level}">${a.threat_level}</span>
        <span>${escapeHtml(a.message)}</span>
        <span class="alert-time">${t}</span>
      </div>`;
  }).join('');
}

function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

async function tick() {
  try {
    await Promise.all([
      refreshSummary(), refreshProcesses(), refreshWebsites(),
      refreshEvents(), refreshAlerts(), refreshHistory(), refreshWhitelist(),
    ]);
    setStatus(true);
  } catch (err) {
    console.error(err);
    setStatus(false);
  }
}

initChart();
updateClock();
tick();
setInterval(tick, POLL_MS);
setInterval(updateClock, 1000);