const POLL_MS = 3000;

let riskChart;

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

async function refreshProcesses() {
  const rows = await fetchJSON('/api/processes');
  const tbody = document.getElementById('processTableBody');

  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-row">No flagged processes yet - system looks quiet.</td></tr>';
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
    await Promise.all([refreshSummary(), refreshProcesses(), refreshEvents(), refreshAlerts()]);
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
