/**
 * SENTRIX Dashboard Application
 * Vanilla JS, no build steps, polls API every 2 seconds.
 */

let selectedHost = '';
let incidentsData = [];
let cachedPrivacyPayloads = [];
let currentPrivacyFilter = 'all'; // 'all' | 'event' | 'metrics'
const POLL_INTERVAL_MS = 2000;

// Chart state buffers
const MAX_CHART_POINTS = 25;
let cpuHistory = [];
let memHistory = [];
let netHistory = [];

// DOM Elements
const elHostsOnline = document.getElementById('valHostsOnline');
const elSubHostsOnline = document.getElementById('subHostsOnline');
const elIncidents = document.getElementById('valIncidents');
const elFailedLogins = document.getElementById('valFailedLogins');
const elAvgCpu = document.getElementById('valAvgCpu');
const elHostSelect = document.getElementById('hostSelect');
const elIncidentList = document.getElementById('incidentList');
const elIncidentCountBadge = document.getElementById('incidentCountBadge');
const elEventsTableBody = document.getElementById('eventsTableBody');
const elPrivacyStream = document.getElementById('privacyStream');
const elChartHostLabel = document.getElementById('chartHostLabel');

const elLiveCpuVal = document.getElementById('liveCpuVal');
const elLiveMemVal = document.getElementById('liveMemVal');
const elLiveNetVal = document.getElementById('liveNetVal');

// Filter Count Elements
const elCountAll = document.getElementById('countAll');
const elCountEvents = document.getElementById('countEvents');
const elCountMetrics = document.getElementById('countMetrics');
const elBtnFilterAll = document.getElementById('btnFilterAll');
const elBtnFilterEvents = document.getElementById('btnFilterEvents');
const elBtnFilterMetrics = document.getElementById('btnFilterMetrics');

// Modal Elements
const elModal = document.getElementById('incidentModal');
const elModalCloseBtn = document.getElementById('modalCloseBtn');
const elModalTitle = document.getElementById('modalTitle');
const elModalSeverityBadge = document.getElementById('modalSeverityBadge');
const elModalLikelyCause = document.getElementById('modalLikelyCause');
const elModalSuggestedAction = document.getElementById('modalSuggestedAction');
const elModalHosts = document.getElementById('modalHosts');
const elModalUpdated = document.getElementById('modalUpdated');
const elModalTimeline = document.getElementById('modalTimeline');

// -----------------------------------------------------------------------------
// Canvas Chart Renderer
// -----------------------------------------------------------------------------
function drawChart(canvasId, dataPoints, colorHex, unit = '%', maxVal = 100) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;

  // Fit canvas to display width
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = 110 * dpr;
  ctx.scale(dpr, dpr);

  const w = rect.width;
  const h = 110;
  const padTop = 15;
  const padBottom = 20;
  const padLeft = 10;
  const padRight = 10;
  const chartH = h - padTop - padBottom;
  const chartW = w - padLeft - padRight;

  ctx.clearRect(0, 0, w, h);

  // Background Grid Lines
  ctx.strokeStyle = '#1E2B48';
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let r = 0; r <= 3; r++) {
    const y = padTop + (chartH / 3) * r;
    ctx.moveTo(padLeft, y);
    ctx.lineTo(w - padRight, y);
  }
  ctx.stroke();

  if (!dataPoints || dataPoints.length < 2) {
    ctx.fillStyle = '#5D7290';
    ctx.font = '11px JetBrains Mono';
    ctx.fillText('Collecting telemetry samples...', w / 2 - 80, h / 2);
    return;
  }

  // Determine dynamic scale if needed (for network)
  let peak = maxVal;
  if (unit !== '%') {
    const localMax = Math.max(...dataPoints, 10);
    peak = Math.ceil(localMax * 1.25);
  }

  const stepX = chartW / (MAX_CHART_POINTS - 1);
  const startIndex = Math.max(0, MAX_CHART_POINTS - dataPoints.length);

  // Path coordinates
  const coords = [];
  dataPoints.forEach((val, i) => {
    const x = padLeft + (startIndex + i) * stepX;
    const norm = Math.min(1, Math.max(0, val / peak));
    const y = padTop + chartH - (norm * chartH);
    coords.push({ x, y, val });
  });

  // Gradient fill under curve
  const grad = ctx.createLinearGradient(0, padTop, 0, h - padBottom);
  grad.addColorStop(0, colorHex + '44');
  grad.addColorStop(1, colorHex + '00');

  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.moveTo(coords[0].x, h - padBottom);
  coords.forEach(pt => ctx.lineTo(pt.x, pt.y));
  ctx.lineTo(coords[coords.length - 1].x, h - padBottom);
  ctx.closePath();
  ctx.fill();

  // Line stroke
  ctx.strokeStyle = colorHex;
  ctx.lineWidth = 2;
  ctx.beginPath();
  coords.forEach((pt, i) => {
    if (i === 0) ctx.moveTo(pt.x, pt.y);
    else ctx.lineTo(pt.x, pt.y);
  });
  ctx.stroke();

  // Glow on the latest point
  const lastPt = coords[coords.length - 1];
  ctx.fillStyle = colorHex;
  ctx.beginPath();
  ctx.arc(lastPt.x, lastPt.y, 4, 0, Math.PI * 2);
  ctx.fill();
}

// -----------------------------------------------------------------------------
// Data Fetching & Polling
// -----------------------------------------------------------------------------
async function fetchDashboardData() {
  try {
    const [statsRes, hostsRes, metricsRes, eventsRes, incidentsRes, privacyRes] = await Promise.all([
      fetch('/api/stats').then(r => r.json()).catch(() => null),
      fetch('/api/hosts').then(r => r.json()).catch(() => ({ hosts: [] })),
      fetch(`/api/metrics?limit=30${selectedHost ? '&host=' + encodeURIComponent(selectedHost) : ''}`).then(r => r.json()).catch(() => ({ metrics: [] })),
      fetch(`/api/events?limit=25${selectedHost ? '&host=' + encodeURIComponent(selectedHost) : ''}`).then(r => r.json()).catch(() => ({ events: [] })),
      fetch('/api/incidents?limit=10').then(r => r.json()).catch(() => ({ incidents: [] })),
      fetch('/api/privacy-proof').then(r => r.json()).catch(() => ({ recent_payloads: [] }))
    ]);

    updateOverviewStats(statsRes, hostsRes.hosts, metricsRes.metrics);
    updateHostDropdown(hostsRes.hosts);
    updateCharts(metricsRes.metrics);
    updateIncidents(incidentsRes.incidents);
    updateEventsTable(eventsRes.events);
    updatePrivacyProofData(privacyRes.recent_payloads);

  } catch (err) {
    console.warn('SENTRIX telemetry poll error:', err);
  }
}

// -----------------------------------------------------------------------------
// UI Updates
// -----------------------------------------------------------------------------
function updateOverviewStats(stats, hosts, metrics) {
  if (stats) {
    elHostsOnline.textContent = stats.hosts_online;
    elIncidents.textContent = stats.active_incidents;
    elIncidentCountBadge.textContent = `${stats.active_incidents} Active`;
    // Consistent count straight from system stats query
    elFailedLogins.textContent = stats.failed_logins;
    elAvgCpu.textContent = `${stats.avg_cpu.toFixed(1)}%`;
  }

  if (hosts) {
    elSubHostsOnline.textContent = hosts.length > 0 ? hosts.map(h => h.host_name).join(', ') : 'No agents connected';
  }
}

function updateHostDropdown(hosts) {
  if (!hosts || hosts.length === 0) return;
  const currentOptions = Array.from(elHostSelect.options).map(o => o.value);
  hosts.forEach(h => {
    if (!currentOptions.includes(h.host_name)) {
      const opt = document.createElement('option');
      opt.value = h.host_name;
      opt.textContent = `${h.host_name} (online)`;
      elHostSelect.appendChild(opt);
    }
  });
}

function updateCharts(metrics) {
  if (!metrics || metrics.length === 0) {
    drawChart('chartCpu', [], '#22D3EE', '%');
    drawChart('chartMem', [], '#A855F7', '%');
    drawChart('chartNet', [], '#10B981', 'KB/s');
    return;
  }

  cpuHistory = metrics.map(m => m.cpu_percent);
  memHistory = metrics.map(m => m.memory_percent);
  netHistory = metrics.map(m => (m.net_recv_bps + m.net_sent_bps) / 1024.0);

  const lastCpu = cpuHistory[cpuHistory.length - 1];
  const lastMem = memHistory[memHistory.length - 1];
  const lastNet = netHistory[netHistory.length - 1];

  elLiveCpuVal.textContent = `${lastCpu.toFixed(1)}%`;
  elLiveMemVal.textContent = `${lastMem.toFixed(1)}%`;
  elLiveNetVal.textContent = `${lastNet.toFixed(1)} KB/s`;

  drawChart('chartCpu', cpuHistory, '#22D3EE', '%', 100);
  drawChart('chartMem', memHistory, '#A855F7', '%', 100);
  drawChart('chartNet', netHistory, '#10B981', 'KB/s', 500);
}

function updateIncidents(incidents) {
  incidentsData = incidents || [];
  if (incidentsData.length === 0) {
    elIncidentList.innerHTML = '<div class="empty-state">No active incidents detected. All systems operational.</div>';
    return;
  }

  elIncidentList.innerHTML = incidentsData.map(inc => {
    const sevClass = inc.severity === 'critical' ? 'badge--critical' : 'badge--warning';
    const hostsList = Array.isArray(inc.affected_hosts) ? inc.affected_hosts.join(', ') : inc.affected_hosts;
    const timeAgo = formatTimeAgo(inc.updated_at);

    return `
      <div class="incident-item" onclick="openIncidentModal(${inc.id})">
        <div class="incident-item__head">
          <span class="incident-item__title">${escapeHtml(inc.title)}</span>
          <span class="badge ${sevClass}">${inc.severity.toUpperCase()}</span>
        </div>
        <div class="incident-item__meta">
          <span>Nodes: ${escapeHtml(hostsList)}</span>
          <span>Updated: ${timeAgo}</span>
        </div>
        <div class="incident-item__cause">
          <strong>Likely Cause:</strong> ${escapeHtml(inc.likely_cause)}
        </div>
      </div>
    `;
  }).join('');
}

function updateEventsTable(events) {
  if (!events || events.length === 0) {
    elEventsTableBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Awaiting incoming telemetry events...</td></tr>';
    return;
  }

  elEventsTableBody.innerHTML = events.slice(0, 15).map(e => {
    const timeStr = formatTimestamp(e.timestamp);
    const badgeColor = e.event_type === 'failed_login' ? 'badge--critical' : (e.event_type === 'error' ? 'badge--warning' : 'badge--cyan');

    return `
      <tr>
        <td class="font-mono text-muted">${timeStr}</td>
        <td class="font-mono">${escapeHtml(e.host_name)}</td>
        <td><span class="badge ${badgeColor}">${escapeHtml(e.event_type)}</span></td>
        <td>${highlightRedactions(escapeHtml(e.message))}</td>
      </tr>
    `;
  }).join('');
}

// -----------------------------------------------------------------------------
// Privacy Proof Panel with Metrics & Events Toggle
// -----------------------------------------------------------------------------
function updatePrivacyProofData(payloads) {
  cachedPrivacyPayloads = payloads || [];

  const totalAll = cachedPrivacyPayloads.length;
  const totalEvents = cachedPrivacyPayloads.filter(p => p.type === 'event').length;
  const totalMetrics = cachedPrivacyPayloads.filter(p => p.type === 'metrics').length;

  if (elCountAll) elCountAll.textContent = totalAll;
  if (elCountEvents) elCountEvents.textContent = totalEvents;
  if (elCountMetrics) elCountMetrics.textContent = totalMetrics;

  renderPrivacyProofStream();
}

function renderPrivacyProofStream() {
  if (!cachedPrivacyPayloads || cachedPrivacyPayloads.length === 0) {
    elPrivacyStream.innerHTML = '<div class="terminal-line text-muted">// Waiting for collector telemetry egress proof...</div>';
    return;
  }

  const filtered = cachedPrivacyPayloads.filter(p => {
    if (currentPrivacyFilter === 'all') return true;
    return p.type === currentPrivacyFilter;
  });

  if (filtered.length === 0) {
    elPrivacyStream.innerHTML = `<div class="terminal-line text-muted">// No payloads matching filter "${currentPrivacyFilter}"</div>`;
    return;
  }

  elPrivacyStream.innerHTML = filtered.slice(0, 20).map(p => {
    const payloadStr = JSON.stringify(p.payload, null, 0);
    const highlighted = highlightRedactions(escapeHtml(payloadStr));
    const typeBadge = p.type === 'event' 
      ? '<span class="text-cyan font-bold">(EVENT - REDACTED):</span>' 
      : '<span class="text-purple font-bold">(METRICS):</span>';

    return `
      <div class="terminal-line">
        <span class="text-dim">[${p.received_at}]</span>
        <span class="text-main">${escapeHtml(p.host)}</span>
        ${typeBadge}
        ${highlighted}
      </div>
    `;
  }).join('');
}

// Privacy Filter Button Click Handlers
function setPrivacyFilter(filterType) {
  currentPrivacyFilter = filterType;
  [elBtnFilterAll, elBtnFilterEvents, elBtnFilterMetrics].forEach(b => {
    if (b) b.classList.remove('active');
  });
  if (filterType === 'all' && elBtnFilterAll) elBtnFilterAll.classList.add('active');
  if (filterType === 'event' && elBtnFilterEvents) elBtnFilterEvents.classList.add('active');
  if (filterType === 'metrics' && elBtnFilterMetrics) elBtnFilterMetrics.classList.add('active');
  renderPrivacyProofStream();
}

if (elBtnFilterAll) elBtnFilterAll.addEventListener('click', () => setPrivacyFilter('all'));
if (elBtnFilterEvents) elBtnFilterEvents.addEventListener('click', () => setPrivacyFilter('event'));
if (elBtnFilterMetrics) elBtnFilterMetrics.addEventListener('click', () => setPrivacyFilter('metrics'));

// -----------------------------------------------------------------------------
// Privacy & Redaction Highlighter
// -----------------------------------------------------------------------------
function highlightRedactions(text) {
  // Turn [EMAIL], [IP], [PASSWORD], etc. into glowing cyan badges
  return text.replace(/\[(EMAIL|IP|TOKEN|API_KEY|PASSWORD|USERNAME|DIGITS)\]/g, 
    '<span class="redaction-tag">[$1]</span>'
  );
}

// -----------------------------------------------------------------------------
// Incident Modal Handler
// -----------------------------------------------------------------------------
window.openIncidentModal = function(incidentId) {
  const inc = incidentsData.find(i => i.id === incidentId);
  if (!inc) return;

  elModalTitle.textContent = inc.title;
  elModalSeverityBadge.textContent = inc.severity.toUpperCase();
  elModalSeverityBadge.className = `badge ${inc.severity === 'critical' ? 'badge--critical' : 'badge--warning'}`;
  elModalLikelyCause.textContent = inc.likely_cause;
  elModalSuggestedAction.textContent = inc.suggested_action;

  const hosts = Array.isArray(inc.affected_hosts) ? inc.affected_hosts.join(', ') : inc.affected_hosts;
  elModalHosts.textContent = hosts;
  elModalUpdated.textContent = formatTimeAgo(inc.updated_at);

  if (Array.isArray(inc.timeline) && inc.timeline.length > 0) {
    elModalTimeline.innerHTML = inc.timeline.map(t => `
      <div class="timeline-item">
        <span class="timeline-item__ts">${formatTimestamp(t.timestamp)}</span>
        <div class="timeline-item__msg">
          <strong class="text-cyan">${escapeHtml(t.host || '')}</strong> [${escapeHtml(t.event_type || '')}]:
          ${highlightRedactions(escapeHtml(t.message || ''))}
        </div>
      </div>
    `).join('');
  } else {
    elModalTimeline.innerHTML = '<div class="text-muted">No detailed timeline recorded for this incident.</div>';
  }

  elModal.classList.add('open');
};

elModalCloseBtn.addEventListener('click', () => elModal.classList.remove('open'));
elModal.addEventListener('click', (e) => {
  if (e.target === elModal) elModal.classList.remove('open');
});

// Host dropdown selection change
elHostSelect.addEventListener('change', (e) => {
  selectedHost = e.target.value;
  elChartHostLabel.textContent = selectedHost ? `Host: ${selectedHost}` : 'Showing All Hosts';
  fetchDashboardData();
});

// Helper formatting functions
function formatTimestamp(isoStr) {
  if (!isoStr) return '--:--:--';
  const parts = isoStr.split('T');
  if (parts.length > 1) {
    return parts[1].slice(0, 8);
  }
  return isoStr.slice(-8);
}

function formatTimeAgo(isoStr) {
  if (!isoStr) return 'recently';
  const d = new Date(isoStr);
  const now = new Date();
  const sec = Math.floor((now - d) / 1000);
  if (isNaN(sec) || sec < 5) return 'Just now';
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  return `${min}m ago`;
}

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Start polling
fetchDashboardData();
setInterval(fetchDashboardData, POLL_INTERVAL_MS);
