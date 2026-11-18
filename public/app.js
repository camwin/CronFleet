const ALL_HOSTS = '__ALL__';
let hosts = [];
let currentHostId = ALL_HOSTS;
let allJobsCache = [];
let jobsCache = [];
let runsCache = [];
let discoveredCache = [];
let activeAdoptItem = null;
let activeEditId = null;
let activeLogsJobId = null;
let statusFilter = 'all';
let searchFilter = '';

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const openModal = id => document.getElementById(id).classList.remove('hidden');
const closeModal = id => document.getElementById(id).classList.add('hidden');
const isAllView = () => currentHostId === ALL_HOSTS;

function formatTime(iso) {
  if (!iso) return 'Never';
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toLocaleString();
}

function updateHostChrome() {
  const banner = document.getElementById('onboard-banner');
  const jobHostWrap = document.getElementById('job-host-wrap');
  const jobHostSel = document.getElementById('job-host');
  const descInput = document.getElementById('desc');
  const cmdInput = document.getElementById('cmd');

  if (isAllView()) {
    banner.classList.add('hidden');
    jobHostWrap.classList.remove('hidden');
    descInput.className = 'md:col-span-2 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm';
    cmdInput.className = 'md:col-span-3 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm font-mono';
    document.getElementById('discover-btn').textContent = 'Scan All Hosts (Discover)';
    document.getElementById('sync-btn').textContent = 'Sync All Hosts';
    document.getElementById('managed-heading').textContent = 'All Fleet Managed Jobs (/etc/cron.d/cronfleet)';
    document.getElementById('telemetry-heading').textContent = 'Recent Fleet Telemetry';
  } else {
    const active = hosts.find(h => h.id === currentHostId);
    banner.classList.remove('hidden');
    document.getElementById('onboard-cmd').textContent = active ? active.onboardCommand : '';
    jobHostWrap.classList.add('hidden');
    if (active) jobHostSel.value = active.id;
    descInput.className = 'md:col-span-3 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm';
    cmdInput.className = 'md:col-span-4 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm font-mono';
    document.getElementById('discover-btn').textContent = 'Scan Host (Discover)';
    document.getElementById('sync-btn').textContent = 'Sync /etc/cron.d/cronfleet';
    document.getElementById('managed-heading').textContent = `Managed Jobs on ${active ? active.name : currentHostId} (/etc/cron.d/cronfleet)`;
    document.getElementById('telemetry-heading').textContent = `Recent Telemetry (${active ? active.name : currentHostId})`;
  }
}

async function loadHosts() {
  hosts = await fetch('/api/hosts').then(r => r.json());
  if (!isAllView() && !hosts.find(h => h.id === currentHostId)) {
    currentHostId = ALL_HOSTS;
  }

  const hostOptions = hosts.map(h =>
    `<option value="${esc(h.id)}" ${h.id === currentHostId ? 'selected' : ''}>${esc(h.name)} (${esc(h.ip)})</option>`
  ).join('');

  document.getElementById('host-select').innerHTML =
    `<option value="${ALL_HOSTS}" ${isAllView() ? 'selected' : ''}>All Servers — Fleet View (${hosts.length})</option>` + hostOptions;

  const jobHostSel = document.getElementById('job-host');
  const prevJobHost = jobHostSel.value;
  jobHostSel.innerHTML = hosts.map(h => `<option value="${esc(h.id)}">${esc(h.name)}</option>`).join('');
  if (isAllView() && hosts.find(h => h.id === prevJobHost)) {
    jobHostSel.value = prevJobHost;
  } else if (!isAllView()) {
    jobHostSel.value = currentHostId;
  }

  updateHostChrome();
}

function selectHost(id) {
  currentHostId = id;
  updateHostChrome();
  document.getElementById('discovered-list').innerHTML = isAllView()
    ? 'Click "Scan All Hosts (Discover)" to inspect existing crontabs across your fleet.'
    : 'Click "Scan Host (Discover)" to inspect existing crontabs.';
  renderJobsAndRuns();
}

function copyOnboard() {
  const text = document.getElementById('onboard-cmd').textContent;
  const btn = document.getElementById('copy-onboard-btn');
  const markCopied = () => {
    if (!btn) return;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(text).then(markCopied);
  } else {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    markCopied();
  }
}

function setStatusFilter(next) {
  statusFilter = statusFilter === next && next !== 'all' ? 'all' : next;
  renderJobsAndRuns();
}

function setSearchFilter(val) {
  searchFilter = val.trim().toLowerCase();
  renderJobsAndRuns();
}

async function loadAll() {
  await loadHosts();
  const [allJobs, runs] = await Promise.all([
    fetch('/api/jobs').then(r => r.json()),
    fetch('/api/runs').then(r => r.json())
  ]);
  allJobsCache = allJobs;
  runsCache = runs;
  renderJobsAndRuns();
}

function renderJobsAndRuns() {
  const scopedJobs = isAllView()
    ? allJobsCache
    : allJobsCache.filter(j => j.hostId === currentHostId);

  const counts = {
    all: scopedJobs.length,
    healthy: scopedJobs.filter(j => j.enabled && j.status === 'healthy').length,
    failing: scopedJobs.filter(j => j.enabled && (j.status === 'failed' || j.status === 'missed')).length,
    disabled: scopedJobs.filter(j => !j.enabled).length
  };

  const pill = (key, label, count, activeCls) =>
    `<button onclick="setStatusFilter('${key}')" class="px-2 py-0.5 rounded border transition ${statusFilter === key ? activeCls : 'bg-slate-800/70 border-slate-700 text-slate-400 hover:text-slate-200'}">${label}: ${count}</button>`;

  document.getElementById('fleet-stats').innerHTML = [
    pill('all', 'All', counts.all, 'bg-indigo-950 border-indigo-700 text-indigo-300 font-medium'),
    pill('healthy', 'Healthy', counts.healthy, 'bg-emerald-950 border-emerald-700 text-emerald-300 font-medium'),
    pill('failing', 'Failing/Missed', counts.failing, 'bg-rose-950 border-rose-700 text-rose-300 font-medium'),
    pill('disabled', 'Disabled', counts.disabled, 'bg-slate-700 border-slate-500 text-slate-200 font-medium')
  ].join('');

  jobsCache = scopedJobs.filter(j => {
    if (statusFilter === 'healthy' && !(j.enabled && j.status === 'healthy')) return false;
    if (statusFilter === 'failing' && !(j.enabled && (j.status === 'failed' || j.status === 'missed'))) return false;
    if (statusFilter === 'disabled' && j.enabled) return false;
    if (searchFilter) {
      const hay = `${j.id} ${j.hostName || ''} ${j.description} ${j.command} ${j.user} ${j.schedule}`.toLowerCase();
      if (!hay.includes(searchFilter)) return false;
    }
    return true;
  });

  document.getElementById('managed-list').innerHTML = jobsCache.map(j => {
    const badge = !j.enabled ? 'bg-slate-800 text-slate-400 border-slate-700'
      : j.status === 'healthy' ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
      : j.status === 'failed' ? 'bg-rose-950 text-rose-400 border-rose-800'
      : j.status === 'missed' ? 'bg-amber-950 text-amber-400 border-amber-800'
      : 'bg-slate-800 text-slate-400 border-slate-700';

    const statusLabel = !j.enabled ? 'disabled' : (j.status || 'pending');

    const hostBadge = isAllView()
      ? `<button onclick="selectHost('${esc(j.hostId)}')" title="Filter to ${esc(j.hostName || j.hostId)}" class="text-xs px-2 py-0.5 rounded bg-indigo-950/90 hover:bg-indigo-900 text-indigo-300 border border-indigo-800/80 font-mono">${esc(j.hostName || j.hostId)}</button>`
      : '';

    const lastRunHtml = j.lastRunAt
      ? `<span class="${j.lastExitCode === 0 ? 'text-slate-400' : 'text-rose-400 font-medium'}">Last run: ${esc(formatTime(j.lastRunAt))} • Exit ${esc(j.lastExitCode)} (${esc(j.lastDurationMs ?? '?')}ms)</span>`
      : `<span class="text-slate-500">Last run: Never</span>`;

    const errorPreviewHtml = j.lastExitCode && j.lastErrorPreview
      ? `<div class="mt-1.5 px-2.5 py-1 rounded bg-rose-950/60 border border-rose-900/80 font-mono text-xs text-rose-300 truncate">↳ ${esc(j.lastErrorPreview)}</div>`
      : '';

    const warnHtml = (j.lint?.warnings || []).map(w => `<div class="text-xs text-amber-400 mt-1">⚠ ${esc(w)}</div>`).join('');

    return `
    <div class="flex flex-wrap items-center justify-between gap-3 bg-slate-800/70 p-3.5 rounded border ${j.enabled && j.status === 'failed' ? 'border-rose-900/80' : 'border-slate-700'} ${!j.enabled ? 'opacity-75' : ''}">
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2">
          ${hostBadge}
          <span class="font-medium text-slate-100">${esc(j.description)}</span>
          <span class="text-xs px-2 py-0.5 rounded border ${badge}">${esc(statusLabel)}</span>
          <span class="text-xs text-slate-400">#${esc(j.id)} • user: ${esc(j.user)}</span>
        </div>
        <div class="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs mt-1">
          <span class="text-emerald-300/90">${esc(j.humanSchedule)} <span class="font-mono text-slate-400">(${esc(j.schedule)})</span></span>
          <span class="text-slate-600">|</span>
          ${lastRunHtml}
        </div>
        <div class="text-xs font-mono text-indigo-300 mt-1 break-all">${esc(j.command)}</div>
        ${errorPreviewHtml}
        ${warnHtml}
      </div>
      <div class="flex items-center gap-2 shrink-0">
        <button onclick="openLogsModal('${esc(j.id)}')" class="px-2.5 py-1 rounded text-xs bg-indigo-950 hover:bg-indigo-900 text-indigo-300 border border-indigo-800/80 font-medium">Logs</button>
        <button onclick="openEditModal('${esc(j.id)}')" class="px-2.5 py-1 rounded text-xs bg-slate-700 hover:bg-slate-600 text-slate-200">Edit</button>
        <button onclick="toggleJob('${esc(j.id)}')" class="px-2.5 py-1 rounded text-xs ${j.enabled ? 'bg-emerald-900 text-emerald-300' : 'bg-slate-700 text-slate-300'}">${j.enabled ? 'Enabled' : 'Disabled'}</button>
        <button onclick="deleteJob('${esc(j.id)}')" class="px-2.5 py-1 rounded text-xs bg-rose-950 text-rose-300 hover:bg-rose-900">Delete</button>
      </div>
    </div>`;
  }).join('') || `<p class="text-sm text-slate-500">${scopedJobs.length ? 'No jobs match the current filter.' : (isAllView() ? 'No managed jobs across the fleet yet.' : 'No managed jobs on this host yet.')}</p>`;

  const jobHostById = Object.fromEntries(allJobsCache.map(j => [String(j.id), j.hostId]));
  const activeHost = hosts.find(h => h.id === currentHostId);
  const scopedRuns = isAllView()
    ? runsCache
    : runsCache.filter(r => {
        const mappedHost = jobHostById[String(r.job_id)];
        if (mappedHost) return mappedHost === currentHostId;
        return activeHost && (r.hostname === activeHost.name || r.hostname === activeHost.ip);
      });

  document.getElementById('runs-list').innerHTML = scopedRuns.slice(0, 20).map(r => `
    <div class="p-2.5 rounded border ${r.exit_code === 0 ? 'bg-slate-800/50 border-slate-700' : 'bg-rose-950/40 border-rose-800'}">
      <div class="flex justify-between">
        <span>Job #${esc(r.job_id)} on <strong>${esc(r.hostname)}</strong> — Exit: <strong>${esc(r.exit_code)}</strong> (${esc(r.duration_ms)}ms)</span>
        <span class="text-slate-400">${esc(formatTime(r.received_at))}</span>
      </div>
      <pre class="mt-1 text-slate-300 whitespace-pre-wrap">${esc(r.output_tail || '(no output)')}</pre>
    </div>
  `).join('') || '<p class="text-slate-500">No telemetry received yet.</p>';
}

async function openLogsModal(jobId) {
  activeLogsJobId = jobId;
  const job = allJobsCache.find(j => j.id === jobId);
  document.getElementById('logs-modal-title').textContent = job ? `${job.description} (#${job.id})` : `Job #${jobId}`;
  document.getElementById('logs-modal-sub').textContent = job ? `${job.hostName || job.hostId} • ${job.schedule} (${job.user}) — ${job.command}` : '';
  openModal('logs-modal');
  await refreshJobLogs();
}

async function refreshJobLogs() {
  if (!activeLogsJobId) return;
  const body = document.getElementById('logs-modal-body');
  body.innerHTML = '<div class="text-slate-400">Loading execution logs...</div>';
  const runs = await fetch(`/api/runs?jobId=${encodeURIComponent(activeLogsJobId)}`).then(r => r.json());
  body.innerHTML = runs.map(r => `
    <div class="p-3 rounded border ${r.exit_code === 0 ? 'bg-slate-950 border-slate-800' : 'bg-rose-950/30 border-rose-800'}">
      <div class="flex justify-between items-center pb-1.5 mb-1.5 border-b border-slate-800/80">
        <span class="${r.exit_code === 0 ? 'text-emerald-400' : 'text-rose-400'} font-semibold">Exit Code: ${esc(r.exit_code)} • Duration: ${esc(r.duration_ms)}ms</span>
        <span class="text-slate-400">${esc(formatTime(r.received_at))}</span>
      </div>
      <pre class="text-slate-200 whitespace-pre-wrap break-words leading-relaxed">${esc(r.output_tail || '(no stdout/stderr output)')}</pre>
    </div>
  `).join('') || '<div class="text-slate-400 py-6 text-center">No execution runs recorded for this job yet.</div>';
}

async function discoverJobs() {
  const el = document.getElementById('discovered-list');
  const targets = isAllView() ? hosts : hosts.filter(h => h.id === currentHostId);
  el.innerHTML = isAllView() ? `Scanning all ${targets.length} hosts over SSH...` : 'Scanning host over SSH...';

  const errors = [];
  const combined = [];

  await Promise.all(targets.map(async h => {
    try {
      const data = await fetch(`/api/hosts/${h.id}/discover`).then(r => r.json());
      if (data.error) {
        errors.push(`${h.name}: ${data.error}`);
      } else {
        for (const item of (data.discovered || [])) {
          combined.push({ ...item, hostId: h.id, hostName: h.name });
        }
      }
    } catch (err) {
      errors.push(`${h.name}: ${err.message}`);
    }
  }));

  discoveredCache = combined;
  const errHtml = errors.map(e => `<div class="p-2 rounded bg-rose-950/50 border border-rose-800 text-rose-300 text-xs">Scan error — ${esc(e)}</div>`).join('');

  el.innerHTML = errHtml + (discoveredCache.map((d, idx) => `
    <div class="flex flex-wrap items-center justify-between gap-3 p-3 rounded border ${d.isProtectedOs ? 'bg-slate-900/60 border-slate-800 opacity-85' : 'bg-slate-800/40 border-slate-700'}">
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2">
          ${isAllView() ? `<span class="text-xs px-2 py-0.5 rounded bg-indigo-950/90 text-indigo-300 border border-indigo-800/80 font-mono">${esc(d.hostName)}</span>` : ''}
          <span class="font-medium text-slate-200">${esc(d.description)}</span>
          <span class="text-xs text-amber-400">[${esc(d.sourceLabel)}]</span>
          ${d.isProtectedOs ? '<span class="text-xs px-2 py-0.5 rounded bg-sky-950 text-sky-300 border border-sky-800">OS / Package Managed</span>' : ''}
        </div>
        <div class="text-xs text-slate-300 mt-1">${esc(d.humanSchedule)} <span class="font-mono text-slate-400">(${esc(d.schedule)} • ${esc(d.user)})</span></div>
        <div class="text-xs font-mono text-slate-400 mt-0.5 break-all">${esc(d.command)}</div>
        ${d.advisories.map(a => `<div class="text-xs ${d.isProtectedOs ? 'text-sky-400' : 'text-amber-400'} mt-1">ℹ ${esc(a)}</div>`).join('')}
      </div>
      ${d.isProtectedOs
        ? `<button onclick="openAdoptModal(${idx})" class="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-400 rounded text-xs">Override</button>`
        : `<button onclick="openAdoptModal(${idx})" class="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded text-xs font-medium">Review &amp; Adopt</button>`}
    </div>
  `).join('') || (errors.length ? '' : 'No unmanaged jobs found.'));
}

function openAdoptModal(idx) {
  activeAdoptItem = discoveredCache[idx];
  document.getElementById('adopt-desc').value = activeAdoptItem.description;
  document.getElementById('adopt-sched').value = activeAdoptItem.schedule;
  document.getElementById('adopt-user').value = activeAdoptItem.user;
  document.getElementById('adopt-cmd').value = activeAdoptItem.command;
  renderAdoptAdvisories();
  openModal('adopt-modal');
}

function renderAdoptAdvisories() {
  const box = document.getElementById('adopt-advisories');
  const cmd = document.getElementById('adopt-cmd').value;
  const usr = document.getElementById('adopt-user').value;
  const items = [];
  if (activeAdoptItem.isProtectedOs) {
    items.push(`<div class="p-2 rounded bg-sky-950/60 border border-sky-800 text-sky-300">⚠ <strong>OS Package Job:</strong> Leaving this unmanaged is strongly recommended so OS updates don't recreate a duplicate.</div>`);
  }
  const homeMatch = cmd.match(/\/home\/([a-zA-Z0-9._-]+)\//);
  if (usr === 'root' && homeMatch) {
    items.push(`<div class="p-2 rounded bg-amber-950/60 border border-amber-800 text-amber-300 flex justify-between items-center">
      <span>Runs as <strong>root</strong> on <code>/home/${esc(homeMatch[1])}/</code>.</span>
      <button type="button" onclick="document.getElementById('adopt-user').value='${esc(homeMatch[1])}'; renderAdoptAdvisories();" class="px-2 py-0.5 bg-amber-700 text-white rounded">Use ${esc(homeMatch[1])}</button>
    </div>`);
  }
  if (/(>>?\s*\S+\.log\s*(2>&1)?|>\s*\/dev\/null\s*(2>&1)?)$/.test(cmd.trim())) {
    items.push(`<div class="p-2 rounded bg-indigo-950/60 border border-indigo-800 text-indigo-300 flex justify-between items-center">
      <span>Output redirects to a local file (hides logs from UI).</span>
      <button type="button" onclick="stripLogRedirect()" class="px-2 py-0.5 bg-indigo-700 text-white rounded">Strip Redirect</button>
    </div>`);
  }
  box.innerHTML = items.join('');
}

function stripLogRedirect() {
  const el = document.getElementById('adopt-cmd');
  el.value = el.value.replace(/\s*(>>?\s*\S+\.log\s*(2>&1)?|>\s*\/dev\/null\s*(2>&1)?)\s*$/, '').trim();
  renderAdoptAdvisories();
}

async function confirmAdopt() {
  const targetHostId = activeAdoptItem.hostId || currentHostId;
  const payload = {
    ...activeAdoptItem,
    description: document.getElementById('adopt-desc').value,
    schedule: document.getElementById('adopt-sched').value,
    user: document.getElementById('adopt-user').value,
    command: document.getElementById('adopt-cmd').value
  };
  const res = await fetch(`/api/hosts/${targetHostId}/adopt`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
  }).then(r => r.json());
  if (res.error) return alert('Adopt failed: ' + res.error);
  closeModal('adopt-modal');
  await Promise.all([loadAll(), discoverJobs()]);
}

function openEditModal(id) {
  const job = allJobsCache.find(j => j.id === id);
  if (!job) return;
  activeEditId = id;
  document.getElementById('edit-desc').value = job.description;
  document.getElementById('edit-sched').value = job.schedule;
  document.getElementById('edit-user').value = job.user;
  document.getElementById('edit-timeout').value = job.timeoutSec || 3600;
  document.getElementById('edit-cmd').value = job.command;
  openModal('edit-modal');
}

async function saveEdit() {
  const res = await fetch(`/api/jobs/${activeEditId}`, {
    method: 'PUT', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      description: document.getElementById('edit-desc').value,
      schedule: document.getElementById('edit-sched').value,
      user: document.getElementById('edit-user').value,
      timeoutSec: Number(document.getElementById('edit-timeout').value),
      command: document.getElementById('edit-cmd').value
    })
  }).then(r => r.json());
  if (res.error) return alert(res.error);
  closeModal('edit-modal');
  loadAll();
}

async function createJob(e) {
  e.preventDefault();
  const targetHostId = isAllView() ? document.getElementById('job-host').value : currentHostId;
  const res = await fetch('/api/jobs', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      hostId: targetHostId,
      description: document.getElementById('desc').value,
      schedule: document.getElementById('sched').value,
      user: document.getElementById('user').value,
      command: document.getElementById('cmd').value
    })
  }).then(r => r.json());
  if (res.error) return alert(res.error);
  e.target.reset();
  document.getElementById('user').value = 'root';
  if (isAllView()) document.getElementById('job-host').value = targetHostId;
  loadAll();
}

async function addHost(e) {
  e.preventDefault();
  const host = await fetch('/api/hosts', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: document.getElementById('host-name').value,
      ip: document.getElementById('host-ip').value,
      username: document.getElementById('host-user').value
    })
  }).then(r => r.json());
  e.target.reset();
  document.getElementById('host-user').value = 'cronfleet';
  closeModal('host-modal');
  currentHostId = host.id;
  loadAll();
}

async function openAlertModal() {
  const meta = await fetch('/api/meta').then(r => r.json());
  document.getElementById('webhook-url').value = meta.alertWebhookUrl || '';
  document.getElementById('grace-mins').value = meta.graceMinutes || 2;
  openModal('alert-modal');
}

async function saveAlerts(testAlert) {
  await fetch('/api/settings', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      alertWebhookUrl: document.getElementById('webhook-url').value,
      graceMinutes: Number(document.getElementById('grace-mins').value),
      testAlert
    })
  });
  if (testAlert) alert('Saved and sent test notification!');
  else closeModal('alert-modal');
}

async function toggleJob(id) { await fetch(`/api/jobs/${id}/toggle`, { method: 'PATCH' }); loadAll(); }
async function deleteJob(id) { await fetch(`/api/jobs/${id}`, { method: 'DELETE' }); loadAll(); }

async function syncHost() {
  if (isAllView()) {
    const res = await fetch('/api/hosts/sync-all', { method: 'POST' }).then(r => r.json());
    const summary = (res.results || []).map(r => `${r.name}: ${r.success ? 'OK' : r.error}`).join('\n');
    alert(`Fleet Sync Complete:\n${summary}`);
    return;
  }
  const res = await fetch(`/api/hosts/${currentHostId}/sync`, { method: 'POST' }).then(r => r.json());
  alert(res.success ? 'Synced /etc/cron.d/cronfleet!' : 'Error: ' + res.error);
}

loadAll();
let autoRefresh = true;
function toggleAutoRefresh() {
  autoRefresh = !autoRefresh;
  const pill = document.getElementById('live-pill');
  if (!pill) return;
  pill.innerHTML = autoRefresh
    ? '<span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>Live (15s)'
    : '<span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>Paused';
  pill.className = autoRefresh
    ? 'ml-2 inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-950/80 border border-emerald-800/80 text-emerald-400 hover:bg-emerald-900/60'
    : 'ml-2 inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-400 hover:bg-slate-700';
}
setInterval(() => {
  if (!autoRefresh || document.hidden) return;
  loadAll();
  if (activeLogsJobId && !document.getElementById('logs-modal').classList.contains('hidden')) {
    refreshJobLogs();
  }
}, 15000);
