const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const { NodeSSH } = require('node-ssh');
const { parseCronExpr, humanizeCron, lintJob, compileCronDropIn, parseInventory } = require('./lib/cron');
const { renderOnboardScript } = require('./lib/onboard');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = Number(process.env.PORT || 4000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SSH_KEY_PATH = process.env.SSH_KEY_PATH || path.join(DATA_DIR, 'ssh', 'cronfleet_ed25519');
const SSH_PUB_PATH = `${SSH_KEY_PATH}.pub`;
const DB_PATH = path.join(DATA_DIR, 'db.json');
const PUBLIC_URL = (process.env.PUBLIC_URL || 'http://netflow.usouthal.edu:4000').replace(/\/$/, '');

fs.mkdirSync(path.join(DATA_DIR, 'ssh'), { recursive: true });

const defaultState = {
  hosts: [
    { id: 'host-1', name: 'netflow', ip: '127.0.0.1', username: 'cronfleet', token: 'dev-host-token-123' }
  ],
  jobs: [
    {
      id: '101',
      hostId: 'host-1',
      description: 'POC Heartbeat Check',
      schedule: '* * * * *',
      user: 'root',
      command: '/bin/echo "CronFleet heartbeat OK at $(date)"',
      timeoutSec: 60,
      enabled: false
    }
  ],
  runs: [],
  alertWebhookUrl: process.env.ALERT_WEBHOOK_URL || '',
  graceMinutes: 2
};

let state = fs.existsSync(DB_PATH)
  ? { ...defaultState, ...JSON.parse(fs.readFileSync(DB_PATH, 'utf8')) }
  : defaultState;

function saveState() {
  fs.writeFileSync(DB_PATH, JSON.stringify(state, null, 2));
}
saveState();

function sendChatAlert(message) {
  if (!state.alertWebhookUrl) return Promise.resolve();
  return new Promise(resolve => {
    try {
      const u = new URL(state.alertWebhookUrl);
      const body = JSON.stringify({ text: message, content: message });
      const client = u.protocol === 'https:' ? https : http;
      const req = client.request(u, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
      }, res => { res.resume(); resolve(); });
      req.on('error', err => { console.error('[ALERT_ERROR]', err.message); resolve(); });
      req.write(body);
      req.end();
    } catch (err) {
      console.error('[ALERT_URL_ERR]', err.message);
      resolve();
    }
  });
}

async function pushSync(host) {
  const hostJobs = state.jobs.filter(j => j.hostId === host.id);
  for (const j of hostJobs.filter(j => j.enabled)) {
    const { errors } = lintJob(j);
    if (errors.length) throw new Error(`Job "${j.description}": ${errors.join(', ')}`);
  }
  const content = compileCronDropIn(hostJobs);
  const ssh = new NodeSSH();
  try {
    await ssh.connect({ host: host.ip, username: host.username, privateKeyPath: SSH_KEY_PATH });
    const b64File = Buffer.from(content).toString('base64');
    const cmd = `echo "${b64File}" | base64 -d > /tmp/cronfleet.staging && sudo /usr/bin/install -o root -g root -m 0644 /tmp/cronfleet.staging /etc/cron.d/cronfleet && rm -f /tmp/cronfleet.staging`;
    const result = await ssh.execCommand(cmd);
    if (result.code !== 0) throw new Error(result.stderr);
    return content;
  } finally {
    ssh.dispose();
  }
}

app.get('/api/meta', (req, res) => {
  res.json({ publicUrl: PUBLIC_URL, alertWebhookUrl: state.alertWebhookUrl, graceMinutes: state.graceMinutes });
});

app.post('/api/settings', async (req, res) => {
  const { alertWebhookUrl, graceMinutes, testAlert } = req.body;
  if (typeof alertWebhookUrl === 'string') state.alertWebhookUrl = alertWebhookUrl.trim();
  if (graceMinutes) state.graceMinutes = Number(graceMinutes);
  saveState();
  if (testAlert && state.alertWebhookUrl) {
    await sendChatAlert(`✅ *CronFleet Test Alert:* Connected to \`${PUBLIC_URL}\`.`);
  }
  res.json({ ok: true });
});

app.get('/api/hosts', (req, res) => {
  res.json(state.hosts.map(h => ({
    ...h,
    onboardCommand: `curl -fsSL "${PUBLIC_URL}/onboard.sh?token=${h.token}" | sudo bash`
  })));
});

app.post('/api/hosts', (req, res) => {
  const host = {
    id: `host-${Date.now().toString(36)}`,
    name: req.body.name.trim(),
    ip: req.body.ip.trim(),
    username: (req.body.username || 'cronfleet').trim(),
    token: crypto.randomBytes(16).toString('hex')
  };
  state.hosts.push(host);
  saveState();
  res.status(201).json({ ...host, onboardCommand: `curl -fsSL "${PUBLIC_URL}/onboard.sh?token=${host.token}" | sudo bash` });
});

app.get('/api/jobs', (req, res) => {
  const hostMap = Object.fromEntries(state.hosts.map(h => [h.id, h]));
  res.json(state.jobs.map(j => {
    const h = hostMap[j.hostId];
    return {
      ...j,
      hostName: h ? h.name : j.hostId,
      hostIp: h ? h.ip : '',
      humanSchedule: humanizeCron(j.schedule),
      lint: lintJob(j)
    };
  }));
});

app.post('/api/jobs', async (req, res) => {
  const job = {
    id: String(Date.now()).slice(-6),
    hostId: req.body.hostId || 'host-1',
    description: req.body.description,
    schedule: req.body.schedule,
    user: req.body.user || 'root',
    command: req.body.command,
    timeoutSec: Number(req.body.timeoutSec || 3600),
    enabled: true,
    status: 'pending'
  };
  const { errors } = lintJob(job);
  if (errors.length) return res.status(400).json({ error: errors.join(' ') });

  state.jobs.push(job);
  saveState();
  const host = state.hosts.find(h => h.id === job.hostId);
  if (host) await pushSync(host).catch(err => console.error('[SYNC_ERR]', err.message));
  res.status(201).json(job);
});

app.put('/api/jobs/:id', async (req, res) => {
  const job = state.jobs.find(j => j.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  Object.assign(job, {
    description: req.body.description ?? job.description,
    schedule: req.body.schedule ?? job.schedule,
    user: req.body.user ?? job.user,
    command: req.body.command ?? job.command,
    timeoutSec: Number(req.body.timeoutSec ?? job.timeoutSec)
  });
  const { errors } = lintJob(job);
  if (errors.length) return res.status(400).json({ error: errors.join(' ') });
  saveState();
  const host = state.hosts.find(h => h.id === job.hostId);
  if (host) await pushSync(host);
  res.json(job);
});

app.patch('/api/jobs/:id/toggle', async (req, res) => {
  const job = state.jobs.find(j => j.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  job.enabled = !job.enabled;
  job.alertedMissed = false;
  saveState();
  const host = state.hosts.find(h => h.id === job.hostId);
  if (host) await pushSync(host);
  res.json(job);
});

app.delete('/api/jobs/:id', async (req, res) => {
  const idx = state.jobs.findIndex(j => j.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Job not found' });
  const [removed] = state.jobs.splice(idx, 1);
  saveState();
  const host = state.hosts.find(h => h.id === removed.hostId);
  if (host) await pushSync(host);
  res.json({ deleted: removed.id });
});

app.post('/api/hosts/sync-all', async (req, res) => {
  const results = [];
  for (const host of state.hosts) {
    try {
      await pushSync(host);
      results.push({ id: host.id, name: host.name, success: true });
    } catch (err) {
      results.push({ id: host.id, name: host.name, success: false, error: err.message });
    }
  }
  res.json({ results });
});

app.post('/api/hosts/:id/sync', async (req, res) => {
  const host = state.hosts.find(h => h.id === req.params.id);
  if (!host) return res.status(404).json({ error: 'Host not found' });
  try {
    const compiled = await pushSync(host);
    res.json({ success: true, compiled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/hosts/:id/discover', async (req, res) => {
  const host = state.hosts.find(h => h.id === req.params.id);
  if (!host) return res.status(404).json({ error: 'Host not found' });
  const ssh = new NodeSSH();
  try {
    await ssh.connect({ host: host.ip, username: host.username, privateKeyPath: SSH_KEY_PATH });
    const result = await ssh.execCommand('sudo /usr/local/bin/cronfleet-scan');
    if (result.code !== 0) throw new Error(result.stderr || `cronfleet-scan exited ${result.code}`);
    res.json({ discovered: parseInventory(result.stdout) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    ssh.dispose();
  }
});

app.post('/api/hosts/:id/adopt', async (req, res) => {
  const host = state.hosts.find(h => h.id === req.params.id);
  if (!host) return res.status(404).json({ error: 'Host not found' });
  const { sourceType, sourceTarget, description, schedule, user, command, exactLine } = req.body;
  const newJob = {
    id: String(Date.now()).slice(-6),
    hostId: host.id,
    description,
    schedule,
    user,
    command,
    timeoutSec: 3600,
    enabled: true,
    status: 'pending'
  };
  const { errors } = lintJob(newJob);
  if (errors.length) return res.status(400).json({ error: errors.join(' ') });

  state.jobs.push(newJob);
  const ssh = new NodeSSH();
  try {
    await pushSync(host);
    await ssh.connect({ host: host.ip, username: host.username, privateKeyPath: SSH_KEY_PATH });
    const b64Line = Buffer.from(exactLine).toString('base64');
    const cmd = `sudo /usr/local/bin/cronfleet-adopt-comment ${sourceType} ${sourceTarget} ${newJob.id} ${b64Line}`;
    const result = await ssh.execCommand(cmd);
    if (result.code !== 0) throw new Error(result.stderr);
    saveState();
    res.json({ success: true, job: newJob });
  } catch (err) {
    state.jobs = state.jobs.filter(j => j.id !== newJob.id);
    res.status(500).json({ error: err.message });
  } finally {
    ssh.dispose();
  }
});

app.get('/api/runs', (req, res) => {
  const list = req.query.jobId ? state.runs.filter(r => String(r.job_id) === String(req.query.jobId)) : state.runs;
  res.json(list.slice(0, 60));
});

app.post('/api/v1/telemetry', async (req, res) => {
  const report = { ...req.body, received_at: new Date().toISOString() };
  state.runs.unshift(report);
  state.runs = state.runs.slice(0, 300);

  const job = state.jobs.find(j => j.id === String(report.job_id));
  if (job) {
    const wasUnhealthy = job.status === 'failed' || job.status === 'missed';
    job.lastRunAt = report.received_at;
    job.lastExitCode = report.exit_code;
    job.lastDurationMs = report.duration_ms;
    const lines = (report.output_tail || '').trim().split('\n').filter(Boolean);
    job.lastErrorPreview = report.exit_code !== 0 && lines.length ? lines[lines.length - 1].slice(0, 140) : '';
    job.status = report.exit_code === 0 ? 'healthy' : 'failed';
    job.alertedMissed = false;

    if (report.exit_code !== 0) {
      await sendChatAlert(
        `🚨 *CronFleet Failure:* Job #${job.id} (*${job.description}*) exited with code \`${report.exit_code}\` on \`${report.hostname}\` (${report.duration_ms}ms)\n\`\`\`${(report.output_tail || '').slice(-600)}\`\`\``
      );
    } else if (wasUnhealthy) {
      await sendChatAlert(`✅ *CronFleet Recovered:* Job #${job.id} (*${job.description}*) succeeded on \`${report.hostname}\`.`);
    }
  }
  saveState();
  res.json({ ok: true });
});

app.get('/onboard.sh', (req, res) => {
  const token = req.query.token || 'invalid-token';
  const pubKey = fs.existsSync(SSH_PUB_PATH) ? fs.readFileSync(SSH_PUB_PATH, 'utf8').trim() : '';
  res.type('text/x-shellscript').send(renderOnboardScript(PUBLIC_URL, token, pubKey));
});

setInterval(async () => {
  const now = new Date();
  const graceMs = (state.graceMinutes || 2) * 60 * 1000;
  let dirty = false;
  for (const job of state.jobs) {
    if (!job.enabled || !job.lastRunAt) continue;
    try {
      const interval = parseCronExpr(job.schedule, { currentDate: new Date(job.lastRunAt) });
      const expectedNext = interval.next().toDate();
      if (now.getTime() > expectedNext.getTime() + graceMs && !job.alertedMissed) {
        job.status = 'missed';
        job.alertedMissed = true;
        dirty = true;
        const host = state.hosts.find(h => h.id === job.hostId);
        await sendChatAlert(
          `⏰ *CronFleet Missed Run:* Job #${job.id} (*${job.description}*) on \`${host ? host.name : job.hostId}\` missed its scheduled run at ${expectedNext.toISOString()}.`
        );
      }
    } catch { /* ignore invalid */ }
  }
  if (dirty) saveState();
}, 60 * 1000);

app.listen(PORT, '0.0.0.0', () => console.log(`CronFleet Control Plane running on http://0.0.0.0:${PORT}`));
