const cronParser = require('cron-parser');
const cronstrue = require('cronstrue');

function parseCronExpr(expr, options = {}) {
  if (cronParser.CronExpressionParser) {
    return cronParser.CronExpressionParser.parse(expr, options);
  }
  return cronParser.parseExpression(expr, options);
}

function humanizeCron(expr) {
  try {
    return cronstrue.toString(expr, { throwExceptionOnParseError: true });
  } catch {
    return 'Invalid cron expression';
  }
}

function lintJob(job) {
  const errors = [];
  const warnings = [];
  if (!job.schedule || humanizeCron(job.schedule) === 'Invalid cron expression') {
    errors.push(`Invalid cron schedule: "${job.schedule}"`);
  }
  if (!/^[a-z_][a-z0-9_-]*[$]?$/.test(job.user || '')) {
    errors.push(`Invalid Linux username: "${job.user}"`);
  }
  if (!job.command || !job.command.trim()) {
    errors.push('Command cannot be empty.');
  }
  if (/(>>?\s*\S+\.log|>\s*\/dev\/null)/.test(job.command || '')) {
    warnings.push('Command redirects output to a file/null; dashboard logs will only show exit codes.');
  }
  const homeMatch = (job.command || '').match(/\/home\/([a-zA-Z0-9._-]+)\//);
  if (job.user === 'root' && homeMatch) {
    warnings.push(`Runs as root against /home/${homeMatch[1]}/ — consider running as "${homeMatch[1]}".`);
  }
  return { errors, warnings };
}

function compileCronDropIn(jobs) {
  const lines = [
    '# /etc/cron.d/cronfleet - Managed by CronFleet Control Plane',
    'SHELL=/bin/bash',
    'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    ''
  ];

  for (const job of jobs.filter(j => j.enabled)) {
    const b64Cmd = Buffer.from(job.command).toString('base64');
    lines.push(`# [Job #${job.id}] ${job.description}`);
    lines.push(
      `${job.schedule} ${job.user} /usr/local/bin/cronfleet-exec --job-id=${job.id} --timeout=${job.timeoutSec || 3600} -- /bin/bash -c "echo ${b64Cmd} | base64 -d | /bin/bash"`
    );
    lines.push('');
  }
  return lines.join('\n') + '\n';
}

function parseInventory(raw) {
  const discovered = [];
  let sourceType = null;
  let sourceTarget = null;
  let lastComment = '';

  const boilerplate = /^(For details see|Example of job|\.\-+|\|\s+|Run the hourly|===)/;
  const cronRegex = /^(@(?:annually|yearly|monthly|weekly|daily|hourly|reboot)|(?:\S+\s+){4}\S+)\s+(.+)$/;
  const osDropInRegex = /^\/etc\/cron\.d\/(0hourly|sysstat|raid-check|e2scrub_all|certbot|rhsm|mdadm|zfsutils)/;

  for (const rawLine of raw.split('\n')) {
    const line = rawLine.trim();
    if (!line) { lastComment = ''; continue; }

    if (line.startsWith('===FILE:') && line.endsWith('===')) {
      sourceType = 'system_file';
      sourceTarget = line.slice(8, -3);
      lastComment = '';
      continue;
    }
    if (line.startsWith('===USER_SPOOL:') && line.endsWith('===')) {
      sourceType = 'user_spool';
      sourceTarget = line.slice(14, -3);
      lastComment = '';
      continue;
    }
    if (line.startsWith('#')) {
      const text = line.replace(/^#+\s*/, '').trim();
      if (text && !boilerplate.test(text)) lastComment = text;
      continue;
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(line)) continue;

    const match = line.match(cronRegex);
    if (!match || !sourceType) continue;

    const schedule = match[1].trim();
    const rest = match[2].trim();
    let user = sourceTarget;
    let rawCmd = rest;

    if (sourceType === 'system_file') {
      const firstSpace = rest.search(/\s/);
      if (firstSpace === -1) continue;
      user = rest.slice(0, firstSpace);
      rawCmd = rest.slice(firstSpace + 1).trim();
    }

    const command = rawCmd.replace(/\\%/g, '%');
    const isProtectedOs =
      (sourceType === 'system_file' && osDropInRegex.test(sourceTarget)) ||
      /run-parts\s+\/etc\/cron\./.test(command);

    const advisories = [];
    if (isProtectedOs) {
      advisories.push('OS / Package Managed: Leave unmanaged so distro updates do not break or duplicate this task.');
    }
    if (sourceTarget === '/etc/crontab') {
      advisories.push('System /etc/crontab entry: Migrating custom entries into /etc/cron.d/cronfleet is recommended.');
    }
    if (/(>>?\s*\S+\.log|>\s*\/dev\/null)/.test(command)) {
      advisories.push('Output is redirected to a local file/null — strip redirect during adoption to view logs in CronFleet.');
    }
    const homeMatch = command.match(/\/home\/([a-zA-Z0-9._-]+)\//);
    if (user === 'root' && homeMatch) {
      advisories.push(`Runs as root on /home/${homeMatch[1]}/ — consider switching user to "${homeMatch[1]}".`);
    }

    discovered.push({
      sourceType,
      sourceTarget,
      sourceLabel: sourceType === 'user_spool' ? `crontab (${sourceTarget})` : sourceTarget,
      description: lastComment || (isProtectedOs ? 'OS System Task' : 'Unmanaged cron job'),
      schedule,
      humanSchedule: humanizeCron(schedule),
      user,
      command,
      exactLine: rawLine,
      isProtectedOs,
      advisories
    });
    lastComment = '';
  }
  return discovered;
}

module.exports = { parseCronExpr, humanizeCron, lintJob, compileCronDropIn, parseInventory };
