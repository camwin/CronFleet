const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const { Client: LdapClient } = require('ldapts');
const { NodeSSH } = require('node-ssh');
const { parseCronExpr, humanizeCron, lintJob, compileCronDropIn, parseInventory } = require('./lib/cron');
const { renderOnboardScript } = require('./lib/onboard');

const app = express();
app.set('trust proxy', 1);
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = Number(process.env.PORT || 4000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SSH_KEY_PATH = process.env.SSH_KEY_PATH || path.join(DATA_DIR, 'ssh', 'cronfleet_ed25519');
const SSH_PUB_PATH = `${SSH_KEY_PATH}.pub`;
const DB_PATH = path.join(DATA_DIR, 'db.json');
const AUDIT_PATH = path.join(DATA_DIR, 'audit.jsonl');
const PUBLIC_URL = (process.env.PUBLIC_URL || 'http://localhost:4000').replace(/\/$/, '');

fs.mkdirSync(path.join(DATA_DIR, 'ssh'), { recursive: true });

const defaultState = {
  hosts: [],
  jobs: [],
  runs: [],
  alertWebhookUrl: process.env.ALERT_WEBHOOK_URL || '',
  graceMinutes: 2,
  auth: {
    configured: false,
    mode: 'local', // 'local' | 'ldap' | 'oidc'
    sessionSecret: crypto.randomBytes(32).toString('hex'),
    sessionTtlHours: 12,
    requireHostToken: false,
    users: [], // [{ username, passwordHash, role: 'admin'|'operator'|'viewer', isBreakGlass, createdAt }]
    ldap: {
      url: '',
      bindDn: '',
      bindPassword: '',
      baseDn: '',
      userFilter: '(|(sAMAccountName={{username}})(userPrincipalName={{username}})(uid={{username}}))',
      adminGroupDn: '',
      operatorGroupDn: '',
      viewerGroupDn: '',
      rejectUnauthorized: true
    },
    oidc: {
      issuerUrl: '',
      clientId: '',
      clientSecret: '',
      scopes: 'openid profile email groups',
      usernameClaim: 'preferred_username',
      groupClaim: 'groups',
      adminGroupValue: '',
      operatorGroupValue: '',
      viewerGroupValue: ''
    }
  }
};

let loaded = fs.existsSync(DB_PATH) ? JSON.parse(fs.readFileSync(DB_PATH, 'utf8')) : {};
let state = {
  ...defaultState,
  ...loaded,
  auth: {
    ...defaultState.auth,
    ...(loaded.auth || {}),
    ldap: { ...defaultState.auth.ldap, ...((loaded.auth && loaded.auth.ldap) || {}) },
    oidc: { ...defaultState.auth.oidc, ...((loaded.auth && loaded.auth.oidc) || {}) }
  }
};

if (process.env.RESET_AUTH === 'true') {
  state.auth.configured = false;
  console.warn('[SECURITY] RESET_AUTH=true detected: Authentication Setup Wizard re-enabled.');
}

const SETUP_CODE = (process.env.SETUP_CODE || '').trim() ||
  `CF-${crypto.randomBytes(2).toString('hex').toUpperCase()}-${crypto.randomBytes(2).toString('hex').toUpperCase()}`;

function saveState() {
  fs.writeFileSync(DB_PATH, JSON.stringify(state, null, 2));
}
saveState();

// --- Cryptographic & Session Helpers ---
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derived}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt') return false;
  const [, salt, hashHex] = parts;
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hashHex, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function b64urlEncode(buf) {
  return Buffer.from(buf).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}

function signSession(userObj) {
  const ttlMs = (Number(state.auth.sessionTtlHours) || 12) * 3600 * 1000;
  const payload = {
    username: userObj.username,
    role: userObj.role || 'viewer',
    provider: userObj.provider || 'local',
    exp: Date.now() + ttlMs
  };
  const body = b64urlEncode(JSON.stringify(payload));
  const sig = b64urlEncode(crypto.createHmac('sha256', state.auth.sessionSecret).update(body).digest());
  return `${body}.${sig}`;
}

function verifySession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, sig] = token.split('.');
  const expectedSig = b64urlEncode(crypto.createHmac('sha256', state.auth.sessionSecret).update(body).digest());
  if (sig.length !== expectedSig.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) return null;
  try {
    const payload = JSON.parse(b64urlDecode(body).toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) {
      out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
    }
  }
  return out;
}

function setSessionCookie(req, res, token) {
  const maxAge = (Number(state.auth.sessionTtlHours) || 12) * 3600;
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https';
  const secureFlag = isHttps ? '; Secure' : '';
  res.setHeader('Set-Cookie', `cf_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secureFlag}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'cf_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}

// --- Append-Only Audit Log ---
function getClientIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').split(',')[0].trim();
}

function writeAudit(req, action, target, details = {}) {
  const entry = {
    ts: new Date().toISOString(),
    actor: req.user ? req.user.username : (details.actor || 'anonymous'),
    role: req.user ? req.user.role : (details.role || 'none'),
    provider: req.user ? req.user.provider : (details.provider || 'none'),
    ip: req ? getClientIp(req) : 'system',
    action,
    target,
    details
  };
  try {
    fs.appendFileSync(AUDIT_PATH, JSON.stringify(entry) + '\n');
  } catch (err) {
    console.error('[AUDIT_WRITE_ERR]', err.message);
  }
}

function readAuditEntries(limit = 150) {
  if (!fs.existsSync(AUDIT_PATH)) return [];
  const lines = fs.readFileSync(AUDIT_PATH, 'utf8').trim().split('\n').filter(Boolean);
  return lines.slice(-limit).reverse().map(line => {
    try { return JSON.parse(line); } catch { return null; }
  }).filter(Boolean);
}

// --- Brute-Force Rate Limiter ---
const loginAttempts = new Map();
function checkRateLimit(ip) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const rec = loginAttempts.get(ip);
  if (!rec || now - rec.firstAt > windowMs) return { allowed: true };
  if (rec.count >= 10) {
    const retrySec = Math.ceil((windowMs - (now - rec.firstAt)) / 1000);
    return { allowed: false, retrySec };
  }
  return { allowed: true };
}
function recordFailedLogin(ip) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const rec = loginAttempts.get(ip);
  if (!rec || now - rec.firstAt > windowMs) {
    loginAttempts.set(ip, { count: 1, firstAt: now });
  } else {
    rec.count += 1;
  }
}
function clearFailedLogin(ip) {
  loginAttempts.delete(ip);
}

// --- LDAP / Active Directory Helper ---
function escapeLdapFilter(input) {
  return String(input).replace(/[\0*()\\]/g, ch => '\\' + ch.charCodeAt(0).toString(16).padStart(2, '0'));
}

function resolveLdapRole(memberOfRaw, cfg) {
  const groups = (Array.isArray(memberOfRaw) ? memberOfRaw : (memberOfRaw ? [memberOfRaw] : []))
    .map(g => String(g).trim().toLowerCase());
  if (cfg.adminGroupDn && groups.includes(cfg.adminGroupDn.trim().toLowerCase())) return 'admin';
  if (cfg.operatorGroupDn && groups.includes(cfg.operatorGroupDn.trim().toLowerCase())) return 'operator';
  if (cfg.viewerGroupDn && groups.includes(cfg.viewerGroupDn.trim().toLowerCase())) return 'viewer';
  return null;
}

async function testLdapConnection(cfg) {
  if (!cfg.url || !cfg.bindDn || !cfg.bindPassword || !cfg.baseDn || !cfg.adminGroupDn) {
    throw new Error('LDAP URL, Bind DN, Bind Password, Base DN, and Admin Group DN are all required.');
  }
  const client = new LdapClient({
    url: cfg.url.trim(),
    timeout: 8000,
    connectTimeout: 8000,
    tlsOptions: { rejectUnauthorized: cfg.rejectUnauthorized !== false }
  });
  try {
    await client.bind(cfg.bindDn.trim(), cfg.bindPassword);
    await client.search(cfg.baseDn.trim(), { scope: 'base', filter: '(objectClass=*)', attributes: ['dn'] });
    try {
      await client.search(cfg.adminGroupDn.trim(), { scope: 'base', filter: '(objectClass=*)', attributes: ['cn', 'dn'] });
    } catch (grpErr) {
      throw new Error(`Connected and bound successfully, but Admin Group DN was not found: ${grpErr.message}`);
    }
    return { ok: true, message: 'Connected to directory, verified Bind DN, Base DN, and Admin Security Group.' };
  } finally {
    await client.unbind().catch(() => {});
  }
}

async function authenticateLdap(username, password, cfg) {
  const client = new LdapClient({
    url: cfg.url.trim(),
    timeout: 8000,
    connectTimeout: 8000,
    tlsOptions: { rejectUnauthorized: cfg.rejectUnauthorized !== false }
  });
  let userEntry = null;
  try {
    await client.bind(cfg.bindDn.trim(), cfg.bindPassword);
    const safeUser = escapeLdapFilter(username.trim());
    const filter = (cfg.userFilter || '(|(sAMAccountName={{username}})(userPrincipalName={{username}})(uid={{username}}))')
      .replace(/\{\{username\}\}/g, safeUser);
    const { searchEntries } = await client.search(cfg.baseDn.trim(), {
      scope: 'sub',
      filter,
      attributes: ['dn', 'memberOf', 'sAMAccountName', 'uid', 'cn']
    });
    if (!searchEntries.length) return null;
    userEntry = searchEntries[0];
  } finally {
    await client.unbind().catch(() => {});
  }

  const role = resolveLdapRole(userEntry.memberOf, cfg);
  if (!role) {
    const err = new Error('Account authenticated in directory, but is not a member of an authorized CronFleet security group.');
    err.statusCode = 403;
    throw err;
  }

  const userClient = new LdapClient({
    url: cfg.url.trim(),
    timeout: 8000,
    connectTimeout: 8000,
    tlsOptions: { rejectUnauthorized: cfg.rejectUnauthorized !== false }
  });
  try {
    await userClient.bind(userEntry.dn, password);
    return { username: username.trim(), role, provider: 'ldap' };
  } finally {
    await userClient.unbind().catch(() => {});
  }
}

// --- OIDC Helper (Native Node 20 fetch + crypto JWKS verification) ---
const oidcPendingStates = new Map();

async function fetchOidcDiscovery(issuerUrl) {
  const cleanIssuer = issuerUrl.trim().replace(/\/$/, '');
  const res = await fetch(`${cleanIssuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery failed (${res.status}) at ${cleanIssuer}/.well-known/openid-configuration`);
  const doc = await res.json();
  if (!doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
    throw new Error('OIDC discovery document missing authorization_endpoint, token_endpoint, or jwks_uri.');
  }
  return doc;
}

async function verifyOidcIdToken(idToken, discovery, clientId) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Malformed OIDC ID token.');
  const header = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
  const claims = JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
  const sigBuf = b64urlDecode(parts[2]);

  const jwksRes = await fetch(discovery.jwks_uri);
  if (!jwksRes.ok) throw new Error(`Failed to fetch JWKS (${jwksRes.status})`);
  const { keys } = await jwksRes.json();
  const jwk = (keys || []).find(k => (!header.kid || k.kid === header.kid) && (!k.use || k.use === 'sig'));
  if (!jwk) throw new Error('Matching signing key not found in OIDC JWKS.');

  const pubKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
  const algMap = { RS256: 'RSA-SHA256', RS384: 'RSA-SHA384', RS512: 'RSA-SHA512', ES256: 'SHA256' };
  const nodeAlg = algMap[header.alg];
  if (!nodeAlg) throw new Error(`Unsupported OIDC signing algorithm: ${header.alg}`);

  const valid = crypto.verify(
    nodeAlg,
    Buffer.from(`${parts[0]}.${parts[1]}`),
    header.alg.startsWith('ES') ? { key: pubKey, dsaEncoding: 'ieee-p1363' } : pubKey,
    sigBuf
  );
  if (!valid) throw new Error('OIDC ID token signature verification failed.');

  const nowSec = Math.floor(Date.now() / 1000);
  if (claims.exp && nowSec > claims.exp + 60) throw new Error('OIDC ID token is expired.');
  const audList = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audList.includes(clientId)) throw new Error('OIDC ID token audience mismatch.');

  return claims;
}

function resolveOidcRole(claims, cfg) {
  const rawGroups = claims[cfg.groupClaim || 'groups'];
  const groups = (Array.isArray(rawGroups) ? rawGroups : (rawGroups ? [rawGroups] : []))
    .map(g => String(g).trim().toLowerCase());
  if (cfg.adminGroupValue && groups.includes(cfg.adminGroupValue.trim().toLowerCase())) return 'admin';
  if (cfg.operatorGroupValue && groups.includes(cfg.operatorGroupValue.trim().toLowerCase())) return 'operator';
  if (cfg.viewerGroupValue && groups.includes(cfg.viewerGroupValue.trim().toLowerCase())) return 'viewer';
  return null;
}

// --- Alerts & SSH Sync ---
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

// --- Auth & RBAC Middleware ---
function attachUser(req, res, next) {
  const cookies = parseCookies(req);
  if (cookies.cf_session) {
    req.user = verifySession(cookies.cf_session);
  }
  next();
}
app.use(attachUser);

function requireAuth(req, res, next) {
  if (!state.auth.configured) {
    return res.status(401).json({ error: 'Initial authentication setup is required.', code: 'SETUP_REQUIRED' });
  }
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required.', code: 'AUTH_REQUIRED' });
  }
  next();
}

const ROLE_RANK = { viewer: 1, operator: 2, admin: 3 };
function requireRole(minRole) {
  return (req, res, next) => {
    const rank = ROLE_RANK[req.user?.role] || 0;
    if (rank < (ROLE_RANK[minRole] || 99)) {
      writeAudit(req, 'auth.denied', req.path, { requiredRole: minRole });
      return res.status(403).json({ error: `Requires ${minRole} privileges (current role: ${req.user?.role || 'none'}).` });
    }
    next();
  };
}

function enforceRootJobPolicy(req, targetRunAsUser) {
  if (String(targetRunAsUser || '').trim() === 'root' && req.user?.role !== 'admin') {
    const err = new Error('Only Admin users can create, modify, or adopt jobs running as root.');
    err.statusCode = 403;
    throw err;
  }
}

// ============================================================================
// AUTHENTICATION, SETUP WIZARD & RBAC ENDPOINTS
// ============================================================================
app.get('/api/auth/status', (req, res) => {
  res.json({
    configured: Boolean(state.auth.configured),
    authenticated: Boolean(req.user),
    user: req.user ? { username: req.user.username, role: req.user.role, provider: req.user.provider } : null,
    authMode: state.auth.mode,
    publicUrl: PUBLIC_URL,
    oidcCallbackUrl: `${PUBLIC_URL}/api/auth/oidc/callback`,
    requireHostToken: Boolean(state.auth.requireHostToken),
    config: req.user?.role === 'admin' ? {
      mode: state.auth.mode,
      requireHostToken: Boolean(state.auth.requireHostToken),
      ldap: { ...state.auth.ldap, bindPassword: state.auth.ldap.bindPassword ? '********' : '' },
      oidc: { ...state.auth.oidc, clientSecret: state.auth.oidc.clientSecret ? '********' : '' }
    } : null
  });
});

app.post('/api/auth/setup', (req, res) => {
  const { setupCode, mode, localAdmin, breakGlassAdmin, ldap, oidc, requireHostToken } = req.body;

  if (!state.auth.configured) {
    if (!setupCode || setupCode.trim() !== SETUP_CODE) {
      writeAudit(req, 'auth.setup_failed', 'wizard', { reason: 'Invalid setup code' });
      return res.status(403).json({ error: 'Invalid Setup Code. Check `docker compose logs cronfleet` on the control plane host.' });
    }
  } else {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin authentication required to modify security configuration.' });
    }
  }

  const chosenMode = ['local', 'ldap', 'oidc'].includes(mode) ? mode : 'local';

  if (chosenMode === 'local') {
    if (!state.auth.configured) {
      if (!localAdmin?.username || !localAdmin?.password || localAdmin.password.length < 10) {
        return res.status(400).json({ error: 'Local admin username and a password of at least 10 characters are required.' });
      }
      state.auth.users = [{
        username: localAdmin.username.trim(),
        passwordHash: hashPassword(localAdmin.password),
        role: 'admin',
        isBreakGlass: true,
        createdAt: new Date().toISOString()
      }];
    }
  } else {
    // External directory/SSO requires a break-glass local admin for IdP outages
    if (!state.auth.configured) {
      if (!breakGlassAdmin?.username || !breakGlassAdmin?.password || breakGlassAdmin.password.length < 10) {
        return res.status(400).json({ error: 'A Break-Glass Local Admin account (10+ char password) is required in case your directory/SSO provider is unreachable.' });
      }
      state.auth.users = [{
        username: breakGlassAdmin.username.trim(),
        passwordHash: hashPassword(breakGlassAdmin.password),
        role: 'admin',
        isBreakGlass: true,
        createdAt: new Date().toISOString()
      }];
    }

    if (chosenMode === 'ldap') {
      if (!ldap?.url || !ldap?.bindDn || !ldap?.baseDn || !ldap?.adminGroupDn) {
        return res.status(400).json({ error: 'LDAP URL, Bind DN, Base DN, and Admin Group DN are required.' });
      }
      const nextPass = (ldap.bindPassword && ldap.bindPassword !== '********')
        ? ldap.bindPassword
        : state.auth.ldap.bindPassword;
      if (!nextPass) return res.status(400).json({ error: 'LDAP Bind Password is required.' });
      state.auth.ldap = {
        ...state.auth.ldap,
        ...ldap,
        bindPassword: nextPass,
        rejectUnauthorized: ldap.rejectUnauthorized !== false
      };
    }

    if (chosenMode === 'oidc') {
      if (!oidc?.issuerUrl || !oidc?.clientId || !oidc?.adminGroupValue) {
        return res.status(400).json({ error: 'OIDC Issuer URL, Client ID, and Admin Group claim value are required.' });
      }
      const nextSecret = (oidc.clientSecret && oidc.clientSecret !== '********')
        ? oidc.clientSecret
        : state.auth.oidc.clientSecret;
      if (!nextSecret) return res.status(400).json({ error: 'OIDC Client Secret is required.' });
      state.auth.oidc = {
        ...state.auth.oidc,
        ...oidc,
        clientSecret: nextSecret
      };
    }
  }

  state.auth.mode = chosenMode;
  state.auth.configured = true;
  if (typeof requireHostToken === 'boolean') state.auth.requireHostToken = requireHostToken;
  saveState();

  const initialActor = req.user || {
    username: (chosenMode === 'local' ? localAdmin?.username : breakGlassAdmin?.username)?.trim() || 'admin',
    role: 'admin',
    provider: 'local'
  };
  const sessionToken = signSession(initialActor);
  setSessionCookie(req, res, sessionToken);
  writeAudit(req, 'auth.configured', `mode:${chosenMode}`, {
    actor: initialActor.username,
    role: 'admin',
    provider: initialActor.provider,
    requireHostToken: state.auth.requireHostToken
  });

  res.json({ ok: true, user: initialActor });
});

app.post('/api/auth/test-ldap', async (req, res) => {
  if (state.auth.configured && req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  const cfg = {
    ...state.auth.ldap,
    ...(req.body.ldap || {}),
    bindPassword: (req.body.ldap?.bindPassword && req.body.ldap.bindPassword !== '********')
      ? req.body.ldap.bindPassword
      : state.auth.ldap.bindPassword
  };
  try {
    const result = await testLdapConnection(cfg);
    res.json(result);
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/auth/test-oidc', async (req, res) => {
  if (state.auth.configured && req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  const issuerUrl = req.body.oidc?.issuerUrl || state.auth.oidc.issuerUrl;
  if (!issuerUrl) return res.status(400).json({ ok: false, error: 'OIDC Issuer URL is required.' });
  try {
    const doc = await fetchOidcDiscovery(issuerUrl);
    const jwksRes = await fetch(doc.jwks_uri);
    if (!jwksRes.ok) throw new Error(`JWKS endpoint returned HTTP ${jwksRes.status}`);
    res.json({
      ok: true,
      message: `Discovered OIDC endpoints (authorization, token, and JWKS) for ${doc.issuer}.`
    });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  if (!state.auth.configured) {
    return res.status(400).json({ error: 'Authentication setup has not been completed.' });
  }
  const ip = getClientIp(req);
  const rl = checkRateLimit(ip);
  if (!rl.allowed) {
    return res.status(429).json({ error: `Too many failed login attempts. Try again in ${rl.retrySec}s.` });
  }

  const { username, password, breakGlass } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password are required.' });

  try {
    let authedUser = null;

    if (state.auth.mode === 'local' || breakGlass) {
      const found = (state.auth.users || []).find(u => u.username.toLowerCase() === username.trim().toLowerCase());
      if (found && (!breakGlass || found.isBreakGlass) && verifyPassword(password, found.passwordHash)) {
        authedUser = { username: found.username, role: found.role, provider: breakGlass ? 'break-glass' : 'local' };
      }
    } else if (state.auth.mode === 'ldap') {
      authedUser = await authenticateLdap(username, password, state.auth.ldap);
    } else {
      return res.status(400).json({ error: 'This instance uses OIDC SSO. Use the SSO button or Break-Glass Local Login.' });
    }

    if (!authedUser) {
      recordFailedLogin(ip);
      writeAudit(req, 'auth.login_failed', username.trim(), { provider: breakGlass ? 'break-glass' : state.auth.mode });
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    clearFailedLogin(ip);
    const token = signSession(authedUser);
    setSessionCookie(req, res, token);
    writeAudit(req, 'auth.login', authedUser.username, { actor: authedUser.username, role: authedUser.role, provider: authedUser.provider });
    res.json({ ok: true, user: authedUser });
  } catch (err) {
    recordFailedLogin(ip);
    writeAudit(req, 'auth.login_error', username.trim(), { error: err.message });
    res.status(err.statusCode || 401).json({ error: err.message });
  }
});

app.get('/api/auth/oidc/login', async (req, res) => {
  if (!state.auth.configured || state.auth.mode !== 'oidc') {
    return res.status(400).send('OIDC authentication is not active.');
  }
  try {
    const doc = await fetchOidcDiscovery(state.auth.oidc.issuerUrl);
    const oauthState = crypto.randomBytes(24).toString('hex');
    const verifier = b64urlEncode(crypto.randomBytes(32));
    const challenge = b64urlEncode(crypto.createHash('sha256').update(verifier).digest());
    oidcPendingStates.set(oauthState, { verifier, createdAt: Date.now() });

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: state.auth.oidc.clientId,
      redirect_uri: `${PUBLIC_URL}/api/auth/oidc/callback`,
      scope: state.auth.oidc.scopes || 'openid profile email groups',
      state: oauthState,
      code_challenge: challenge,
      code_challenge_method: 'S256'
    });
    res.redirect(`${doc.authorization_endpoint}?${params.toString()}`);
  } catch (err) {
    res.status(500).send(`OIDC redirect failed: ${err.message}`);
  }
});

app.get('/api/auth/oidc/callback', async (req, res) => {
  const { code, state: oauthState, error, error_description } = req.query;
  if (error) return res.status(400).send(`OIDC Provider Error: ${error_description || error}`);
  const pending = oidcPendingStates.get(oauthState);
  oidcPendingStates.delete(oauthState);
  if (!pending || Date.now() - pending.createdAt > 10 * 60 * 1000) {
    return res.status(400).send('Invalid or expired OIDC state parameter.');
  }

  try {
    const doc = await fetchOidcDiscovery(state.auth.oidc.issuerUrl);
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: String(code),
      redirect_uri: `${PUBLIC_URL}/api/auth/oidc/callback`,
      client_id: state.auth.oidc.clientId,
      client_secret: state.auth.oidc.clientSecret,
      code_verifier: pending.verifier
    });
    const tokenRes = await fetch(doc.token_endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok || !tokenData.id_token) {
      throw new Error(tokenData.error_description || tokenData.error || 'Token exchange failed');
    }

    const claims = await verifyOidcIdToken(tokenData.id_token, doc, state.auth.oidc.clientId);
    const role = resolveOidcRole(claims, state.auth.oidc);
    const username = claims[state.auth.oidc.usernameClaim || 'preferred_username'] || claims.email || claims.sub;
    if (!role) {
      writeAudit(req, 'auth.oidc_denied', String(username), { reason: 'Missing authorized group claim' });
      return res.status(403).send('Access Denied: Your SSO account is not in an authorized CronFleet security group.');
    }

    const authedUser = { username: String(username), role, provider: 'oidc' };
    setSessionCookie(req, res, signSession(authedUser));
    writeAudit(req, 'auth.login', authedUser.username, { actor: authedUser.username, role, provider: 'oidc' });
    res.redirect('/');
  } catch (err) {
    writeAudit(req, 'auth.oidc_error', 'callback', { error: err.message });
    res.status(500).send(`OIDC Callback Error: ${err.message}`);
  }
});

app.post('/api/auth/logout', (req, res) => {
  if (req.user) writeAudit(req, 'auth.logout', req.user.username);
  clearSessionCookie(res);
  res.json({ ok: true });
});

// --- Local / Break-Glass User Management (Admin only) ---
app.get('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  res.json((state.auth.users || []).map(u => ({
    username: u.username,
    role: u.role,
    isBreakGlass: Boolean(u.isBreakGlass),
    createdAt: u.createdAt
  })));
});

app.post('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  const { username, password, role, isBreakGlass } = req.body;
  if (!username || !password || password.length < 10) {
    return res.status(400).json({ error: 'Username and password (minimum 10 characters) are required.' });
  }
  const cleanRole = ['admin', 'operator', 'viewer'].includes(role) ? role : 'viewer';
  const cleanUser = username.trim();
  state.auth.users = (state.auth.users || []).filter(u => u.username.toLowerCase() !== cleanUser.toLowerCase());
  state.auth.users.push({
    username: cleanUser,
    passwordHash: hashPassword(password),
    role: cleanRole,
    isBreakGlass: Boolean(isBreakGlass),
    createdAt: new Date().toISOString()
  });
  saveState();
  writeAudit(req, 'user.upsert', cleanUser, { role: cleanRole, isBreakGlass: Boolean(isBreakGlass) });
  res.status(201).json({ ok: true });
});

app.delete('/api/users/:username', requireAuth, requireRole('admin'), (req, res) => {
  const target = req.params.username.trim().toLowerCase();
  if (req.user.username.toLowerCase() === target) {
    return res.status(400).json({ error: 'You cannot delete your own active account.' });
  }
  const remaining = (state.auth.users || []).filter(u => u.username.toLowerCase() !== target);
  if (!remaining.some(u => u.role === 'admin')) {
    return res.status(400).json({ error: 'At least one local/break-glass admin account must remain.' });
  }
  state.auth.users = remaining;
  saveState();
  writeAudit(req, 'user.delete', req.params.username);
  res.json({ ok: true });
});

// --- Audit Log Viewer (Authenticated users) ---
app.get('/api/audit', requireAuth, (req, res) => {
  res.json(readAuditEntries(200));
});

// ============================================================================
// CONTROL PLANE API (Session & RBAC Protected)
// ============================================================================
app.get('/api/meta', requireAuth, (req, res) => {
  res.json({
    publicUrl: PUBLIC_URL,
    alertWebhookUrl: state.alertWebhookUrl,
    graceMinutes: state.graceMinutes,
    user: req.user
  });
});

app.post('/api/settings', requireAuth, requireRole('admin'), async (req, res) => {
  const { alertWebhookUrl, graceMinutes, testAlert } = req.body;
  if (typeof alertWebhookUrl === 'string') state.alertWebhookUrl = alertWebhookUrl.trim();
  if (graceMinutes) state.graceMinutes = Number(graceMinutes);
  saveState();
  writeAudit(req, 'settings.update', 'global', { graceMinutes: state.graceMinutes, webhookConfigured: Boolean(state.alertWebhookUrl) });
  if (testAlert && state.alertWebhookUrl) {
    await sendChatAlert(`✅ *CronFleet Test Alert:* Connected to \`${PUBLIC_URL}\` (triggered by \`${req.user.username}\`).`);
  }
  res.json({ ok: true });
});

app.get('/api/hosts', requireAuth, (req, res) => {
  res.json(state.hosts.map(h => ({
    ...h,
    onboardCommand: `curl -fsSL "${PUBLIC_URL}/onboard.sh?token=${h.token}" | sudo bash`
  })));
});

app.post('/api/hosts', requireAuth, requireRole('admin'), async (req, res) => {
  const host = {
    id: `host-${Date.now().toString(36)}`,
    name: req.body.name.trim(),
    ip: req.body.ip.trim(),
    username: (req.body.username || 'cronfleet').trim(),
    token: crypto.randomBytes(16).toString('hex')
  };
  state.hosts.push(host);
  saveState();
  writeAudit(req, 'host.create', `${host.name} (${host.ip})`);
  await sendChatAlert(`🖥️ *CronFleet Server Added:* \`${host.name}\` (\`${host.ip}\`) added by \`${req.user.username}\`.`);
  res.status(201).json({ ...host, onboardCommand: `curl -fsSL "${PUBLIC_URL}/onboard.sh?token=${host.token}" | sudo bash` });
});

app.get('/api/jobs', requireAuth, (req, res) => {
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

app.post('/api/jobs', requireAuth, requireRole('operator'), async (req, res) => {
  try {
    enforceRootJobPolicy(req, req.body.user || 'root');
  } catch (err) {
    return res.status(err.statusCode || 403).json({ error: err.message });
  }

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
  writeAudit(req, 'job.create', `#${job.id} (${job.description})`, { host: host?.name, user: job.user, schedule: job.schedule, command: job.command });

  if (job.user === 'root') {
    await sendChatAlert(`🔐 *CronFleet Privileged Job Created:* Job #${job.id} (*${job.description}*) scheduled as \`root\` on \`${host?.name || job.hostId}\` by \`${req.user.username}\`.`);
  }
  if (host) await pushSync(host).catch(err => console.error('[SYNC_ERR]', err.message));
  res.status(201).json(job);
});

app.put('/api/jobs/:id', requireAuth, requireRole('operator'), async (req, res) => {
  const job = state.jobs.find(j => j.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  const nextUser = req.body.user ?? job.user;
  try {
    enforceRootJobPolicy(req, job.user);
    enforceRootJobPolicy(req, nextUser);
  } catch (err) {
    return res.status(err.statusCode || 403).json({ error: err.message });
  }

  const before = { schedule: job.schedule, user: job.user, command: job.command };
  Object.assign(job, {
    description: req.body.description ?? job.description,
    schedule: req.body.schedule ?? job.schedule,
    user: nextUser,
    command: req.body.command ?? job.command,
    timeoutSec: Number(req.body.timeoutSec ?? job.timeoutSec)
  });
  const { errors } = lintJob(job);
  if (errors.length) return res.status(400).json({ error: errors.join(' ') });
  saveState();
  const host = state.hosts.find(h => h.id === job.hostId);
  writeAudit(req, 'job.update', `#${job.id} (${job.description})`, { host: host?.name, before, after: { schedule: job.schedule, user: job.user, command: job.command } });

  if (job.user === 'root') {
    await sendChatAlert(`🔐 *CronFleet Privileged Job Modified:* Job #${job.id} (*${job.description}*) running as \`root\` on \`${host?.name || job.hostId}\` was edited by \`${req.user.username}\`.`);
  }
  if (host) await pushSync(host);
  res.json(job);
});

app.patch('/api/jobs/:id/toggle', requireAuth, requireRole('operator'), async (req, res) => {
  const job = state.jobs.find(j => j.id === req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  try {
    enforceRootJobPolicy(req, job.user);
  } catch (err) {
    return res.status(err.statusCode || 403).json({ error: err.message });
  }
  job.enabled = !job.enabled;
  job.alertedMissed = false;
  saveState();
  const host = state.hosts.find(h => h.id === job.hostId);
  writeAudit(req, 'job.toggle', `#${job.id} (${job.description})`, { host: host?.name, enabled: job.enabled });
  if (host) await pushSync(host);
  res.json(job);
});

app.delete('/api/jobs/:id', requireAuth, requireRole('operator'), async (req, res) => {
  const idx = state.jobs.findIndex(j => j.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Job not found' });
  try {
    enforceRootJobPolicy(req, state.jobs[idx].user);
  } catch (err) {
    return res.status(err.statusCode || 403).json({ error: err.message });
  }
  const [removed] = state.jobs.splice(idx, 1);
  saveState();
  const host = state.hosts.find(h => h.id === removed.hostId);
  writeAudit(req, 'job.delete', `#${removed.id} (${removed.description})`, { host: host?.name, user: removed.user, command: removed.command });
  if (host) await pushSync(host);
  res.json({ deleted: removed.id });
});

app.post('/api/hosts/sync-all', requireAuth, requireRole('operator'), async (req, res) => {
  const results = [];
  for (const host of state.hosts) {
    try {
      await pushSync(host);
      results.push({ id: host.id, name: host.name, success: true });
    } catch (err) {
      results.push({ id: host.id, name: host.name, success: false, error: err.message });
    }
  }
  writeAudit(req, 'fleet.sync_all', 'all-hosts', { count: results.length });
  res.json({ results });
});

app.post('/api/hosts/:id/sync', requireAuth, requireRole('operator'), async (req, res) => {
  const host = state.hosts.find(h => h.id === req.params.id);
  if (!host) return res.status(404).json({ error: 'Host not found' });
  try {
    const compiled = await pushSync(host);
    writeAudit(req, 'host.sync', host.name);
    res.json({ success: true, compiled });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/hosts/:id/discover', requireAuth, requireRole('operator'), async (req, res) => {
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

app.post('/api/hosts/:id/adopt', requireAuth, requireRole('operator'), async (req, res) => {
  const host = state.hosts.find(h => h.id === req.params.id);
  if (!host) return res.status(404).json({ error: 'Host not found' });
  const { sourceType, sourceTarget, description, schedule, user, command, exactLine } = req.body;
  try {
    enforceRootJobPolicy(req, user);
  } catch (err) {
    return res.status(err.statusCode || 403).json({ error: err.message });
  }

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
    writeAudit(req, 'job.adopt', `#${newJob.id} (${newJob.description})`, { host: host.name, user: newJob.user, sourceType, sourceTarget });
    if (newJob.user === 'root') {
      await sendChatAlert(`🔐 *CronFleet Privileged Job Adopted:* Job #${newJob.id} (*${newJob.description}*) running as \`root\` on \`${host.name}\` was adopted by \`${req.user.username}\`.`);
    }
    res.json({ success: true, job: newJob });
  } catch (err) {
    state.jobs = state.jobs.filter(j => j.id !== newJob.id);
    res.status(500).json({ error: err.message });
  } finally {
    ssh.dispose();
  }
});

app.get('/api/runs', requireAuth, (req, res) => {
  const list = req.query.jobId ? state.runs.filter(r => String(r.job_id) === String(req.query.jobId)) : state.runs;
  res.json(list.slice(0, 60));
});

// ============================================================================
// MANAGED NODE AGENT ENDPOINTS (Host-Token Authenticated)
// ============================================================================
app.post('/api/v1/telemetry', async (req, res) => {
  const authHeader = req.headers.authorization || '';
  const presentedToken = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7).trim()
    : (req.headers['x-host-token'] || req.body?.host_token || '').trim();

  if (presentedToken) {
    const validHost = state.hosts.find(h => h.token === presentedToken);
    if (!validHost) {
      return res.status(401).json({ error: 'Invalid host token.' });
    }
  } else if (state.auth.requireHostToken) {
    return res.status(401).json({ error: 'Host token required on telemetry endpoint.' });
  }

  const report = { ...req.body, received_at: new Date().toISOString() };
  delete report.host_token;
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
  const token = String(req.query.token || '').trim();
  const matchedHost = state.hosts.find(h => h.token === token);
  if (!matchedHost) {
    return res.status(403).type('text/plain').send('# Error: Invalid or unrecognized CronFleet host onboarding token.\nexit 1\n');
  }
  const pubKey = fs.existsSync(SSH_PUB_PATH) ? fs.readFileSync(SSH_PUB_PATH, 'utf8').trim() : '';
  res.type('text/x-shellscript').send(renderOnboardScript(PUBLIC_URL, token, pubKey));
});

// --- Missed-Run Watchdog ---
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`CronFleet Control Plane running on http://0.0.0.0:${PORT}`);
  if (!state.auth.configured) {
    console.log('========================================================================');
    console.log('  FIRST-RUN SECURITY SETUP REQUIRED');
    console.log(`  Open ${PUBLIC_URL} in your browser and enter Setup Code: ${SETUP_CODE}`);
    console.log('========================================================================');
  }
});
