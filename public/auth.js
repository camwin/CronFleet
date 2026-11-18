(function () {
  let authState = null;

  // Intercept 401/403 responses from background polling so app.js never throws noisy alerts while logged out
  const origFetch = window.fetch.bind(window);
  window.fetch = async function (input, init) {
    const res = await origFetch(input, init);
    const url = typeof input === 'string' ? input : (input && input.url) || '';
    if (res.status === 401 && url.startsWith('/api/') && !url.startsWith('/api/auth/')) {
      if (!document.getElementById('cf-auth-overlay')) {
        bootstrapAuthUI();
      }
    }
    return res;
  };

  function esc(str) {
    return String(str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function roleBadge(role) {
    const colors = {
      admin: 'bg-rose-500/20 text-rose-300 border-rose-500/40',
      operator: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
      viewer: 'bg-sky-500/20 text-sky-300 border-sky-500/40'
    };
    return `<span class="px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider rounded border ${colors[role] || colors.viewer}">${esc(role)}</span>`;
  }

  function mountOverlay(html) {
    let el = document.getElementById('cf-auth-overlay');
    if (!el) {
      el = document.createElement('div');
      el.id = 'cf-auth-overlay';
      el.className = 'fixed inset-0 z-50 bg-slate-950/95 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto';
      document.body.appendChild(el);
    }
    el.innerHTML = html;
    return el;
  }

  function closeOverlay() {
    const el = document.getElementById('cf-auth-overlay');
    if (el) el.remove();
  }

  // ==========================================================================
  // 1. FIRST-RUN SETUP WIZARD & AUTH EDITOR
  // ==========================================================================
  function openSetupWizard(isReconfigure = false) {
    const cfg = authState?.config || {};
    const initialMode = cfg.mode || 'local';
    const callbackUrl = authState?.oidcCallbackUrl || `${window.location.origin}/api/auth/oidc/callback`;

    mountOverlay(`
      <div class="w-full max-w-3xl bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden my-8">
        <!-- Security Briefing Banner -->
        <div class="bg-gradient-to-r from-rose-950/90 via-slate-900 to-indigo-950/90 border-b border-slate-800 p-6">
          <div class="flex items-start justify-between gap-4">
            <div>
              <div class="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-rose-500/15 border border-rose-500/30 text-rose-300 text-xs font-semibold mb-2">
                <span>🛡️</span> ${isReconfigure ? 'Authentication & AAA Configuration' : 'Mandatory First-Run Security Setup'}
              </div>
              <h2 class="text-2xl font-bold text-white tracking-tight">Protect Your CronFleet Control Plane</h2>
              <p class="text-slate-300 text-sm mt-1.5 leading-relaxed">
                CronFleet manages an SSH key that writes <code class="text-amber-300 bg-slate-950/70 px-1.5 py-0.5 rounded">/etc/cron.d/cronfleet</code> as <strong class="text-white">root</strong> across every registered Linux host. Leaving this dashboard unauthenticated—or connecting AD/SSO without a security group restriction—grants root command execution to anyone who can reach this port.
              </p>
            </div>
            ${isReconfigure ? `<button id="cf-wiz-close" class="text-slate-400 hover:text-white text-sm px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700">Close</button>` : ''}
          </div>
        </div>

        <form id="cf-setup-form" class="p-6 space-y-6 text-sm text-slate-200">
          ${!isReconfigure ? `
          <div class="bg-slate-950/80 border border-amber-500/30 rounded-xl p-4">
            <label class="block text-xs font-bold uppercase tracking-wider text-amber-300 mb-1.5">
              Step 1 · Verify Host Ownership (One-Time Setup Code)
            </label>
            <p class="text-xs text-slate-400 mb-2">
              Run <code class="text-slate-200">docker compose logs cronfleet</code> on your Docker host to read the one-time setup code.
            </p>
            <input id="cf-setup-code" type="text" required placeholder="CF-XXXX-XXXX"
              class="w-full md:w-72 bg-slate-900 border border-slate-700 rounded-lg px-3.5 py-2 font-mono text-white tracking-widest uppercase focus:outline-none focus:border-indigo-500" />
          </div>
          ` : ''}

          <!-- Provider Selector Cards -->
          <div>
            <label class="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-2.5">
              ${isReconfigure ? 'Authentication Provider' : 'Step 2 · Choose Authentication Provider'}
            </label>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
              <label class="cf-mode-card cursor-pointer rounded-xl border p-3.5 transition ${initialMode === 'local' ? 'border-indigo-500 bg-indigo-500/10' : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'}">
                <input type="radio" name="cf_auth_mode" value="local" class="sr-only" ${initialMode === 'local' ? 'checked' : ''} />
                <div class="font-semibold text-white">Local Admin</div>
                <div class="text-xs text-slate-400 mt-1">30-second setup. Passwords hashed with scrypt in local db.json.</div>
              </label>
              <label class="cf-mode-card cursor-pointer rounded-xl border p-3.5 transition ${initialMode === 'ldap' ? 'border-indigo-500 bg-indigo-500/10' : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'}">
                <input type="radio" name="cf_auth_mode" value="ldap" class="sr-only" ${initialMode === 'ldap' ? 'checked' : ''} />
                <div class="font-semibold text-white">Active Directory / LDAP</div>
                <div class="text-xs text-slate-400 mt-1">Bind against AD/OpenLDAP with mandatory Security Group RBAC mapping.</div>
              </label>
              <label class="cf-mode-card cursor-pointer rounded-xl border p-3.5 transition ${initialMode === 'oidc' ? 'border-indigo-500 bg-indigo-500/10' : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'}">
                <input type="radio" name="cf_auth_mode" value="oidc" class="sr-only" ${initialMode === 'oidc' ? 'checked' : ''} />
                <div class="font-semibold text-white">OIDC Single Sign-On</div>
                <div class="text-xs text-slate-400 mt-1">Entra ID, Okta, Keycloak, or Google with MFA &amp; group claims.</div>
              </label>
            </div>
          </div>

          <!-- LOCAL AUTH PANEL -->
          <div id="cf-panel-local" class="${initialMode === 'local' ? '' : 'hidden'} space-y-3 bg-slate-950/60 border border-slate-800 rounded-xl p-4">
            <div class="font-semibold text-white">${isReconfigure ? 'Local Authentication Active' : 'Create Primary Local Admin Account'}</div>
            ${!isReconfigure ? `
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label class="block text-xs text-slate-400 mb-1">Admin Username</label>
                <input id="cf-local-user" type="text" value="admin" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Password (min 10 chars)</label>
                <input id="cf-local-pass" type="password" placeholder="Strong passphrase..." class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white" />
              </div>
            </div>
            ` : `<p class="text-xs text-slate-400">Use the <strong>Users &amp; Roles</strong> button in the header to add Operators, Viewers, or additional Admins.</p>`}
          </div>

          <!-- LDAP / AD PANEL -->
          <div id="cf-panel-ldap" class="${initialMode === 'ldap' ? '' : 'hidden'} space-y-3 bg-slate-950/60 border border-slate-800 rounded-xl p-4">
            <div class="flex items-center justify-between">
              <div class="font-semibold text-white">Active Directory / LDAP Settings</div>
              <button type="button" id="cf-test-ldap" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-indigo-300 text-xs font-semibold border border-slate-700">
                Test Directory Bind &amp; Group
              </button>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label class="block text-xs text-slate-400 mb-1">LDAP / LDAPS Server URL</label>
                <input id="cf-ldap-url" type="text" value="${esc(cfg.ldap?.url || '')}" placeholder="ldaps://dc01.example.edu:636" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Search Base DN</label>
                <input id="cf-ldap-base" type="text" value="${esc(cfg.ldap?.baseDn || '')}" placeholder="DC=example,DC=edu" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Service Account Bind DN</label>
                <input id="cf-ldap-binddn" type="text" value="${esc(cfg.ldap?.bindDn || '')}" placeholder="CN=svc-cronfleet,OU=ServiceAccounts,DC=example,DC=edu" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Service Account Password</label>
                <input id="cf-ldap-bindpw" type="password" value="${esc(cfg.ldap?.bindPassword || '')}" placeholder="Service bind password" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs" />
              </div>
            </div>
            <div>
              <label class="block text-xs text-slate-400 mb-1">User Search Filter</label>
              <input id="cf-ldap-filter" type="text" value="${esc(cfg.ldap?.userFilter || '(|(sAMAccountName={{username}})(userPrincipalName={{username}})(uid={{username}}))')}" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
              <div>
                <label class="block text-xs text-rose-300 font-semibold mb-1">Admin Group DN (Required · Root Jobs)</label>
                <input id="cf-ldap-admingrp" type="text" value="${esc(cfg.ldap?.adminGroupDn || '')}" placeholder="CN=NetOps-Admins,OU=Groups,DC=example,DC=edu" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-amber-300 mb-1">Operator Group DN (Optional · Non-Root)</label>
                <input id="cf-ldap-opgrp" type="text" value="${esc(cfg.ldap?.operatorGroupDn || '')}" placeholder="CN=NetOps-Operators,..." class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-sky-300 mb-1">Viewer Group DN (Optional · Read-Only)</label>
                <input id="cf-ldap-viewgrp" type="text" value="${esc(cfg.ldap?.viewerGroupDn || '')}" placeholder="CN=NetOps-Viewers,..." class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
            </div>
            <label class="inline-flex items-center gap-2 text-xs text-slate-300 pt-1">
              <input id="cf-ldap-tls" type="checkbox" ${cfg.ldap?.rejectUnauthorized !== false ? 'checked' : ''} class="rounded bg-slate-900 border-slate-700" />
              Verify LDAPS TLS certificate (uncheck only for self-signed/internal Enterprise CAs without NODE_EXTRA_CA_CERTS)
            </label>
          </div>

          <!-- OIDC SSO PANEL -->
          <div id="cf-panel-oidc" class="${initialMode === 'oidc' ? '' : 'hidden'} space-y-3 bg-slate-950/60 border border-slate-800 rounded-xl p-4">
            <div class="flex items-center justify-between">
              <div class="font-semibold text-white">OIDC Single Sign-On Settings</div>
              <button type="button" id="cf-test-oidc" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-indigo-300 text-xs font-semibold border border-slate-700">
                Test OIDC Discovery
              </button>
            </div>
            <div class="bg-slate-900 border border-slate-700/80 rounded-lg p-2.5 flex items-center justify-between gap-2">
              <div class="text-xs text-slate-300 truncate">
                <span class="text-slate-400">Redirect / Callback URI:</span> <code id="cf-oidc-cb" class="text-emerald-300 font-mono">${esc(callbackUrl)}</code>
              </div>
              <button type="button" onclick="navigator.clipboard.writeText('${esc(callbackUrl)}')" class="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-white shrink-0">Copy</button>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div class="md:col-span-2">
                <label class="block text-xs text-slate-400 mb-1">Issuer URL (Entra ID, Okta, Keycloak, Authentik)</label>
                <input id="cf-oidc-issuer" type="text" value="${esc(cfg.oidc?.issuerUrl || '')}" placeholder="https://login.microsoftonline.com/<tenant-id>/v2.0" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Client ID</label>
                <input id="cf-oidc-cid" type="text" value="${esc(cfg.oidc?.clientId || '')}" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Client Secret</label>
                <input id="cf-oidc-csec" type="password" value="${esc(cfg.oidc?.clientSecret || '')}" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Username Claim</label>
                <input id="cf-oidc-uclaim" type="text" value="${esc(cfg.oidc?.usernameClaim || 'preferred_username')}" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Groups Claim Name</label>
                <input id="cf-oidc-gclaim" type="text" value="${esc(cfg.oidc?.groupClaim || 'groups')}" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
            </div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-3 pt-1">
              <div>
                <label class="block text-xs text-rose-300 font-semibold mb-1">Admin Group ID/Name (Required)</label>
                <input id="cf-oidc-admingrp" type="text" value="${esc(cfg.oidc?.adminGroupValue || '')}" placeholder="group-object-id-or-name" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-amber-300 mb-1">Operator Group (Optional)</label>
                <input id="cf-oidc-opgrp" type="text" value="${esc(cfg.oidc?.operatorGroupValue || '')}" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
              <div>
                <label class="block text-xs text-sky-300 mb-1">Viewer Group (Optional)</label>
                <input id="cf-oidc-viewgrp" type="text" value="${esc(cfg.oidc?.viewerGroupValue || '')}" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white font-mono text-xs" />
              </div>
            </div>
          </div>

          <!-- BREAK-GLASS LOCAL ADMIN (Shown when LDAP or OIDC selected on initial setup) -->
          <div id="cf-panel-breakglass" class="${(!isReconfigure && initialMode !== 'local') ? '' : 'hidden'} space-y-3 bg-amber-950/20 border border-amber-500/30 rounded-xl p-4">
            <div class="font-semibold text-amber-300">Break-Glass Local Admin Account (Required for Outage Recovery)</div>
            <p class="text-xs text-slate-300">
              If your Domain Controller or SSO provider goes offline during an incident, this local admin account lets you still manage critical cron jobs.
            </p>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label class="block text-xs text-slate-400 mb-1">Break-Glass Username</label>
                <input id="cf-bg-user" type="text" value="breakglass-admin" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white" />
              </div>
              <div>
                <label class="block text-xs text-slate-400 mb-1">Break-Glass Password (min 10 chars)</label>
                <input id="cf-bg-pass" type="password" placeholder="Store in password vault..." class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white" />
              </div>
            </div>
          </div>

          <!-- TELEMETRY TOKEN ENFORCEMENT -->
          <div class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 flex items-start justify-between gap-4">
            <div>
              <div class="font-semibold text-white">Require Host Token on Node Telemetry (<code class="text-xs text-indigo-300">/api/v1/telemetry</code>)</div>
              <div class="text-xs text-slate-400 mt-0.5">
                Enable after all managed nodes run an updated <code class="text-slate-300">cronfleet-exec</code> sending <code class="text-slate-300">Authorization: Bearer &lt;HOST_TOKEN&gt;</code>.
              </div>
            </div>
            <input id="cf-req-host-token" type="checkbox" ${cfg.requireHostToken ? 'checked' : ''} class="mt-1 h-4 w-4 rounded bg-slate-900 border-slate-700" />
          </div>

          <div id="cf-wiz-feedback" class="hidden rounded-lg p-3 text-xs font-medium"></div>

          <div class="flex items-center justify-end gap-3 pt-2 border-t border-slate-800">
            <button type="submit" class="px-5 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-semibold shadow-lg">
              ${isReconfigure ? 'Save Security Settings' : 'Complete Security Setup & Sign In'}
            </button>
          </div>
        </form>
      </div>
    `);

    if (isReconfigure) {
      document.getElementById('cf-wiz-close').onclick = closeOverlay;
    }

    function syncModePanels() {
      const selected = document.querySelector('input[name="cf_auth_mode"]:checked').value;
      document.querySelectorAll('.cf-mode-card').forEach(card => {
        const active = card.querySelector('input').value === selected;
        card.className = `cf-mode-card cursor-pointer rounded-xl border p-3.5 transition ${active ? 'border-indigo-500 bg-indigo-500/10' : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'}`;
      });
      document.getElementById('cf-panel-local').classList.toggle('hidden', selected !== 'local');
      document.getElementById('cf-panel-ldap').classList.toggle('hidden', selected !== 'ldap');
      document.getElementById('cf-panel-oidc').classList.toggle('hidden', selected !== 'oidc');
      const bgPanel = document.getElementById('cf-panel-breakglass');
      if (bgPanel) bgPanel.classList.toggle('hidden', isReconfigure || selected === 'local');
    }

    document.querySelectorAll('input[name="cf_auth_mode"]').forEach(r => r.addEventListener('change', syncModePanels));

    function showFeedback(msg, ok) {
      const fb = document.getElementById('cf-wiz-feedback');
      fb.textContent = msg;
      fb.className = `rounded-lg p-3 text-xs font-medium border ${ok ? 'bg-emerald-950/70 text-emerald-300 border-emerald-500/40' : 'bg-rose-950/70 text-rose-300 border-rose-500/40'}`;
    }

    function collectLdap() {
      return {
        url: document.getElementById('cf-ldap-url').value,
        baseDn: document.getElementById('cf-ldap-base').value,
        bindDn: document.getElementById('cf-ldap-binddn').value,
        bindPassword: document.getElementById('cf-ldap-bindpw').value,
        userFilter: document.getElementById('cf-ldap-filter').value,
        adminGroupDn: document.getElementById('cf-ldap-admingrp').value,
        operatorGroupDn: document.getElementById('cf-ldap-opgrp').value,
        viewerGroupDn: document.getElementById('cf-ldap-viewgrp').value,
        rejectUnauthorized: document.getElementById('cf-ldap-tls').checked
      };
    }

    function collectOidc() {
      return {
        issuerUrl: document.getElementById('cf-oidc-issuer').value,
        clientId: document.getElementById('cf-oidc-cid').value,
        clientSecret: document.getElementById('cf-oidc-csec').value,
        usernameClaim: document.getElementById('cf-oidc-uclaim').value,
        groupClaim: document.getElementById('cf-oidc-gclaim').value,
        adminGroupValue: document.getElementById('cf-oidc-admingrp').value,
        operatorGroupValue: document.getElementById('cf-oidc-opgrp').value,
        viewerGroupValue: document.getElementById('cf-oidc-viewgrp').value
      };
    }

    document.getElementById('cf-test-ldap')?.addEventListener('click', async () => {
      showFeedback('Testing directory connection and bind...', true);
      const r = await origFetch('/api/auth/test-ldap', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ldap: collectLdap() })
      });
      const data = await r.json();
      showFeedback(data.ok ? data.message : data.error, data.ok);
    });

    document.getElementById('cf-test-oidc')?.addEventListener('click', async () => {
      showFeedback('Fetching OIDC discovery & JWKS metadata...', true);
      const r = await origFetch('/api/auth/test-oidc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ oidc: collectOidc() })
      });
      const data = await r.json();
      showFeedback(data.ok ? data.message : data.error, data.ok);
    });

    document.getElementById('cf-setup-form').addEventListener('submit', async e => {
      e.preventDefault();
      const mode = document.querySelector('input[name="cf_auth_mode"]:checked').value;
      const payload = {
        setupCode: document.getElementById('cf-setup-code')?.value,
        mode,
        requireHostToken: document.getElementById('cf-req-host-token').checked,
        localAdmin: !isReconfigure && mode === 'local' ? {
          username: document.getElementById('cf-local-user').value,
          password: document.getElementById('cf-local-pass').value
        } : undefined,
        breakGlassAdmin: !isReconfigure && mode !== 'local' ? {
          username: document.getElementById('cf-bg-user').value,
          password: document.getElementById('cf-bg-pass').value
        } : undefined,
        ldap: mode === 'ldap' ? collectLdap() : undefined,
        oidc: mode === 'oidc' ? collectOidc() : undefined
      };

      const r = await origFetch('/api/auth/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await r.json();
      if (!r.ok) {
        showFeedback(data.error || 'Setup failed.', false);
        return;
      }
      window.location.reload();
    });
  }

  // ==========================================================================
  // 2. LOGIN SCREEN (Local / AD-LDAP / OIDC + Break-Glass)
  // ==========================================================================
  function openLoginScreen() {
    const mode = authState?.authMode || 'local';
    const isOidc = mode === 'oidc';
    const providerLabel = mode === 'ldap' ? 'Active Directory / LDAP' : (isOidc ? 'Enterprise SSO (OIDC)' : 'Local Account');

    mountOverlay(`
      <div class="w-full max-w-md bg-slate-900 border border-slate-700/80 rounded-2xl shadow-2xl overflow-hidden">
        <div class="p-6 border-b border-slate-800 bg-gradient-to-r from-slate-900 to-indigo-950/60">
          <div class="flex items-center gap-2 text-indigo-400 font-bold text-xl">
            <span>🛡️</span> CronFleet
          </div>
          <p class="text-xs text-slate-400 mt-1">Authenticated Access Required · Provider: <span class="text-slate-200 font-medium">${esc(providerLabel)}</span></p>
        </div>

        <div class="p-6 space-y-4">
          ${isOidc ? `
            <a href="/api/auth/oidc/login" class="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-sm shadow-lg transition">
              <span>🔐</span> Sign in with Single Sign-On (OIDC)
            </a>
            <div class="pt-2 border-t border-slate-800">
              <button type="button" id="cf-toggle-bg" class="text-xs text-slate-400 hover:text-amber-300">
                IdP outage? Use Break-Glass Local Login ▾
              </button>
            </div>
          ` : ''}

          <form id="cf-login-form" class="${isOidc ? 'hidden' : ''} space-y-3.5 text-sm">
            <input id="cf-login-bg" type="hidden" value="${isOidc ? 'true' : 'false'}" />
            <div>
              <label class="block text-xs text-slate-400 mb-1">${mode === 'ldap' ? 'Directory Username (sAMAccountName / UPN)' : 'Username'}</label>
              <input id="cf-login-user" type="text" required autocomplete="username" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2.5 text-white focus:outline-none focus:border-indigo-500" />
            </div>
            <div>
              <label class="block text-xs text-slate-400 mb-1">Password</label>
              <input id="cf-login-pass" type="password" required autocomplete="current-password" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2.5 text-white focus:outline-none focus:border-indigo-500" />
            </div>
            <div id="cf-login-err" class="hidden rounded-lg p-2.5 text-xs bg-rose-950/70 text-rose-300 border border-rose-500/40"></div>
            <button type="submit" class="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold shadow-lg">
              Sign In
            </button>
          </form>

          ${mode === 'ldap' ? `
          <div class="pt-2 border-t border-slate-800 flex items-center justify-between text-xs">
            <label class="inline-flex items-center gap-1.5 text-slate-400 cursor-pointer">
              <input id="cf-ldap-bg-chk" type="checkbox" class="rounded bg-slate-950 border-slate-700" />
              Break-glass local login
            </label>
          </div>
          ` : ''}
        </div>
      </div>
    `);

    document.getElementById('cf-toggle-bg')?.addEventListener('click', () => {
      document.getElementById('cf-login-form').classList.toggle('hidden');
    });

    document.getElementById('cf-ldap-bg-chk')?.addEventListener('change', e => {
      document.getElementById('cf-login-bg').value = e.target.checked ? 'true' : 'false';
    });

    document.getElementById('cf-login-form')?.addEventListener('submit', async e => {
      e.preventDefault();
      const errEl = document.getElementById('cf-login-err');
      errEl.classList.add('hidden');
      const r = await origFetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: document.getElementById('cf-login-user').value,
          password: document.getElementById('cf-login-pass').value,
          breakGlass: document.getElementById('cf-login-bg').value === 'true'
        })
      });
      const data = await r.json();
      if (!r.ok) {
        errEl.textContent = data.error || 'Authentication failed.';
        errEl.classList.remove('hidden');
        return;
      }
      window.location.reload();
    });
  }

  // ==========================================================================
  // 3. USERS & RBAC MODAL (Admin Only)
  // ==========================================================================
  async function openUsersModal() {
    const r = await origFetch('/api/users');
    const users = r.ok ? await r.json() : [];

    mountOverlay(`
      <div class="w-full max-w-2xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden">
        <div class="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 class="text-lg font-bold text-white">Local &amp; Break-Glass Users (RBAC)</h3>
            <p class="text-xs text-slate-400">Admin = Root &amp; Non-Root Jobs + Settings · Operator = Non-Root Jobs Only · Viewer = Read-Only</p>
          </div>
          <button id="cf-users-close" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300">Close</button>
        </div>
        <div class="p-5 space-y-4 text-sm">
          <div class="divide-y divide-slate-800 border border-slate-800 rounded-xl overflow-hidden">
            ${users.map(u => `
              <div class="p-3 bg-slate-950/60 flex items-center justify-between gap-3">
                <div class="flex items-center gap-2.5">
                  <span class="font-semibold text-white">${esc(u.username)}</span>
                  ${roleBadge(u.role)}
                  ${u.isBreakGlass ? '<span class="text-[11px] px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30">Break-Glass</span>' : ''}
                </div>
                <button data-del-user="${esc(u.username)}" class="text-xs text-rose-400 hover:text-rose-300 px-2 py-1">Remove</button>
              </div>
            `).join('')}
          </div>

          <form id="cf-add-user-form" class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-3">
            <div class="font-semibold text-white text-xs uppercase tracking-wider">Add / Update User</div>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-2.5">
              <input id="cf-nu-name" type="text" required placeholder="Username" class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs" />
              <input id="cf-nu-pass" type="password" required placeholder="Password (10+ chars)" class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs" />
              <select id="cf-nu-role" class="bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white text-xs">
                <option value="viewer">Viewer (Read-Only)</option>
                <option value="operator">Operator (Non-Root Jobs)</option>
                <option value="admin">Admin (Full / Root Access)</option>
              </select>
            </div>
            <div class="flex items-center justify-between">
              <label class="inline-flex items-center gap-2 text-xs text-slate-300">
                <input id="cf-nu-bg" type="checkbox" class="rounded bg-slate-900 border-slate-700" />
                Allow as Break-Glass emergency login
              </label>
              <button type="submit" class="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold">Save User</button>
            </div>
            <div id="cf-nu-msg" class="hidden text-xs"></div>
          </form>
        </div>
      </div>
    `);

    document.getElementById('cf-users-close').onclick = closeOverlay;
    document.querySelectorAll('[data-del-user]').forEach(btn => {
      btn.onclick = async () => {
        const res = await origFetch(`/api/users/${encodeURIComponent(btn.dataset.delUser)}`, { method: 'DELETE' });
        const d = await res.json();
        if (!res.ok) return alert(d.error);
        openUsersModal();
      };
    });

    document.getElementById('cf-add-user-form').onsubmit = async e => {
      e.preventDefault();
      const res = await origFetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: document.getElementById('cf-nu-name').value,
          password: document.getElementById('cf-nu-pass').value,
          role: document.getElementById('cf-nu-role').value,
          isBreakGlass: document.getElementById('cf-nu-bg').checked
        })
      });
      const d = await res.json();
      if (!res.ok) {
        const msg = document.getElementById('cf-nu-msg');
        msg.textContent = d.error;
        msg.className = 'text-xs text-rose-400';
        return;
      }
      openUsersModal();
    };
  }

  // ==========================================================================
  // 4. AUDIT LOG VIEWER MODAL (Accounting)
  // ==========================================================================
  async function openAuditModal() {
    const r = await origFetch('/api/audit');
    const entries = r.ok ? await r.json() : [];

    mountOverlay(`
      <div class="w-full max-w-4xl bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl overflow-hidden my-8">
        <div class="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 class="text-lg font-bold text-white">Control Plane Security &amp; Change Audit Log</h3>
            <p class="text-xs text-slate-400">Append-only record of logins, job creations/edits, root escalations, and security changes (<code class="text-slate-300">data/audit.jsonl</code>)</p>
          </div>
          <button id="cf-audit-close" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-300">Close</button>
        </div>
        <div class="max-h-[70vh] overflow-y-auto divide-y divide-slate-800/80 text-xs">
          ${entries.length ? entries.map(a => `
            <div class="p-3.5 hover:bg-slate-950/60 flex flex-col md:flex-row md:items-center justify-between gap-2">
              <div class="space-y-1">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="font-mono text-slate-400">${esc(a.ts)}</span>
                  <span class="font-semibold text-indigo-300">${esc(a.actor)}</span>
                  ${roleBadge(a.role)}
                  <span class="px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-mono">${esc(a.action)}</span>
                  <span class="text-white font-medium">${esc(a.target)}</span>
                </div>
                <div class="text-slate-400 font-mono text-[11px] break-all">${esc(JSON.stringify(a.details || {}))}</div>
              </div>
              <div class="text-slate-500 font-mono shrink-0">${esc(a.ip)}</div>
            </div>
          `).join('') : '<div class="p-6 text-slate-400 text-center">No audit entries recorded yet.</div>'}
        </div>
      </div>
    `);

    document.getElementById('cf-audit-close').onclick = closeOverlay;
  }

  // ==========================================================================
  // 5. TOP SECURITY & AAA BAR (Injected once authenticated)
  // ==========================================================================
  function injectSecurityToolbar(user) {
    if (document.getElementById('cf-aaa-bar')) return;
    const bar = document.createElement('div');
    bar.id = 'cf-aaa-bar';
    bar.className = 'bg-slate-950 border-b border-slate-800/90 px-4 py-2 text-xs text-slate-300';
    bar.innerHTML = `
      <div class="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3">
        <div class="flex items-center gap-2.5">
          <span class="text-emerald-400">🛡️</span>
          <span>Signed in as <strong class="text-white">${esc(user.username)}</strong></span>
          ${roleBadge(user.role)}
          <span class="text-slate-500">via ${esc(user.provider)}</span>
        </div>
        <div class="flex items-center gap-2">
          <button id="cf-btn-audit" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-200">
            Audit Log
          </button>
          ${user.role === 'admin' ? `
            <button id="cf-btn-users" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-slate-200">
              Users &amp; Roles
            </button>
            <button id="cf-btn-authcfg" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-indigo-500/40 text-indigo-300">
              Auth &amp; Security
            </button>
          ` : ''}
          <button id="cf-btn-logout" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-rose-950/70 border border-slate-700/80 text-rose-300">
            Sign Out
          </button>
        </div>
      </div>
    `;
    document.body.insertBefore(bar, document.body.firstChild);

    document.getElementById('cf-btn-audit').onclick = openAuditModal;
    document.getElementById('cf-btn-users')?.addEventListener('click', openUsersModal);
    document.getElementById('cf-btn-authcfg')?.addEventListener('click', () => openSetupWizard(true));
    document.getElementById('cf-btn-logout').onclick = async () => {
      await origFetch('/api/auth/logout', { method: 'POST' });
      window.location.reload();
    };
  }

  async function bootstrapAuthUI() {
    try {
      const res = await origFetch('/api/auth/status');
      authState = await res.json();
      if (!authState.configured) {
        openSetupWizard(false);
      } else if (!authState.authenticated) {
        openLoginScreen();
      } else {
        closeOverlay();
        injectSecurityToolbar(authState.user);
      }
    } catch (err) {
      console.error('[AUTH_BOOTSTRAP_ERR]', err);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrapAuthUI);
  } else {
    bootstrapAuthUI();
  }
})();
