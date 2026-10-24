const CSRF = document.querySelector('meta[name="csrf-token"]')?.content || '';
const CLUSTER = document.querySelector('meta[name="cluster-id"]')?.content || '';

function api(path, opts = {}) {
  return fetch(path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': CSRF, ...(opts.headers || {}) },
    credentials: 'same-origin',
  });
}

// Resolves once no scan is running for the cluster (or, without one, for any cluster).
function waitForScans(cid = CLUSTER) {
  return new Promise((done) => {
    const poll = async () => {
      const { running } = await (await api('/api/status')).json();
      const busy = cid ? running.includes(cid) : running.length > 0;
      busy ? setTimeout(poll, 1000) : done();
    };
    setTimeout(poll, 500);
  });
}

// Header scan button: scans the current cluster, or all clusters on the overview.
function scanner(initiallyRunning, cid) {
  return {
    running: initiallyRunning,
    init() { if (this.running) this.wait(); },
    async scan() {
      this.running = true;
      await api(cid ? `/api/c/${cid}/scan` : '/api/scan', { method: 'POST' });
      this.wait();
    },
    async wait() {
      await waitForScans(cid);
      location.reload();
    },
  };
}

// Folder picker for the base folder (Settings).
function folderPicker(initial) {
  return {
    open: !initial,
    cwd: { path: '', parent: null, dirs: [] },
    error: '',
    toggle() {
      this.open = !this.open;
      if (this.open) this.go(initial || '');
    },
    init() { if (this.open) this.go(''); },
    async go(path) {
      const r = await api('/api/dirs?path=' + encodeURIComponent(path || ''));
      if (!r.ok) {
        this.error = (await r.json()).detail || 'Folder not found';
        if (path) return this.go('');
        return;
      }
      this.error = '';
      this.cwd = await r.json();
    },
  };
}

// Let's Encrypt form: show the provider's required variables, follow a running request.
function acmeForm(challenge, provider, running) {
  return {
    challenge, provider, running, helpText: '',
    init() {
      if (this.provider) this.help();
      if (this.running) this.wait();
    },
    async help() {
      const r = await api('/api/acme/dnshelp?provider=' + encodeURIComponent(this.provider || ''));
      this.helpText = r.ok ? (await r.json()).help : '';
    },
    async wait() {
      const s = await (await api('/api/acme/status')).json();
      s.running ? setTimeout(() => this.wait(), 2000) : location.reload();
    },
  };
}

// In-page dialog: native confirm()/prompt() are blocked in some browsers
// (e.g. embedded webviews) and then silently return "cancel".
function dialog({ message, value = null, ok = 'OK' }) {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4';
    overlay.innerHTML = `
      <div class="card w-full max-w-lg p-5 space-y-4" role="dialog" aria-modal="true">
        <div class="text-sm text-slate-200 whitespace-pre-line"></div>
        ${value === null ? '' : '<input class="input font-mono text-xs">'}
        <div class="flex justify-end gap-2">
          <button type="button" data-act="cancel" class="btn-secondary">Cancel</button>
          <button type="button" data-act="ok" class="btn-primary"></button>
        </div>
      </div>`;
    overlay.querySelector('.whitespace-pre-line').textContent = message;
    overlay.querySelector('[data-act=ok]').textContent = ok;
    const input = overlay.querySelector('input');
    if (input) input.value = value;
    const close = (result) => { overlay.remove(); resolve(result); };
    overlay.querySelector('[data-act=cancel]').onclick = () => close(null);
    overlay.querySelector('[data-act=ok]').onclick = () => close(input ? input.value : true);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(null); });
    overlay.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') close(null);
      if (e.key === 'Enter') close(input ? input.value : true);
    });
    document.body.appendChild(overlay);
    (input || overlay.querySelector('[data-act=ok]')).focus();
  });
}

// <form onsubmit="return confirmSubmit(event, 'Are you sure?')">
function confirmSubmit(event, message) {
  event.preventDefault();
  const form = event.target;
  dialog({ message, ok: 'Yes' }).then((yes) => { if (yes) form.submit(); });
  return false;
}

// Patches tab: edit or write a patch, validate it with a dry run, then roll it out.
function patchEditor({ nodes, patches, rollout, cluster }) {
  return {
    nodes, patches, rollout, cluster,
    editing: false, sync: false, removing: false, rollbackOf: null, currentLabel: '', patchId: null, patchPath: null, name: '', path: '', text: '',
    targetType: 'all', selected: [], mode: 'no-reboot', canary: false, skipUnreachable: false,
    busy: false, result: null, error: '', loadError: '',
    init() { if (this.running()) this.poll(); },
    running() { return !!(this.rollout && this.rollout.running); },
    statusClass(s) {
      return { 'in-sync': 'badge-ok', done: 'badge-ok', drift: 'badge-warn', checking: 'badge-warn', applying: 'badge-warn',
               waiting: 'badge-warn', health: 'badge-warn', verifying: 'badge-warn',
               unreachable: 'badge-err', 'patch-error': 'badge-err', failed: 'badge-err', interrupted: 'badge-err' }[s] || 'badge-muted';
    },
    reboots(n) { return /reboot/i.test(n.summary || '') && !/without a reboot/i.test(n.summary || ''); },
    // Nodes a failed or interrupted rollout already changed: candidates for a sync back to baseline.
    revertable() {
      return (this.rollout && this.rollout.nodes || []).filter((n) => ['done', 'interrupted', 'failed'].includes(n.status)).map((n) => n.hostname);
    },
    revertSucceeded() {
      const hosts = this.revertable();
      this.startSync();
      this.selected = this.nodes.filter((n) => hosts.includes(n.hostname)).map((n) => n.hostname);
    },
    async decide(d) {
      const r = await api(`/api/c/${CLUSTER}/patches/rollout/${d}`, { method: 'POST' });
      if (!r.ok) this.error = (await r.json()).detail || `Failed (${r.status})`;
    },
    countFor(type) {
      if (type === 'all') return this.nodes.length;
      if (type === 'nodes') return this.selected.length;
      return this.nodes.filter((n) => n.role === type).length;
    },
    target() {
      if (this.targetType !== 'nodes') return this.targetType;
      return this.selected.length === 1 ? `node:${this.selected[0]}` : `nodes:${this.selected.join(',')}`;
    },
    // A selection covering only part of a role makes those nodes differ from their peers.
    splitWarning() {
      if (this.sync || this.targetType !== 'nodes' || !this.selected.length) return '';
      const parts = [['controlplane', 'control planes'], ['worker', 'workers']].flatMap(([role, label]) => {
        const all = this.nodes.filter((n) => n.role === role);
        const picked = all.filter((n) => this.selected.includes(n.hostname)).length;
        return picked && picked < all.length ? [`${picked} of ${all.length} ${label}`] : [];
      });
      return parts.length
        ? `This patch covers only ${parts.join(' and ')}: they will differ from the others. ` +
          'That shows as "via patch" under Consistency. Is that intended?'
        : '';
    },
    // Any edit invalidates an earlier validation: only what was checked can be applied.
    changed() { this.result = null; this.error = ''; },
    setTarget(target) {
      const names = target.startsWith('node:') ? [target.slice(5)]
        : target.startsWith('nodes:') ? target.slice(6).split(',') : null;
      this.targetType = names ? 'nodes' : target;
      this.selected = names
        ? this.nodes.filter((n) => names.includes(n.hostname) || names.includes(n.address)).map((n) => n.hostname)
        : [];
    },
    newPatch() {
      Object.assign(this, { editing: true, sync: false, removing: false, rollbackOf: null, patchId: null, patchPath: null, name: '', path: '', text: '', loadError: '' });
      this.setTarget('all');
      this.changed();
    },
    async edit(p) {
      Object.assign(this, { editing: true, sync: false, removing: false, rollbackOf: null, currentLabel: p.label, patchId: p.id, patchPath: p.path || null, name: p.name, text: '', loadError: '' });
      this.changed();
      const r = await api(`/api/c/${CLUSTER}/patches/${p.id}/text`);
      const body = await r.json();
      if (!r.ok) { this.loadError = body.detail || `Loading failed (${r.status})`; return; }
      this.text = body.text;
      this.setTarget(body.target);
    },
    // Delete the patch being edited: undo unsaved text edits so what is shown is what is removed.
    async startDelete() {
      await this.edit(this.patches.find((p) => p.id === this.patchId));
      this.removing = true;
    },
    // Roll back a rollout from the history (event from the history table).
    startRollback(entry) {
      Object.assign(this, { editing: true, sync: false, removing: false, rollbackOf: entry, patchId: null, patchPath: null, loadError: '' });
      this.changed();
      window.scrollTo({ top: 0, behavior: 'smooth' });
    },
    // Bring nodes back to their baseline without changing a patch; drifting nodes preselected.
    startSync() {
      Object.assign(this, { editing: true, sync: true, removing: false, rollbackOf: null, patchId: null, patchPath: null, name: '', path: '', text: '', loadError: '' });
      this.targetType = 'nodes';
      this.selected = this.nodes.filter((n) => n.status === 'drift').map((n) => n.hostname);
      this.changed();
    },
    renderDiff(diff) {
      return Diff2Html.html(diff, { drawFileList: false, outputFormat: 'line-by-line', matching: 'lines', colorScheme: 'dark' });
    },
    async validate() {
      this.changed();
      this.busy = true;
      try {
        const r = this.rollbackOf
          ? await api(`/api/c/${CLUSTER}/patches/rollback`, { method: 'POST', body: JSON.stringify({ entry_id: this.rollbackOf.id, mode: this.mode, canary: this.canary, skip_unreachable: this.skipUnreachable }) })
          : await api(`/api/c/${CLUSTER}/patches/validate`, {
          method: 'POST',
          body: JSON.stringify({ text: this.text, target: this.target(), mode: this.mode, patch_id: this.patchId, name: this.name, path: this.path, sync: this.sync, delete: this.removing, canary: this.canary, skip_unreachable: this.skipUnreachable }),
        });
        const body = await r.json();
        if (r.ok) this.result = body; else this.error = body.detail || `Validation failed (${r.status})`;
      } finally {
        this.busy = false;
      }
    },
    async apply() {
      const r0 = this.result;
      const names = r0.nodes.map((n) => `${n.hostname} (${n.role})${n.removes && !r0.delete ? ': patch removed' : ''}`);
      const yes = await dialog({
        message: (this.rollbackOf ? `ROLL BACK ${this.rollbackOf.label} on cluster ${r0.cluster.toUpperCase()}?\n\n` +
            `${r0.delete ? 'Deletes' : 'Sets'} ${r0.name}${r0.delete ? '' : ` (${r0.target_label})`}; ${names.length} node(s) change, one by one:\n`
          : r0.delete ? `DELETE ${r0.name} from cluster ${r0.cluster.toUpperCase()}?\n\n` +
            `It is removed from ${names.length} node(s), one by one:\n`
          : `Apply ${r0.name} to cluster ${r0.cluster.toUpperCase()}?\n\n${names.length} node(s), one by one:\n`) +
          `${names.join('\n') || '(none)'}\n\nMode: ${r0.mode}` +
          (r0.nodes.some((n) => this.reboots(n)) ? `\n\nWARNING: ${r0.nodes.filter((n) => this.reboots(n)).length} node(s) will REBOOT.` : '') +
          (r0.canary ? '\nThe rollout pauses after the first node.' : '') +
          ((r0.skipped || []).length ? `\nSkipped (unreachable): ${r0.skipped.map((n) => n.hostname).join(', ')}` : ''),
        ok: `${this.rollbackOf ? 'Roll back on' : r0.delete ? 'Delete from' : 'Apply to'} ${r0.cluster}`,
      });
      if (!yes) return;
      const r = await api(`/api/c/${CLUSTER}/patches/apply`, { method: 'POST', body: JSON.stringify({ plan_id: this.result.plan_id }) });
      const body = await r.json();
      this.result = null;
      if (!r.ok) { this.error = body.detail || `Apply failed (${r.status})`; return; }
      this.rollout = body;
      window.scrollTo({ top: 0, behavior: 'smooth' });
      this.poll();
    },
    async poll() {
      this.rollout = await (await api(`/api/c/${CLUSTER}/patches/rollout`)).json();
      if (this.running()) setTimeout(() => this.poll(), 2000);
      else location.reload();  // refresh the patch list and history
    },
  };
}

// New node tab: copy a node patch from an existing node, generate and download the config.
function newNode({ templates, blocked, cluster }) {
  return {
    templates, blocked, cluster,
    role: 'worker', hostname: '', address: '', template: '', nodePatch: '', mode: 'metal', savePatch: true,
    busy: false, result: null, error: '', downloaded: false,
    changed() { this.result = null; this.error = ''; },
    roleChanged() { this.template = ''; this.changed(); },
    async loadTemplate() {
      const q = new URLSearchParams({ node: this.template, hostname: this.hostname, address: this.address });
      const r = await api(`/api/c/${CLUSTER}/newnode/template?${q}`);
      const body = await r.json();
      if (!r.ok) { this.error = body.detail || `Loading failed (${r.status})`; return; }
      this.nodePatch = body.text;
      this.changed();
    },
    async generate() {
      this.changed();
      this.busy = true;
      try {
        const r = await api(`/api/c/${CLUSTER}/newnode/generate`, {
          method: 'POST',
          body: JSON.stringify({ role: this.role, hostname: this.hostname, address: this.address, node_patch: this.nodePatch,
                                 mode: this.mode, save_patch: this.savePatch, template: this.template }),
        });
        const body = await r.json();
        if (r.ok) { this.result = body; this.downloaded = false; } else this.error = body.detail || `Failed (${r.status})`;
      } finally {
        this.busy = false;
      }
    },
    applyCommand() {
      const ip = this.address || '<ip-of-the-new-node>';
      return `talosctl apply-config --insecure -n ${ip} --file ${this.result.hostname}.yaml`;
    },
  };
}

async function ignorePath(path) {
  const rule = await dialog({
    message:
      'Add an ignore rule and rescan.\n' +
      'Edit to ignore more broadly: [*] = any list index or document name, * = one segment, ' +
      '** = anything. A rule also ignores everything below it.',
    value: path,
    ok: 'Ignore',
  });
  if (!rule || !rule.trim()) return;
  const r = await api(`/api/c/${CLUSTER}/ignore`, { method: 'POST', body: JSON.stringify({ path: rule.trim() }) });
  if (!r.ok) return dialog({ message: `Saving failed (${r.status}).` });
  // Wait for the rescan so the page shows the result without the ignored path.
  await waitForScans();
  location.reload();
}

// Show ISO timestamps as relative time ("5 minutes ago").
(function () {
  const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  const units = [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
  document.querySelectorAll('time.rel').forEach((el) => {
    const d = new Date(el.getAttribute('datetime'));
    if (isNaN(d)) return;
    const diff = (d - Date.now()) / 1000;
    const [unit, secs] = units.find(([, s]) => Math.abs(diff) >= s) || units[3];
    el.textContent = rtf.format(Math.round(diff / secs), unit);
    el.title = d.toLocaleString('en-GB');
  });
})();
