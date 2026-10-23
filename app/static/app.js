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
        this.error = (await r.json()).detail || 'Map niet gevonden';
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
          <button type="button" data-act="cancel" class="btn-secondary">Annuleren</button>
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

// <form onsubmit="return confirmSubmit(event, 'Weet je het zeker?')">
function confirmSubmit(event, message) {
  event.preventDefault();
  const form = event.target;
  dialog({ message, ok: 'Ja' }).then((yes) => { if (yes) form.submit(); });
  return false;
}

async function ignorePath(path) {
  const rule = await dialog({
    message:
      'Ignore-regel toevoegen en opnieuw scannen.\n' +
      'Pas aan om breder te negeren: [*] = elke lijstindex of documentnaam, * = één segment, ' +
      '** = alles. Een regel negeert ook alles eronder.',
    value: path,
    ok: 'Negeren',
  });
  if (!rule || !rule.trim()) return;
  const r = await api(`/api/c/${CLUSTER}/ignore`, { method: 'POST', body: JSON.stringify({ path: rule.trim() }) });
  if (!r.ok) return dialog({ message: `Opslaan mislukt (${r.status}).` });
  // Wait for the rescan so the page shows the result without the ignored path.
  await waitForScans();
  location.reload();
}

// Show ISO timestamps as relative Dutch time ("5 minuten geleden").
(function () {
  const rtf = new Intl.RelativeTimeFormat('nl', { numeric: 'auto' });
  const units = [['day', 86400], ['hour', 3600], ['minute', 60], ['second', 1]];
  document.querySelectorAll('time.rel').forEach((el) => {
    const d = new Date(el.getAttribute('datetime'));
    if (isNaN(d)) return;
    const diff = (d - Date.now()) / 1000;
    const [unit, secs] = units.find(([, s]) => Math.abs(diff) >= s) || units[3];
    el.textContent = rtf.format(Math.round(diff / secs), unit);
    el.title = d.toLocaleString('nl-NL');
  });
})();
