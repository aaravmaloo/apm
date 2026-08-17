// APM Passkeys — popup logic.
'use strict';

const $ = (id) => document.getElementById(id);
const show = (id) => {
  document.querySelectorAll('.view').forEach((v) => v.classList.add('hidden'));
  $(id).classList.remove('hidden');
};

const send = (msg) =>
  new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, (resp) => {
      if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
      else resolve(resp || { ok: false });
    });
  });

let state = { paired: false, unlocked: false, pending: null, entries: [] };
let selectedRef = null;

// ── Routing ───────────────────────────────────────────────────────────────────

async function boot() {
  state = await send({ type: 'get-state' });
  if (!state.paired) return show('view-pair');

  $('bridge-version').textContent = state.version ? 'v' + state.version : '';
  $('bridge-dot').classList.toggle('ok', true);
  $('vault-dot').classList.toggle('ok', state.unlocked);
  $('vault-label').textContent = state.unlocked ? 'Vault unlocked' : 'Vault locked';

  const ierr = $('intent-error');
  if (state.intentError) {
    ierr.textContent = '⚠ Passkey interception failed: ' + state.intentError;
    ierr.classList.remove('hidden');
  } else {
    ierr.classList.add('hidden');
  }

  if (state.pending) {
    if (!state.unlocked) {
      show('view-status');
      $('pending-card').classList.add('hidden');
      $('pending-locked').classList.remove('hidden');
      return;
    }
    $('pending-rp').textContent = state.pending.rpId || 'unknown site';
    $('pending-locked').classList.add('hidden');
    $('pending-card').classList.remove('hidden');
    show('view-status');
  } else {
    $('pending-card').classList.add('hidden');
    $('pending-locked').classList.add('hidden');
    show('view-status');
  }
}

// ── Pairing ───────────────────────────────────────────────────────────────────

$('pair-connect').addEventListener('click', async () => {
  const token = $('pair-token').value.trim();
  if (!token) { $('pair-error').textContent = 'Paste the token from APM → Settings → Passkeys.'; $('pair-error').classList.remove('hidden'); return; }
  $('pair-error').classList.add('hidden');
  const r = await send({ type: 'pair', token });
  if (!r.ok) {
    $('pair-error').textContent = r.error || 'Pairing failed.';
    $('pair-error').classList.remove('hidden');
    return;
  }
  await boot();
});

$('pair-token').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('pair-connect').click();
});

$('status-forget').addEventListener('click', async () => {
  await send({ type: 'forget-pairing' });
  $('pair-token').value = '';
  show('view-pair');
});

// ── Save ──────────────────────────────────────────────────────────────────────

$('pending-save').addEventListener('click', () => openSave());
$('pending-dismiss').addEventListener('click', async () => {
  await send({ type: 'dismiss-capture' });
  await boot();
});

function openSave() {
  selectedRef = null;
  $('save-rp').textContent = state.pending ? state.pending.rpId : '';
  renderEntries(state.entries || []);
  $('new-entry').classList.add('hidden');
  $('new-name').value = '';
  $('new-user').value = '';
  $('new-space').value = '';
  $('save-error').classList.add('hidden');
  show('view-save');
  $('save-search').focus();
}

function renderEntries(entries) {
  const list = $('save-list');
  list.innerHTML = '';
  if (!entries || entries.length === 0) {
    const d = document.createElement('div');
    d.className = 'empty';
    d.textContent = 'No entries yet — create one below.';
    list.appendChild(d);
    return;
  }
  for (const e of entries) {
    const row = document.createElement('div');
    row.className = 'row';
    row.dataset.key = e.vaultKey + ':' + e.index;
    row.innerHTML =
      '<div class="r-ico">' + (e.icon || '🔑') + '</div>' +
      '<div><div class="r-name"></div><div class="r-sub"></div></div>' +
      '<span class="r-space">' + (e.space || '') + '</span>';
    row.querySelector('.r-name').textContent = e.name;
    row.querySelector('.r-sub').textContent = e.sub || '';
    row.addEventListener('click', () => {
      document.querySelectorAll('.row').forEach((r) => r.classList.remove('sel'));
      row.classList.add('sel');
      selectedRef = { vaultKey: e.vaultKey, index: e.index };
    });
    list.appendChild(row);
  }
}

$('save-search').addEventListener('input', (e) => {
  const q = e.target.value.trim().toLowerCase();
  const filtered = (state.entries || []).filter(
    (x) => !q || x.name.toLowerCase().includes(q) || (x.sub || '').toLowerCase().includes(q) || (x.space || '').toLowerCase().includes(q)
  );
  renderEntries(filtered);
});

$('save-new-toggle').addEventListener('click', () => {
  $('new-entry').classList.toggle('hidden');
});

$('save-back').addEventListener('click', () => boot());
$('save-cancel').addEventListener('click', () => boot());
$('done-close').addEventListener('click', () => boot());

$('save-confirm').addEventListener('click', async () => {
  $('save-error').classList.add('hidden');
  const newMode = !$('new-entry').classList.contains('hidden') &&
    ($('new-name').value.trim() || selectedRef === null);
  let ref = null;
  let newEntry = null;

  if (newMode) {
    const name = $('new-name').value.trim();
    if (!name) { $('save-error').textContent = 'Give the new entry a name.'; $('save-error').classList.remove('hidden'); return; }
    newEntry = {
      type: 'password',
      name,
      username: $('new-user').value.trim() || '',
      space: $('new-space').value.trim() || '',
    };
  } else {
    if (!selectedRef) { $('save-error').textContent = 'Pick an entry to save to.'; $('save-error').classList.remove('hidden'); return; }
    ref = selectedRef;
  }

  const r = await send({ type: 'save-passkey', ref, newEntry });
  if (!r.ok) {
    $('save-error').textContent = r.error || 'Save failed.';
    $('save-error').classList.remove('hidden');
    return;
  }
  $('done-entry').textContent = 'Saved to ' + (r.entryName || 'entry');
  show('view-done');
});

// ── Manage ───────────────────────────────────────────────────────────────────
// List / rename / delete saved passkeys (talks to the bridge; the vault stays
// in the APM app).
let managePasskeys = [];
let manageDel = null; // credentialId waiting for confirm

$('status-manage').addEventListener('click', () => openManage());
$('manage-back').addEventListener('click', () => boot());

async function openManage() {
  manageDel = null;
  $('manage-search').value = '';
  $('manage-error').classList.add('hidden');
  $('manage-count').textContent = '';
  show('view-manage');
  $('manage-list').innerHTML = '<div class="empty">Loading passkeys…</div>';
  const r = await send({ type: 'list-passkeys' });
  if (!r.payload || !r.payload.ok) {
    $('manage-error').textContent =
      (r.payload && r.payload.error) || 'Unlock the APM app to manage passkeys.';
    $('manage-error').classList.remove('hidden');
    $('manage-list').innerHTML = '';
    return;
  }
  managePasskeys = r.payload.passkeys || [];
  renderManage();
}

function renderManage() {
  const q = $('manage-search').value.trim().toLowerCase();
  const list = managePasskeys.filter(
    (p) =>
      !q ||
      (p.rpId || '').toLowerCase().includes(q) ||
      (p.userName || '').toLowerCase().includes(q) ||
      (p.label || '').toLowerCase().includes(q) ||
      (p.entryName || '').toLowerCase().includes(q)
  );
  $('manage-count').textContent = list.length ? list.length + ' saved' : '';
  const el = $('manage-list');
  el.innerHTML = '';
  if (list.length === 0) {
    const d = document.createElement('div');
    d.className = 'empty';
    d.textContent = q ? 'No matching passkeys.' : 'No passkeys saved yet.';
    el.appendChild(d);
    return;
  }
  for (const p of list) {
    const row = document.createElement('div');
    row.className = 'm-row' + (manageDel === p.credentialId ? ' confirming' : '');
    row.innerHTML =
      '<div class="m-ico">🔑</div>' +
      '<div class="m-body"></div>' +
      '<div class="m-actions"></div>';
    const body = row.querySelector('.m-body');
    const actions = row.querySelector('.m-actions');

    if (manageDel === p.credentialId) {
      body.innerHTML = '<div class="m-title"></div><div class="m-sub"></div>';
      body.querySelector('.m-title').textContent = 'Delete this passkey?';
      // textContent only — rpId/entryName are user-controlled vault data.
      body.querySelector('.m-sub').textContent =
        (p.rpId || 'unknown site') + ' · ' + (p.entryName || '');
      const yes = document.createElement('button');
      yes.className = 'm-btn danger';
      yes.textContent = 'Delete';
      yes.addEventListener('click', async () => {
        const rr = await send({ type: 'remove-passkey', credentialId: p.credentialId });
        manageDel = null;
        if (rr.payload && rr.payload.ok) {
          managePasskeys = managePasskeys.filter((x) => x.credentialId !== p.credentialId);
          $('manage-error').classList.add('hidden');
        } else {
          $('manage-error').textContent = (rr.payload && rr.payload.error) || 'Delete failed.';
          $('manage-error').classList.remove('hidden');
        }
        renderManage();
      });
      const no = document.createElement('button');
      no.className = 'm-btn';
      no.textContent = 'Keep';
      no.addEventListener('click', () => { manageDel = null; renderManage(); });
      actions.append(yes, no);
      el.appendChild(row);
      continue;
    }

    body.innerHTML =
      '<div class="m-title"></div>' +
      '<div class="m-sub"></div>';
    body.querySelector('.m-title').textContent = p.label || p.userName || p.rpId || 'Passkey';
    body.querySelector('.m-sub').textContent =
      (p.rpId || 'unknown site') + (p.entryName ? ' · ' + p.entryName : '');

    const edit = document.createElement('button');
    edit.className = 'm-btn icon';
    edit.title = 'Rename';
    edit.textContent = '✎';
    edit.addEventListener('click', () => {
      const cur = p.label || p.userName || '';
      body.innerHTML =
        '<div class="m-edit-row">' +
        '<input class="m-input" type="text" maxlength="120" />' +
        '<button class="m-btn primary">Save</button>' +
        '<button class="m-btn">Cancel</button>' +
        '</div>';
      const input = body.querySelector('.m-input');
      input.value = cur;
      input.focus();
      const finish = async (save) => {
        if (save) {
          const label = input.value.trim();
          if (label) {
            const rr = await send({ type: 'rename-passkey', credentialId: p.credentialId, label });
            if (rr.payload && rr.payload.ok) p.label = label;
            else {
              $('manage-error').textContent = (rr.payload && rr.payload.error) || 'Rename failed.';
              $('manage-error').classList.remove('hidden');
            }
          }
        }
        renderManage();
      };
      body.querySelector('.m-btn.primary').addEventListener('click', () => finish(true));
      body.querySelector('.m-btn:last-child').addEventListener('click', () => finish(false));
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') finish(true);
        if (e.key === 'Escape') finish(false);
      });
    });
    const del = document.createElement('button');
    del.className = 'm-btn icon danger';
    del.title = 'Delete';
    del.textContent = '🗑';
    del.addEventListener('click', () => { manageDel = p.credentialId; renderManage(); });
    actions.append(edit, del);
    el.appendChild(row);
  }
}

$('manage-search').addEventListener('input', renderManage);

boot();
