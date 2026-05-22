'use strict';

/* =========================================================================
 * パスワード帳 — Web Crypto API による AES-GCM 暗号化を利用したローカル保管
 * - データは localStorage に暗号文として保存
 * - マスターパスワードから PBKDF2 で鍵を導出
 * - 平文のマスターパスワード/鍵はメモリ上にのみ保持し、ロック時に破棄
 * =======================================================================*/

const STORAGE_KEY = 'password-vault-v1';
const PBKDF2_ITERATIONS = 250_000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;

const enc = new TextEncoder();
const dec = new TextDecoder();

let derivedKey = null;   // CryptoKey: 解錠中のみ保持
let currentSalt = null;  // Uint8Array
let entries = [];        // [{ id, service, username, password, url, notes, createdAt, updatedAt }]

/* ---------- ユーティリティ ---------- */

function buf2b64(buf) {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function b642buf(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function randomBytes(len) {
  return crypto.getRandomValues(new Uint8Array(len));
}

function uuid() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return 'id-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

/* ---------- 暗号化 ---------- */

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(key, plaintextObj) {
  const iv = randomBytes(IV_LENGTH);
  const data = enc.encode(JSON.stringify(plaintextObj));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );
  return { iv: buf2b64(iv), ct: buf2b64(ciphertext) };
}

async function decryptData(key, iv_b64, ct_b64) {
  const iv = b642buf(iv_b64);
  const ct = b642buf(ct_b64);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ct
  );
  return JSON.parse(dec.decode(plaintext));
}

/* ---------- 永続化 ---------- */

function loadVault() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function saveVault(vault) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
}

async function persistEntries() {
  if (!derivedKey || !currentSalt) throw new Error('未解錠');
  const { iv, ct } = await encryptData(derivedKey, entries);
  saveVault({
    version: 1,
    salt: buf2b64(currentSalt),
    iv,
    ct,
  });
}

/* ---------- 画面操作 ---------- */

const $ = (id) => document.getElementById(id);

function showToast(message, duration = 1800) {
  const toast = $('toast');
  toast.textContent = message;
  toast.style.display = 'block';
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => {
    toast.style.display = 'none';
  }, duration);
}

function setLockMessage(isFirstTime) {
  $('lock-message').textContent = isFirstTime
    ? '初回利用: マスターパスワードを設定してください'
    : 'マスターパスワードを入力してください';
  $('confirm-group').style.display = isFirstTime ? 'flex' : 'none';
  $('unlock-btn').textContent = isFirstTime ? '設定して開始' : '解除';
}

function showLockScreen() {
  derivedKey = null;
  currentSalt = null;
  entries = [];
  $('lock-screen').style.display = '';
  $('main-screen').style.display = 'none';
  $('master-password').value = '';
  $('master-password-confirm').value = '';
  $('lock-error').textContent = '';
  const vault = loadVault();
  setLockMessage(!vault);
  $('master-password').focus();
}

function showMainScreen() {
  $('lock-screen').style.display = 'none';
  $('main-screen').style.display = '';
  renderEntries();
}

/* ---------- エントリ描画 ---------- */

function escapeHtml(str) {
  if (str == null) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderEntries() {
  const list = $('entry-list');
  const empty = $('empty-message');
  const query = $('search-input').value.trim().toLowerCase();

  const filtered = entries.filter((e) => {
    if (!query) return true;
    return (
      (e.service || '').toLowerCase().includes(query) ||
      (e.username || '').toLowerCase().includes(query) ||
      (e.url || '').toLowerCase().includes(query)
    );
  });

  filtered.sort((a, b) => (a.service || '').localeCompare(b.service || '', 'ja'));

  list.innerHTML = '';

  if (entries.length === 0) {
    empty.style.display = '';
    empty.textContent = 'まだパスワードが登録されていません。「＋ 新規追加」から登録してください。';
    return;
  }
  if (filtered.length === 0) {
    empty.style.display = '';
    empty.textContent = '該当するエントリが見つかりませんでした。';
    return;
  }
  empty.style.display = 'none';

  for (const entry of filtered) {
    const card = document.createElement('div');
    card.className = 'entry-card';
    card.dataset.id = entry.id;

    const urlHtml = entry.url
      ? `<a href="${escapeHtml(entry.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(entry.url)}</a>`
      : '<span style="color:var(--muted);">—</span>';

    const notesHtml = entry.notes
      ? `<div class="entry-field"><span class="entry-field-label">メモ</span><span class="entry-field-value" style="white-space:pre-wrap;">${escapeHtml(entry.notes)}</span></div>`
      : '';

    card.innerHTML = `
      <div class="entry-card-header">
        <div class="entry-service">${escapeHtml(entry.service)}</div>
        <div class="entry-actions">
          <button type="button" class="secondary-btn small-btn" data-action="edit">✏️ 編集</button>
          <button type="button" class="danger-btn small-btn" data-action="delete">🗑 削除</button>
        </div>
      </div>
      <div class="entry-field">
        <span class="entry-field-label">ユーザー</span>
        <span class="entry-field-value">${escapeHtml(entry.username) || '<span style="color:var(--muted);">—</span>'}</span>
        ${entry.username ? '<button type="button" class="secondary-btn small-btn" data-action="copy-username">📋</button>' : ''}
      </div>
      <div class="entry-field">
        <span class="entry-field-label">パスワード</span>
        <span class="entry-field-value password-value" data-pwd-display>••••••••••</span>
        <button type="button" class="secondary-btn small-btn" data-action="toggle-password">👁</button>
        <button type="button" class="secondary-btn small-btn" data-action="copy-password">📋</button>
      </div>
      <div class="entry-field">
        <span class="entry-field-label">URL</span>
        <span class="entry-field-value">${urlHtml}</span>
      </div>
      ${notesHtml}
    `;

    card.addEventListener('click', (ev) => handleEntryAction(ev, entry));
    list.appendChild(card);
  }
}

function handleEntryAction(ev, entry) {
  const btn = ev.target.closest('button[data-action]');
  if (!btn) return;
  const action = btn.dataset.action;

  if (action === 'edit') {
    openEntryModal(entry);
  } else if (action === 'delete') {
    if (confirm(`「${entry.service}」を削除しますか？この操作は取り消せません。`)) {
      deleteEntry(entry.id);
    }
  } else if (action === 'copy-username') {
    copyToClipboard(entry.username, 'ユーザー名をコピーしました');
  } else if (action === 'copy-password') {
    copyToClipboard(entry.password, 'パスワードをコピーしました');
  } else if (action === 'toggle-password') {
    const card = btn.closest('.entry-card');
    const display = card.querySelector('[data-pwd-display]');
    if (display.dataset.shown === 'true') {
      display.textContent = '••••••••••';
      display.dataset.shown = 'false';
      btn.textContent = '👁';
    } else {
      display.textContent = entry.password;
      display.dataset.shown = 'true';
      btn.textContent = '🙈';
    }
  }
}

async function copyToClipboard(text, message) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    showToast(message || 'コピーしました');
  } catch {
    // フォールバック
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      showToast(message || 'コピーしました');
    } catch {
      showToast('コピーに失敗しました');
    }
    document.body.removeChild(ta);
  }
}

/* ---------- エントリ編集 ---------- */

function openEntryModal(entry) {
  const isEdit = !!entry;
  $('modal-title').textContent = isEdit ? '編集' : '新規追加';
  $('entry-id').value = entry?.id || '';
  $('entry-service').value = entry?.service || '';
  $('entry-username').value = entry?.username || '';
  $('entry-password').value = entry?.password || '';
  $('entry-url').value = entry?.url || '';
  $('entry-notes').value = entry?.notes || '';
  $('entry-error').textContent = '';
  $('entry-modal').style.display = 'flex';
  setTimeout(() => $('entry-service').focus(), 50);
}

function closeEntryModal() {
  $('entry-modal').style.display = 'none';
}

async function saveEntry(ev) {
  ev.preventDefault();
  const id = $('entry-id').value;
  const service = $('entry-service').value.trim();
  const username = $('entry-username').value.trim();
  const password = $('entry-password').value;
  const url = $('entry-url').value.trim();
  const notes = $('entry-notes').value;

  if (!service) {
    $('entry-error').textContent = 'サービス名を入力してください';
    return;
  }
  if (!password) {
    $('entry-error').textContent = 'パスワードを入力してください';
    return;
  }

  const now = Date.now();
  if (id) {
    const idx = entries.findIndex((e) => e.id === id);
    if (idx >= 0) {
      entries[idx] = { ...entries[idx], service, username, password, url, notes, updatedAt: now };
    }
  } else {
    entries.push({
      id: uuid(),
      service,
      username,
      password,
      url,
      notes,
      createdAt: now,
      updatedAt: now,
    });
  }

  try {
    await persistEntries();
    closeEntryModal();
    renderEntries();
    showToast(id ? '更新しました' : '追加しました');
  } catch (err) {
    console.error(err);
    $('entry-error').textContent = '保存に失敗しました: ' + err.message;
  }
}

async function deleteEntry(id) {
  entries = entries.filter((e) => e.id !== id);
  try {
    await persistEntries();
    renderEntries();
    showToast('削除しました');
  } catch (err) {
    console.error(err);
    showToast('削除の保存に失敗しました');
  }
}

/* ---------- パスワード生成 ---------- */

function generatePassword() {
  const length = Math.max(4, Math.min(128, parseInt($('gen-length').value, 10) || 16));
  const useUpper = $('gen-upper').checked;
  const useLower = $('gen-lower').checked;
  const useDigits = $('gen-digits').checked;
  const useSymbols = $('gen-symbols').checked;

  const sets = [];
  if (useUpper) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  if (useLower) sets.push('abcdefghijklmnopqrstuvwxyz');
  if (useDigits) sets.push('0123456789');
  if (useSymbols) sets.push('!@#$%^&*()-_=+[]{};:,.<>?/');

  if (sets.length === 0) {
    showToast('文字種を1つ以上選んでください');
    return;
  }

  const all = sets.join('');
  const chars = [];
  // 各文字種から最低1文字
  for (const s of sets) {
    chars.push(s[crypto.getRandomValues(new Uint32Array(1))[0] % s.length]);
  }
  while (chars.length < length) {
    chars.push(all[crypto.getRandomValues(new Uint32Array(1))[0] % all.length]);
  }
  // シャッフル (Fisher-Yates with crypto random)
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  $('entry-password').value = chars.join('');
}

/* ---------- 解錠 / 初回設定 ---------- */

async function handleUnlock(ev) {
  ev.preventDefault();
  const password = $('master-password').value;
  const errorEl = $('lock-error');
  errorEl.textContent = '';

  if (!password) {
    errorEl.textContent = 'マスターパスワードを入力してください';
    return;
  }

  const vault = loadVault();

  if (!vault) {
    // 初回登録
    const confirmPwd = $('master-password-confirm').value;
    if (password.length < 6) {
      errorEl.textContent = 'マスターパスワードは6文字以上にしてください';
      return;
    }
    if (password !== confirmPwd) {
      errorEl.textContent = '確認用パスワードが一致しません';
      return;
    }
    try {
      currentSalt = randomBytes(SALT_LENGTH);
      derivedKey = await deriveKey(password, currentSalt);
      entries = [];
      await persistEntries();
      showMainScreen();
      showToast('マスターパスワードを設定しました');
    } catch (err) {
      console.error(err);
      errorEl.textContent = '設定に失敗しました: ' + err.message;
    }
  } else {
    // 既存解錠
    try {
      const salt = b642buf(vault.salt);
      const key = await deriveKey(password, salt);
      const decrypted = await decryptData(key, vault.iv, vault.ct);
      derivedKey = key;
      currentSalt = salt;
      entries = Array.isArray(decrypted) ? decrypted : [];
      showMainScreen();
    } catch (err) {
      errorEl.textContent = 'マスターパスワードが正しくないか、データが破損しています';
    }
  }
}

/* ---------- エクスポート/インポート ---------- */

function exportVault() {
  const vault = loadVault();
  if (!vault) {
    showToast('エクスポートするデータがありません');
    return;
  }
  const blob = new Blob([JSON.stringify(vault, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  a.href = url;
  a.download = `password-vault-${stamp}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  showToast('エクスポートしました');
}

let pendingImportVault = null;

function openImportFile() {
  $('import-file').click();
}

async function handleImportFile(ev) {
  const file = ev.target.files[0];
  ev.target.value = '';
  if (!file) return;
  try {
    const text = await file.text();
    const data = JSON.parse(text);
    if (!data.salt || !data.iv || !data.ct) {
      throw new Error('ファイル形式が不正です');
    }
    pendingImportVault = data;
    $('import-password').value = '';
    $('import-error').textContent = '';
    $('import-modal').style.display = 'flex';
    setTimeout(() => $('import-password').focus(), 50);
  } catch (err) {
    showToast('ファイル読み込み失敗: ' + err.message);
  }
}

async function confirmImport(ev) {
  ev.preventDefault();
  const password = $('import-password').value;
  const errorEl = $('import-error');
  const mode = document.querySelector('input[name="import-mode"]:checked').value;

  errorEl.textContent = '';
  if (!password) {
    errorEl.textContent = 'パスワードを入力してください';
    return;
  }

  try {
    const salt = b642buf(pendingImportVault.salt);
    const key = await deriveKey(password, salt);
    const imported = await decryptData(key, pendingImportVault.iv, pendingImportVault.ct);
    if (!Array.isArray(imported)) throw new Error('データ形式が不正です');

    if (mode === 'replace') {
      entries = imported.map((e) => ({ ...e, id: e.id || uuid() }));
    } else {
      const existingIds = new Set(entries.map((e) => e.id));
      for (const e of imported) {
        const newEntry = { ...e, id: e.id && !existingIds.has(e.id) ? e.id : uuid() };
        entries.push(newEntry);
      }
    }
    await persistEntries();
    pendingImportVault = null;
    $('import-modal').style.display = 'none';
    renderEntries();
    showToast(`${imported.length}件をインポートしました`);
  } catch (err) {
    errorEl.textContent = 'インポートに失敗しました: パスワードが違うかファイルが破損しています';
  }
}

/* ---------- イベント登録 ---------- */

document.addEventListener('DOMContentLoaded', () => {
  // ロック画面
  $('unlock-form').addEventListener('submit', handleUnlock);
  $('reset-all-btn').addEventListener('click', () => {
    if (confirm('本当にすべてのデータを削除しますか？この操作は取り消せません。')) {
      localStorage.removeItem(STORAGE_KEY);
      showToast('データを削除しました');
      showLockScreen();
    }
  });

  // メイン画面
  $('lock-btn').addEventListener('click', showLockScreen);
  $('add-btn').addEventListener('click', () => openEntryModal(null));
  $('search-input').addEventListener('input', renderEntries);
  $('export-btn').addEventListener('click', exportVault);
  $('import-btn').addEventListener('click', openImportFile);
  $('import-file').addEventListener('change', handleImportFile);

  // モーダル
  $('entry-form').addEventListener('submit', saveEntry);
  $('cancel-btn').addEventListener('click', closeEntryModal);
  $('generate-password-btn').addEventListener('click', generatePassword);

  $('import-form').addEventListener('submit', confirmImport);
  $('import-cancel-btn').addEventListener('click', () => {
    $('import-modal').style.display = 'none';
    pendingImportVault = null;
  });

  // 表示切替
  document.querySelectorAll('.toggle-visibility').forEach((btn) => {
    btn.addEventListener('click', () => {
      const target = $(btn.dataset.target);
      if (!target) return;
      if (target.type === 'password') {
        target.type = 'text';
        btn.textContent = '🙈';
      } else {
        target.type = 'password';
        btn.textContent = '👁';
      }
    });
  });

  // モーダルの背景クリックで閉じる
  $('entry-modal').addEventListener('click', (e) => {
    if (e.target.id === 'entry-modal') closeEntryModal();
  });
  $('import-modal').addEventListener('click', (e) => {
    if (e.target.id === 'import-modal') {
      $('import-modal').style.display = 'none';
      pendingImportVault = null;
    }
  });

  // 初期表示
  showLockScreen();
});
