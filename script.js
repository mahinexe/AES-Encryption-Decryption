'use strict';
/* ---------- Crypto utilities (no UI code) ---------- */
const IV_BYTES = 12;
const TAG_BYTES = 16;
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });

class AppError extends Error {}

const generateRandomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));
const generateAESKey = (bits) => generateRandomBytes(bits / 8);
const generateIV = () => generateRandomBytes(IV_BYTES);
const utf8ToBytes = (t) => enc.encode(t);
const bytesToUtf8 = (b) => dec.decode(b);

function arrayBufferToBase64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function base64ToArrayBuffer(b64) {
  const clean = b64.replace(/\s+/g, '');
  if (!clean || !/^[A-Za-z0-9+/]*={0,2}$/.test(clean) || clean.length % 4 === 1) throw new AppError('Invalid Base64 data. Please check your input.');
  try {
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch { throw new AppError('Invalid Base64 data. Please check your input.'); }
}

const importKey = (key) => crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

async function aesEncrypt(plaintext, key, iv) {
  return new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
    await importKey(key),
    utf8ToBytes(plaintext),
  ));
}

async function aesDecrypt(ciphertext, key, iv) {
  if (ciphertext.length < TAG_BYTES) throw new AppError('Invalid ciphertext. Please make sure the encrypted data is complete.');
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: TAG_BYTES * 8 },
      await importKey(key),
      ciphertext,
    ));
  } catch { throw new AppError('Decryption failed authentication. The key, IV, or ciphertext may be incorrect or tampered with.'); }
  try { return bytesToUtf8(plain); }
  catch { throw new AppError('The decrypted data is not valid UTF-8. Please verify the key and ciphertext.'); }
}

/* ---------- Validation ---------- */
function parseKey(b64) {
  const k = base64ToArrayBuffer(b64);
  if (![16, 24, 32].includes(k.length)) throw new AppError('Invalid AES key. AES keys must be 128, 192, or 256 bits.');
  return k;
}
function parseIV(b64) {
  const v = base64ToArrayBuffer(b64);
  if (v.length !== IV_BYTES) throw new AppError('Invalid nonce. AES-GCM requires a 12-byte nonce.');
  return v;
}

/* ---------- UI ---------- */
const $ = (id) => document.getElementById(id);
const state = { mode: 'enc', size: 256, result: null };

function toast(msg, type = 'info') {
  const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  const text = document.createElement('span');
  text.className = 'flex-1 text-sm';
  text.textContent = `${icons[type]} ${msg}`;
  const x = document.createElement('button');
  x.type = 'button'; x.textContent = '×'; x.setAttribute('aria-label', 'Dismiss notification');
  x.className = 'px-1 text-lg leading-none muted';
  el.append(text, x);
  const close = () => { el.classList.add('out-anim'); setTimeout(() => el.remove(), 250); };
  x.addEventListener('click', close);
  $('toasts').append(el);
  setTimeout(close, 3500);
}

function showError(id, msg) { const e = $(id); e.textContent = msg; e.classList.toggle('hidden', !msg); }
const friendly = (err) => (err instanceof AppError ? err.message : 'Something went wrong. Please check your input and try again.');

function setMode(mode) {
  state.mode = mode;
  const isEnc = mode === 'enc';
  $('tabEnc').setAttribute('aria-selected', isEnc);
  $('tabDec').setAttribute('aria-selected', !isEnc);
  $('encPanel').classList.toggle('hidden', !isEnc);
  $('decPanel').classList.toggle('hidden', isEnc);
  $('encResult').classList.toggle('hidden', !(isEnc && state.result));
  $('decResult').classList.toggle('hidden', isEnc || !$('out').value);
}

function setSize(bits) {
  state.size = bits;
  document.querySelectorAll('.size-card').forEach((c) => c.setAttribute('aria-checked', c.dataset.size == bits));
  $('sizeNote').textContent = bits === 256 ? 'AES-256 provides the largest supported key size.'
    : bits === 192 ? 'AES-192 uses a 192-bit key, between AES-128 and AES-256.'
    : 'AES-128 uses a 128-bit key and is widely supported.';
}

function setBusy(btn, busy, label) {
  btn.disabled = busy;
  btn.textContent = busy ? label : btn.dataset.label;
}

function updateCount() {
  const n = [...$('plain').value].length;
  $('count').textContent = `${n.toLocaleString()} character${n === 1 ? '' : 's'}`;
}

async function handleEncrypt(e) {
  e.preventDefault();
  showError('encErr', '');
  const text = $('plain').value;
  if (!text) { showError('encErr', 'Please enter the required information.'); toast('Please enter plaintext', 'warning'); return; }
  const btn = $('encBtn');
  setBusy(btn, true, 'Encrypting...');
  try {
    const key = generateAESKey(state.size);
    const iv = generateIV();
    const ct = await aesEncrypt(text, key, iv);
    state.result = {
      algorithm: 'AES-GCM', keySize: state.size,
      ciphertext: arrayBufferToBase64(ct), iv: arrayBufferToBase64(iv), key: arrayBufferToBase64(key),
      chars: [...text].length, ctBytes: ct.length,
    };
    renderResult();
    toast('Encryption completed', 'success');
  } catch (err) { showError('encErr', friendly(err)); toast('Encryption failed', 'error'); }
  finally { setBusy(btn, false); }
}

function renderResult() {
  const r = state.result;
  $('rCt').textContent = r.ciphertext;
  $('rIv').textContent = r.iv;
  setKeyVisible(false);
  const stats = [['Key Size', `${r.keySize}-bit`], ['Plaintext Characters', r.chars.toLocaleString()], ['Ciphertext Size', `${r.ctBytes.toLocaleString()} bytes`], ['Nonce Size', `${IV_BYTES} bytes`]];
  $('stats').replaceChildren(...stats.map(([k, v]) => {
    const d = document.createElement('div'); d.className = 'rounded-lg p-3'; d.style.background = 'var(--field)';
    const dt = document.createElement('dt'); dt.className = 'text-xs muted'; dt.textContent = k;
    const dd = document.createElement('dd'); dd.className = 'mono font-semibold'; dd.textContent = v;
    d.append(dt, dd); return d;
  }));
  $('encResult').classList.remove('hidden');
  $('encResult').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function setKeyVisible(show) {
  $('rKey').textContent = show ? state.result.key : '••••••••••••••••';
  $('rKey').setAttribute('aria-label', show ? 'Encryption key' : 'Encryption key, hidden');
  $('toggleKeyOut').textContent = show ? 'Hide' : 'Show';
  $('toggleKeyOut').setAttribute('aria-pressed', show);
}

async function handleDecrypt(e) {
  e.preventDefault();
  showError('decErr', '');
  $('decResult').classList.add('hidden');
  const [ct, iv, key] = [$('ct').value.trim(), $('iv').value.trim(), $('key').value.trim()];
  if (!ct || !iv || !key) { showError('decErr', 'Please enter the required information.'); toast('Please fill in all fields', 'warning'); return; }
  const btn = $('decBtn');
  setBusy(btn, true, 'Decrypting...');
  try {
    const ctBytes = base64ToArrayBuffer(ct);
    const ivBytes = parseIV(iv);
    const keyBytes = parseKey(key);
    $('out').value = await aesDecrypt(ctBytes, keyBytes, ivBytes);
    $('decResult').classList.remove('hidden');
    toast('Decryption completed', 'success');
  } catch (err) {
    $('out').value = '';
    showError('decErr', friendly(err));
    toast(err instanceof AppError ? err.message.split('.')[0] : 'Decryption failed', 'error');
  } finally { setBusy(btn, false); }
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const t = document.createElement('textarea');
    t.value = text; t.style.position = 'fixed'; t.style.opacity = '0';
    document.body.append(t); t.select();
    const ok = document.execCommand('copy'); t.remove();
    if (!ok) { toast('Copy failed. Select the text and copy it manually.', 'error'); return false; }
  }
  if (btn) {
    const old = btn.textContent; btn.textContent = '✓ Copied';
    setTimeout(() => { btn.textContent = old; }, 1500);
  }
  return true;
}

const algoName = (r) => `AES-${r.keySize}-GCM`;
const summaryText = (r) => `AES Algorithm: ${algoName(r)}\n\nEncrypted Text:\n${r.ciphertext}\n\nNonce:\n${r.iv}\n\nKey:\n${r.key}\n`;

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('File downloaded', 'success');
}

function importData(text) {
  let d;
  try { d = JSON.parse(text); } catch { toast('Invalid encryption file.', 'error'); return; }
  try {
    if (!d || typeof d !== 'object' || d.algorithm !== 'AES-GCM' || ![128, 192, 256].includes(d.keySize)
      || [d.ciphertext, d.iv, d.key].some((v) => typeof v !== 'string')) throw new AppError('bad');
    base64ToArrayBuffer(d.ciphertext); parseIV(d.iv);
    if (parseKey(d.key).length * 8 !== d.keySize) throw new AppError('bad');
  } catch { toast('Invalid encryption file.', 'error'); return; }
  $('ct').value = d.ciphertext; $('iv').value = d.iv; $('key').value = d.key;
  showError('decErr', ''); $('out').value = '';
  setMode('dec');
  toast('Encryption data imported', 'success');
}

function readFile(file) {
  if (!file) return;
  if (file.size > 5e6) { toast('Invalid encryption file.', 'error'); return; }
  const fr = new FileReader();
  fr.onload = () => importData(String(fr.result));
  fr.onerror = () => toast('Invalid encryption file.', 'error');
  fr.readAsText(file);
}

function clearWorkspace() {
  ['plain', 'ct', 'iv', 'key', 'out'].forEach((id) => { $(id).value = ''; });
  state.result = null;
  ['encErr', 'decErr'].forEach((id) => showError(id, ''));
  $('encResult').classList.add('hidden'); $('decResult').classList.add('hidden');
  $('key').type = 'password'; $('toggleKeyIn').textContent = 'Show'; $('toggleKeyIn').setAttribute('aria-pressed', 'false');
  updateCount();
}

function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  $('themeIcon').textContent = t === 'dark' ? '☾' : '☀';
  $('themeLabel').textContent = t === 'dark' ? 'Dark' : 'Light';
}

function init() {
  if (!window.isSecureContext || !crypto?.subtle) toast('Web Crypto needs a secure context. Run via a local server (python3 -m http.server) or https.', 'warning');
  ['encBtn', 'decBtn'].forEach((id) => { $(id).dataset.label = $(id).textContent; });
  applyTheme(document.documentElement.dataset.theme || 'dark');
  setSize(256); updateCount();

  $('themeBtn').addEventListener('click', () => {
    const t = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    applyTheme(t);
    try { localStorage.setItem('aes-theme', t); } catch { /* ignore */ }
  });
  $('tabEnc').addEventListener('click', () => setMode('enc'));
  $('tabDec').addEventListener('click', () => setMode('dec'));
  $('sizes').addEventListener('click', (e) => { const c = e.target.closest('.size-card'); if (c) setSize(Number(c.dataset.size)); });
  $('plain').addEventListener('input', updateCount);
  $('clearPlain').addEventListener('click', () => { $('plain').value = ''; updateCount(); $('plain').focus(); });
  $('clearCt').addEventListener('click', () => { $('ct').value = ''; $('ct').focus(); });
  $('pasteCt').addEventListener('click', async () => {
    try { $('ct').value = (await navigator.clipboard.readText()).trim(); }
    catch { toast('Paste is not available here. Press Ctrl/Cmd + V instead.', 'info'); }
  });
  $('encForm').addEventListener('submit', handleEncrypt);
  $('decForm').addEventListener('submit', handleDecrypt);

  $('toggleKeyIn').addEventListener('click', (e) => {
    const show = $('key').type === 'password';
    $('key').type = show ? 'text' : 'password';
    e.currentTarget.textContent = show ? 'Hide' : 'Show';
    e.currentTarget.setAttribute('aria-pressed', show);
  });
  $('toggleKeyOut').addEventListener('click', () => setKeyVisible($('toggleKeyOut').getAttribute('aria-pressed') !== 'true'));

  document.querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', async () => {
    const id = b.dataset.copy;
    const value = id === 'key' ? state.result?.key : $(id).textContent;
    if (value && await copyText(value, b)) toast('Copied to clipboard', 'success');
  }));
  $('copyAll').addEventListener('click', async (e) => {
    if (state.result && await copyText(summaryText(state.result), e.currentTarget)) toast('Encryption data copied to clipboard', 'success');
  });
  $('copyOut').addEventListener('click', async (e) => {
    if (await copyText($('out').value, e.currentTarget)) toast('Copied to clipboard', 'success');
  });
  $('dlJson').addEventListener('click', () => {
    const { algorithm, keySize, ciphertext, iv, key } = state.result;
    download('aes-encryption-result.json', JSON.stringify({ algorithm, keySize, ciphertext, iv, key }, null, 2), 'application/json');
  });
  $('dlTxt').addEventListener('click', () => {
    const r = state.result;
    download('aes-encryption-result.txt', `AES Encryption Result\n=====================\n\nAlgorithm: ${algoName(r)}\n\nEncrypted Text:\n${r.ciphertext}\n\nNonce:\n${r.iv}\n\nKey:\n${r.key}\n`, 'text/plain');
  });
  $('dlOut').addEventListener('click', () => download('decrypted-text.txt', $('out').value, 'text/plain;charset=utf-8'));
  $('again').addEventListener('click', () => {
    state.result = null; $('plain').value = ''; updateCount();
    $('encResult').classList.add('hidden'); $('plain').focus();
  });
  $('clearAll').addEventListener('click', () => { clearWorkspace(); toast('Workspace cleared', 'info'); });

  $('file').addEventListener('change', (e) => { readFile(e.target.files[0]); e.target.value = ''; });
  let depth = 0;
  const hasFiles = (e) => e.dataTransfer?.types?.includes('Files');
  window.addEventListener('dragenter', (e) => { if (hasFiles(e)) { depth++; $('drop').classList.add('drop-active'); } });
  window.addEventListener('dragleave', (e) => { if (hasFiles(e) && --depth <= 0) { depth = 0; $('drop').classList.remove('drop-active'); } });
  window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault(); depth = 0; $('drop').classList.remove('drop-active');
    readFile(e.dataTransfer.files[0]);
  });

  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      (state.mode === 'enc' ? $('encForm') : $('decForm')).requestSubmit();
    } else if (e.key === 'Escape') {
      document.querySelectorAll('#toasts button').forEach((b) => b.click());
    }
  });
}

document.addEventListener('DOMContentLoaded', init);
