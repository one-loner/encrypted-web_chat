let csrf = '';
let keys = [];

const $ = (id) => document.getElementById(id);

function toBase64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}

function fromBase64(text) {
  return Uint8Array.from(atob(text), c => c.charCodeAt(0));
}

async function digestHex(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function api(action, options = {}) {
  const response = await fetch(`index.php?action=${action}`, {
    credentials: 'same-origin',
    ...options,
    headers: {
      ...(options.headers || {}),
      ...(csrf ? { 'X-CSRF-Token': csrf } : {})
    }
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Ошибка запроса');
  return data;
}

async function loadKeys() {
  keys = [];
  const lines = $('keyList').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);

  for (const line of lines) {
    const raw = fromBase64(line);
    if (raw.length !== 32) throw new Error('Каждый ключ должен быть 32 байта в Base64.');
    const key = await crypto.subtle.importKey(
      'raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']
    );
    keys.push({ id: await digestHex(raw), key });
  }

  await renderMessages();
}

async function createKey() {
  const raw = crypto.getRandomValues(new Uint8Array(32));
  $('keyList').value += ($('keyList').value.trim() ? '\n' : '') + toBase64(raw);
  await loadKeys();
  alert('Сохраните ключ в безопасном месте: потерянный ключ восстановить нельзя.');
}

async function login() {
  const result = await api('login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: $('username').value,
      password: $('password').value
    })
  });
  csrf = result.csrf;
  $('loginBox').hidden = true;
  $('chatBox').hidden = false;
  await renderMessages();
}

async function sendMessage() {
  if (!keys.length) throw new Error('Сначала добавьте ключ шифрования.');

  const keyId = $('sendKey').value;
  const selected = keys.find(k => k.id === keyId);
  if (!selected) throw new Error('Выберите ключ.');

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode($('message').value);
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, selected.key, plaintext
  );

  await api('messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      keyId,
      iv: toBase64(iv),
      ciphertext: toBase64(new Uint8Array(encrypted))
    })
  });

  $('message').value = '';
  await renderMessages();
}

async function renderMessages() {
  if (!$('chatBox') || $('chatBox').hidden) return;

  const data = await api('messages');
  const usable = new Map(keys.map(k => [k.id, k]));
  const output = [];

  for (const message of data.messages) {
    const match = usable.get(message.keyId);
    if (!match) continue;

    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromBase64(message.iv) },
        match.key,
        fromBase64(message.ciphertext)
      );
      const text = new TextDecoder().decode(plaintext);
      output.push(`${message.createdAt} — ${message.sender}: ${text}`);
    } catch {
      // Неверный ключ или повреждённое сообщение: пропускаем.
    }
  }

  $('messages').textContent = output.join('\n') || 'Нет сообщений, расшифровываемых текущими ключами.';
  $('sendKey').innerHTML = keys.map(k =>
    `<option value="${k.id}">${k.id.slice(0, 12)}…</option>`
  ).join('');
}

function report(error) {
  $('status').textContent = error.message || String(error);
}

$('loginButton').onclick = () => login().catch(report);
$('addKeyButton').onclick = () => createKey().catch(report);
$('loadKeysButton').onclick = () => loadKeys().catch(report);
$('sendButton').onclick = () => sendMessage().catch(report);
