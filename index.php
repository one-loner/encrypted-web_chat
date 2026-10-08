<?php
declare(strict_types=1);

const DATA_DIR = __DIR__ . '/private';
const USERS_FILE = DATA_DIR . '/users.txt';
const MESSAGES_FILE = DATA_DIR . '/messages.json';

if (!is_dir(DATA_DIR)) {
    http_response_code(500);
    exit('Не найден каталог private.');
}

ini_set('session.use_cookies', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_strict_mode', '1');

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);

session_start();

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');

function jsonReply(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        $data,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

function readUserCredential(string $username): ?string
{
    $lines = is_file(USERS_FILE)
        ? file(USERS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
        : false;

    if ($lines === false) {
        throw new RuntimeException('Не удалось прочитать файл пользователей.');
    }

    foreach ($lines as $line) {
        $parts = explode(':', $line, 2);

        if (count($parts) === 2 && hash_equals($parts[0], $username)) {
            return $parts[1];
        }
    }

    return null;
}

function requireLogin(): void
{
    if (empty($_SESSION['user'])) {
        jsonReply(['error' => 'Требуется вход'], 401);
    }

    try {
        $credential = readUserCredential((string) $_SESSION['user']);
    } catch (Throwable $exception) {
        error_log((string) $exception);
        jsonReply(['error' => 'Не удалось проверить сессию'], 500);
    }

    $sessionVersion = (string) ($_SESSION['auth_version'] ?? '');

    if (
        $credential === null ||
        $sessionVersion === '' ||
        !hash_equals(hash('sha256', $credential), $sessionVersion)
    ) {
        unset($_SESSION['user'], $_SESSION['auth_version']);
        jsonReply(['error' => 'Сессия сброшена. Войдите снова.'], 401);
    }
}

function requestInput(): array
{
    static $input = null;

    if ($input === null) {
        $decoded = json_decode((string) file_get_contents('php://input'), true);
        $input = is_array($decoded) ? $decoded : [];
    }

    return $input;
}

function requestCsrfToken(): string
{
    $headerToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';

    if ($headerToken !== '') {
        return $headerToken;
    }

    return (string) (requestInput()['csrf'] ?? '');
}

function readMessages(): array
{
    if (!is_file(MESSAGES_FILE)) {
        return [];
    }

    $contents = file_get_contents(MESSAGES_FILE);

    if ($contents === false || trim($contents) === '') {
        return [];
    }

    $messages = json_decode($contents, true);

    return is_array($messages) ? $messages : [];
}

$action = $_GET['action'] ?? '';

if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!is_file(USERS_FILE)) {
        jsonReply(['error' => 'Файл пользователей не найден'], 500);
    }

    $input = requestInput();
    $username = (string) ($input['username'] ?? '');
    $password = (string) ($input['password'] ?? '');

    if (!preg_match('/^[a-zA-Z0-9_.-]{1,40}$/', $username)) {
        jsonReply(['error' => 'Неверный логин или пароль'], 401);
    }

    try {
        $credential = readUserCredential($username);
    } catch (Throwable $exception) {
        error_log((string) $exception);
        jsonReply(['error' => 'Не удалось проверить учётную запись'], 500);
    }

    if ($credential === null || !password_verify($password, explode(':', $credential, 2)[0])) {
        jsonReply(['error' => 'Неверный логин или пароль'], 401);
    }

    session_regenerate_id(true);
    $_SESSION['user'] = $username;
    $_SESSION['auth_version'] = hash('sha256', $credential);
    $_SESSION['csrf'] = bin2hex(random_bytes(32));

    jsonReply([
        'ok' => true,
        'user' => $username,
        'csrf' => $_SESSION['csrf'],
    ]);
}

if ($action === 'me' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    requireLogin();

    jsonReply([
        'user' => $_SESSION['user'],
        'csrf' => $_SESSION['csrf'],
    ]);
}

if ($action === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    requireLogin();

    $providedToken = requestCsrfToken();
    $sessionToken = (string) ($_SESSION['csrf'] ?? '');

    if ($sessionToken === '' || !hash_equals($sessionToken, $providedToken)) {
        jsonReply(['error' => 'Неверный CSRF-токен'], 403);
    }

    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();
    jsonReply(['ok' => true]);
}

if ($action === 'messages') {
    requireLogin();

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        jsonReply([
            'messages' => readMessages(),
            'csrf' => $_SESSION['csrf'],
        ]);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = requestInput();
        $providedToken = requestCsrfToken();
        $sessionToken = (string) ($_SESSION['csrf'] ?? '');

        if ($sessionToken === '' || !hash_equals($sessionToken, $providedToken)) {
            jsonReply(['error' => 'Неверный CSRF-токен'], 403);
        }

        $iv = (string) ($input['iv'] ?? '');
        $ciphertext = (string) ($input['ciphertext'] ?? '');

        if (
            $iv === '' ||
            strlen($iv) > 100 ||
            $ciphertext === '' ||
            strlen($ciphertext) > 12000000
        ) {
            jsonReply(['error' => 'Некорректные данные сообщения'], 400);
        }

        $file = fopen(MESSAGES_FILE, 'c+');

        if ($file === false || !flock($file, LOCK_EX)) {
            if (is_resource($file)) {
                fclose($file);
            }

            jsonReply(['error' => 'Не удалось открыть хранилище сообщений'], 500);
        }

        rewind($file);
        $contents = stream_get_contents($file);
        $messages = json_decode($contents ?: '[]', true);

        if (!is_array($messages)) {
            $messages = [];
        }

        $messages[] = [
            'id' => bin2hex(random_bytes(16)),
            'sender' => $_SESSION['user'],
            'createdAt' => gmdate('c'),
            'iv' => $iv,
            'ciphertext' => $ciphertext,
        ];

        $encoded = json_encode(
            $messages,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        if ($encoded === false) {
            flock($file, LOCK_UN);
            fclose($file);
            jsonReply(['error' => 'Не удалось сохранить сообщения'], 500);
        }

        rewind($file);
        ftruncate($file, 0);
        fwrite($file, $encoded);
        fflush($file);
        flock($file, LOCK_UN);
        fclose($file);

        jsonReply(['ok' => true]);
    }

    jsonReply(['error' => 'Метод не поддерживается'], 405);
}

if ($action !== '') {
    jsonReply(['error' => 'Неизвестный запрос'], 404);
}
?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Зашифрованный чат</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" type="image/png" href="favicon.png">

</head>
<body>
<main class="shell">
    <header class="brand">
        <div class="brand-icon" aria-hidden="true">✦</div>
        <div>
            <h1>Зашифрованный чат</h1>
            <p class="subtitle">Сообщения шифруются в браузере</p>
        </div>
    </header>

    <section id="loginBox" class="card login-card">
        <h2>Войти в чат</h2>
        <form id="loginForm">
            <label for="username">Логин</label>
            <input id="username" autocomplete="username" required>

            <label for="password">Пароль учётной записи</label>
            <input
                id="password"
                type="password"
                autocomplete="current-password"
                required
            >

            <label for="encryptionPassphrase">Ключевая фраза шифрования</label>
            <input
                id="encryptionPassphrase"
                type="password"
                autocomplete="off"
                minlength="12"
                required
                aria-describedby="keyHint"
            >

            <p id="keyHint" class="hint">
                Придумайте длинную фразу и запомните её. Участникам,
                которым нужно читать одни и те же сообщения, нужна одинаковая фраза.
            </p>

            <button class="primary login-submit" type="submit">
                Войти в чат
            </button><br><hr>
<button class="primary login-submit" type="button" onclick="window.location.href='mobile.html'">    Мобильная версия</button>
        </form>
    </section>

    <section id="chatBox" class="card" hidden>
        <div class="chat-header">
            <div>
                <h2 style="margin-bottom: 2px">Общий чат</h2>
                <span class="security-label">● Шифрование включено</span>
            </div>
<button id="refreshButton" class="quiet" type="button">↻ Обновить</button>

            <button id="logoutButton" class="quiet" type="button">Выйти</button>
        </div>

        <div class="chat-body">
            <div id="messages" class="messages" aria-live="polite"></div>

            <div class="divider"></div>

            <label for="message">Сообщение</label>
            <textarea
                id="message"
                maxlength="10000"
                placeholder="Напишите сообщение…"
            ></textarea>

            <input id="fileInput" type="file">

            <div class="composer-actions">
                <div class="composer-left">
                    <label class="file-button" for="fileInput">
                        <span aria-hidden="true">＋</span>
                        Прикрепить файл
                    </label>
                    <span id="selectedFile">Файл не выбран</span>
                </div>

                <button id="sendButton" class="primary" type="button">
                    Зашифровать и отправить
                </button>
            </div>

            <p class="hint">Максимальный размер файла — 5 МБ.</p>
        </div>
    </section>

    <p id="status" role="status"></p>
</main>

<script>
'use strict';

let csrfToken = '';
let cryptoKey = null;
let selectedFile = null;
let messagesPollTimer = null;
let messagesLoading = false;
let lastMessagesSignature = null;
let currentUser = '';

const MAX_FILE_SIZE = 5 * 1024 * 1024;
const PBKDF2_ITERATIONS = 600000;
const PBKDF2_SALT = new TextEncoder().encode(
    'encrypted-chat-v1-global-salt'
);

const el = id => document.getElementById(id);
const KEY_DB_NAME = 'encrypted-chat';
const KEY_STORE_NAME = 'crypto-keys';

function openKeyDb() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(KEY_DB_NAME, 1);

        request.onupgradeneeded = () => {
            request.result.createObjectStore(KEY_STORE_NAME);
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function saveCryptoKey(username, key) {
    const db = await openKeyDb();

    return new Promise((resolve, reject) => {
        const tx = db.transaction(KEY_STORE_NAME, 'readwrite');
        tx.objectStore(KEY_STORE_NAME).put(key, username);

        tx.oncomplete = () => {
            db.close();
            resolve();
        };
        tx.onerror = () => {
            db.close();
            reject(tx.error);
        };
    });
}

async function loadCryptoKey(username) {
    const db = await openKeyDb();

    return new Promise((resolve, reject) => {
        const tx = db.transaction(KEY_STORE_NAME, 'readonly');
        const request = tx.objectStore(KEY_STORE_NAME).get(username);

        request.onsuccess = () => {
            db.close();
            resolve(request.result ?? null);
        };
        request.onerror = () => {
            db.close();
            reject(request.error);
        };
    });
}

async function deleteCryptoKey(username) {
    if (!username) return;

    const db = await openKeyDb();

    return new Promise((resolve, reject) => {
        const tx = db.transaction(KEY_STORE_NAME, 'readwrite');
        tx.objectStore(KEY_STORE_NAME).delete(username);

        tx.oncomplete = () => {
            db.close();
            resolve();
        };
        tx.onerror = () => {
            db.close();
            reject(tx.error);
        };
    });
}



function base64Encode(bytes) {
    let binary = '';

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary);
}

function base64Decode(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
}

function setStatus(message = '') {
    el('status').textContent = message;
}

function showError(error) {
    setStatus(error.message || String(error));
}

async function deriveEncryptionKey(passphrase) {
    const material = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(passphrase),
        'PBKDF2',
        false,
        ['deriveKey']
    );

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: PBKDF2_SALT,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256',
        },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function api(action, options = {}) {
    const requestSessionToken = csrfToken;
    const headers = new Headers(options.headers || {});
    const requestOptions = { ...options };

    if (csrfToken) {
        headers.set('X-CSRF-Token', csrfToken);

        if ((requestOptions.method || 'GET').toUpperCase() === 'POST') {
            headers.set('Content-Type', 'application/json');

            let body = {};

            if (typeof requestOptions.body === 'string') {
                try {
                    body = JSON.parse(requestOptions.body);
                } catch {
                    body = {};
                }
            }

            requestOptions.body = JSON.stringify({
                ...body,
                csrf: csrfToken,
            });
        }
    }

    const response = await fetch(
        `?action=${encodeURIComponent(action)}`,
        {
            credentials: 'same-origin',
            ...requestOptions,
            headers,
        }
    );

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
        if (response.status === 401 && action !== 'login' && csrfToken === requestSessionToken) {
            await clearLocalChatState();
        }

        throw new Error(data.error || `Ошибка запроса (${response.status})`);
    }

    return data;
}

async function login(event) {
    event.preventDefault();
    setStatus();

    const passphrase = el('encryptionPassphrase').value;

    if (passphrase.trim().length < 12) {
        throw new Error('Ключевая фраза должна содержать не менее 12 символов.');
    }

    const result = await api('login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            username: el('username').value,
            password: el('password').value,
        }),
    });

csrfToken = result.csrf;
currentUser = result.user || el('username').value.trim();
cryptoKey = await deriveEncryptionKey(passphrase);

try {
    await saveCryptoKey(currentUser, cryptoKey);
} catch {
    setStatus('Ключ не удалось сохранить в этом браузере. После обновления потребуется ввести его снова.');
}


    el('password').value = '';
    el('encryptionPassphrase').value = '';
    el('loginBox').hidden = true;
    el('chatBox').hidden = false;

    lastMessagesSignature = null;
    await renderMessages();
    startMessagesPolling();
}

async function encryptAndSend() {
    setStatus();

    if (!cryptoKey) {
        throw new Error('Сначала войдите и введите ключевую фразу.');
    }

    const text = el('message').value;

    if (!text.trim() && !selectedFile) {
        throw new Error('Введите сообщение или выберите файл.');
    }

    let payload;

    if (selectedFile) {
        if (selectedFile.size > MAX_FILE_SIZE) {
            throw new Error('Размер файла превышает 5 МБ.');
        }

        const fileBytes = new Uint8Array(await selectedFile.arrayBuffer());

        payload = {
            kind: 'file',
            name: selectedFile.name,
            mime: selectedFile.type || 'application/octet-stream',
            data: base64Encode(fileBytes),
            text: text,
        };
    } else {
        payload = {
            kind: 'text',
            text: text,
        };
    }

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        plaintext
    );

    await api('messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            iv: base64Encode(iv),
            ciphertext: base64Encode(new Uint8Array(ciphertext)),
        }),
    });

    el('message').value = '';
    el('fileInput').value = '';
    selectedFile = null;
    el('selectedFile').textContent = 'Файл не выбран';

    await renderMessages();
}

function addTextMessage(container, text) {
    const textNode = document.createElement('div');
    textNode.className = 'message-text';
    textNode.textContent = text;
    container.appendChild(textNode);
}

function addFileLink(container, file) {
    const bytes = base64Decode(file.data);
    const blob = new Blob([bytes], {
        type: file.mime || 'application/octet-stream',
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.className = 'download-link';
    link.href = url;
    link.download = file.name || 'download';
    link.textContent = `⬇ Скачать: ${file.name || 'файл'}`;

    container.appendChild(link);
}

function startMessagesPolling() {
    stopMessagesPolling();

    messagesPollTimer = setInterval(() => {
        renderMessages().catch(showError);
    }, 2000);
}

function stopMessagesPolling() {
    if (messagesPollTimer !== null) {
        clearInterval(messagesPollTimer);
        messagesPollTimer = null;
    }
}

async function renderMessages() {
    if (!cryptoKey || el('chatBox').hidden || messagesLoading) {
        return;
    }

    messagesLoading = true;

    try {
        const result = await api('messages');

        // Получаем актуальный токен вместе со списком сообщений.
        if (result.csrf) {
            csrfToken = result.csrf;
        }

        // Пользователь мог выйти, пока выполнялся запрос.
        if (!cryptoKey || el('chatBox').hidden) {
            return;
        }

        // Не перерисовываем список, если новых сообщений нет.
        const signature = result.messages
            .map(record => record.id ?? `${record.createdAt}:${record.sender}:${record.iv}`)
            .join('|');

        if (signature === lastMessagesSignature) {
            return;
        }

        lastMessagesSignature = signature;

        const container = el('messages');
        const renderingKey = cryptoKey;
        container.replaceChildren();

        let shown = 0;

        for (const record of result.messages) {
            try {
                const plaintext = await crypto.subtle.decrypt(
                    {
                        name: 'AES-GCM',
                        iv: base64Decode(record.iv),
                    },
                    renderingKey,
                    base64Decode(record.ciphertext)
                );

                if (cryptoKey !== renderingKey || el('chatBox').hidden) {
                    return;
                }

                const decoded = new TextDecoder().decode(plaintext);
                let payload;

                try {
                    payload = JSON.parse(decoded);
                } catch {
                    payload = { kind: 'text', text: decoded };
                }

                const card = document.createElement('article');
                card.className = 'message';

                const meta = document.createElement('div');
                meta.className = 'message-meta';
                meta.textContent = `${record.sender} · ${record.createdAt}`;
                card.appendChild(meta);

                if (payload.kind === 'file') {
                    if (payload.text) {
                        addTextMessage(card, payload.text);
                    }

                    addFileLink(card, payload);
                } else {
                    addTextMessage(card, payload.text || '');
                }

                container.appendChild(card);
                shown++;
            } catch {
                // Неподходящий ключ или повреждённая запись.
            }
        }

        if (!shown) {
            const empty = document.createElement('p');
            empty.className = 'hint';
            empty.textContent = 'Пока нет сообщений, доступных с этим ключом.';
            container.appendChild(empty);
        }

        container.scrollTop = container.scrollHeight;
    } finally {
        messagesLoading = false;
    }
}

async function clearLocalChatState(username = currentUser) {
    stopMessagesPolling();

    csrfToken = '';
    cryptoKey = null;
    currentUser = '';
    selectedFile = null;
    lastMessagesSignature = null;

    el('chatBox').hidden = true;
    el('loginBox').hidden = false;
    el('messages').replaceChildren();
    el('message').value = '';
    el('password').value = '';
    el('encryptionPassphrase').value = '';
    el('fileInput').value = '';
    el('selectedFile').textContent = 'Файл не выбран';

    try {
        await deleteCryptoKey(username);
    } catch {
        // Локальная очистка интерфейса не должна зависеть от IndexedDB.
    }
}

async function logout() {
    setStatus();
    const username = currentUser;

    try {
        await api('logout', { method: 'POST' });
    } finally {
        await clearLocalChatState(username);
    }
}

async function restoreSession() {
    try {
        const result = await api('me');

        csrfToken = result.csrf || '';
        currentUser = result.user || '';

        if (!currentUser) return;

        cryptoKey = await loadCryptoKey(currentUser);

        if (!cryptoKey) {
            el('username').value = currentUser;
            setStatus('Сессия сохранена, но для расшифровки сообщений введите ключевую фразу.');
            return;
        }

        el('loginBox').hidden = true;
        el('chatBox').hidden = false;

        lastMessagesSignature = null;
        await renderMessages();
        startMessagesPolling();
    } catch {
        // Нет активной сессии или браузерное хранилище недоступно.
    }
}



el('loginForm').addEventListener('submit', event => {
    login(event).catch(showError);
});

el('sendButton').addEventListener('click', () => {
    encryptAndSend().catch(showError);
});

el('logoutButton').addEventListener('click', () => {
    logout().catch(showError);
});

el('fileInput').addEventListener('change', event => {
    selectedFile = event.target.files[0] || null;

    if (selectedFile && selectedFile.size > MAX_FILE_SIZE) {
        selectedFile = null;
        event.target.value = '';
        el('selectedFile').textContent = 'Файл не выбран';
        setStatus('Размер файла превышает 5 МБ.');
        return;
    }

    setStatus();

    el('selectedFile').textContent = selectedFile
        ? `${selectedFile.name} (${(selectedFile.size / 1024 / 1024).toFixed(2)} МБ)`
        : 'Файл не выбран';
});

// 
restoreSession().catch(showError);


</script>
<script>
el('refreshButton').addEventListener('click', async () => {
  const button = el('refreshButton');
  button.disabled = true;
  setStatus();

  try {
    await renderMessages();
  } catch (error) {
    showError(error);
  } finally {
    button.disabled = false;
  }
});
</script>

</body>
</html>
