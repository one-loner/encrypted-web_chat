<?php
declare(strict_types=1);

/*
 * Замените эти значения на собственные.
 */
const ADMIN_LOGIN = 'admin';
const ADMIN_PASSWORD = 'admin';

const USERS_FILE = __DIR__ . '/private/users.txt';
const LOCK_FILE = __DIR__ . '/private/users.txt.lock';

$isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

session_set_cookie_params([
    'httponly' => true,
    'secure'   => $isHttps,
    'samesite' => 'Strict',
]);

session_start();

if (!isset($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
}

function redirectToSelf(): void
{
    header('Location: admin.php');
    exit;
}

function setFlash(string $message, string $type = 'success'): void
{
    $_SESSION['flash'] = [
        'message' => $message,
        'type' => $type,
    ];
}

function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function validateUsername(string $username): string
{
    $username = trim($username);

    if (
        $username === ''
        || strlen($username) > 64
        || preg_match('//u', $username) !== 1
        || preg_match('/[:\x00-\x1F\x7F]/', $username)
    ) {
        throw new InvalidArgumentException(
            'Логин должен содержать не более 64 байт и не содержать двоеточие или управляющие символы.'
        );
    }

    return $username;
}

/**
 * Разбирает файл формата логин:хэш.
 */
function parseUsers(string $contents): array
{
    $users = [];
    $lines = preg_split('/\r\n|\n|\r/', $contents);

    if ($lines === false) {
        throw new RuntimeException('Не удалось разобрать файл пользователей.');
    }

    foreach ($lines as $line) {
        if ($line === '') {
            continue;
        }

        $separator = strpos($line, ':');

        if ($separator === false) {
            throw new RuntimeException('Файл users.txt содержит строку неверного формата.');
        }

        $username = substr($line, 0, $separator);
        $hash = substr($line, $separator + 1);

        if ($username === '' || $hash === '' || isset($users[$username])) {
            throw new RuntimeException('Файл users.txt содержит некорректные или повторяющиеся записи.');
        }

        $users[$username] = $hash;
    }

    return $users;
}

/**
 * Выполняет callback, заблокировав файл блокировки.
 */
function withLock(int $mode, callable $callback)
{
    $directory = dirname(USERS_FILE);

    if (!is_dir($directory) || !is_writable($directory)) {
        throw new RuntimeException('Папка private не найдена или недоступна для записи.');
    }

    $lock = fopen(LOCK_FILE, 'c');

    if ($lock === false) {
        throw new RuntimeException('Не удалось открыть файл блокировки.');
    }

    try {
        @chmod(LOCK_FILE, 0600);

        if (!flock($lock, $mode)) {
            throw new RuntimeException('Не удалось заблокировать файл пользователей.');
        }

        return $callback();
    } finally {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

function readUsers(): array
{
    return withLock(LOCK_SH, static function (): array {
        if (!is_file(USERS_FILE)) {
            return [];
        }

        $contents = file_get_contents(USERS_FILE);

        if ($contents === false) {
            throw new RuntimeException('Не удалось прочитать файл пользователей.');
        }

        return parseUsers($contents);
    });
}

/**
 * Меняет список пользователей и сохраняет его через временный файл.
 */
function updateUsers(callable $callback): void
{
    withLock(LOCK_EX, static function () use ($callback): void {
        $contents = is_file(USERS_FILE) ? file_get_contents(USERS_FILE) : '';

        if ($contents === false) {
            throw new RuntimeException('Не удалось прочитать файл пользователей.');
        }

        $users = parseUsers($contents);
        $callback($users);

        $newContents = '';

        foreach ($users as $username => $hash) {
            $newContents .= $username . ':' . $hash . PHP_EOL;
        }

        $temporaryFile = tempnam(dirname(USERS_FILE), 'users-');

        if ($temporaryFile === false) {
            throw new RuntimeException('Не удалось создать временный файл.');
        }

        try {
            if (file_put_contents($temporaryFile, $newContents, LOCK_EX) === false) {
                throw new RuntimeException('Не удалось записать файл пользователей.');
            }

            @chmod($temporaryFile, 0600);

            if (!rename($temporaryFile, USERS_FILE)) {
                throw new RuntimeException('Не удалось сохранить файл пользователей.');
            }

            @chmod(USERS_FILE, 0600);
        } finally {
            if (is_file($temporaryFile)) {
                unlink($temporaryFile);
            }
        }
    });
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postedCsrf = (string)($_POST['csrf'] ?? '');

    if (!hash_equals((string)$_SESSION['csrf'], $postedCsrf)) {
        setFlash('Проверка формы не пройдена. Обновите страницу и попробуйте снова.', 'error');
        redirectToSelf();
    }

    $action = (string)($_POST['action'] ?? '');

    if ($action === 'login') {
        $login = (string)($_POST['login'] ?? '');
        $password = (string)($_POST['password'] ?? '');

        if (hash_equals(ADMIN_LOGIN, $login) && hash_equals(ADMIN_PASSWORD, $password)) {
            session_regenerate_id(true);
            $_SESSION['admin_authenticated'] = true;
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            setFlash('Вы вошли в панель управления.');
        } else {
            setFlash('Неверный логин или пароль.', 'error');
        }

        redirectToSelf();
    }

    if (empty($_SESSION['admin_authenticated'])) {
        setFlash('Сначала войдите в панель управления.', 'error');
        redirectToSelf();
    }

    try {
        if ($action === 'logout') {
            unset($_SESSION['admin_authenticated']);
            session_regenerate_id(true);
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            setFlash('Вы вышли из панели управления.');
        } elseif ($action === 'add') {
            $username = validateUsername((string)($_POST['username'] ?? ''));
            $password = (string)($_POST['password'] ?? '');
            $passwordConfirm = (string)($_POST['password_confirm'] ?? '');

            if (strlen($password) < 8) {
                throw new InvalidArgumentException('Пароль должен содержать не менее 8 байт.');
            }

            if (!hash_equals($password, $passwordConfirm)) {
                throw new InvalidArgumentException('Пароли не совпадают.');
            }

            updateUsers(static function (array &$users) use ($username, $password): void {
                if (isset($users[$username])) {
                    throw new InvalidArgumentException('Пользователь с таким логином уже существует.');
                }

                $users[$username] = password_hash($password, PASSWORD_DEFAULT);
            });

            setFlash('Пользователь добавлен.');
        } elseif ($action === 'change_password') {
            $username = validateUsername((string)($_POST['username'] ?? ''));
            $password = (string)($_POST['password'] ?? '');
            $passwordConfirm = (string)($_POST['password_confirm'] ?? '');

            if (strlen($password) < 8) {
                throw new InvalidArgumentException('Пароль должен содержать не менее 8 байт.');
            }

            if (!hash_equals($password, $passwordConfirm)) {
                throw new InvalidArgumentException('Пароли не совпадают.');
            }

            updateUsers(static function (array &$users) use ($username, $password): void {
                if (!isset($users[$username])) {
                    throw new InvalidArgumentException('Пользователь не найден.');
                }

                $users[$username] = password_hash($password, PASSWORD_DEFAULT);
            });

            setFlash('Пароль изменён.');
        } elseif ($action === 'delete') {
            $username = validateUsername((string)($_POST['username'] ?? ''));

            updateUsers(static function (array &$users) use ($username): void {
                if (!isset($users[$username])) {
                    throw new InvalidArgumentException('Пользователь не найден.');
                }

                unset($users[$username]);
            });

            setFlash('Пользователь удалён.');
        } else {
            setFlash('Неизвестное действие.', 'error');
        }
    } catch (InvalidArgumentException $exception) {
        setFlash($exception->getMessage(), 'error');
    } catch (Throwable $exception) {
        error_log((string)$exception);
        setFlash('Не удалось выполнить операцию. Проверьте файл users.txt и права доступа.', 'error');
    }

    redirectToSelf();
}

$authenticated = !empty($_SESSION['admin_authenticated']);
$flash = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);

$users = [];
$loadError = null;

if ($authenticated) {
    try {
        $users = readUsers();
    } catch (Throwable $exception) {
        error_log((string)$exception);
        $loadError = 'Не удалось прочитать users.txt. Проверьте его формат и права доступа.';
    }
}
?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Управление пользователями</title>
    <link rel="stylesheet" href="styles.css">
    <link rel="icon" type="image/png" href="favicon.png">
</head>
<body>
<main class="admin">
    <h1>Управление пользователями</h1>

    <?php if ($flash): ?>
        <p class="message <?= h($flash['type']) ?>">
            <?= h($flash['message']) ?>
        </p>
    <?php endif; ?>

    <?php if (!$authenticated): ?>
        <form method="post" class="login-form">
            <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="login">

            <label>
                Логин администратора
                <input type="text" name="login" autocomplete="username" required>
            </label>

            <label>
                Пароль администратора
                <input type="password" name="password" autocomplete="current-password" required>
            </label>

            <button type="submit">Войти</button>
        </form>
    <?php else: ?>
        <form method="post" class="logout-form">
            <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
            <input type="hidden" name="action" value="logout">
            <button type="submit">Выйти</button>
        </form>

        <?php if ($loadError): ?>
            <p class="message error"><?= h($loadError) ?></p>
        <?php else: ?>
            <section>
                <h2>Пользователи</h2>

                <button type="button" id="open-add-dialog">
                    Добавить пользователя
                </button>

                <?php if (!$users): ?>
                    <p>Пользователей пока нет.</p>
                <?php else: ?>
                    <ul class="user-list">
                        <?php foreach ($users as $username => $hash): ?>
                            <li class="user-card">
                                <button
                                    type="button"
                                    class="user-open"
                                    data-username="<?= h($username) ?>"
                                >
                                    <?= h($username) ?>
                                </button>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                <?php endif; ?>
            </section>

            <dialog id="add-dialog" class="admin-dialog">
                <h2>Добавить пользователя</h2>

                <form method="post">
                    <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
                    <input type="hidden" name="action" value="add">

                    <label>
                        Логин
                        <input type="text" name="username" maxlength="64" required>
                    </label>

                    <label>
                        Пароль
                        <input
                            type="password"
                            name="password"
                            minlength="8"
                            autocomplete="new-password"
                            required
                        >
                    </label>

                    <label>
                        Подтвердите пароль
                        <input
                            type="password"
                            name="password_confirm"
                            minlength="8"
                            autocomplete="new-password"
                            required
                        >
                    </label>

                    <div class="dialog-actions">
                        <button type="submit">Создать</button>
                        <button type="button" class="close-dialog">Отмена</button>
                    </div>
                </form>
            </dialog>

            <dialog id="user-dialog" class="admin-dialog">
                <h2>Пользователь: <span id="selected-username"></span></h2>

                <form method="post" class="change-password-form">
                    <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
                    <input type="hidden" name="action" value="change_password">
                    <input type="hidden" name="username" id="change-username">

                    <label>
                        Новый пароль
                        <input
                            type="password"
                            name="password"
                            minlength="8"
                            autocomplete="new-password"
                            required
                        >
                    </label>

                    <label>
                        Подтвердите новый пароль
                        <input
                            type="password"
                            name="password_confirm"
                            minlength="8"
                            autocomplete="new-password"
                            required
                        >
                    </label>

                    <div class="dialog-actions">
                        <button type="submit">Изменить пароль</button>
                        <button type="button" class="close-dialog">Отмена</button>
                    </div>
                </form>

                <form method="post" onsubmit="return confirm('Удалить пользователя?');">
                    <input type="hidden" name="csrf" value="<?= h($_SESSION['csrf']) ?>">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="username" id="delete-username">

                    <button type="submit" class="delete-button">
                        Удалить пользователя
                    </button>
                </form>
            </dialog>
        <?php endif; ?>
    <?php endif; ?>
</main>

<script>
    const addDialog = document.getElementById('add-dialog');
    const userDialog = document.getElementById('user-dialog');

    document.getElementById('open-add-dialog')?.addEventListener('click', () => {
        addDialog.showModal();
    });

    document.querySelectorAll('.user-open').forEach((button) => {
        button.addEventListener('click', () => {
            const username = button.dataset.username;

            document.getElementById('selected-username').textContent = username;
            document.getElementById('change-username').value = username;
            document.getElementById('delete-username').value = username;

            userDialog.showModal();
        });
    });

    document.querySelectorAll('.close-dialog').forEach((button) => {
        button.addEventListener('click', () => {
            button.closest('dialog').close();
        });
    });

    document.querySelectorAll('dialog').forEach((dialog) => {
        dialog.addEventListener('click', (event) => {
            if (event.target === dialog) {
                dialog.close();
            }
        });
    });
</script>
</body>
</html>
