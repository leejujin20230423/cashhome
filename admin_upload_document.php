<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');

const ADMIN_SESSION_TTL = 7200;
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

function cashhome_boot_session(): void
{
    $isHttps = (
        (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
    );

    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    if (session_status() !== PHP_SESSION_ACTIVE) {
        session_start();
    }
}

function respond(bool $ok, string $message = '', array $data = [], int $httpCode = 200): void
{
    http_response_code($httpCode);
    echo json_encode([
        'ok' => $ok,
        'message' => $message,
        'data' => $data,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

function upload_error_message(int $code): string
{
    return match ($code) {
        UPLOAD_ERR_OK => 'OK',
        UPLOAD_ERR_INI_SIZE => '파일이 너무 큽니다(upload_max_filesize 초과)',
        UPLOAD_ERR_FORM_SIZE => '파일이 너무 큽니다(폼 MAX_FILE_SIZE 초과)',
        UPLOAD_ERR_PARTIAL => '파일이 일부만 업로드되었습니다',
        UPLOAD_ERR_NO_FILE => '파일이 없습니다',
        UPLOAD_ERR_NO_TMP_DIR => '서버 임시폴더(tmp)가 없습니다',
        UPLOAD_ERR_CANT_WRITE => '디스크에 파일을 쓸 수 없습니다(권한/용량)',
        UPLOAD_ERR_EXTENSION => 'PHP 확장에 의해 업로드가 중단되었습니다',
        default => '알 수 없는 업로드 오류 코드: ' . $code,
    };
}

function is_admin_authed(): bool
{
    if (empty($_SESSION['cashhome_admin_authed']) || empty($_SESSION['cashhome_admin_authed_at'])) {
        return false;
    }
    if ((time() - (int)$_SESSION['cashhome_admin_authed_at']) > ADMIN_SESSION_TTL) {
        return false;
    }
    return true;
}

function cashhome_pdo(): PDO
{
    return new PDO(
        'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
}

cashhome_boot_session();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    respond(false, '허용되지 않은 요청입니다.', [], 405);
}

if (!is_admin_authed()) {
    respond(false, '권한이 없습니다. 다시 로그인해주세요.', [], 403);
}

$csrfSession = (string)($_SESSION['csrf_token_admin_upload'] ?? '');
$csrfInput = (string)($_POST['csrf_token'] ?? '');
if ($csrfSession === '' || $csrfInput === '' || !hash_equals($csrfSession, $csrfInput)) {
    respond(false, '요청이 만료되었습니다. 페이지를 새로고침 후 다시 시도해주세요.', [], 419);
}

$inquiryId = (int)($_POST['inquiry_id'] ?? 0);
if ($inquiryId <= 0) {
    respond(false, '잘못된 접수번호입니다.', [], 400);
}

if (empty($_FILES['files'])) {
    respond(false, '업로드 파일이 없습니다.', ['_FILES_keys' => array_keys($_FILES)], 400);
}

$files = $_FILES['files'];
$count = is_array($files['name'] ?? null) ? count($files['name']) : 0;
if ($count < 1) {
    respond(false, '업로드 파일이 없습니다.', [], 400);
}

try {
    $uploadDir = __DIR__ . '/uploads';
    if (!is_dir($uploadDir)) {
        @mkdir($uploadDir, 0755, true);
    }
    if (!is_dir($uploadDir)) {
        respond(false, 'uploads 폴더 생성에 실패했습니다.', ['path' => $uploadDir], 500);
    }
    if (!is_writable($uploadDir)) {
        respond(false, 'uploads 폴더 쓰기 권한이 없습니다.', ['path' => $uploadDir], 500);
    }

    $pdo = cashhome_pdo();

    $chk = $pdo->prepare("SELECT COUNT(*) FROM cashhome_1000_inquiries WHERE cashhome_1000_id = :id");
    $chk->execute([':id' => $inquiryId]);
    if ((int)$chk->fetchColumn() < 1) {
        respond(false, '존재하지 않는 접수번호입니다.', ['inquiry_id' => $inquiryId], 404);
    }

    require_once __DIR__ . '/lib/Storage/StorageAdapterInterface.php';
    require_once __DIR__ . '/lib/Storage/LocalStorageAdapter.php';
    require_once __DIR__ . '/lib/DocumentUploader.php';

    $isHttps =
        (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

    $scheme = $isHttps ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $basePath = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    $publicBaseUrl = $scheme . $host . ($basePath ? $basePath : '') . '/uploads';

    $storage = new \Cashhome\Storage\LocalStorageAdapter(
        baseDir: __DIR__ . '/uploads',
        publicBaseUrl: $publicBaseUrl
    );
    $uploader = new \Cashhome\DocumentUploader($pdo, $storage);

    $saved = [];
    $sort = 1;

    for ($i = 0; $i < $count; $i++) {
        $file = [
            'name' => (string)($files['name'][$i] ?? ''),
            'type' => (string)($files['type'][$i] ?? ''),
            'tmp_name' => (string)($files['tmp_name'][$i] ?? ''),
            'error' => (int)($files['error'][$i] ?? UPLOAD_ERR_NO_FILE),
            'size' => (int)($files['size'][$i] ?? 0),
        ];

        if ($file['error'] !== UPLOAD_ERR_OK) {
            respond(false, upload_error_message($file['error']), ['index' => $i, 'name' => $file['name']], 400);
        }
        if ($file['tmp_name'] === '' || !is_uploaded_file($file['tmp_name'])) {
            respond(false, '임시 업로드 파일이 유효하지 않습니다.', ['index' => $i], 400);
        }

        $saved[] = $uploader->handleUploadedFile($inquiryId, $file, 'admin_extra', $sort++);
    }

    $_SESSION['csrf_token_admin_upload'] = bin2hex(random_bytes(32));

    respond(true, '업로드 완료', [
        'saved' => $saved,
        'count' => count($saved),
        'csrf_token' => $_SESSION['csrf_token_admin_upload'],
    ]);
} catch (Throwable $e) {
    error_log('[ADMIN_UPLOAD_DOC_ERROR] ' . $e->getMessage());
    respond(false, '관리자 서류 업로드 중 오류 발생', [
        'real_error' => $e->getMessage(),
        'where' => $e->getFile() . ':' . $e->getLine(),
    ], 500);
}

