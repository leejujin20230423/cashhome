<?php
declare(strict_types=1);

/**
 * admin_doc_image.php
 * - 관리자 로그인된 상태에서만 서류 이미지 출력
 * - cashhome_1200_documents의 file_path를 읽어 디스크 파일을 전송
 */

session_start();
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

// admin_login.php와 동일 TTL로 맞추세요(여기선 admin_inquiries.php 기준)
const ADMIN_SESSION_TTL = 7200;

function cashhome_pdo(): PDO {
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;

    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function is_admin_authed(): bool {
    if (empty($_SESSION['cashhome_admin_authed']) || empty($_SESSION['cashhome_admin_authed_at'])) return false;
    if ((time() - (int)$_SESSION['cashhome_admin_authed_at']) > ADMIN_SESSION_TTL) return false;

    // IP/UA 고정(원하면 admin_login.php처럼)
    return true;
}

function safe_realpath(?string $path): ?string {
    if (!$path) return null;

    // 절대경로면 그대로
    if (str_starts_with($path, '/') || preg_match('#^[A-Za-z]:[\\\\/]#', $path)) {
        $rp = realpath($path);
        return $rp ?: null;
    }

    // 상대경로면 현재 디렉토리 기준
    $full = __DIR__ . '/' . ltrim($path, '/');
    $rp = realpath($full);
    return $rp ?: null;
}

if (!is_admin_authed()) {
    http_response_code(403);
    echo 'Forbidden';
    exit;
}

$docId = (int)($_GET['id'] ?? 0);
if ($docId <= 0) {
    http_response_code(400);
    echo 'Bad Request';
    exit;
}

try {
    $pdo = cashhome_pdo();
    $st = $pdo->prepare("
        SELECT
          cashhome_1200_id,
          cashhome_1200_file_path,
          cashhome_1200_mime
        FROM cashhome_1200_documents
        WHERE cashhome_1200_id = :id
        LIMIT 1
    ");
    $st->execute([':id' => $docId]);
    $row = $st->fetch();

    if (!$row) {
        http_response_code(404);
        echo 'Not Found';
        exit;
    }

    $mime = (string)($row['cashhome_1200_mime'] ?? 'application/octet-stream');
    $filePath = safe_realpath((string)($row['cashhome_1200_file_path'] ?? ''));

    if (!$filePath || !is_file($filePath)) {
        http_response_code(404);
        echo 'File Not Found';
        exit;
    }

    header('Content-Type: ' . $mime);
    header('Content-Length: ' . (string)filesize($filePath));
    header('Cache-Control: private, max-age=0, no-store');

    readfile($filePath);
    exit;

} catch (Throwable $e) {
    error_log('[DOC IMAGE ERROR] ' . $e->getMessage());
    http_response_code(500);
    echo 'Server Error';
    exit;
}