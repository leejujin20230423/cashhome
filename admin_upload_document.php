<?php

declare(strict_types=1);

/**
 * admin_upload_document.php
 * - 관리자(로그인) 전용: 관리자 추가 서류 업로드 API
 * - document_upload.php(대출자 제출)와 동일한 저장 로직(DocumentUploader) 사용
 */

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

session_start();

header('Content-Type: application/json; charset=utf-8');
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

const ADMIN_SESSION_TTL = 7200;

// ===== DB 설정(프로젝트 기존과 동일) =====
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

function respond(bool $ok, string $message, array $extra = []): void
{
    echo json_encode(array_merge(['ok' => $ok, 'message' => $message], $extra), JSON_UNESCAPED_UNICODE);
    exit;
}

function is_admin_authed(): bool
{
    if (empty($_SESSION['cashhome_admin_authed']) || empty($_SESSION['cashhome_admin_authed_at'])) return false;
    if ((time() - (int)$_SESSION['cashhome_admin_authed_at']) > ADMIN_SESSION_TTL) return false;
    return true;
}

function pdo(): PDO
{
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    return new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

if (!is_admin_authed()) {
    respond(false, '권한이 없습니다. 다시 로그인 해주세요.');
}

$csrf = (string)($_POST['csrf_token'] ?? '');
if (empty($_SESSION['csrf_token_admin_upload']) || !hash_equals((string)$_SESSION['csrf_token_admin_upload'], $csrf)) {
    respond(false, '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.');
}

$inquiryId = (int)($_POST['inquiry_id'] ?? 0);
if ($inquiryId <= 0) {
    respond(false, '잘못된 요청입니다.');
}

// files[]
$files = $_FILES['files'] ?? null;
if (!$files || !isset($files['tmp_name'])) {
    respond(false, '업로드 파일이 없습니다.');
}

// normalize multi-file
$items = [];
if (is_array($files['tmp_name'])) {
    $n = count($files['tmp_name']);
    for ($i = 0; $i < $n; $i++) {
        $items[] = [
            'name' => $files['name'][$i] ?? 'camera.jpg',
            'type' => $files['type'][$i] ?? '',
            'tmp_name' => $files['tmp_name'][$i] ?? '',
            'error' => $files['error'][$i] ?? UPLOAD_ERR_NO_FILE,
            'size' => $files['size'][$i] ?? 0,
        ];
    }
} else {
    $items[] = $files;
}

require_once __DIR__ . '/lib/Storage/LocalStorageAdapter.php';
require_once __DIR__ . '/lib/DocumentUploader.php';

try {
    $pdo = pdo();

    // inquiry 존재 확인
    $st = $pdo->prepare('SELECT cashhome_1000_id FROM cashhome_1000_inquiries WHERE cashhome_1000_id = :id LIMIT 1');
    $st->execute([':id' => $inquiryId]);
    if (!$st->fetch()) {
        respond(false, '대상이 존재하지 않습니다.');
    }

    $publicBaseUrl = 'https://cashhome.bizstore.co.kr/uploads';

    $storage = new LocalStorageAdapter(
        __DIR__ . '/uploads',
        $publicBaseUrl
    );

    $uploader = new DocumentUploader($pdo, $storage);

    $saved = [];
    $sort = 1;
    foreach ($items as $f) {
        if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) continue;
        $saved[] = $uploader->handleUploadedFile($inquiryId, $f, 'admin_extra', $sort++);
    }

    if (!$saved) {
        respond(false, '저장된 파일이 없습니다.');
    }

    // CSRF 갱신
    $_SESSION['csrf_token_admin_upload'] = bin2hex(random_bytes(32));

    respond(true, '업로드 완료', [
        'saved_count' => count($saved),
        'csrf_token' => $_SESSION['csrf_token_admin_upload'],
    ]);
} catch (Throwable $e) {
    error_log('[ADMIN_UPLOAD_DOC] ' . $e->getMessage());
    respond(false, '업로드 중 오류가 발생했습니다.');
}
