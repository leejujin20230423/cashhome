<?php

/**
 * ===========================
 * 파일명: upload_document.php
 * 역할: 파일 업로드(JSON) + 업로드 성공 직후 메일 발송
 * ✅ 세션쿠키 옵션 통일(가장 중요): fetch 업로드에서도 세션 유지
 * ===========================
 */

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');

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

    if (session_status() !== PHP_SESSION_ACTIVE) session_start();
}
cashhome_boot_session();

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

function safe_mime(string $path, string $fallback = 'application/octet-stream'): string
{
    if (!is_file($path)) return $fallback;
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if (!$finfo) return $fallback;
    $type = finfo_file($finfo, $path);
    finfo_close($finfo);
    return $type ?: $fallback;
}

function build_saved_urls_text(array $saved): string
{
    $lines = [];
    foreach ($saved as $i => $row) {
        $url = '';
        if (is_array($row)) {
            $url = (string)($row['public_url'] ?? $row['url'] ?? $row['file_url'] ?? '');
        }
        if ($url !== '') {
            $n = $i + 1;
            $lines[] = "- 파일 {$n}: {$url}";
        }
    }
    return implode("\n", $lines);
}

// debug
if (!empty($_GET['debug_env'])) {
    respond(true, 'env', [
        'session_id' => session_id(),
        'cookie' => $_SERVER['HTTP_COOKIE'] ?? '(no cookie)',
        'session' => [
            'cashhome_doc_upload_inquiry_id' => $_SESSION['cashhome_doc_upload_inquiry_id'] ?? null,
            'cashhome_doc_upload_token' => $_SESSION['cashhome_doc_upload_token'] ?? null,
        ],
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'post_max_size' => ini_get('post_max_size'),
    ]);
}

$inquiryId = (int)($_POST['inquiry_id'] ?? 0);
$sessionInquiryId = (int)($_SESSION['cashhome_doc_upload_inquiry_id'] ?? 0);

if ($inquiryId < 1 || $sessionInquiryId !== $inquiryId) {
    respond(false, '접수 정보가 확인되지 않습니다.(세션 만료/쿠키 차단)', [
        'inquiry_id' => $inquiryId,
        'session_inquiry_id' => $sessionInquiryId,
        'session_id' => session_id(),
        'cookie' => $_SERVER['HTTP_COOKIE'] ?? '(no cookie)',
    ], 401);
}

$docType = (string)($_POST['doc_type'] ?? 'etc');

if (empty($_FILES['files'])) {
    respond(false, '업로드 파일이 없습니다.', ['_FILES_keys' => array_keys($_FILES)], 400);
}

$files = $_FILES['files'];
$count = is_array($files['name'] ?? null) ? count($files['name']) : 0;
if ($count < 1) respond(false, '업로드 파일이 없습니다.', [], 400);

// ===== DB 설정 =====
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

function cashhome_pdo(): PDO
{
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    return new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

try {
    $uploadDir = __DIR__ . '/uploads';
    if (!is_dir($uploadDir)) @mkdir($uploadDir, 0755, true);
    if (!is_dir($uploadDir)) respond(false, 'uploads 폴더가 없습니다(생성 실패).', ['path' => $uploadDir], 500);
    if (!is_writable($uploadDir)) respond(false, 'uploads 폴더에 쓰기 권한이 없습니다.', ['path' => $uploadDir], 500);

    $pdo = cashhome_pdo();

    require_once __DIR__ . '/lib/Storage/LocalStorageAdapter.php';
    require_once __DIR__ . '/lib/DocumentUploader.php';
    require_once __DIR__ . '/mail_sender.php';

    $isHttps =
        (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');

    $scheme = $isHttps ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    $basePath = rtrim(str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/')), '/');
    $publicBaseUrl = $scheme . $host . ($basePath ? $basePath : '') . '/uploads';

    $storage = new LocalStorageAdapter(
        baseDir: __DIR__ . '/uploads',
        publicBaseUrl: $publicBaseUrl
    );
    $uploader = new DocumentUploader($pdo, $storage);

    $saved = [];

    // 첨부(20MB)
    $attachments = [];
    $maxAttachBytes = 20 * 1024 * 1024;
    $attachBytes = 0;
    $skippedForSize = 0;

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

        $size = (int)$file['size'];
        if ($size > 0 && ($attachBytes + $size) <= $maxAttachBytes) {
            $bin = @file_get_contents($file['tmp_name']);
            if ($bin !== false) {
                $mime = $file['type'] !== '' ? $file['type'] : safe_mime($file['tmp_name']);
                $safeName = $file['name'] !== '' ? $file['name'] : ('upload_' . ($i + 1) . '.jpg');
                $attachments[] = ['filename' => $safeName, 'mime' => $mime, 'content' => $bin];
                $attachBytes += $size;
            }
        } else {
            $skippedForSize++;
        }

        $saved[] = $uploader->handleUploadedFile($inquiryId, $file, $docType, $i + 1);
    }

    // ✅ 신청자 정보 + 랜덤 대출번호(loan_no) 조회
    $st = $pdo->prepare("
        SELECT 
            cashhome_1000_loan_no,
            cashhome_1000_customer_name,
            cashhome_1000_customer_phone
        FROM cashhome_1000_inquiries 
        WHERE cashhome_1000_id = :id 
        LIMIT 1
    ");
    $st->execute([':id' => $inquiryId]);
    $row = $st->fetch();

    $loanNo = (string)($row['cashhome_1000_loan_no'] ?? '');
    $name   = (string)($row['cashhome_1000_customer_name'] ?? '');
    $phone  = (string)($row['cashhome_1000_customer_phone'] ?? '');
    $token  = (string)($_SESSION['cashhome_doc_upload_token'] ?? '');

    // ✅ 표시용 접수번호: loan_no 우선, 없으면 기존 PK로 fallback
    // ✅ 표시용 접수번호: loan_no 뒤 4자리만, 없으면 기존 PK fallback
    if ($loanNo !== '') {
        $displayNo = substr($loanNo, -4);  // ← 여기 핵심
    } else {
        $displayNo = "#{$inquiryId}";
    }

    $mailOk = false;
    $mailErr = '';

    // ✅ 이메일 중복 발송 방지
    // - 업로드 알림 메일은 index.php?action=upload_notice 에서 1회만 발송합니다.
    // - 여기(upload_document.php)에서는 메일을 발송하지 않습니다.
    $mailOk = false;
    $mailErr = 'disabled (send from index.php upload_notice only)';

    respond(true, '업로드 완료', [
        'saved' => $saved,
        'mail' => [
            'ok' => $mailOk,
            'error' => $mailErr,
            'attached_count' => count($attachments),
            'skipped_for_size' => $skippedForSize,
            'attach_total_kb' => (int)round($attachBytes / 1024),
        ],
        'inquiry' => [
            'inquiry_id' => $inquiryId,
            'loan_no' => $loanNo,
            'display_no' => $displayNo,
        ],
    ]);
} catch (Throwable $e) {
    error_log('[UPLOAD_DOC_ERROR] ' . $e->getMessage());
    respond(false, '서류 업로드 중 오류 발생', [
        'real_error' => $e->getMessage(),
        'where' => $e->getFile() . ':' . $e->getLine(),
    ], 500);
}
