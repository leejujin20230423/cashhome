<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

function die404(string $msg = 'Not Found'): void {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg;
    exit;
}

function die500(string $msg = 'Server Error'): void {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo $msg;
    exit;
}

// ===== DB 설정 =====
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

function cashhome_pdo(): PDO {
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    return new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

$id = (int)($_GET['id'] ?? 0);
if ($id < 1) die404('Invalid id');

try {
    $pdo = cashhome_pdo();

    // ✅ 문서 테이블에서 1건 조회
    // (컬럼명은 프로젝트마다 다를 수 있어서, 가능한 후보들을 모두 읽어보는 방식)
    $stmt = $pdo->prepare("SELECT * FROM cashhome_1200_documents WHERE cashhome_1200_id = :id LIMIT 1");
    $stmt->execute([':id' => $id]);
    $doc = $stmt->fetch();

    if (!$doc) die404('Document not found');

    // ===== 1) DB에 public URL이 저장돼 있으면 그걸로 바로 redirect =====
    $publicUrl =
        (string)($doc['cashhome_1200_file_url'] ?? '') ?:   // 예: https://.../uploads/xxx.jpg
        (string)($doc['cashhome_1200_public_url'] ?? '');

    if ($publicUrl !== '') {
        header('Location: ' . $publicUrl, true, 302);
        exit;
    }

    // ===== 2) 파일 경로/파일명으로 서버에서 직접 읽어서 내려주기 =====
    // 저장된 경로 후보들
    $relPath =
        (string)($doc['cashhome_1200_file_path'] ?? '') ?:   // 예: 2026/02/xxx.jpg
        (string)($doc['cashhome_1200_saved_path'] ?? '') ?:  // 예: uploads/2026/...
        (string)($doc['cashhome_1200_path'] ?? '') ?:        // 예: ...
        (string)($doc['cashhome_1200_storage_path'] ?? '');

    $filename =
        (string)($doc['cashhome_1200_original_name'] ?? '') ?:
        (string)($doc['cashhome_1200_file_name'] ?? '') ?:
        (string)($doc['cashhome_1200_name'] ?? 'document');

    $mime =
        (string)($doc['cashhome_1200_mime'] ?? '') ?:
        (string)($doc['cashhome_1200_file_mime'] ?? '');

    // relPath가 비어있으면 파일명을 stored_name 같은 컬럼에서 찾아보기
    if ($relPath === '') {
        $stored =
            (string)($doc['cashhome_1200_stored_name'] ?? '') ?:
            (string)($doc['cashhome_1200_saved_name'] ?? '') ?:
            (string)($doc['cashhome_1200_disk_name'] ?? '');
        if ($stored !== '') $relPath = $stored;
    }

    if ($relPath === '') {
        die404('No file path in DB');
    }

    // uploads 기준으로 파일 찾기
    $uploadsDir = __DIR__ . '/uploads';

    // DB에 uploads/로 시작할 수도 있어서 정리
    $relPath = ltrim($relPath, '/');
    if (str_starts_with($relPath, 'uploads/')) {
        $relPath = substr($relPath, strlen('uploads/'));
    }

    $fullPath = $uploadsDir . '/' . $relPath;

    if (!is_file($fullPath)) {
        die404("File not found on disk");
    }

    // mime이 없으면 추정
    if ($mime === '') {
        $mime = mime_content_type($fullPath) ?: 'application/octet-stream';
    }

    // inline 보기(이미지면 브라우저에 표시됨)
    header('Content-Type: ' . $mime);
    header('X-Content-Type-Options: nosniff');

    // 파일명 깨짐 방지
    $safeName = preg_replace('/[^\w\.\-가-힣 ]+/u', '_', $filename) ?: 'document';
    header('Content-Disposition: inline; filename="' . $safeName . '"');

    header('Content-Length: ' . filesize($fullPath));
    readfile($fullPath);
    exit;

} catch (Throwable $e) {
    error_log('[DOCUMENT_VIEW_ERROR] ' . $e->getMessage());
    die500('Server Error');
}