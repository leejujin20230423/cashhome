<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
session_start();

function respond(bool $ok, string $msg = '', array $data = []): void {
    echo json_encode(['ok'=>$ok,'message'=>$msg,'data'=>$data], JSON_UNESCAPED_UNICODE);
    exit;
}

$inquiryId = (int)($_POST['inquiry_id'] ?? 0);
$sessionInquiryId = (int)($_SESSION['cashhome_last_inquiry_id'] ?? 0);

if ($inquiryId < 1 || $sessionInquiryId !== $inquiryId) {
    respond(false, '접수 정보가 확인되지 않습니다.');
}

const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

function cashhome_pdo(): PDO {
    $dsn = 'mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4';
    return new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
}

try {
    $pdo = cashhome_pdo();

    require_once __DIR__.'/lib/Storage/LocalStorageAdapter.php';
    require_once __DIR__.'/lib/DocumentUploader.php';

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $isHttps ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'];

    $storage = new LocalStorageAdapter(
        baseDir: __DIR__.'/uploads',
        publicBaseUrl: $scheme.$host.'/uploads'
    );

    $uploader = new DocumentUploader($pdo, $storage);

    if (empty($_FILES['files'])) {
        respond(false, '업로드 파일이 없습니다.');
    }

    $files = $_FILES['files'];
    $count = count($files['name']);

    $saved = [];
    for ($i=0; $i<$count; $i++) {

        $file = [
            'name' => $files['name'][$i],
            'type' => $files['type'][$i],
            'tmp_name' => $files['tmp_name'][$i],
            'error' => $files['error'][$i],
            'size' => $files['size'][$i],
        ];

        $docType = $_POST['doc_type'] ?? 'etc';
        $sort = $i + 1;

        $saved[] = $uploader->handleUploadedFile(
            $inquiryId,
            $file,
            $docType,
            $sort
        );
    }

    respond(true, '업로드 완료', $saved);

} catch (Throwable $e) {
    error_log('[UPLOAD_DOC_ERROR] '.$e->getMessage());
    respond(false, '서류 업로드 중 오류 발생');
}