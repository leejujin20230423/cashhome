<?php
declare(strict_types=1);


ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');

function fail(string $msg, array $extra = []): void {
  http_response_code(400);
  echo json_encode([
    'ok' => false,
    'message' => $msg,
    'extra' => $extra,
  ], JSON_UNESCAPED_UNICODE);
  exit;
}

function ok(array $data = []): void {
  echo json_encode(array_merge(['ok' => true], $data), JSON_UNESCAPED_UNICODE);
  exit;
}

// ✅ PHP 업로드 환경 확인용(문제 해결되면 삭제 가능)
if (!empty($_GET['debug_env'])) {
  ok([
    'post_max_size' => ini_get('post_max_size'),
    'upload_max_filesize' => ini_get('upload_max_filesize'),
    'max_file_uploads' => ini_get('max_file_uploads'),
    'max_input_time' => ini_get('max_input_time'),
    'max_execution_time' => ini_get('max_execution_time'),
    'memory_limit' => ini_get('memory_limit'),
  ]);
}

// ✅ 업로드 파일 존재 확인
if (empty($_FILES['file'])) {
  fail('파일이 전달되지 않았습니다.', ['_FILES' => array_keys($_FILES)]);
}

$f = $_FILES['file'];

// ✅ PHP 업로드 에러코드 체크 (이거 안하면 대부분 “오류발생”으로만 보임)
if (!empty($f['error'])) {
  $map = [
    UPLOAD_ERR_INI_SIZE   => '파일이 너무 큽니다(upload_max_filesize 초과)',
    UPLOAD_ERR_FORM_SIZE  => '파일이 너무 큽니다(폼 MAX_FILE_SIZE 초과)',
    UPLOAD_ERR_PARTIAL    => '파일이 일부만 업로드되었습니다',
    UPLOAD_ERR_NO_FILE    => '파일이 없습니다',
    UPLOAD_ERR_NO_TMP_DIR => '서버 임시폴더(tmp)가 없습니다',
    UPLOAD_ERR_CANT_WRITE => '디스크에 파일을 쓸 수 없습니다(권한/용량)',
    UPLOAD_ERR_EXTENSION  => 'PHP 확장에 의해 업로드가 중단되었습니다',
  ];
  $msg = $map[$f['error']] ?? ('알 수 없는 업로드 오류 코드: ' . $f['error']);
  fail($msg, ['error_code' => $f['error']]);
}

// ✅ tmp 파일 실존 확인
if (empty($f['tmp_name']) || !is_uploaded_file($f['tmp_name'])) {
  fail('임시 업로드 파일이 유효하지 않습니다.', ['tmp_name' => $f['tmp_name'] ?? null]);
}

// 여기부터는 기존 업로드/리사이즈/DB 저장 로직 진행





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