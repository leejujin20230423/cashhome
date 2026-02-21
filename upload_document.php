<?php
declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
session_start();

/** 공통 응답 */
function respond(bool $ok, string $message = '', array $data = [], int $httpCode = 200): void {
    http_response_code($httpCode);
    echo json_encode([
        'ok' => $ok,
        'message' => $message,
        'data' => $data,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

/** 업로드 에러 메시지 */
function upload_error_message(int $code): string {
    $map = [
        UPLOAD_ERR_INI_SIZE   => '파일이 너무 큽니다(upload_max_filesize 초과)',
        UPLOAD_ERR_FORM_SIZE  => '파일이 너무 큽니다(폼 MAX_FILE_SIZE 초과)',
        UPLOAD_ERR_PARTIAL    => '파일이 일부만 업로드되었습니다',
        UPLOAD_ERR_NO_FILE    => '파일이 없습니다',
        UPLOAD_ERR_NO_TMP_DIR => '서버 임시폴더(tmp)가 없습니다',
        UPLOAD_ERR_CANT_WRITE => '디스크에 파일을 쓸 수 없습니다(권한/용량)',
        UPLOAD_ERR_EXTENSION  => 'PHP 확장에 의해 업로드가 중단되었습니다',
    ];
    return $map[$code] ?? ('알 수 없는 업로드 오류 코드: ' . $code);
}

/** ✅ PHP 업로드 환경 확인용 (문제 해결되면 삭제 가능) */
if (!empty($_GET['debug_env'])) {
    respond(true, 'env', [
        'post_max_size' => ini_get('post_max_size'),
        'upload_max_filesize' => ini_get('upload_max_filesize'),
        'max_file_uploads' => ini_get('max_file_uploads'),
        'max_input_time' => ini_get('max_input_time'),
        'max_execution_time' => ini_get('max_execution_time'),
        'memory_limit' => ini_get('memory_limit'),
    ]);
}

/** ✅ inquiry_id 세션 검증 */
$inquiryId = (int)($_POST['inquiry_id'] ?? 0);
$sessionInquiryId = (int)($_SESSION['cashhome_last_inquiry_id'] ?? 0);

if ($inquiryId < 1 || $sessionInquiryId !== $inquiryId) {
    respond(false, '접수 정보가 확인되지 않습니다.', [
        'inquiry_id' => $inquiryId,
        'session_inquiry_id' => $sessionInquiryId,
    ], 403);
}

/**
 * ✅ 파일 받기
 * - index.php는 fd.append('files[]', ...) 로 보내고 있으니 기본은 $_FILES['files']
 * - 혹시 fd.append('file', ...) 로 보내는 경우도 대비해서 둘 다 허용
 */
$filesKey = null;
if (!empty($_FILES['files'])) $filesKey = 'files';
elseif (!empty($_FILES['file'])) $filesKey = 'file';

if ($filesKey === null) {
    respond(false, '파일이 전달되지 않았습니다.', [
        '_FILES_keys' => array_keys($_FILES),
    ], 400);
}

/** DB 설정 */
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

    $isHttps = (
        (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
    );
    $scheme = $isHttps ? 'https://' : 'http://';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';

    $storage = new LocalStorageAdapter(
        baseDir: __DIR__.'/uploads',
        publicBaseUrl: $scheme.$host.'/uploads'
    );

    $uploader = new DocumentUploader($pdo, $storage);

    $docType = (string)($_POST['doc_type'] ?? 'etc');
    if ($docType === '') $docType = 'etc';

    $saved = [];

    // ✅ (A) files[] 여러개 업로드
    if ($filesKey === 'files') {
        $files = $_FILES['files'];

        // 배열 구조 체크
        if (!isset($files['name']) || !is_array($files['name'])) {
            respond(false, '업로드 파일 구조가 올바르지 않습니다.', [
                'files' => $files,
            ], 400);
        }

        $count = count($files['name']);
        if ($count < 1) {
            respond(false, '업로드 파일이 없습니다.', [], 400);
        }

        for ($i = 0; $i < $count; $i++) {
            $file = [
                'name' => $files['name'][$i] ?? '',
                'type' => $files['type'][$i] ?? '',
                'tmp_name' => $files['tmp_name'][$i] ?? '',
                'error' => (int)($files['error'][$i] ?? UPLOAD_ERR_NO_FILE),
                'size' => (int)($files['size'][$i] ?? 0),
            ];

            if ($file['error'] !== UPLOAD_ERR_OK) {
                respond(false, upload_error_message($file['error']), [
                    'index' => $i,
                    'name' => $file['name'],
                    'error_code' => $file['error'],
                ], 400);
            }

            if ($file['tmp_name'] === '' || !is_uploaded_file($file['tmp_name'])) {
                respond(false, '임시 업로드 파일이 유효하지 않습니다.', [
                    'index' => $i,
                    'tmp_name' => $file['tmp_name'],
                    'name' => $file['name'],
                ], 400);
            }

            $sort = $i + 1;

            $saved[] = $uploader->handleUploadedFile(
                $inquiryId,
                $file,
                $docType,
                $sort
            );
        }

        respond(true, '업로드 완료', $saved);
    }

    // ✅ (B) file 단일 업로드(호환용)
    $f = $_FILES['file'];

    $file = [
        'name' => $f['name'] ?? '',
        'type' => $f['type'] ?? '',
        'tmp_name' => $f['tmp_name'] ?? '',
        'error' => (int)($f['error'] ?? UPLOAD_ERR_NO_FILE),
        'size' => (int)($f['size'] ?? 0),
    ];

    if ($file['error'] !== UPLOAD_ERR_OK) {
        respond(false, upload_error_message($file['error']), [
            'name' => $file['name'],
            'error_code' => $file['error'],
        ], 400);
    }

    if ($file['tmp_name'] === '' || !is_uploaded_file($file['tmp_name'])) {
        respond(false, '임시 업로드 파일이 유효하지 않습니다.', [
            'tmp_name' => $file['tmp_name'],
            'name' => $file['name'],
        ], 400);
    }

    $saved[] = $uploader->handleUploadedFile(
        $inquiryId,
        $file,
        $docType,
        1
    );

    respond(true, '업로드 완료', $saved);

} catch (Throwable $e) {
    error_log('[UPLOAD_DOC_ERROR] '.$e->getMessage());

    // ✅ 디버그 모드일 때만 실제 에러를 응답으로 내려줌
    $debug = !empty($_GET['debug']) || !empty($_POST['debug']);

    respond(false, '서류 업로드 중 오류 발생', [
        'error' => $debug ? $e->getMessage() : null,
        'trace' => $debug ? $e->getTraceAsString() : null,
    ], 500);
}