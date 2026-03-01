<?php
declare(strict_types=1);

require_once __DIR__ . '/lib/Storage/StorageAdapterInterface.php';
require_once __DIR__ . '/lib/Storage/LocalStorageAdapter.php';
require_once __DIR__ . '/lib/DocumentUploader.php';

use Cashhome\DocumentUploader;
use Cashhome\Storage\LocalStorageAdapter;

/*
|--------------------------------------------------------------------------
| DB 연결 (기존 프로젝트 방식에 맞게 수정 가능)
|--------------------------------------------------------------------------
*/
$pdo = new PDO(
    'mysql:host=localhost;dbname=cashhome;charset=utf8mb4',
    'db_user',
    'db_password',
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]
);

/*
|--------------------------------------------------------------------------
| Storage 설정
|--------------------------------------------------------------------------
*/
$publicBaseUrl = 'https://cashhome.bizstore.co.kr/uploads';

$storage = new LocalStorageAdapter(
    baseDir: __DIR__ . '/uploads',
    publicBaseUrl: $publicBaseUrl
);

/*
|--------------------------------------------------------------------------
| 업로더 생성
|--------------------------------------------------------------------------
*/
$uploader = new DocumentUploader($pdo, $storage);

/*
|--------------------------------------------------------------------------
| 업로드 처리
|--------------------------------------------------------------------------
*/
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    $inquiryId = (int)($_POST['inquiry_id'] ?? 0);
    $items = $_FILES['files'] ?? null;

    if ($inquiryId <= 0) {
        die('잘못된 문의 ID');
    }

    if (!$items || !isset($items['name'])) {
        die('파일이 없습니다.');
    }

    $saved = [];
    $sort = 1;

    foreach ($items['name'] as $idx => $name) {

        $file = [
            'name'     => $items['name'][$idx],
            'type'     => $items['type'][$idx],
            'tmp_name' => $items['tmp_name'][$idx],
            'error'    => $items['error'][$idx],
            'size'     => $items['size'][$idx],
        ];

        if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
            continue;
        }

        try {
            $saved[] = $uploader->handleUploadedFile(
                inquiryId: $inquiryId,
                file: $file,
                docType: 'admin_upload',
                sort: $sort++
            );
        } catch (Throwable $e) {
            echo "업로드 실패: " . $e->getMessage() . "<br>";
        }
    }

    echo "<pre>";
    print_r($saved);
    echo "</pre>";
}