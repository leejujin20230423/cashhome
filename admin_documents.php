<?php
declare(strict_types=1);

session_start();
header('Content-Type: application/json; charset=utf-8');

function respond(bool $ok, string $msg = '', array $data = []): void {
  echo json_encode(['ok'=>$ok,'message'=>$msg,'data'=>$data], JSON_UNESCAPED_UNICODE);
  exit;
}

// ✅ 관리자 세션 체크 (네 프로젝트 기준으로 맞춤)
if (empty($_SESSION['cashhome_admin_authed'])) {
  respond(false, '권한 없음');
}

const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

$inquiryId = (int)($_GET['inquiry_id'] ?? 0);
if ($inquiryId < 1) respond(false, 'inquiry_id가 필요합니다.');

try {
  $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4', DB_USER, DB_PASS, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
  ]);

  $stmt = $pdo->prepare("
    SELECT
      cashhome_1200_id AS id,
      cashhome_1200_doc_type AS doc_type,
      cashhome_1200_sort AS sort,
      cashhome_1200_file_path AS file_path,
      cashhome_1200_mime AS mime,
      cashhome_1200_size_bytes AS size_bytes,
      cashhome_1200_width AS w,
      cashhome_1200_height AS h,
      cashhome_1200_created_at AS created_at
    FROM cashhome_1200_documents
    WHERE cashhome_1200_inquiry_id = :iid
    ORDER BY cashhome_1200_doc_type ASC, cashhome_1200_sort ASC, cashhome_1200_id ASC
  ");
  $stmt->execute([':iid' => $inquiryId]);
  $rows = $stmt->fetchAll();

  // ✅ doc_type별 그룹핑
  $grouped = [];
  foreach ($rows as $r) {
    $t = (string)$r['doc_type'];
    if (!isset($grouped[$t])) $grouped[$t] = [];
    $grouped[$t][] = $r;
  }

  respond(true, 'ok', ['grouped' => $grouped, 'count' => count($rows)]);
} catch (Throwable $e) {
  error_log('[admin_documents] '.$e->getMessage());
  respond(false, '서버 오류');
}