<?php
declare(strict_types=1);

session_start();
header('Content-Type: application/json; charset=utf-8');

function respond(bool $ok, string $msg = '', array $data = []): void {
  echo json_encode(['ok'=>$ok,'message'=>$msg,'data'=>$data], JSON_UNESCAPED_UNICODE);
  exit;
}

// ✅ 관리자 세션 체크
if (empty($_SESSION['cashhome_admin_authed'])) {
  respond(false, '권한 없음');
}

const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

$docId = (int)($_POST['doc_id'] ?? 0);
if ($docId < 1) respond(false, 'doc_id가 필요합니다.');

try {
  $pdo = new PDO('mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4', DB_USER, DB_PASS, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
  ]);

  // 1) 파일경로 조회
  $stmt = $pdo->prepare("SELECT cashhome_1200_file_path AS file_path FROM cashhome_1200_documents WHERE cashhome_1200_id=:id");
  $stmt->execute([':id' => $docId]);
  $row = $stmt->fetch();
  if (!$row) respond(false, '문서가 존재하지 않습니다.');

  $filePath = (string)$row['file_path']; // 예: /uploads/docs/123/xxx.jpg

  // 2) DB 삭제
  $del = $pdo->prepare("DELETE FROM cashhome_1200_documents WHERE cashhome_1200_id=:id");
  $del->execute([':id' => $docId]);

  // 3) 디스크 삭제 (프로젝트 루트 기준)
  $abs = __DIR__ . $filePath; // __DIR__/uploads/...
  $deleted = false;
  if (is_file($abs)) {
    $deleted = @unlink($abs);
  }

  respond(true, '삭제 완료', ['file_deleted' => $deleted]);
} catch (Throwable $e) {
  error_log('[admin_document_delete] '.$e->getMessage());
  respond(false, '서버 오류');
}