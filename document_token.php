<?php
/**
 * ===========================
 * 파일명: document_token.php
 * 역할: 6자리 인증코드 입력 → DB 검증 → 세션 저장 → document_upload.php 이동
 * ✅ 무한 리다이렉트 방지: "세션 있으면 자동 이동" 제거
 * ===========================
 */

declare(strict_types=1);

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

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

header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; connect-src 'self' https:;");

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ===== DB 설정 =====
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

const UPLOAD_PAGE = 'document_upload.php';
const TOKEN_SESSION_TTL = 1800;

function cashhome_pdo(): PDO
{
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

function normalize_token(string $t): string
{
    $t = preg_replace('/\D+/', '', $t) ?? '';
    return substr($t, 0, 6);
}

function fetch_inquiry_by_token(PDO $pdo, string $token): ?array
{
    if (!preg_match('/^\d{6}$/', $token)) return null;

    $st = $pdo->prepare("
        SELECT
            cashhome_1000_id,
            cashhome_1000_customer_name,
            cashhome_1000_customer_phone,
            cashhome_1000_doc_token,
            cashhome_1000_doc_token_status,
            cashhome_1000_doc_token_expires_at
        FROM cashhome_1000_inquiries
        WHERE cashhome_1000_doc_token = :tk
          AND cashhome_1000_doc_token_status = 1
          AND (cashhome_1000_doc_token_expires_at IS NULL OR cashhome_1000_doc_token_expires_at >= NOW())
        ORDER BY cashhome_1000_id DESC
        LIMIT 1
    ");
    $st->execute([':tk' => $token]);
    $row = $st->fetch();
    return $row ?: null;
}

// CSRF
if (empty($_SESSION['csrf_token_user'])) {
    $_SESSION['csrf_token_user'] = bin2hex(random_bytes(32));
}

$err = '';
$info = '';

if (!empty($_SESSION['cashhome_doc_upload_inquiry_id']) && !empty($_SESSION['cashhome_doc_upload_authed_at'])) {
    $authedAt = (int)$_SESSION['cashhome_doc_upload_authed_at'];
    if ((time() - $authedAt) <= TOKEN_SESSION_TTL) {
        $iid = (int)$_SESSION['cashhome_doc_upload_inquiry_id'];
        $info = "이미 인증이 완료되었습니다. (접수번호 #{$iid}) 아래 버튼으로 계속 진행하세요.";
    } else {
        unset(
            $_SESSION['cashhome_doc_upload_inquiry_id'],
            $_SESSION['cashhome_doc_upload_token'],
            $_SESSION['cashhome_doc_upload_authed_at']
        );
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $info === '') {
    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token_user'], $csrf)) {
        $err = '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.';
    } else {
        $token = normalize_token((string)($_POST['token'] ?? ''));
        if (!preg_match('/^\d{6}$/', $token)) {
            $err = '인증코드는 6자리 숫자만 입력 가능합니다.';
        } else {
            try {
                $pdo = cashhome_pdo();
                $row = fetch_inquiry_by_token($pdo, $token);

                if (!$row) {
                    $err = '인증코드가 올바르지 않거나 만료되었습니다. 관리자에게 문의해주세요.';
                } else {
                    $_SESSION['cashhome_doc_upload_inquiry_id'] = (int)$row['cashhome_1000_id'];
                    $_SESSION['cashhome_doc_upload_token'] = $token;
                    $_SESSION['cashhome_doc_upload_authed_at'] = time();

                    $_SESSION['csrf_token_user'] = bin2hex(random_bytes(32));
                    header('Location: ' . UPLOAD_PAGE);
                    exit;
                }
            } catch (Throwable $e) {
                error_log('[TOKEN CHECK ERROR] ' . $e->getMessage());
                $err = '서버 오류가 발생했습니다. 잠시 후 다시 시도해주세요.';
            }
        }
    }
}

$self = basename((string)($_SERVER['PHP_SELF'] ?? 'document_token.php'));
?>
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow" />
  <title>서류 제출 인증</title>
  <style>
    :root { --bg:#0B1220; --card:rgba(16,26,51,.80); --line:rgba(234,240,255,.12); --text:#EAF0FF; --muted:#9DB0D0; --shadow:0 14px 40px rgba(0,0,0,.38); --r2:22px; --accent:#6EE7FF; }
    *{box-sizing:border-box}
    body{margin:0;font-family:system-ui,"Noto Sans KR";background:radial-gradient(1200px 600px at 20% -10%, rgba(110,231,255,.18), transparent 60%), radial-gradient(900px 520px at 90% 10%, rgba(167,139,250,.16), transparent 55%), var(--bg);color:var(--text);}
    .wrap{max-width:520px;margin:0 auto;padding:22px 16px 30px}
    .card{border:1px solid var(--line);border-radius:var(--r2);background:var(--card);box-shadow:var(--shadow);padding:18px;}
    h1{margin:0 0 6px;font-size:18px}
    .muted{color:var(--muted);font-size:12px;line-height:1.5}
    .hr{height:1px;background:rgba(234,240,255,.08);margin:14px 0}
    label{display:block;font-size:12px;color:var(--muted);font-weight:800;margin-bottom:8px}
    input[type="text"]{width:100%;padding:14px;border-radius:16px;border:1px solid var(--line);background:rgba(8,12,24,.55);color:var(--text);outline:none;font-size:18px;letter-spacing:2px;text-align:center;}
    .btn{width:100%;margin-top:12px;padding:12px 14px;border-radius:999px;border:0;cursor:pointer;font-weight:1000;font-size:13px;color:#061025;background:linear-gradient(135deg, rgba(110,231,255,.95), rgba(167,139,250,.95));}
    .btnGhost{display:inline-block;margin-top:10px;padding:10px 14px;border-radius:999px;border:1px solid var(--line);background:rgba(255,255,255,.04);color:var(--text);text-decoration:none;font-weight:900;font-size:12px}
    .err{margin-top:12px;padding:10px 12px;border-radius:14px;border:1px solid rgba(255,120,120,.35);background:rgba(255,255,255,.03);font-size:12px;color:#FFD3D3;white-space:pre-wrap;}
    .ok{margin-top:12px;padding:10px 12px;border-radius:14px;border:1px solid rgba(110,231,255,.35);background:rgba(255,255,255,.03);font-size:12px;color:#EAF0FF;white-space:pre-wrap;}
  </style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>서류 제출 인증</h1>
    <div class="muted">관리자에게 받은 <b>6자리 인증코드</b>를 입력하면 서류 촬영/업로드가 가능합니다.</div>
    <div class="hr"></div>

    <?php if ($info): ?>
      <div class="ok"><?= h($info) ?></div>
      <a class="btnGhost" href="<?= h(UPLOAD_PAGE) ?>">서류 제출 계속하기</a>
    <?php else: ?>
      <form method="post" action="<?= h($self) ?>" autocomplete="off">
        <label for="token">인증코드(6자리)</label>
        <input id="token" name="token" type="text" inputmode="numeric" maxlength="6" placeholder="예: 123456" required />
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token_user']) ?>" />
        <button class="btn" type="submit">확인하고 서류 제출하기</button>
        <?php if ($err): ?><div class="err"><?= h($err) ?></div><?php endif; ?>
      </form>
    <?php endif; ?>
  </div>
</div>

<script>
(function(){
  const el = document.getElementById('token');
  if(!el) return;
  el.addEventListener('input', ()=>{ el.value = (el.value||'').replace(/\D+/g,'').slice(0,6); });
  try{ el.focus(); }catch(e){}
})();
</script>
</body>
</html>