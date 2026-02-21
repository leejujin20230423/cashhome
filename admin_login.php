<?php
declare(strict_types=1);

/**
 * admin_login.php
 * - 관리자 비밀번호 입력 → 성공 시 admin_inquiries.php 이동
 * - 브라우저 종료 시 세션 쿠키 삭제(세션 유지 X)
 * - IP/UA 고정 + 세션 ID 재생성
 */

ini_set('session.cookie_lifetime', '0'); // 브라우저 종료 시 쿠키 삭제

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => isset($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => 'Strict'
]);

session_start();

header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * ✅ 관리자 비밀번호 해시
 * 생성 방법(서버/로컬에서 1회):
 * php -r "echo password_hash('원하는비번', PASSWORD_DEFAULT), PHP_EOL;"
 */
const ADMIN_PASSWORD_HASH = '$2y$10$.O/nub6v3J/rrrTbI/Dwsen99YYOAaR7R2PQsP8N40rBEUuUJVt7u';

/** 로그인 유지 시간(초) */
const ADMIN_SESSION_TTL = 1800; // 30분 권장

function is_admin_authed(): bool
{
    if (empty($_SESSION['cashhome_admin_authed']) || empty($_SESSION['cashhome_admin_authed_at'])) {
        return false;
    }
    if ((time() - (int)$_SESSION['cashhome_admin_authed_at']) > ADMIN_SESSION_TTL) {
        session_destroy();
        return false;
    }
    // IP/UA 고정 체크(보안)
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (($_SESSION['cashhome_admin_ip'] ?? '') !== $ip) return false;
    if (($_SESSION['cashhome_admin_ua'] ?? '') !== $ua) return false;

    return true;
}

// 이미 로그인 상태면 바로 이동
if (is_admin_authed()) {
    header('Location: admin_inquiries.php');
    exit;
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $pw = (string)($_POST['password'] ?? '');

    if (password_verify($pw, ADMIN_PASSWORD_HASH)) {
        // 로그인 성공
        $_SESSION['cashhome_admin_authed'] = true;
        $_SESSION['cashhome_admin_authed_at'] = time();
        $_SESSION['cashhome_admin_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
        $_SESSION['cashhome_admin_ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';

        // 세션 하이재킹 방지(로그인 시 세션ID 재발급)
        session_regenerate_id(true);

        header('Location: admin_inquiries.php');
        exit;
    } else {
        $error = '비밀번호가 올바르지 않습니다.';
    }
}
?>
<!doctype html>
<html lang="ko">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="robots" content="noindex,nofollow" />
  <title>관리자 로그인</title>
  <style>
    body{margin:0;font-family:system-ui,"Noto Sans KR";background:#0B1220;color:#EAF0FF}
    .wrap{max-width:420px;margin:0 auto;padding:28px 16px}
    .card{background:rgba(16,26,51,.85);border:1px solid rgba(234,240,255,.12);border-radius:18px;padding:18px}
    label{display:block;font-size:12px;color:#9DB0D0;margin-bottom:6px}
    input{width:100%;padding:12px;border-radius:14px;border:1px solid rgba(234,240,255,.12);background:rgba(8,12,24,.55);color:#EAF0FF}
    button{margin-top:12px;padding:12px 14px;border:0;border-radius:999px;font-weight:800;cursor:pointer;
      background:linear-gradient(135deg, rgba(110,231,255,.9), rgba(167,139,250,.9));color:#061025}
    .err{margin-top:12px;padding:10px 12px;border-radius:14px;border:1px solid rgba(255,120,120,.35);background:rgba(255,255,255,.03)}
    .tiny{margin-top:10px;color:#9DB0D0;font-size:12px}
    a{color:#9DB0D0;text-decoration:none}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h2 style="margin:0 0 12px;">관리자 로그인</h2>

      <form method="post" action="">
        <label for="password">비밀번호</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required />
        <button type="submit">접수이력 보기</button>
      </form>

      <?php if ($error): ?>
        <div class="err"><?=h($error)?></div>
      <?php endif; ?>

      <div class="tiny">※ 브라우저를 닫으면 로그인 상태가 종료됩니다.</div>
      <div class="tiny"><a href="./">← 홈으로</a></div>
    </div>
  </div>
</body>
</html>