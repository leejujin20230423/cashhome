<?php

declare(strict_types=1);

/**
 * admin_login.php
 * - 관리자 선택(master/admin) + 비밀번호 입력 → 성공 시 admin_inquiries.php 이동
 * - 브라우저 종료 시 세션 쿠키 삭제(세션 유지 X)
 * - IP/UA 고정 + 세션 ID 재생성
 * - ✅ 세션에 관리자 ID/ROLE 저장: cashhome_admin_id, cashhome_admin_role
 * - ✅ PWA 설치 버튼(지원 브라우저에서만 노출)
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

function h(string $s): string
{
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * ✅ admin 비밀번호 해시 (기존 해시 = admin용)
 * 생성 방법(서버/로컬에서 1회):
 * php -r "echo password_hash('원하는비번', PASSWORD_DEFAULT), PHP_EOL;"
 */
const ADMIN_PASSWORD_HASH = '$2y$10$.O/nub6v3J/rrrTbI/Dwsen99YYOAaR7R2PQsP8N40rBEUuUJVt7u';

/**
 * ✅ master 비밀번호 해시
 * 원문: dlzptnl4568965233
 */
const MASTER_PASSWORD_HASH = '$2y$10$9zKdBkdWPcGg.DeVyy3TBu0P9G8Oe8bKN/IEKx6Hh8whu/nsHvcTG';

/**
 * ✅ role → 세션에 저장할 관리자 ID 매핑
 * (DB에 저장할 값이라 숫자 권장)
 */
const ADMIN_ID_ADMIN  = 2;
const ADMIN_ID_MASTER = 1;

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

  // ✅ 관리자ID 세션 필수(토큰발급/저장 기록에 필요)
  if (empty($_SESSION['cashhome_admin_id']) || (int)$_SESSION['cashhome_admin_id'] <= 0) return false;

  // ✅ role도 있으면 좋음
  if (empty($_SESSION['cashhome_admin_role'])) return false;

  return true;
}

// 이미 로그인 상태면 바로 이동
if (is_admin_authed()) {
  header('Location: admin_inquiries.php');
  exit;
}

$error = '';
$selectedRole = 'admin'; // 기본값

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $role = (string)($_POST['role'] ?? 'admin');
  $pw = (string)($_POST['password'] ?? '');

  $allowedRoles = ['admin', 'master'];
  if (!in_array($role, $allowedRoles, true)) $role = 'admin';
  $selectedRole = $role;

  // role별 해시 선택
  $hash = ($role === 'master') ? MASTER_PASSWORD_HASH : ADMIN_PASSWORD_HASH;

  if (password_verify($pw, $hash)) {
    // 로그인 성공
    $_SESSION['cashhome_admin_authed'] = true;
    $_SESSION['cashhome_admin_authed_at'] = time();
    $_SESSION['cashhome_admin_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
    $_SESSION['cashhome_admin_ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // ✅ 관리자 ID/ROLE 세션 저장
    $_SESSION['cashhome_admin_role'] = $role;
    $_SESSION['cashhome_admin_id'] = ($role === 'master') ? ADMIN_ID_MASTER : ADMIN_ID_ADMIN;

    // ✅ admin_inquiries.php가 요구하는 세션키(중요!)
    $_SESSION['cashhome_admin_username'] = $role; // 'admin' 또는 'master'

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

  <!-- ✅ PWA -->
  <link rel="manifest" href="/manifest.webmanifest">
  <meta name="theme-color" content="#0B1220">
  <link rel="apple-touch-icon" href="/icons/icon-192.png">

  <style>
    body {
      margin: 0;
      font-family: system-ui, "Noto Sans KR";
      background: #0B1220;
      color: #EAF0FF
    }

    .wrap {
      max-width: 420px;
      margin: 0 auto;
      padding: 28px 16px
    }

    .card {
      background: rgba(16, 26, 51, .85);
      border: 1px solid rgba(234, 240, 255, .12);
      border-radius: 18px;
      padding: 18px
    }

    label {
      display: block;
      font-size: 12px;
      color: #9DB0D0;
      margin-bottom: 6px
    }

    input,
    select {
      box-sizing: border-box;
      width: 100%;
      padding: 12px;
      border-radius: 14px;
      border: 1px solid rgba(234, 240, 255, .12);
      background: rgba(8, 12, 24, .55);
      color: #EAF0FF;
      outline: none;
    }

    select {
      appearance: none;
    }

    button {
      margin-top: 12px;
      padding: 12px 14px;
      border: 0;
      border-radius: 999px;
      font-weight: 800;
      cursor: pointer;
      background: linear-gradient(135deg, rgba(110, 231, 255, .9), rgba(167, 139, 250, .9));
      color: #061025
    }

    .err {
      margin-top: 12px;
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(255, 120, 120, .35);
      background: rgba(255, 255, 255, .03)
    }

    .tiny {
      margin-top: 10px;
      color: #9DB0D0;
      font-size: 12px
    }

    a {
      color: #9DB0D0;
      text-decoration: none
    }

    /* ✅ 설치 버튼(설치 가능할 때만 노출) */
    .installBtn {
      margin-top: 12px;
      width: 100%;
      padding: 12px 14px;
      border-radius: 999px;
      font-weight: 800;
      cursor: pointer;
      border: 1px solid rgba(234, 240, 255, .12);
      background: rgba(255, 255, 255, .04);
      color: #EAF0FF;
      display: none;
    }

    .installBtn:hover {
      background: rgba(255, 255, 255, .06)
    }

    .installHint {
      margin-top: 10px;
      padding: 10px 12px;
      border-radius: 14px;
      border: 1px solid rgba(234, 240, 255, .12);
      background: rgba(255, 255, 255, .03);
      color: #9DB0D0;
      font-size: 12px;
      display: none;
      line-height: 1.45;
    }
  </style>
</head>

<body>
  <div class="wrap">
    <div class="card">
      <h2 style="margin:0 0 12px;">관리자 로그인</h2>

      <form method="post" action="">
        <label for="role">관리자 선택</label>
        <select id="role" name="role" required>
          <option value="admin" <?= $selectedRole === 'admin' ? 'selected' : '' ?>>admin</option>
          <option value="master" <?= $selectedRole === 'master' ? 'selected' : '' ?>>master</option>
        </select>

        <label for="password" style="margin-top:12px;">비밀번호</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required />

        <button type="submit">접수이력 보기</button>

        <!-- ✅ PWA 설치 버튼 -->
        <button type="button" id="installBtn" class="installBtn">앱 설치하기</button>
      </form>

      <!-- ✅ iOS 안내(사파리는 설치 팝업 API가 없어서 안내문으로 처리) -->
      <div id="iosHint" class="installHint">
        iPhone/iPad에서는 아래 방법으로 설치할 수 있어요.<br>
        1) Safari에서 열기<br>
        2) 공유 버튼(⬆︎) 누르기<br>
        3) “홈 화면에 추가” 선택
      </div>

      <?php if ($error): ?>
        <div class="err"><?= h($error) ?></div>
      <?php endif; ?>

      <div class="tiny">※ 브라우저를 닫으면 로그인 상태가 종료됩니다.</div>
      <div class="tiny"><a href="./">← 홈으로</a></div>
    </div>
  </div>

  <script>
    // ✅ Service Worker 등록(PWA 조건)
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("/service-worker.js").catch(() => {});
    }

    // ✅ iOS Safari는 beforeinstallprompt 미지원 → 안내 표시
    const isIOS = /iP(hone|ad|od)/.test(navigator.userAgent);
    const isInStandalone =
      window.matchMedia && window.matchMedia("(display-mode: standalone)").matches ||
      window.navigator.standalone === true;

    const iosHint = document.getElementById("iosHint");
    if (isIOS && !isInStandalone) {
      iosHint.style.display = "block";
    }

    // ✅ 설치 버튼 제어 (Chrome/Edge/Samsung Internet 등)
    let deferredPrompt = null;
    const installBtn = document.getElementById("installBtn");

    window.addEventListener("beforeinstallprompt", (e) => {
      e.preventDefault(); // 자동 배너 대신 버튼으로 설치 유도
      deferredPrompt = e;
      if (!isInStandalone) installBtn.style.display = "block";
    });

    installBtn?.addEventListener("click", async () => {
      if (!deferredPrompt) return;
      deferredPrompt.prompt();
      try {
        await deferredPrompt.userChoice;
      } catch (e) {}
      deferredPrompt = null;
      installBtn.style.display = "none";
    });

    window.addEventListener("appinstalled", () => {
      deferredPrompt = null;
      installBtn.style.display = "none";
    });
  </script>
</body>

</html>