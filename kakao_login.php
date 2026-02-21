<?php
declare(strict_types=1);

/**
 * kakao_login.php
 * - 카카오 인가 페이지로 이동
 * - state 저장 (CSRF 방어)
 * - return 파라미터 세션 저장
 */

/* =========================================================
 * ✅ 세션 부트스트랩 (index.php / callback 과 동일하게)
 * ========================================================= */
$isHttps = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
    || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
);

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    // 필요하면 도메인 고정 (서브도메인 공유 필요 시 .bizstore.co.kr)
    // 'domain' => 'cashhome.bizstore.co.kr',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

/* =========================
 * Kakao OAuth Config
 * ========================= */
const KAKAO_REST_API_KEY = 'd6cf1b953dfb5b853674b0c265090b1b';
const KAKAO_REDIRECT_URI = 'https://cashhome.bizstore.co.kr/kakao_callback.php';

// return 유지 (hash 포함 가능)
$return = (string)($_GET['return'] ?? 'index.php#apply');
$_SESSION['kakao_return'] = $return;

// state 저장 (CSRF 방어)
$state = bin2hex(random_bytes(16));
$_SESSION['kakao_oauth_state'] = $state;

// ✅ scope (필요한 것만)
// phone_number는 카카오 앱 설정/동의항목/권한이 필요할 수 있음
$scope = [
    'profile_nickname',
    // 'phone_number',
];

$params = [
    'client_id'     => KAKAO_REST_API_KEY,
    'redirect_uri'  => KAKAO_REDIRECT_URI,
    'response_type' => 'code',
    'state'         => $state,
    'scope'         => implode(' ', $scope), // 공백 구분이 가장 안정적
];

$authorizeUrl = 'https://kauth.kakao.com/oauth/authorize?' . http_build_query($params);

header('Location: ' . $authorizeUrl);
exit;