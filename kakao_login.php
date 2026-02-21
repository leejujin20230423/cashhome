<?php
declare(strict_types=1);

/**
 * kakao_login.php
 * - 카카오 인가 페이지로 이동
 * - state 저장 (CSRF 방어)
 * - return 파라미터 세션 저장
 */

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => true,      // HTTPS면 true
    'httponly' => true,
    'samesite' => 'Lax',   // ✅ OAuth 리다이렉트 안정화
]);
session_start();

const KAKAO_REST_API_KEY = 'd6cf1b953dfb5b853674b0c265090b1b';
const KAKAO_REDIRECT_URI = 'https://cashhome.bizstore.co.kr/kakao_callback.php';

// return 유지
$return = (string)($_GET['return'] ?? 'index.php#apply');
$_SESSION['kakao_return'] = $return;

// state 저장
$state = bin2hex(random_bytes(16));
$_SESSION['kakao_oauth_state'] = $state;

// ✅ scope는 공백 구분이 가장 안정적
$scope = [
    'profile_nickname',
    // 'phone_number', // 필요하면 콘솔 동의항목/심사 확인 후 추가
];

$params = [
    'client_id'     => KAKAO_REST_API_KEY,
    'redirect_uri'  => KAKAO_REDIRECT_URI,
    'response_type' => 'code',
    'state'         => $state,
    'scope'         => implode(' ', $scope),
];

$authorizeUrl = 'https://kauth.kakao.com/oauth/authorize?' . http_build_query($params);

header('Location: ' . $authorizeUrl);
exit;