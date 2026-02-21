<?php
declare(strict_types=1);

/**
 * kakao_login.php
 * - 카카오 인가 페이지로 이동
 * - state 저장 (CSRF 방어)
 * - return 파라미터 세션 저장
 * ⚠️ 파일 맨 앞 공백/문자 절대 금지 (반드시 <?php 로 시작)
 */

$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
      || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $https,
    'httponly' => true,
    'samesite' => 'Lax',
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

// scope
$scope = [
    'profile_nickname',
    // 'phone_number', // 카카오 콘솔/심사 승인되어야 정상 수신됨
];

$params = [
    'client_id'     => KAKAO_REST_API_KEY,
    'redirect_uri'  => KAKAO_REDIRECT_URI,
    'response_type' => 'code',
    'state'         => $state,
    'scope'         => implode(' ', $scope),
];

$authorizeUrl = 'https://kauth.kakao.com/oauth/authorize?' . http_build_query($params);

// 세션 저장 확실히
session_write_close();

header('Location: ' . $authorizeUrl);
exit;