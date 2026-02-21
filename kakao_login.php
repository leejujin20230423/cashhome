<?php
declare(strict_types=1);

require __DIR__ . '/session_bootstrap.php';

/**
 * kakao_login.php
 * - 카카오 인가 페이지로 이동
 * - state 저장 (CSRF 방어)
 * - return 파라미터 세션 저장
 */

const KAKAO_REST_API_KEY = 'd6cf1b953dfb5b853674b0c265090b1b';
const KAKAO_REDIRECT_URI = 'https://cashhome.bizstore.co.kr/kakao_callback.php';

// return 유지 (hash 포함)
$return = (string)($_GET['return'] ?? 'index.php#apply');
$_SESSION['kakao_return'] = $return;

// state 저장
$state = bin2hex(random_bytes(16));
$_SESSION['kakao_oauth_state'] = $state;

// ✅ scope: 닉네임만이면 profile_nickname
// ⚠️ phone_number는 카카오 비즈앱/동의항목 승인 필요 + scope 추가 필요
$scope = [
    'profile_nickname',
    // 'phone_number',
];

// 카카오 authorize URL
$params = [
    'client_id'     => KAKAO_REST_API_KEY,
    'redirect_uri'  => KAKAO_REDIRECT_URI,
    'response_type' => 'code',
    'state'         => $state,
    'scope'         => implode(' ', $scope), // 공백 구분
];

$authorizeUrl = 'https://kauth.kakao.com/oauth/authorize?' . http_build_query($params);

// 이동
header('Location: ' . $authorizeUrl);
exit;