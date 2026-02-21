<?php
declare(strict_types=1);
session_start();

// ✅ 카카오 REST API 키 (앱 > 요약정보 또는 앱키에서 확인)
const KAKAO_REST_API_KEY = 'd6cf1b953dfb5b853674b0c265090b1b';

// ✅ 카카오 로그인 Redirect URI (콘솔에 등록한 것과 100% 동일해야 함)
const KAKAO_REDIRECT_URI = 'https://cashhome.bizstore.co.kr/kakao_callback.php';

// CSRF 방지용 state
$state = bin2hex(random_bytes(16));
$_SESSION['kakao_oauth_state'] = $state;

// ✅ 1) scope 없이 먼저 성공 확인 (KOE205 방지용)
$params = [
    'client_id'     => KAKAO_REST_API_KEY,
    'redirect_uri'  => KAKAO_REDIRECT_URI,
    'response_type' => 'code',
    'state'         => $state,
];

// authorize URL
$authorizeUrl = 'https://kauth.kakao.com/oauth/authorize?' . http_build_query($params);

// 이동
header('Location: ' . $authorizeUrl);
exit;