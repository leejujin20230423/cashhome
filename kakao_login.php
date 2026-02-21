<?php
declare(strict_types=1);
session_start();

const KAKAO_REST_API_KEY = 'd6cf1b953dfb5b853674b0c265090b1b';
const KAKAO_REDIRECT_URI = 'https://cashhome.bizstore.co.kr/kakao_callback.php';

$state = bin2hex(random_bytes(16));
$_SESSION['kakao_oauth_state'] = $state;

// ✅ 동의항목(콘솔: 제품 설정 > 카카오 로그인 > 동의항목에서 "사용"이어야 함)
$scope = [
    'profile_nickname',
    'profile_image',
    // 'account_email',
    // 'phone_number', // 이건 처음엔 빼는 걸 강력 추천
];

$params = [
    'client_id'     => KAKAO_REST_API_KEY,
    'redirect_uri'  => KAKAO_REDIRECT_URI,
    'response_type' => 'code',
    'state'         => $state,
    'scope'         => implode(',', $scope), // 환경에 따라 공백이 필요하면 implode(' ', $scope)로 테스트
];

$authorizeUrl = 'https://kauth.kakao.com/oauth/authorize?' . http_build_query($params);

header('Location: ' . $authorizeUrl);
exit;