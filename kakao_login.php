<?php
declare(strict_types=1);
session_start();

const KAKAO_REST_API_KEY = '여기에_REST_API_KEY';
const KAKAO_CLIENT_SECRET = '여기에_CLIENT_SECRET'; // 카카오 콘솔에 ON이면 필요 :contentReference[oaicite:2]{index=2}
const KAKAO_REDIRECT_URI = 'https://your-domain.com/kakao_callback.php';

$state = bin2hex(random_bytes(16));
$_SESSION['kakao_oauth_state'] = $state;

// 받고 싶은 동의항목(앱 설정에 있어야 함)
// phone_number는 앱에서 동의항목 활성화+사용자 동의 필요
$scope = [
  'profile',        // 닉네임/프로필
  // 'account_email', // 이메일이 필요하면
  // 'phone_number',  // 전화번호(가능하면)
];

$q = http_build_query([
  'client_id'     => KAKAO_REST_API_KEY,
  'redirect_uri'  => KAKAO_REDIRECT_URI,
  'response_type' => 'code',
  'state'         => $state,
  'scope'         => implode(',', $scope), // 추가 동의 요청 시 사용 :contentReference[oaicite:3]{index=3}
]);

header('Location: https://kauth.kakao.com/oauth/authorize?' . $q);
exit;