<?php
declare(strict_types=1);
session_start();

// const KAKAO_REST_API_KEY   = 'd6cf1b953dfb5b853674b0c265090b1b';
const KAKAO_REST_API_KEY   = 'd6cf1b953dfb5b853674b0c265090b1b';
const KAKAO_CLIENT_SECRET = 'YqcjxkwRyqjK813eckdVyn4eAP87q4U7'; // 콘솔에서 Client Secret 사용 ON일 때만
// const KAKAO_REDIRECT_URI  = 'https://cashhome.bizstore.co.kr/kakao_callback.php';
const KAKAO_REDIRECT_URI  = 'https://cashhome.bizstore.co.kr/kakao_callback.php';

$state = bin2hex(random_bytes(16));
$_SESSION['kakao_oauth_state'] = $state;

// 필요 동의 항목
$scope = [
  'profile_nickname',
  'profile_image',
  // 'account_email',
  // 'phone_number',
];

$q = http_build_query([
  'client_id'     => KAKAO_REST_API_KEY,
  'redirect_uri'  => KAKAO_REDIRECT_URI,
  'response_type' => 'code',
  'state'         => $state,
  'scope'         => implode(',', $scope),
]);

header('Location: https://kauth.kakao.com/oauth/authorize?' . $q);
exit;