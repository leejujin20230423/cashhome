<?php
declare(strict_types=1);

session_start();

const KAKAO_REST_API_KEY = 'd6cf1b953dfb5b853674b0c265090b1b';
const KAKAO_CLIENT_SECRET = 'YqcjxkwRyqjK813eckdVyn4eAP87q4U7'; // 콘솔에서 Client Secret 사용 ON일 때만
const KAKAO_REDIRECT_URI = 'https://cashhome.bizstore.co.kr/kakao_callback.php';
function http_post(string $url, array $data, array $headers = []): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($data),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => array_merge([
            'Content-Type: application/x-www-form-urlencoded;charset=utf-8',
        ], $headers),
        CURLOPT_TIMEOUT => 15,
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    return [$code, $body ?: '', $err];
}

function http_get(string $url, array $headers = []): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 15,
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);
    return [$code, $body ?: '', $err];
}

// 에러/취소 처리
if (!empty($_GET['error'])) {
    header('Location: index.php#apply');
    exit;
}

$code  = (string)($_GET['code'] ?? '');
$state = (string)($_GET['state'] ?? '');

if ($code === '' || $state === '' || empty($_SESSION['kakao_oauth_state']) || !hash_equals($_SESSION['kakao_oauth_state'], $state)) {
    header('Location: index.php#apply');
    exit;
}
unset($_SESSION['kakao_oauth_state']);

// 1) 토큰 발급 요청 (인가 코드 -> 액세스 토큰) :contentReference[oaicite:4]{index=4}
[$http, $body, $err] = http_post('https://kauth.kakao.com/oauth/token', [
    'grant_type'   => 'authorization_code',
    'client_id'    => KAKAO_REST_API_KEY,
    'redirect_uri' => KAKAO_REDIRECT_URI,
    'code'         => $code,
    'client_secret'=> KAKAO_CLIENT_SECRET,
]);

if ($http !== 200) {
    header('Location: index.php#apply');
    exit;
}

$token = json_decode($body, true);
$accessToken = (string)($token['access_token'] ?? '');
if ($accessToken === '') {
    header('Location: index.php#apply');
    exit;
}

// 2) 사용자 정보 조회 (/v2/user/me) :contentReference[oaicite:5]{index=5}
[$http2, $body2, $err2] = http_get('https://kapi.kakao.com/v2/user/me', [
    'Authorization: Bearer ' . $accessToken,
]);

if ($http2 !== 200) {
    header('Location: index.php#apply');
    exit;
}

$me = json_decode($body2, true);

// 여기서 원하는 값 추출
$nickname = (string)($me['kakao_account']['profile']['nickname'] ?? '');
$phoneNum = (string)($me['kakao_account']['phone_number'] ?? ''); // 동의/설정되면 내려옴 :contentReference[oaicite:6]{index=6}

// 세션에 저장(폼 자동채움 용)
$_SESSION['kakao_profile'] = [
    'nickname' => $nickname,
    'phone_number' => $phoneNum, // "+82 010-xxxx-xxxx" 형태일 수 있음 :contentReference[oaicite:7]{index=7}
];

// index.php 폼 위치로 복귀
header('Location: index.php#apply');
exit;