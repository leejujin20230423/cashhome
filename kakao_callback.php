<?php
declare(strict_types=1);

/**
 * kakao_callback.php
 * - 카카오에서 돌아오면 토큰 발급 -> /v2/user/me 조회
 * - nickname(성함) 세션 저장
 * - 실패 원인을 $_SESSION['kakao_error']로 저장해서 index.php에서 alert로 보여줌
 */

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

const KAKAO_REST_API_KEY = 'd6cf1b953dfb5b853674b0c265090b1b';
const KAKAO_CLIENT_SECRET = 'YqcjxkwRyqjK813eckdVyn4eAP87q4U7'; // Secret ON일 때만 의미 있음
const KAKAO_REDIRECT_URI = 'https://cashhome.bizstore.co.kr/kakao_callback.php';

function http_post_form(string $url, array $data): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($data),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/x-www-form-urlencoded;charset=utf-8',
        ],
        CURLOPT_TIMEOUT => 15,
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = (string)curl_error($ch);
    curl_close($ch);
    return [$code, $body !== false ? (string)$body : '', $err];
}

function http_get(string $url, array $headers = []): array {
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_TIMEOUT => 15,
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = (string)curl_error($ch);
    curl_close($ch);
    return [$code, $body !== false ? (string)$body : '', $err];
}

function json_array(string $json): array {
    $d = json_decode($json, true);
    return is_array($d) ? $d : [];
}

function normalize_phone_kr(string $phone): string {
    $p = trim($phone);
    if ($p === '') return '';
    $p = str_replace([' ', '-', '(', ')'], '', $p);

    if (str_starts_with($p, '+82')) {
        $p = substr($p, 3);
        $p = ltrim($p, '0');
        $p = '0' . $p;
    }
    $digits = preg_replace('/\D+/', '', $p) ?? '';
    if ($digits === '') return '';

    if (strlen($digits) === 11) return preg_replace('/^(\d{3})(\d{4})(\d{4})$/', '$1-$2-$3', $digits) ?? $digits;
    if (strlen($digits) === 10) return preg_replace('/^(\d{3})(\d{3})(\d{4})$/', '$1-$2-$3', $digits) ?? $digits;
    return $digits;
}

// ✅ return 가져오기
$return = (string)($_SESSION['kakao_return'] ?? 'index.php#apply');
unset($_SESSION['kakao_return']);

// ✅ 카카오에서 에러로 돌아온 경우
if (!empty($_GET['error'])) {
    $_SESSION['kakao_error'] = '카카오 에러: ' . (string)($_GET['error_description'] ?? $_GET['error']);
    header('Location: ' . $return);
    exit;
}

$code  = (string)($_GET['code'] ?? '');
$state = (string)($_GET['state'] ?? '');

if ($code === '' || $state === '') {
    $_SESSION['kakao_error'] = '카카오 콜백 파라미터(code/state)가 없습니다.';
    header('Location: ' . $return);
    exit;
}

if (empty($_SESSION['kakao_oauth_state']) || !hash_equals((string)$_SESSION['kakao_oauth_state'], $state)) {
    $_SESSION['kakao_error'] = '카카오 로그인 state 검증 실패(세션/SameSite 설정 문제 가능)';
    header('Location: ' . $return);
    exit;
}
unset($_SESSION['kakao_oauth_state']);

// 1) 토큰 발급
$tokenReq = [
    'grant_type'   => 'authorization_code',
    'client_id'    => KAKAO_REST_API_KEY,
    'redirect_uri' => KAKAO_REDIRECT_URI,
    'code'         => $code,
];

// ✅ secret은 넣어도 되지만, 콘솔에서 Secret OFF면 실패할 수 있음.
// 여기서는 값이 있으면 보내도록 했는데, 만약 계속 토큰 실패면 이 줄을 주석 처리해봐.
if (KAKAO_CLIENT_SECRET !== '') {
    $tokenReq['client_secret'] = KAKAO_CLIENT_SECRET;
}

[$http, $body, $err] = http_post_form('https://kauth.kakao.com/oauth/token', $tokenReq);

if ($http !== 200) {
    $_SESSION['kakao_error'] = '카카오 토큰 발급 실패 (HTTP ' . $http . ')';
    error_log('[KAKAO TOKEN FAIL] http=' . $http . ' err=' . $err . ' body=' . $body);
    header('Location: ' . $return);
    exit;
}

$token = json_array($body);
$accessToken = (string)($token['access_token'] ?? '');
if ($accessToken === '') {
    $_SESSION['kakao_error'] = '카카오 토큰 응답에 access_token이 없습니다.';
    error_log('[KAKAO TOKEN NO ACCESS_TOKEN] body=' . $body);
    header('Location: ' . $return);
    exit;
}

// 2) 사용자 정보 조회
[$http2, $body2, $err2] = http_get('https://kapi.kakao.com/v2/user/me', [
    'Authorization: Bearer ' . $accessToken,
    'Content-Type: application/x-www-form-urlencoded;charset=utf-8',
]);

if ($http2 !== 200) {
    $_SESSION['kakao_error'] = '카카오 사용자 정보 조회 실패 (HTTP ' . $http2 . ')';
    error_log('[KAKAO ME FAIL] http=' . $http2 . ' err=' . $err2 . ' body=' . $body2);
    header('Location: ' . $return);
    exit;
}

$me = json_array($body2);
$nickname = (string)($me['kakao_account']['profile']['nickname'] ?? '');
$phoneRaw = (string)($me['kakao_account']['phone_number'] ?? '');
$phone = normalize_phone_kr($phoneRaw);

// ✅ 세션 저장 (index.php 자동 채움)
$_SESSION['kakao_profile'] = [
    'nickname' => $nickname,
    'phone_number' => $phone,
];

$_SESSION['kakao_ok'] = $nickname !== ''
    ? '카카오 로그인 완료! 성함이 자동 입력되었습니다.'
    : '카카오 로그인 완료! (성함 정보는 제공되지 않았습니다.)';

header('Location: ' . $return);
exit;