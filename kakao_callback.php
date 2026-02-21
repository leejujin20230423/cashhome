<?php

declare(strict_types=1);

/**
 * kakao_callback.php
 * - code/state 수신
 * - state 검증
 * - 토큰 발급
 * - 사용자 정보 조회
 * - 세션에 kakao_profile 저장
 * - return으로 kakao_ok=1 또는 kakao_error=... 붙여 리다이렉트
 */

/* =========================================================
 * ✅ 세션 부트스트랩 (index.php / login 과 동일하게)
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
const KAKAO_CLIENT_SECRET = 'YqcjxkwRyqjK813eckdVyn4eAP87q4U7'; // 없으면 '' 가능
const KAKAO_REDIRECT_URI = 'https://cashhome.bizstore.co.kr/kakao_callback.php';

/* =========================
 * HTTP helpers
 * ========================= */
function http_post_form(string $url, array $data): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($data),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded;charset=utf-8'],
        CURLOPT_TIMEOUT => 15,
    ]);
    $body = curl_exec($ch);
    $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = (string)curl_error($ch);
    curl_close($ch);
    return [$code, $body !== false ? (string)$body : '', $err];
}

function http_get(string $url, array $headers = []): array
{
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

function json_array(string $json): array
{
    $d = json_decode($json, true);
    return is_array($d) ? $d : [];
}

/* =========================
 * 전화번호 정규화 (+82 -> 0xxx)
 * ========================= */
function normalize_phone_kr(string $phone): string
{
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

/* =========================================================
 * return(url+hash) 보존하면서 query 붙여 redirect
 * ========================================================= */
function redirect_with_query(string $return, array $q): void
{
    $u = parse_url($return);
    $path  = $u['path'] ?? 'index.php';
    $query = $u['query'] ?? '';
    $frag  = $u['fragment'] ?? '';

    parse_str($query, $orig);
    $merged = array_merge($orig, $q);
    $newQuery = http_build_query($merged);

    $url = $path;
    if ($newQuery !== '') $url .= '?' . $newQuery;
    if ($frag !== '') $url .= '#' . $frag;

    header('Location: ' . $url);
    exit;
}

/* =========================================================
 * 1) return 복원
 * ========================================================= */
$return = (string)($_SESSION['kakao_return'] ?? 'index.php#apply');
unset($_SESSION['kakao_return']);

/* =========================================================
 * 2) 카카오 에러 응답 처리
 * ========================================================= */
if (!empty($_GET['error'])) {
    $msg = (string)($_GET['error_description'] ?? $_GET['error']);
    redirect_with_query($return, ['kakao_error' => $msg]);
}

/* =========================================================
 * 3) code/state 확인
 * ========================================================= */
$code  = (string)($_GET['code'] ?? '');
$state = (string)($_GET['state'] ?? '');

if ($code === '' || $state === '') {
    redirect_with_query($return, ['kakao_error' => '콜백에 code/state 없음']);
}

/* =========================================================
 * 4) state 검증
 * ========================================================= */
if (empty($_SESSION['kakao_oauth_state']) || !hash_equals((string)$_SESSION['kakao_oauth_state'], $state)) {
    redirect_with_query($return, ['kakao_error' => 'state 검증 실패(세션 문제)']);
}
unset($_SESSION['kakao_oauth_state']);

/* =========================================================
 * 5) 토큰 발급
 * ========================================================= */
$tokenReq = [
    'grant_type'   => 'authorization_code',
    'client_id'    => KAKAO_REST_API_KEY,
    'redirect_uri' => KAKAO_REDIRECT_URI,
    'code'         => $code,
];

if (KAKAO_CLIENT_SECRET !== '') {
    $tokenReq['client_secret'] = KAKAO_CLIENT_SECRET;
}

[$http, $body, $err] = http_post_form('https://kauth.kakao.com/oauth/token', $tokenReq);

if ($http !== 200) {
    error_log('[KAKAO TOKEN FAIL] http=' . $http . ' err=' . $err . ' body=' . $body);
    redirect_with_query($return, ['kakao_error' => '토큰 발급 실패(HTTP ' . $http . ')']);
}

$token = json_array($body);
$accessToken = (string)($token['access_token'] ?? '');

if ($accessToken === '') {
    redirect_with_query($return, ['kakao_error' => 'access_token 없음']);
}

/* =========================================================
 * 6) 사용자 정보 조회
 * ========================================================= */
[$http2, $body2, $err2] = http_get('https://kapi.kakao.com/v2/user/me', [
    'Authorization: Bearer ' . $accessToken,
]);

if ($http2 !== 200) {
    error_log('[KAKAO ME FAIL] http=' . $http2 . ' err=' . $err2 . ' body=' . $body2);
    redirect_with_query($return, ['kakao_error' => '사용자정보 조회 실패(HTTP ' . $http2 . ')']);
}

$me = json_array($body2);
$nickname = (string)($me['kakao_account']['profile']['nickname'] ?? '');
$phoneRaw = (string)($me['kakao_account']['phone_number'] ?? '');
$phone = normalize_phone_kr($phoneRaw);

/* =========================================================
 * 7) 세션 저장
 * ========================================================= */
$_SESSION['kakao_profile'] = [
    'nickname' => $nickname,
    'phone_number' => $phone,
];

// 디버그: callback에서 세션이 실제로 저장되는지
$_SESSION['__debug_callback'] = [
  'time' => date('Y-m-d H:i:s'),
  'session_id' => session_id(),
  'cookie_name' => session_name(),
  'cookie_in_request' => $_COOKIE[session_name()] ?? null,
  'kakao_profile' => $_SESSION['kakao_profile'] ?? null,
];
/* =========================================================
 * 8) 리다이렉트
 * ========================================================= */
redirect_with_query($return, [
  'kakao_ok' => '1',
  'sid' => session_id(),   // ✅ 디버그용
]);


// redirect_with_query($return, ['kakao_ok' => '1']);
