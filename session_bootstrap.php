<?php
declare(strict_types=1);

/**
 * session_bootstrap.php
 * - 모든 페이지에서 동일한 세션 쿠키 옵션으로 세션을 시작해야 OAuth 리다이렉트 후에도 세션이 유지됨
 */

$isHttps = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
    || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
);

// ⚠️ 중요: 모든 파일에서 동일하게
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    // 필요하면 도메인 고정 (서브도메인 공유 필요 시 .bizstore.co.kr)
    // 'domain' => 'cashhome.bizstore.co.kr',
    'secure' => $isHttps,     // ✅ https에서만 secure
    'httponly' => true,
    'samesite' => 'Lax',      // ✅ 카카오 OAuth 리다이렉트 안정적
]);

session_start();