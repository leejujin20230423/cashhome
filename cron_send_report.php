<?php
declare(strict_types=1);

// ✅ 3시간마다 통계 메일 발송용 크론 전용 파일
// 크론 예시:
//   0 */3 * * * /usr/bin/php /var/www/cashhome/cron_send_report.php >/dev/null 2>&1

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    echo "Forbidden";
    exit;
}

$php = PHP_BINARY ?: '/usr/bin/php';
$target = __DIR__ . '/admin_inquiries.php';

$cmd = escapeshellcmd($php) . ' ' . escapeshellarg($target) . ' --send-report';
passthru($cmd, $code);
exit((int)$code);
