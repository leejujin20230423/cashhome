<?php
declare(strict_types=1);

class MailSender
{
    private string $GMAIL_USER;
    private string $GMAIL_APP_PASSWORD;
    private string $MAIL_TO;

    /**
     * CLI/cron 환경에서도 .env 값을 읽을 수 있게 로드
     * - 이미 설정된 환경변수/$_ENV 값은 덮어쓰지 않음
     */
    private function loadDotEnv(): void
    {
        $path = __DIR__ . '/.env';
        if (!is_file($path) || !is_readable($path)) return;

        // .env가 key=value 형태면 parse_ini_file로 안정적으로 로드 가능
        $vars = @parse_ini_file($path, false, INI_SCANNER_RAW);
        if (!is_array($vars)) return;

        foreach ($vars as $k => $v) {
            $k = trim((string)$k);
            if ($k === '') continue;

            // parse_ini_file은 따옴표를 포함해서 주는 경우가 있어 trim 처리
            $val = is_string($v) ? trim($v) : (string)$v;

            // 이미 설정된 값이 있으면 덮어쓰지 않음
            if (array_key_exists($k, $_ENV)) continue;
            if (getenv($k) !== false) continue;

            $_ENV[$k] = $val;
            putenv($k . '=' . $val);
        }
    }

    /**
     * getenv()는 값이 없으면 false를 반환하므로 string으로 안전 변환
     */
    private function envString(string $key, string $default = ''): string
    {
        $v = $_ENV[$key] ?? null;
        if (is_string($v) && $v !== '') return $v;

        $g = getenv($key);
        if ($g === false || $g === '') return $default;

        return (string)$g;
    }

    public function __construct()
    {
        // ✅ cron/CLI에서도 .env 읽도록
        $this->loadDotEnv();

        // ✅ getenv(false) 타입 에러 방지
        $this->GMAIL_USER = $this->envString('GMAIL_USER', 'ecashhome@gmail.com');
        $this->GMAIL_APP_PASSWORD = $this->envString('GMAIL_APP_PASSWORD', '');
        $this->MAIL_TO = $this->envString('MAIL_TO', $this->GMAIL_USER);

        if ($this->GMAIL_APP_PASSWORD === '') {
            error_log('[mail_sender] Missing env: GMAIL_APP_PASSWORD');
        }
    }

    private function encodeHeaderUtf8(string $s): string
    {
        return "=?UTF-8?B?" . base64_encode($s) . "?=";
    }

    /**
     * SMTP raw send (Gmail 587 STARTTLS)
     * $rawData should contain full RFC822 message (headers + blank line + body)
     */
    private function smtpSendRaw(string $rawData): bool
    {
        $host = 'smtp.gmail.com';
        $port = 587;

        $socket = @fsockopen($host, $port, $errno, $errstr, 20);
        if (!$socket) {
            error_log("[mail_sender] SMTP connect failed: $errno $errstr");
            return false;
        }

        $read = function () use ($socket): string {
            $data = '';
            while (!feof($socket)) {
                $line = fgets($socket, 515);
                if ($line === false) break;
                $data .= $line;
                if (preg_match('/^\d{3} /', $line)) break;
            }
            return $data;
        };

        $write = function (string $cmd) use ($socket): void {
            fwrite($socket, $cmd . "\r\n");
        };

        $expect = function (string $resp, array $codes): bool {
            $code = (int)substr($resp, 0, 3);
            return in_array($code, $codes, true);
        };

        $resp = $read();
        if (!$expect($resp, [220])) {
            fclose($socket);
            return false;
        }

        $write("EHLO localhost");
        $resp = $read();
        if (!$expect($resp, [250])) {
            fclose($socket);
            return false;
        }

        $write("STARTTLS");
        $resp = $read();
        if (!$expect($resp, [220])) {
            fclose($socket);
            return false;
        }

        if (!@stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
            error_log("[mail_sender] TLS failed");
            fclose($socket);
            return false;
        }

        $write("EHLO localhost");
        $resp = $read();
        if (!$expect($resp, [250])) {
            fclose($socket);
            return false;
        }

        // AUTH LOGIN
        $write("AUTH LOGIN");
        $resp = $read();
        if (!$expect($resp, [334])) {
            fclose($socket);
            return false;
        }

        $write(base64_encode($this->GMAIL_USER));
        $resp = $read();
        if (!$expect($resp, [334])) {
            fclose($socket);
            return false;
        }

        $write(base64_encode($this->GMAIL_APP_PASSWORD));
        $resp = $read();
        if (!$expect($resp, [235])) {
            error_log("[mail_sender] AUTH failed: " . trim($resp));
            fclose($socket);
            return false;
        }

        $write("MAIL FROM:<{$this->GMAIL_USER}>");
        $resp = $read();
        if (!$expect($resp, [250])) {
            fclose($socket);
            return false;
        }

        $write("RCPT TO:<{$this->MAIL_TO}>");
        $resp = $read();
        if (!$expect($resp, [250, 251])) {
            fclose($socket);
            return false;
        }

        $write("DATA");
        $resp = $read();
        if (!$expect($resp, [354])) {
            fclose($socket);
            return false;
        }

        // End with <CRLF>.<CRLF>
        fwrite($socket, $rawData . "\r\n.\r\n");
        $resp = $read();
        if (!$expect($resp, [250])) {
            error_log("[mail_sender] DATA failed: " . trim($resp));
            fclose($socket);
            return false;
        }

        $write("QUIT");
        fclose($socket);
        return true;
    }

    /**
     * 첨부 포함(또는 첨부 없이) text/plain 메일 전송
     * $attachments: [ ['path'=>'/path/a.jpg','filename'=>'a.jpg','mime'=>'image/jpeg'], ... ]
     */
    public function sendEmailWithAttachments(string $subject, string $bodyText, array $attachments = []): bool
    {
        $boundary = '==MIXED_' . bin2hex(random_bytes(12));

        $headers = [
            "From: ECashHome <{$this->GMAIL_USER}>",
            "MIME-Version: 1.0",
            "Content-Type: multipart/mixed; boundary=\"{$boundary}\"",
        ];

        $parts = [];

        // text/plain
        $parts[] =
            "--{$boundary}\r\n" .
            "Content-Type: text/plain; charset=UTF-8\r\n" .
            "Content-Transfer-Encoding: 8bit\r\n\r\n" .
            str_replace("\n", "\r\n", $bodyText) . "\r\n";

        // attachments
        foreach ($attachments as $a) {
            if (!is_array($a)) continue;

            $path = (string)($a['path'] ?? '');
            $filename = (string)($a['filename'] ?? '');
            if ($path === '' || !is_file($path)) continue;

            $mime = (string)($a['mime'] ?? '');
            if ($mime === '') {
                $mime = function_exists('mime_content_type') ? (string)@mime_content_type($path) : '';
                if ($mime === '') $mime = 'application/octet-stream';
            }

            $data = @file_get_contents($path);
            if ($data === false) continue;

            $b64 = chunk_split(base64_encode($data), 76, "\r\n");
            $safeFilename = $filename !== '' ? $filename : basename($path);
            $safeFilename = str_replace(['"', "\r", "\n"], '', $safeFilename);

            $parts[] =
                "--{$boundary}\r\n" .
                "Content-Type: {$mime}; name=\"{$safeFilename}\"\r\n" .
                "Content-Transfer-Encoding: base64\r\n" .
                "Content-Disposition: attachment; filename=\"{$safeFilename}\"\r\n\r\n" .
                $b64 . "\r\n";
        }

        $parts[] = "--{$boundary}--\r\n";

        // 1) SMTP try (only if app password present)
        if ($this->GMAIL_APP_PASSWORD !== '') {
            $raw =
                "From: ECashHome <{$this->GMAIL_USER}>\r\n" .
                "To: <{$this->MAIL_TO}>\r\n" .
                "Subject: " . $this->encodeHeaderUtf8($subject) . "\r\n" .
                implode("\r\n", $headers) . "\r\n\r\n" .
                implode('', $parts);

            $ok = $this->smtpSendRaw($raw);
            if ($ok) return true;

            error_log('[mail_sender] SMTP send failed. fallback to mail()');
        }

        // 2) mail() fallback
        $headerStr = implode("\r\n", $headers);
        $ok = @mail($this->MAIL_TO, $this->encodeHeaderUtf8($subject), implode('', $parts), $headerStr);
        if (!$ok) error_log('[mail_sender] mail() failed');
        return (bool)$ok;
    }

    // 상담 접수 메일 (첨부 없음) - loan_no 뒤 4자리 우선
    public function sendLoanRequestEmail(array $payload, int $inquiryId = 0): bool
    {
        $name   = (string)($payload['name'] ?? '이름없음');
        $phone  = (string)($payload['phone'] ?? '-');
        $amount = (string)($payload['amount'] ?? '-');
        $region = (string)($payload['region'] ?? '-');
        $memo   = (string)($payload['memo'] ?? '-');

        $loanNo = (string)($payload['loan_no'] ?? '');
        $displayNo = $loanNo !== '' ? substr($loanNo, -4) : ($inquiryId > 0 ? "#{$inquiryId}" : '-');

        $subject = "[ECASH][상담접수] 접수번호 {$displayNo} {$name} / {$phone}";
        $body = implode("\n", [
            "📌 상담 신청 접수",
            "",
            "접수번호: {$displayNo}",
            "성함: {$name}",
            "연락처: {$phone}",
            "희망금액: {$amount}",
            "지역: {$region}",
            "메모: {$memo}",
            "",
            "접수시각: " . (new DateTime('now', new DateTimeZone('Asia/Seoul')))->format('Y-m-d H:i:s'),
        ]);

        return $this->sendEmailWithAttachments($subject, $body, []);
    }

    // 서류 업로드 알림 (첨부 없음) - loan_no 뒤 4자리 우선
    public function sendLoanDocumentSubmissionEmail(array $payload, int $inquiryId = 0): bool
    {
        $name   = (string)($payload['name'] ?? '이름없음');
        $phone  = (string)($payload['phone'] ?? '-');
        $amount = (string)($payload['amount'] ?? '-');
        $region = (string)($payload['region'] ?? '-');
        $memo   = (string)($payload['memo'] ?? '-');

        $loanNo = (string)($payload['loan_no'] ?? '');
        $displayNo = $loanNo !== '' ? substr($loanNo, -4) : ($inquiryId > 0 ? "#{$inquiryId}" : '-');

        $subject = "[ECASH][서류업로드알림] 접수번호 {$displayNo} {$name}";
        $body = implode("\n", [
            "📸 서류 업로드 알림",
            "",
            "성함: {$name}",
            "접수번호: {$displayNo}",
            "연락처: {$phone}",
            "희망금액: {$amount}",
            "지역: {$region}",
            "메모: {$memo}",
            "",
            "업로드시각: " . (new DateTime('now', new DateTimeZone('Asia/Seoul')))->format('Y-m-d H:i:s'),
        ]);

        return $this->sendEmailWithAttachments($subject, $body, []);
    }

    // HTML 메일 발송 (통계 리포트 등)
    public function sendHtmlTo(string $to, string $subject, string $bodyHtml, string $bodyPlainFallback = ''): bool
    {
        $to = trim($to);
        if ($to === '') $to = $this->MAIL_TO;

        $origTo = $this->MAIL_TO;
        $this->MAIL_TO = $to;
        try {
            return $this->sendEmailAlternative($subject, $bodyPlainFallback, $bodyHtml);
        } finally {
            $this->MAIL_TO = $origTo;
        }
    }

    // multipart/alternative (text/plain + text/html)
    private function sendEmailAlternative(string $subject, string $plain, string $html): bool
    {
        $altBoundary = '==ALT_' . bin2hex(random_bytes(12));

        $headers = [
            "From: ECashHome <{$this->GMAIL_USER}>",
            "MIME-Version: 1.0",
            "Content-Type: multipart/alternative; boundary=\"{$altBoundary}\"",
        ];

        $plain = $plain !== '' ? $plain : strip_tags($html);

        $body =
            "--{$altBoundary}\r\n" .
            "Content-Type: text/plain; charset=UTF-8\r\n" .
            "Content-Transfer-Encoding: 8bit\r\n\r\n" .
            str_replace("\n", "\r\n", $plain) . "\r\n" .
            "--{$altBoundary}\r\n" .
            "Content-Type: text/html; charset=UTF-8\r\n" .
            "Content-Transfer-Encoding: 8bit\r\n\r\n" .
            $html . "\r\n" .
            "--{$altBoundary}--\r\n";

        // 1) SMTP try
        if ($this->GMAIL_APP_PASSWORD !== '') {
            $raw =
                "From: ECashHome <{$this->GMAIL_USER}>\r\n" .
                "To: <{$this->MAIL_TO}>\r\n" .
                "Subject: " . $this->encodeHeaderUtf8($subject) . "\r\n" .
                implode("\r\n", $headers) . "\r\n\r\n" .
                $body;

            $ok = $this->smtpSendRaw($raw);
            if ($ok) return true;

            error_log('[mail_sender] SMTP send failed. fallback to mail() (html)');
        }

        // 2) mail() fallback
        $rawHeaders = implode("\r\n", $headers);
        $ok = @mail($this->MAIL_TO, $this->encodeHeaderUtf8($subject), $body, $rawHeaders);
        if (!$ok) error_log('[mail_sender] mail() failed (html)');
        return (bool)$ok;
    }

    // 텍스트 메일 전송(수신자 지정)
    public function sendPlainTextTo(string $to, string $subject, string $bodyText): bool
    {
        $to = trim($to);
        if ($to === '') $to = $this->MAIL_TO;

        $origTo = $this->MAIL_TO;
        $this->MAIL_TO = $to;
        try {
            return $this->sendEmailWithAttachments($subject, $bodyText, []);
        } finally {
            $this->MAIL_TO = $origTo;
        }
    }
}