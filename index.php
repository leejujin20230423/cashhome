<?php

declare(strict_types=1);

/**
 * ECASH (이케쉬대부) - Single-file index.php
 * - Responsive landing page
 * - Contact / 상담신청 form with CSRF + validation + honeypot
 * - Save inquiry to MySQL (PDO)
 * - Mail send (if configured) or fallback to file storage
 */

session_start();
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
// CSP는 환경에 따라 깨질 수 있어 기본은 완화. 운영 시 이미지/스크립트 정책을 맞춰 강화하세요.
header("Content-Security-Policy: default-src 'self' 'unsafe-inline' https: data:;");

/** HTML escape */
function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * ===== DB CONFIG =====
 * - 비밀번호(DB_PASS)는 직접 입력하세요.
 * - 운영 시에는 코드에 직접 넣지 말고, 환경변수(.env)로 분리하는 것을 권장합니다.
 */
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**'; // <-- 여기에 비밀번호 입력하세요

/**
 * 개인정보처리방침 버전 (문서 수정 시 v2, v3로 올리세요)
 */
const PRIVACY_POLICY_VERSION = 'v1';

/**
 * PDO 연결을 함수로 제공 (호출해서 사용)
 */
function cashhome_pdo(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';

    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $pdo;
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$successMsg = '';
$errorMsg = '';
$old = [
    'name' => '',
    'phone' => '',
    'amount' => '',
    'purpose' => '',
    'memo' => '',
    'agree_privacy' => '',
    'agree_marketing' => '',
];

// --- FORM HANDLER ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Honeypot (봇 방지)
    $hp = trim((string)($_POST['company_website'] ?? ''));
    if ($hp !== '') {
        // 조용히 성공처럼 처리(봇에 신호 주지 않기)
        $successMsg = '상담 신청이 접수되었습니다. 담당자가 확인 후 연락드리겠습니다.';
    } else {
        $token = (string)($_POST['csrf_token'] ?? '');
        if (!hash_equals($_SESSION['csrf_token'], $token)) {
            $errorMsg = '요청이 만료되었거나 올바르지 않습니다. 새로고침 후 다시 시도해주세요.';
        } else {
            // Collect
            $name = trim((string)($_POST['name'] ?? ''));
            $phone = trim((string)($_POST['phone'] ?? ''));
            $amount = trim((string)($_POST['amount'] ?? ''));
            $purpose = trim((string)($_POST['purpose'] ?? ''));
            $memo = trim((string)($_POST['memo'] ?? ''));
            $agree_privacy = (string)($_POST['agree_privacy'] ?? '');
            $agree_marketing = (string)($_POST['agree_marketing'] ?? '');

            $old = [
                'name' => $name,
                'phone' => $phone,
                'amount' => $amount,
                'purpose' => $purpose,
                'memo' => $memo,
                'agree_privacy' => $agree_privacy,
                'agree_marketing' => $agree_marketing,
            ];

            // Validate
            $errors = [];
            if ($name === '' || mb_strlen($name) < 2) {
                $errors[] = '성함을 2자 이상 입력해주세요.';
            }

            // 전화번호: 숫자/하이픈/공백 허용 후 숫자길이 체크
            $phoneDigits = preg_replace('/\D+/', '', $phone);
            if ($phoneDigits === null) $phoneDigits = '';
            if ($phoneDigits === '' || strlen($phoneDigits) < 9 || strlen($phoneDigits) > 12) {
                $errors[] = '연락처를 정확히 입력해주세요.';
            }

            // 금액(선택): 입력 시 숫자만 (표시 텍스트는 그대로 저장해도 되지만, 여기서는 입력 유효성만 체크)
            if ($amount !== '') {
                $amountDigits = preg_replace('/\D+/', '', $amount);
                if ($amountDigits === null || $amountDigits === '') {
                    $errors[] = '희망금액은 숫자로 입력해주세요.';
                }
            }

            // 개인정보 필수 동의
            if ($agree_privacy !== '1') {
                $errors[] = '개인정보 수집·이용 동의(필수)에 체크해주세요.';
            }

            if (mb_strlen($memo) > 1000) {
                $errors[] = '요청사항은 1000자 이하로 입력해주세요.';
            }

            if ($errors) {
                $errorMsg = implode(' ', $errors);
            } else {
                // Prepare
                $ts = date('Y-m-d H:i:s');
                $ip = $_SERVER['REMOTE_ADDR'] ?? '';
                $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

                // ===== DB INSERT (cashhome_1000_inquiries) =====
                // - 개인정보 동의 증적(버전/일시)을 함께 저장
                $newId = null;

                try {
                    $pdo = cashhome_pdo();

                    // 동의 일시 (필수 동의는 항상 1이지만, 방어적으로 처리)
                    $privacyAgreedAt = ($agree_privacy === '1') ? $ts : null;
                    $marketingAgreedAt = ($agree_marketing === '1') ? $ts : null;

                    $stmt = $pdo->prepare("
                        INSERT INTO cashhome_1000_inquiries (
                            cashhome_1000_created_at,
                            cashhome_1000_user_ip,
                            cashhome_1000_user_agent,
                            cashhome_1000_customer_name,
                            cashhome_1000_customer_phone,
                            cashhome_1000_loan_amount,
                            cashhome_1000_loan_purpose,
                            cashhome_1000_request_memo,
                            cashhome_1000_agree_privacy,
                            cashhome_1000_privacy_policy_version,
                            cashhome_1000_privacy_agreed_at,
                            cashhome_1000_agree_marketing,
                            cashhome_1000_marketing_agreed_at,
                            cashhome_1000_status
                        ) VALUES (
                            :created_at,
                            :user_ip,
                            :user_agent,
                            :customer_name,
                            :customer_phone,
                            :loan_amount,
                            :loan_purpose,
                            :request_memo,
                            :agree_privacy,
                            :privacy_policy_version,
                            :privacy_agreed_at,
                            :agree_marketing,
                            :marketing_agreed_at,
                            :status
                        )
                    ");

                    $stmt->execute([
                        ':created_at' => $ts,
                        ':user_ip' => $ip !== '' ? $ip : null,
                        ':user_agent' => $ua !== '' ? mb_substr($ua, 0, 255) : null,

                        ':customer_name' => $name,
                        ':customer_phone' => $phone,

                        // 선택값은 비어있으면 NULL 저장
                        ':loan_amount' => $amount !== '' ? $amount : null,
                        ':loan_purpose' => $purpose !== '' ? $purpose : null,
                        ':request_memo' => $memo !== '' ? $memo : null,

                        ':agree_privacy' => 1,
                        ':privacy_policy_version' => PRIVACY_POLICY_VERSION,
                        ':privacy_agreed_at' => $privacyAgreedAt,

                        ':agree_marketing' => ($agree_marketing === '1') ? 1 : 0,
                        ':marketing_agreed_at' => $marketingAgreedAt,

                        ':status' => 'new',
                    ]);

                    $newId = (int)$pdo->lastInsertId();
                } catch (Throwable $e) {
                    error_log('[DB INSERT ERROR] ' . $e->getMessage());
                    $errorMsg = '일시적인 오류로 접수가 완료되지 않았습니다. 잠시 후 다시 시도해주세요.';
                }

                // DB 저장 성공시에만 알림(메일/파일) 진행
                if ($errorMsg === '') {
                    $payload = [
                        'time' => $ts,
                        'db_id' => $newId,
                        'ip' => $ip,
                        'user_agent' => $ua,
                        'name' => $name,
                        'phone' => $phone,
                        'amount' => $amount,
                        'purpose' => $purpose,
                        'memo' => $memo,
                        'privacy_policy_version' => PRIVACY_POLICY_VERSION,
                        'agree_privacy' => 'Y',
                        'agree_marketing' => $agree_marketing === '1' ? 'Y' : 'N',
                    ];

                    // ✅ 운영 시 여기 이메일을 실제 수신 메일로 변경
                    $to = 'your@email.com';
                    $subject = '[ECASH] 상담 신청 접수';
                    $bodyLines = [];
                    foreach ($payload as $k => $v) $bodyLines[] = strtoupper($k) . ': ' . $v;
                    $body = implode("\n", $bodyLines);

                    $sent = false;

                    // mail() 사용 가능할 때만
                    if (function_exists('mail')) {
                        $headers = "Content-Type: text/plain; charset=UTF-8\r\n";
                        $headers .= "From: no-reply@{$_SERVER['HTTP_HOST']}\r\n";
                        $sent = @mail($to, $subject, $body, $headers);
                    }

                    // Fallback: 파일 저장 (서버 메일 미설정 대비)
                    if (!$sent) {
                        $dir = __DIR__ . '/data';
                        if (!is_dir($dir)) @mkdir($dir, 0755, true);
                        $file = $dir . '/inquiries-' . date('Y-m') . '.log';
                        $line = json_encode($payload, JSON_UNESCAPED_UNICODE) . PHP_EOL;
                        @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
                    }

                    // Rotate CSRF
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                    $successMsg = '상담 신청이 접수되었습니다. 담당자가 확인 후 연락드리겠습니다.';
                    $old = [
                        'name' => '',
                        'phone' => '',
                        'amount' => '',
                        'purpose' => '',
                        'memo' => '',
                        'agree_privacy' => '',
                        'agree_marketing' => '',
                    ];
                }
            }
        }
    }
}

// --- DISPLAY DATA (사업자/등록 정보는 실제 값으로 교체하세요) ---
$brandKr = '이케쉬대부';
$brandEn = 'ECASH';

// ✅ 요청 반영: 전화번호/주소 업데이트
$companyInfo = [
    '상호' => $brandKr,
    '영문' => $brandEn,
    '대표' => '홍길동',
    '사업자등록번호' => '000-00-00000',
    '대부업등록번호' => '제0000-대부-0000호',
    '등록기관' => '○○시청(또는 금융감독원 등록 현황 기준)',
    '주소' => '충남 천안시 동남구 봉명동 9번지',
    '대표전화' => '010-5651-0030',
    '운영시간' => '평일 09:00 ~ 18:00 (주말/공휴일 휴무)',
];

// ✅ 이자율/연체이자/중개수수료 등 표기는 실제 약관/상품 기준으로 교체
$disclosure = [
    '최고금리' => '법정 최고금리 이내 (상품/신용도에 따라 차등)',
    '연체이자' => '약정금리 + 연체가산금리 (법정 한도 이내)',
    '중개수수료' => '대출중개수수료 없음 (당사 기준)',
    '유의사항' => '과도한 대출은 개인신용평점 하락의 원인이 될 수 있으며, 연체 시 신용정보에 등록될 수 있습니다.',
];
?>
<!doctype html>
<html lang="ko">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#0B1220" />
    <title><?= h($brandEn) ?> | <?= h($brandKr) ?> - 빠르고 간편한 상담</title>
    <meta name="description" content="<?= h($brandEn) ?>(<?= h($brandKr) ?>) 대출 상담/한도조회/상담신청. 빠르고 정확한 안내를 제공합니다." />
    <meta name="robots" content="index,follow" />
    <meta property="og:title" content="<?= h($brandEn) ?> | <?= h($brandKr) ?>" />
    <meta property="og:description" content="빠르고 간편한 상담신청. 담당자가 확인 후 연락드립니다." />
    <meta property="og:type" content="website" />

    <style>
        :root {
            --bg: #0B1220;
            --card: #101A33;
            --muted: #9DB0D0;
            --text: #EAF0FF;
            --accent: #6EE7FF;
            --accent2: #A78BFA;
            --line: rgba(234, 240, 255, .12);
            --shadow: 0 10px 30px rgba(0, 0, 0, .35);
            --radius: 18px;
            --radius2: 24px;
            --max: 1120px;
        }

        * {
            box-sizing: border-box
        }

        html,
        body {
            height: 100%
        }

        body {
            margin: 0;
            font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans KR", "Apple SD Gothic Neo", "Malgun Gothic", sans-serif;
            background:
                radial-gradient(1200px 600px at 20% -10%, rgba(110, 231, 255, .28), transparent 60%),
                radial-gradient(900px 520px at 90% 10%, rgba(167, 139, 250, .25), transparent 55%),
                radial-gradient(900px 520px at 40% 110%, rgba(110, 231, 255, .12), transparent 55%),
                var(--bg);
            color: var(--text);
            line-height: 1.5;
        }

        a {
            color: inherit
        }

        .wrap {
            max-width: var(--max);
            margin: 0 auto;
            padding: 22px 18px 80px;
        }

        .nav {
            position: sticky;
            top: 0;
            z-index: 30;
            backdrop-filter: blur(12px);
            background: rgba(11, 18, 32, .55);
            border-bottom: 1px solid var(--line);
        }

        .navin {
            max-width: var(--max);
            margin: 0 auto;
            padding: 12px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            text-decoration: none
        }

        .logo {
            width: 40px;
            height: 40px;
            border-radius: 14px;
            background: linear-gradient(135deg, rgba(110, 231, 255, .9), rgba(167, 139, 250, .85));
            box-shadow: var(--shadow);
            display: grid;
            place-items: center;
            font-weight: 800;
            color: #081022;
            letter-spacing: .5px;
        }

        .brand strong {
            display: block;
            font-size: 14px;
            letter-spacing: .6px
        }

        .brand span {
            display: block;
            font-size: 12px;
            color: var(--muted)
        }

        .navlinks {
            display: flex;
            gap: 14px;
            align-items: center;
            flex-wrap: wrap;
            justify-content: flex-end
        }

        .navlinks a {
            text-decoration: none;
            color: var(--muted);
            font-size: 13px;
            padding: 8px 10px;
            border-radius: 999px;
            border: 1px solid transparent;
        }

        .navlinks a:hover {
            color: var(--text);
            border-color: var(--line);
            background: rgba(255, 255, 255, .04)
        }

        .cta {
            text-decoration: none;
            padding: 10px 14px;
            border-radius: 999px;
            background: linear-gradient(135deg, rgba(110, 231, 255, .9), rgba(167, 139, 250, .9));
            color: #061025;
            font-weight: 800;
            font-size: 13px;
            box-shadow: var(--shadow);
            border: 0;
            cursor: pointer;
            white-space: nowrap;
        }

        .hero {
            padding: 26px 0 10px;
            display: grid;
            gap: 16px;
            grid-template-columns: 1.2fr .8fr;
            align-items: stretch;
        }

        .card {
            background: rgba(16, 26, 51, .78);
            border: 1px solid var(--line);
            border-radius: var(--radius2);
            box-shadow: var(--shadow);
        }

        .heroL {
            padding: 26px 22px;
        }

        .kicker {
            display: inline-flex;
            gap: 8px;
            align-items: center;
            color: var(--muted);
            font-size: 12px;
            padding: 6px 10px;
            border: 1px solid var(--line);
            border-radius: 999px;
            background: rgba(255, 255, 255, .03);
        }

        .dot {
            width: 8px;
            height: 8px;
            border-radius: 99px;
            background: var(--accent);
            box-shadow: 0 0 18px rgba(110, 231, 255, .7)
        }

        h1 {
            margin: 12px 0 10px;
            font-size: 36px;
            line-height: 1.15;
            letter-spacing: -0.6px
        }

        .sub {
            color: var(--muted);
            margin: 0 0 18px;
            font-size: 14px
        }

        .bullets {
            display: grid;
            gap: 10px;
            margin: 14px 0 20px;
        }

        .b {
            display: flex;
            gap: 10px;
            align-items: flex-start;
            padding: 10px 12px;
            border-radius: var(--radius);
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
        }

        .b i {
            width: 22px;
            height: 22px;
            border-radius: 10px;
            background: rgba(110, 231, 255, .18);
            border: 1px solid rgba(110, 231, 255, .22);
            display: inline-block;
            margin-top: 1px;
        }

        .b strong {
            display: block;
            font-size: 13px
        }

        .b span {
            display: block;
            font-size: 12px;
            color: var(--muted)
        }

        .heroBtns {
            display: flex;
            gap: 10px;
            flex-wrap: wrap
        }

        .btnGhost {
            background: transparent;
            border: 1px solid var(--line);
            color: var(--text);
            padding: 10px 14px;
            border-radius: 999px;
            text-decoration: none;
            font-weight: 700;
            font-size: 13px;
        }

        .btnGhost:hover {
            background: rgba(255, 255, 255, .05)
        }

        .heroR {
            padding: 18px;
            display: grid;
            gap: 12px
        }

        .mini {
            padding: 14px 14px;
            border-radius: var(--radius2);
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
        }

        .mini h3 {
            margin: 0 0 8px;
            font-size: 14px
        }

        .mini p {
            margin: 0;
            color: var(--muted);
            font-size: 12px
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 14px;
            margin-top: 14px;
        }

        .col4 {
            grid-column: span 4
        }

        .col6 {
            grid-column: span 6
        }

        .col12 {
            grid-column: span 12
        }

        .sectionTitle {
            margin: 26px 0 10px;
            font-size: 18px;
            letter-spacing: -0.2px;
        }

        .sectionSub {
            margin: 0 0 12px;
            color: var(--muted);
            font-size: 13px
        }

        .box {
            padding: 18px
        }

        .box h3 {
            margin: 0 0 8px;
            font-size: 15px
        }

        .box p {
            margin: 0;
            color: var(--muted);
            font-size: 13px
        }

        .pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 10px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            color: var(--muted);
            font-size: 12px;
        }

        .formWrap {
            padding: 18px
        }

        form {
            display: grid;
            gap: 10px
        }

        .row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px
        }

        label {
            font-size: 12px;
            color: var(--muted)
        }

        input,
        select,
        textarea {
            width: 100%;
            padding: 12px 12px;
            border-radius: 14px;
            border: 1px solid var(--line);
            background: rgba(8, 12, 24, .55);
            color: var(--text);
            outline: none;
        }

        input:focus,
        select:focus,
        textarea:focus {
            border-color: rgba(110, 231, 255, .55);
            box-shadow: 0 0 0 3px rgba(110, 231, 255, .12)
        }

        textarea {
            min-height: 110px;
            resize: vertical
        }

        .checks {
            display: grid;
            gap: 8px;
            margin-top: 6px
        }

        .check {
            display: flex;
            gap: 10px;
            align-items: flex-start;
            padding: 10px 12px;
            border: 1px solid var(--line);
            border-radius: 16px;
            background: rgba(255, 255, 255, .03);
        }

        .check input {
            width: 18px;
            height: 18px;
            margin-top: 2px
        }

        .check small {
            display: block;
            color: var(--muted);
            font-size: 12px;
            margin-top: 2px
        }

        .alert {
            padding: 12px 14px;
            border-radius: 16px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            color: var(--text);
            font-size: 13px;
        }

        .alert.ok {
            border-color: rgba(110, 231, 255, .35)
        }

        .alert.err {
            border-color: rgba(255, 120, 120, .35)
        }

        .footer {
            margin-top: 22px;
            padding: 18px;
            color: var(--muted);
            font-size: 12px;
        }

        .footer .cols {
            display: grid;
            grid-template-columns: 1.2fr .8fr;
            gap: 14px
        }

        .kv {
            display: grid;
            gap: 6px
        }

        .kv div {
            display: flex;
            gap: 10px;
            align-items: flex-start
        }

        .kv b {
            min-width: 110px;
            color: rgba(234, 240, 255, .85)
        }

        .hr {
            height: 1px;
            background: var(--line);
            margin: 14px 0
        }

        .tiny {
            font-size: 11px;
            color: rgba(157, 176, 208, .9)
        }

        .topbtn {
            position: fixed;
            right: 16px;
            bottom: 16px;
            z-index: 50;
            padding: 10px 12px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(16, 26, 51, .8);
            color: var(--text);
            cursor: pointer;
            box-shadow: var(--shadow);
            display: none;
        }

        @media (max-width: 920px) {
            .hero {
                grid-template-columns: 1fr;
            }

            .row {
                grid-template-columns: 1fr;
            }

            .col4,
            .col6 {
                grid-column: span 12;
            }

            h1 {
                font-size: 30px
            }

            .footer .cols {
                grid-template-columns: 1fr
            }
        }
    </style>
</head>

<body>
    <div class="nav">
        <div class="navin">
            <a class="brand" href="#top" aria-label="<?= h($brandEn) ?> 홈으로">
                <div class="logo">E</div>
                <div>
                    <strong><?= h($brandEn) ?></strong>
                    <span><?= h($brandKr) ?></span>
                </div>
            </a>

            <div class="navlinks" role="navigation" aria-label="상단 메뉴">
                <a href="#services">서비스</a>
                <a href="#process">절차</a>
                <a href="#disclosure">고지</a>
                <a href="#apply">상담신청</a>
                <a class="cta" href="#apply">빠른 상담</a>
            </div>
        </div>
    </div>

    <main class="wrap" id="top">
        <section class="hero">
            <div class="card heroL">
                <div class="kicker"><span class="dot"></span> 신속 · 정확 · 친절 상담</div>
                <h1>
                    <?= h($brandEn) ?>,<br />
                    필요한 순간에 <span style="color:var(--accent)">빠르게</span> 안내드립니다.
                </h1>
                <p class="sub">
                    이케쉬대부(ECASH)는 상담 신청 접수 후 담당자가 확인하여 연락드립니다.
                    (※ 실제 조건은 심사/신용도/상품에 따라 달라질 수 있습니다.)
                </p>

                <div class="bullets" aria-label="핵심 장점">
                    <div class="b"><i></i>
                        <div><strong>간편 상담 신청</strong><span>기본 정보 입력으로 빠르게 접수</span></div>
                    </div>
                    <div class="b"><i></i>
                        <div><strong>개인정보 최소 수집</strong><span>상담에 필요한 항목 중심으로 안내</span></div>
                    </div>
                    <div class="b"><i></i>
                        <div><strong>투명한 고지</strong><span>금리/유의사항 등 필수 정보를 명확히 안내</span></div>
                    </div>
                </div>

                <div class="heroBtns">
                    <a class="cta" href="#apply">상담 신청하기</a>
                    <a class="btnGhost" href="#disclosure">필수 고지 확인</a>
                </div>
            </div>

            <aside class="card heroR" aria-label="요약 정보">
                <div class="mini">
                    <h3>운영시간</h3>
                    <p><?= h($companyInfo['운영시간']) ?></p>
                </div>
                <div class="mini">
                    <h3>대표전화</h3>
                    <p><?= h($companyInfo['대표전화']) ?></p>
                </div>
                <div class="mini">
                    <h3>안내</h3>
                    <p>상담은 본인 확인 및 심사 과정이 포함될 수 있으며, 과도한 대출은 금융 부담을 초래할 수 있습니다.</p>
                </div>
            </aside>
        </section>

        <section id="services">
            <h2 class="sectionTitle">서비스</h2>
            <p class="sectionSub">상담부터 안내까지, 핵심 흐름을 간결하게 구성했습니다.</p>

            <div class="grid">
                <div class="card box col4">
                    <div class="pill">01 · 상담 접수</div>
                    <h3>기본 정보로 접수</h3>
                    <p>연락처/희망금액/용도 등 최소 항목으로 빠르게 접수합니다.</p>
                </div>
                <div class="card box col4">
                    <div class="pill">02 · 가능 여부 안내</div>
                    <h3>조건/유의사항 고지</h3>
                    <p>상품/신용도에 따라 가능한 범위와 필수 고지 사항을 안내합니다.</p>
                </div>
                <div class="card box col4">
                    <div class="pill">03 · 진행 및 문의</div>
                    <h3>추가 문의 대응</h3>
                    <p>필요 시 추가 서류/절차를 안내하고 문의를 지원합니다.</p>
                </div>
            </div>
        </section>

        <section id="process">
            <h2 class="sectionTitle">진행 절차</h2>
            <p class="sectionSub">웹에서 접수 → 확인 연락 → 안내(심사/조건/유의사항) 순으로 진행됩니다.</p>

            <div class="grid">
                <div class="card box col6">
                    <h3>상담 신청</h3>
                    <p>아래 폼을 작성하시면 접수됩니다. (필수 동의 포함)</p>
                </div>
                <div class="card box col6">
                    <h3>담당자 확인 연락</h3>
                    <p>접수 내용 확인 후 연락드리며, 필요 시 추가 정보를 요청드릴 수 있습니다.</p>
                </div>
                <div class="card box col6">
                    <h3>조건 안내</h3>
                    <p>금리/상환/유의사항 등 필수 내용을 사전에 명확히 안내합니다.</p>
                </div>
                <div class="card box col6">
                    <h3>최종 진행</h3>
                    <p>본인 의사에 따라 진행되며, 계약 전 반드시 내용을 확인하세요.</p>
                </div>
            </div>
        </section>

        <section id="disclosure">
            <h2 class="sectionTitle">필수 고지</h2>
            <p class="sectionSub">아래 내용은 예시입니다. 실제 수치/문구는 반드시 귀사 정보로 교체하세요.</p>

            <div class="grid">
                <div class="card box col6">
                    <h3>금리 및 비용</h3>
                    <p>• 최고금리: <?= h($disclosure['최고금리']) ?></p>
                    <p>• 연체이자: <?= h($disclosure['연체이자']) ?></p>
                    <p>• 중개수수료: <?= h($disclosure['중개수수료']) ?></p>
                </div>
                <div class="card box col6">
                    <h3>유의사항</h3>
                    <p><?= h($disclosure['유의사항']) ?></p>
                    <p class="tiny" style="margin-top:8px;">※ 위 문구는 일반 안내이며, 개별 계약 조건에 따라 달라질 수 있습니다.</p>
                </div>
            </div>
        </section>

        <section id="apply">
            <h2 class="sectionTitle">상담 신청</h2>
            <p class="sectionSub">접수 후 담당자가 확인하여 연락드립니다. (필수 동의 체크 필요)</p>

            <div class="grid">
                <div class="card formWrap col12">
                    <?php if ($successMsg): ?>
                        <div class="alert ok" role="status" aria-live="polite"><?= h($successMsg) ?></div>
                    <?php elseif ($errorMsg): ?>
                        <div class="alert err" role="alert"><?= h($errorMsg) ?></div>
                    <?php endif; ?>

                    <form method="post" action="#apply" autocomplete="on" novalidate>
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>" />
                        <input type="hidden" name="privacy_policy_version" value="<?= h(PRIVACY_POLICY_VERSION) ?>" />

                        <!-- Honeypot -->
                        <input type="text" name="company_website" value="" tabindex="-1" autocomplete="off"
                            style="position:absolute; left:-9999px; width:1px; height:1px;" aria-hidden="true" />

                        <div class="row">
                            <div>
                                <label for="name">성함 (필수)</label>
                                <input id="name" name="name" type="text" inputmode="text" placeholder="예: 홍길동"
                                    required minlength="2" value="<?= h($old['name']) ?>" />
                            </div>
                            <div>
                                <label for="phone">연락처 (필수)</label>
                                <input id="phone" name="phone" type="tel" inputmode="tel"
                                    placeholder="예: 010-1234-5678" required
                                    value="<?= h($old['phone']) ?>" />
                            </div>
                        </div>

                        <div class="row">
                            <div>
                                <label for="amount">희망금액 (선택)</label>
                                <input id="amount" name="amount" type="text" inputmode="numeric" placeholder="예: 500만원"
                                    value="<?= h($old['amount']) ?>" />
                            </div>
                            <div>
                                <label for="purpose">자금용도 (선택)</label>
                                <select id="purpose" name="purpose">
                                    <?php
                                    $options = ['선택 안함', '생활자금', '사업자금', '대환', '기타'];
                                    foreach ($options as $opt) {
                                        $sel = ($old['purpose'] === $opt) ? 'selected' : '';
                                        echo '<option value="' . h($opt) . '" ' . $sel . '>' . h($opt) . '</option>';
                                    }
                                    ?>
                                </select>
                            </div>
                        </div>

                        <div>
                            <label for="memo">요청사항 (선택)</label>
                            <textarea id="memo" name="memo" placeholder="상담 시 참고할 내용을 적어주세요."><?= h($old['memo']) ?></textarea>
                        </div>

                        <div class="checks" aria-label="동의 항목">
                            <div class="check">
                                <input id="agree_privacy" name="agree_privacy" type="checkbox" value="1"
                                    <?= $old['agree_privacy'] === '1' ? 'checked' : '' ?> />
                                <div>
                                    <label for="agree_privacy" style="color:var(--text); font-weight:800;">
                                        개인정보 수집·이용 동의 (필수)
                                        <span class="tiny">(<?= h(PRIVACY_POLICY_VERSION) ?>)</span>
                                    </label>
                                    <small>상담 진행을 위해 성함/연락처/상담내용을 수집하며, 목적 달성 후 보관기간에 따라 파기합니다.</small>
                                </div>
                            </div>
                            <div class="check">
                                <input id="agree_marketing" name="agree_marketing" type="checkbox" value="1"
                                    <?= $old['agree_marketing'] === '1' ? 'checked' : '' ?> />
                                <div>
                                    <label for="agree_marketing" style="color:var(--text); font-weight:800;">마케팅 정보 수신 동의 (선택)</label>
                                    <small>이벤트/상품 안내를 받을 수 있습니다. 동의하지 않아도 상담이 가능합니다.</small>
                                </div>
                            </div>
                        </div>

                        <button class="cta" type="submit" style="justify-self:start;">
                            상담 신청 접수
                        </button>

                        <div class="tiny">
                            ※ 접수 내용은 담당자 확인 후 연락드리며, 심사 결과에 따라 진행이 제한될 수 있습니다.
                        </div>
                    </form>
                </div>
            </div>
        </section>

        <footer class="card footer" aria-label="사업자 정보">
            <div class="cols">
                <div>
                    <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                        <div class="logo" style="width:34px;height:34px;border-radius:14px;">E</div>
                        <div>
                            <div style="font-weight:900; color: rgba(234,240,255,.92);"><?= h($brandEn) ?> · <?= h($brandKr) ?></div>
                            <div class="tiny">대부업 관련 법령 및 표시 의무에 따라 정보를 제공합니다.</div>
                        </div>
                    </div>

                    <div class="hr"></div>

                    <div class="kv">
                        <?php foreach ($companyInfo as $k => $v): ?>
                            <div><b><?= h($k) ?></b><span><?= h($v) ?></span></div>
                        <?php endforeach; ?>
                    </div>

                    <div class="hr"></div>
                    <div class="tiny">
                        © <?= date('Y') ?> <?= h($brandEn) ?>. All rights reserved.
                    </div>
                </div>

                <div>
                    <div class="pill">개인정보처리방침(요약)</div>
                    <p style="margin:10px 0 0; color:var(--muted); font-size:12px;">
                        • 수집항목: 성함, 연락처, 상담내용(선택), 접속기록(보안 목적)<br />
                        • 이용목적: 상담 및 안내, 민원 대응, 서비스 품질 개선<br />
                        • 보관기간: 목적 달성 후 지체 없이 파기(관계법령에 따른 보관은 예외)<br />
                        • 문의: <?= h($companyInfo['대표전화']) ?>
                    </p>

                    <div class="hr"></div>

                    <div class="pill">고객 안내</div>
                    <p style="margin:10px 0 0; color:var(--muted); font-size:12px;">
                        <?= h($disclosure['유의사항']) ?>
                    </p>
                </div>
            </div>
        </footer>
    </main>

    <button class="topbtn" id="topbtn" type="button" aria-label="맨 위로">↑</button>

    <script>
        // Smooth scroll (in-page)
        document.querySelectorAll('a[href^="#"]').forEach(a => {
            a.addEventListener('click', (e) => {
                const id = a.getAttribute('href');
                if (!id || id === '#') return;
                const el = document.querySelector(id);
                if (!el) return;
                e.preventDefault();
                el.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
                history.replaceState(null, '', id);
            });
        });

        // Top button
        const topBtn = document.getElementById('topbtn');
        const onScroll = () => {
            if (window.scrollY > 600) topBtn.style.display = 'block';
            else topBtn.style.display = 'none';
        };
        window.addEventListener('scroll', onScroll, {
            passive: true
        });
        topBtn.addEventListener('click', () => window.scrollTo({
            top: 0,
            behavior: 'smooth'
        }));
        onScroll();
    </script>
</body>

</html>