<?php

declare(strict_types=1);

/**
 * index.php (전체) - 헤더 로고 이미지 적용 버전
 * ✅ 추가: 신청유형(개인/기업) + 기업정보(자동 펼침)
 * ✅ 추가: 주소(실거주지/등본주소지) + 다음(카카오) 주소 API
 * ✅ 추가: 예상 대출기간(1~24개월)
 * ✅ 추가: 서류제출(카메라 촬영만) + 무제한 업로드(디스크 저장 + DB)
 */

$isHttps = (
    (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (!empty($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
    || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
);

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);

session_start();

if (!empty($_GET['reset'])) {
    unset(
        $_SESSION['cashhome_inquiry_draft'],
        $_SESSION['kakao_profile'],
        $_SESSION['kakao_oauth_state'],
        $_SESSION['cashhome_consent']
        // ✅ cashhome_last_inquiry_id 는 "서류 업로드" 연결을 위해 유지(원하면 reset에 포함 가능)
    );
    header('Location: index.php#apply');
    exit;
}

header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
// ✅ 카메라/프리뷰(blob) + 다음 주소 API 포함 CSP
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://t1.daumcdn.net https://postcode.map.daum.net; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https: blob:; connect-src 'self' https:; media-src 'self' blob:; frame-src https://t1.daumcdn.net https://postcode.map.daum.net;");
header('Permissions-Policy: camera=(self)');

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

const PRIVACY_POLICY_VERSION = 'v1';

function cashhome_pdo(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) return $pdo;

    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4';
    $pdo = new PDO($dsn, DB_USER, DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function cashhome_consent_ok(): bool
{
    if (empty($_SESSION['cashhome_consent']) || !is_array($_SESSION['cashhome_consent'])) return false;
    $c = $_SESSION['cashhome_consent'];

    $privacy = !empty($c['privacy']);
    $marketing = !empty($c['marketing']);
    if (!$privacy || !$marketing) return false;

    $hasPrivacyAt = !empty($c['privacy_at']);
    $hasMarketingAt = !empty($c['marketing_at']);
    $hasPrivacyVer = !empty($c['privacy_ver']);
    $hasMarketingVer = !empty($c['marketing_ver']);

    $hasLegacy = (!empty($c['version']) && !empty($c['consented_at']));

    return (($hasPrivacyAt && $hasMarketingAt && $hasPrivacyVer && $hasMarketingVer) || $hasLegacy);
}

/**
 * ✅ 입력 검증 (추가 항목 반영)
 */
function validate_inquiry_input(array $in): array
{
    $name = trim((string)($in['name'] ?? ''));
    $phone = trim((string)($in['phone'] ?? ''));
    $amount = trim((string)($in['amount'] ?? ''));
    $purpose = trim((string)($in['purpose'] ?? ''));
    $memo = trim((string)($in['memo'] ?? ''));

    // ✅ 신규 항목
    $applicantType = trim((string)($in['applicant_type'] ?? '')); // personal/company
    $companyInfo = trim((string)($in['company_info'] ?? ''));
    $addrLive = trim((string)($in['addr_live'] ?? ''));
    $addrResident = trim((string)($in['addr_resident'] ?? ''));
    $loanPeriodRaw = trim((string)($in['loan_period'] ?? ''));

    $errors = [];

    if ($name === '' || mb_strlen($name) < 2) $errors[] = '성함을 2자 이상 입력해주세요.';

    $phoneDigits = preg_replace('/\D+/', '', $phone) ?? '';
    if ($phoneDigits === '' || strlen($phoneDigits) < 9 || strlen($phoneDigits) > 12) {
        $errors[] = '연락처를 정확히 입력해주세요.';
    }

    if ($amount === '') {
        $errors[] = '희망금액을 입력해주세요.';
    } else {
        $amountDigits = preg_replace('/\D+/', '', $amount);
        if ($amountDigits === null || $amountDigits === '') $errors[] = '희망금액은 숫자로 입력해주세요.';
    }

    if ($purpose === '' || $purpose === '선택 안함') $errors[] = '자금용도를 선택해주세요.';

    // ✅ 신청유형
    if ($applicantType !== 'personal' && $applicantType !== 'company') {
        $errors[] = '신청 유형(개인/기업)을 선택해주세요.';
    }

    // ✅ 주소 2개 (필수)
    if ($addrLive === '') $errors[] = '주소(실거주지)를 입력해주세요.';
    if ($addrResident === '') $errors[] = '주소(등본 주소지)를 입력해주세요.';

    // ✅ 예상 대출기간 1~24개월
    $loanPeriod = 0;
    if ($loanPeriodRaw === '' || !ctype_digit($loanPeriodRaw)) {
        $errors[] = '예상 대출기간을 선택해주세요.';
    } else {
        $loanPeriod = (int)$loanPeriodRaw;
        if ($loanPeriod < 1 || $loanPeriod > 24) {
            $errors[] = '예상 대출기간은 1~24개월 범위로 선택해주세요.';
        }
    }

    // ✅ 기업일 때 기업정보 길이 제한
    if (mb_strlen($companyInfo) > 2000) $errors[] = '기업 정보는 2000자 이하로 입력해주세요.';

    if (mb_strlen($memo) > 1000) $errors[] = '요청사항은 1000자 이하로 입력해주세요.';

    return [$errors, [
        'name' => $name,
        'phone' => $phone,
        'amount' => $amount,
        'purpose' => $purpose,
        'memo' => $memo,

        'applicant_type' => $applicantType,
        'company_info' => $companyInfo,
        'addr_live' => $addrLive,
        'addr_resident' => $addrResident,
        'loan_period' => (string)$loanPeriod,
    ]];
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$consentOk = cashhome_consent_ok();

$successMsg = '';
$errorMsg = '';

$draft = $_SESSION['cashhome_inquiry_draft'] ?? null;

// ✅ draft/old 확장
$old = [
    'name' => is_array($draft) ? (string)($draft['name'] ?? '') : '',
    'phone' => is_array($draft) ? (string)($draft['phone'] ?? '') : '',
    'amount' => is_array($draft) ? (string)($draft['amount'] ?? '') : '',
    'purpose' => is_array($draft) ? (string)($draft['purpose'] ?? '선택 안함') : '선택 안함',
    'memo' => is_array($draft) ? (string)($draft['memo'] ?? '') : '',

    'applicant_type' => is_array($draft) ? (string)($draft['applicant_type'] ?? '') : '',
    'company_info' => is_array($draft) ? (string)($draft['company_info'] ?? '') : '',
    'addr_live' => is_array($draft) ? (string)($draft['addr_live'] ?? '') : '',
    'addr_resident' => is_array($draft) ? (string)($draft['addr_resident'] ?? '') : '',
    'loan_period' => is_array($draft) ? (string)($draft['loan_period'] ?? '') : '',
];

$kakaoErr = (string)($_GET['kakao_error'] ?? '');
$kakaoOk = !empty($_GET['kakao_ok']);
$kakaoOkMsg = $kakaoOk ? '카카오 로그인 완료! 성함이 자동 입력되었습니다.' : '';

/**
 * ✅ preconsent: 입력값 검증 후 세션 draft 저장
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'preconsent') {
    header('Content-Type: application/json; charset=utf-8');

    $token = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token'], $token)) {
        echo json_encode(['ok' => false, 'message' => '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    [$errs, $clean] = validate_inquiry_input($_POST);
    if ($errs) {
        echo json_encode(['ok' => false, 'message' => implode("\n", $errs)], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $_SESSION['cashhome_inquiry_draft'] = $clean;

    echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * ✅ 실제 접수
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') !== 'preconsent') {

    $hp = trim((string)($_POST['company_website'] ?? ''));
    if ($hp !== '') {
        $successMsg = '상담 신청이 접수되었습니다. 담당자가 확인 후 연락드리겠습니다.';
    } else {

        $token = (string)($_POST['csrf_token'] ?? '');
        if (!hash_equals($_SESSION['csrf_token'], $token)) {
            $errorMsg = '요청이 만료되었거나 올바르지 않습니다. 새로고침 후 다시 시도해주세요.';
        } else {

            [$errs, $clean] = validate_inquiry_input($_POST);

            $old = [
                'name' => $clean['name'],
                'phone' => $clean['phone'],
                'amount' => $clean['amount'],
                'purpose' => $clean['purpose'] !== '' ? $clean['purpose'] : '선택 안함',
                'memo' => $clean['memo'],
                'applicant_type' => $clean['applicant_type'],
                'company_info' => $clean['company_info'],
                'addr_live' => $clean['addr_live'],
                'addr_resident' => $clean['addr_resident'],
                'loan_period' => $clean['loan_period'],
            ];

            if (!cashhome_consent_ok()) {
                $errs[] = "개인정보/마케팅 동의가 필요합니다.\n입력 완료 후 동의 버튼을 눌러 동의페이지에서 동의를 완료해주세요.";
            }

            if ($errs) {
                $errorMsg = implode(' ', $errs);
            } else {
                $ts = date('Y-m-d H:i:s');
                $ip = $_SERVER['REMOTE_ADDR'] ?? '';
                $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

                $name = $clean['name'];
                $phone = $clean['phone'];
                $amount = $clean['amount'];
                $purpose = $clean['purpose'];
                $memo = $clean['memo'];

                $applicantType = $clean['applicant_type'];
                $companyInfoText = $clean['company_info'];
                $addrLive = $clean['addr_live'];
                $addrResident = $clean['addr_resident'];
                $loanPeriod = (int)$clean['loan_period'];

                $consent = $_SESSION['cashhome_consent'];

                $privacyVer = (string)($consent['privacy_ver'] ?? PRIVACY_POLICY_VERSION);
                $marketingVer = (string)($consent['marketing_ver'] ?? 'v1');
                $privacyAt = (string)($consent['privacy_at'] ?? '');
                $marketingAt = (string)($consent['marketing_at'] ?? '');

                if ($privacyAt === '' && !empty($consent['consented_at'])) $privacyAt = (string)$consent['consented_at'];
                if ($marketingAt === '' && !empty($consent['consented_at'])) $marketingAt = (string)$consent['consented_at'];
                if ($privacyVer === '' && !empty($consent['version'])) $privacyVer = (string)$consent['version'];

                try {
                    $pdo = cashhome_pdo();
                    $pdo->beginTransaction();

                    $stmt = $pdo->prepare("
                        INSERT INTO cashhome_1000_inquiries (
                            cashhome_1000_created_at,
                            cashhome_1000_user_ip,
                            cashhome_1000_user_agent,
                            cashhome_1000_customer_name,
                            cashhome_1000_customer_phone,

                            cashhome_1000_addr_live,
                            cashhome_1000_addr_resident,
                            cashhome_1000_applicant_type,
                            cashhome_1000_loan_period,

                            cashhome_1000_loan_amount,
                            cashhome_1000_loan_purpose,
                            cashhome_1000_request_memo,
                            cashhome_1000_company_info,

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

                            :addr_live,
                            :addr_resident,
                            :applicant_type,
                            :loan_period,

                            :loan_amount,
                            :loan_purpose,
                            :request_memo,
                            :company_info,

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

                        ':addr_live' => $addrLive !== '' ? $addrLive : null,
                        ':addr_resident' => $addrResident !== '' ? $addrResident : null,
                        ':applicant_type' => $applicantType !== '' ? $applicantType : null,
                        ':loan_period' => $loanPeriod > 0 ? $loanPeriod : null,

                        ':loan_amount' => $amount,
                        ':loan_purpose' => $purpose,
                        ':request_memo' => $memo !== '' ? $memo : null,
                        ':company_info' => $companyInfoText !== '' ? $companyInfoText : null,

                        ':agree_privacy' => 1,
                        ':privacy_policy_version' => $privacyVer,
                        ':privacy_agreed_at' => $privacyAt !== '' ? $privacyAt : $ts,
                        ':agree_marketing' => 1,
                        ':marketing_agreed_at' => $marketingAt !== '' ? $marketingAt : $ts,
                        ':status' => 'new',
                    ]);

                    $newId = (int)$pdo->lastInsertId();

                    // ✅ 서류 업로드 연결용(중요)
                    $_SESSION['cashhome_last_inquiry_id'] = $newId;

                    $stmtP = $pdo->prepare("
                        INSERT INTO cashhome_1100_consent_logs (
                            cashhome_1100_inquiry_id,
                            cashhome_1100_consent_type,
                            cashhome_1100_consent_version,
                            cashhome_1100_consented,
                            cashhome_1100_user_ip,
                            cashhome_1100_user_agent
                        ) VALUES (
                            :inquiry_id,
                            :consent_type,
                            :consent_version,
                            :consented,
                            :user_ip,
                            :user_agent
                        )
                    ");

                    $stmtP->execute([
                        ':inquiry_id' => $newId,
                        ':consent_type' => 'privacy',
                        ':consent_version' => $privacyVer,
                        ':consented' => 1,
                        ':user_ip' => $ip !== '' ? $ip : null,
                        ':user_agent' => $ua !== '' ? mb_substr($ua, 0, 255) : null,
                    ]);

                    $stmtP->execute([
                        ':inquiry_id' => $newId,
                        ':consent_type' => 'marketing',
                        ':consent_version' => $marketingVer !== '' ? $marketingVer : $privacyVer,
                        ':consented' => 1,
                        ':user_ip' => $ip !== '' ? $ip : null,
                        ':user_agent' => $ua !== '' ? mb_substr($ua, 0, 255) : null,
                    ]);

                    $pdo->commit();
                } catch (Throwable $e) {
                    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) $pdo->rollBack();
                    error_log('[DB/CONSENT INSERT ERROR] ' . $e->getMessage());
                    $errorMsg = '일시적인 오류로 접수가 완료되지 않았습니다. 잠시 후 다시 시도해주세요.';
                }

                if ($errorMsg === '') {
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                    unset($_SESSION['cashhome_consent'], $_SESSION['cashhome_inquiry_draft']);
                    $consentOk = false;

                    $successMsg = '상담 신청이 접수되었습니다. 담당자가 확인 후 연락드리겠습니다.';
                    $old = [
                        'name' => '',
                        'phone' => '',
                        'amount' => '',
                        'purpose' => '선택 안함',
                        'memo' => '',
                        'applicant_type' => '',
                        'company_info' => '',
                        'addr_live' => '',
                        'addr_resident' => '',
                        'loan_period' => ''
                    ];
                } else {
                    $_SESSION['cashhome_inquiry_draft'] = $clean;
                }
            }
        }
    }
}

$brandKr = '이케쉬대부';
$brandEn = 'ECASH';

$companyInfo = [
    '상호' => $brandKr,
    '영문' => $brandEn,
    '대표' => '이주진',
    '주소' => '충남 천안시 동남구 봉명동 9번지',
    '대표전화' => '010-5651-0030',
    '운영시간' => '평일 09:00 ~ 18:00 (주말/공휴일 휴무)',
];

$disclosure = [
    '최고금리' => '법정 최고금리 이내 (상품/신용도에 따라 차등)',
    '연체이자' => '약정금리 + 연체가산금리 (법정 한도 이내)',
    '중개수수료' => '대출중개수수료 없음 (당사 기준)',
    '유의사항' => '과도한 대출은 개인신용평점 하락의 원인이 될 수 있으며, 연체 시 신용정보에 등록될 수 있습니다.',
];

$logoImg = '/cashhome_icon/ecash_icon_512.png';

// ✅ 서류 업로드 연결용 inquiry id
$lastInquiryId = (int)($_SESSION['cashhome_last_inquiry_id'] ?? 0);
?>

<!doctype html>
<html lang="ko">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#0B1220" />
    <title><?= h($brandEn) ?> | <?= h($brandKr) ?> - 빠르고 간편한 상담</title>

    <!-- ✅ 다음(카카오) 주소 API -->
    <script src="https://t1.daumcdn.net/mapjsapi/bundle/postcode/prod/postcode.v2.js"></script>

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
            --navH: 74px;
        }

        * { box-sizing: border-box }
        html, body { height: 100% }

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
            padding-top: var(--navH);
        }

        a { color: inherit }

        .wrap { max-width: var(--max); margin: 0 auto; padding: 22px 18px 80px; }

        .nav {
            position: fixed; top: 0; left: 0; width: 100%; height: var(--navH); z-index: 30;
            backdrop-filter: blur(12px);
            background: rgba(11, 18, 32, .55);
            border-bottom: 1px solid var(--line);
        }

        .navin {
            max-width: var(--max);
            margin: 0 auto;
            height: var(--navH);
            padding: 12px 18px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
        }

        .brand { display: flex; align-items: center; gap: 12px; text-decoration: none }

        .logo {
            width: 50px; height: 50px; border-radius: 14px; overflow: hidden;
            background: none; border: 0; box-shadow: none; padding: 0; flex: 0 0 auto;
        }

        .logo img { width: 100%; height: 100%; display: block; object-fit: cover; padding: 0; }

        .brand strong { display: block; font-size: 14px; letter-spacing: .6px }
        .brand span { display: block; font-size: 12px; color: var(--muted) }

        .navlinks { display: flex; gap: 14px; align-items: center; flex-wrap: wrap; justify-content: flex-end }
        .navlinks a {
            text-decoration: none;
            font-size: 13px;
            padding: 8px 10px;
            border-radius: 999px;
            border: 1px solid transparent;
        }
        .navlinks a:hover { color: var(--text); border-color: var(--line); background: rgba(255, 255, 255, .04); }

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
            display: inline-flex;
            align-items: center;
            justify-content: center;
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
        .btnGhost:hover { background: rgba(255, 255, 255, .05); }

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

        .heroL { padding: 26px 22px; }

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

        .dot { width: 8px; height: 8px; border-radius: 99px; background: var(--accent); box-shadow: 0 0 18px rgba(110, 231, 255, .7); }

        h1 { margin: 12px 0 10px; font-size: 36px; line-height: 1.15; letter-spacing: -0.6px; }
        .sub { color: var(--muted); margin: 0 0 18px; font-size: 14px; }

        .bullets { display: grid; gap: 10px; margin: 14px 0 20px; }

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
            width: 22px; height: 22px; border-radius: 10px;
            background: rgba(110, 231, 255, .18);
            border: 1px solid rgba(110, 231, 255, .22);
            display: inline-block;
            margin-top: 1px;
        }
        .b strong { display: block; font-size: 13px; }
        .b span { display: block; font-size: 12px; color: var(--muted); }

        .heroBtns { display: flex; gap: 10px; flex-wrap: wrap; }

        .heroR { padding: 18px; display: grid; gap: 12px; }

        .mini {
            padding: 14px 14px;
            border-radius: var(--radius2);
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
        }
        .mini h3 { margin: 0 0 8px; font-size: 14px; }
        .mini p { margin: 0; color: var(--muted); font-size: 12px; }

        .grid { display: grid; grid-template-columns: repeat(12, 1fr); gap: 14px; margin-top: 14px; }
        .col4 { grid-column: span 4; }
        .col6 { grid-column: span 6; }
        .col12 { grid-column: span 12; }

        .sectionTitle { margin: 26px 0 10px; font-size: 18px; letter-spacing: -0.2px; }
        .sectionSub { margin: 0 0 12px; color: var(--muted); font-size: 13px; }

        .box { padding: 18px; }
        .box h3 { margin: 0 0 8px; font-size: 15px; }
        .box p { margin: 0; color: var(--muted); font-size: 13px; }

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

        .formWrap { padding: 18px; }
        form { display: grid; gap: 10px; }

        .row { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }

        label { font-size: 12px; color: var(--muted); }

        input, select, textarea {
            width: 100%;
            padding: 12px 12px;
            border-radius: 14px;
            border: 1px solid var(--line);
            background: rgba(8, 12, 24, .55);
            color: var(--text);
            outline: none;
        }

        input:focus, select:focus, textarea:focus {
            border-color: rgba(110, 231, 255, .55);
            box-shadow: 0 0 0 3px rgba(110, 231, 255, .12);
        }

        textarea { min-height: 110px; resize: vertical; }

        .checks { display: grid; gap: 10px; margin-top: 6px; }

        .consentCard {
            display: flex;
            gap: 12px;
            align-items: flex-start;
            padding: 12px 12px;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: rgba(255, 255, 255, .03);
            cursor: pointer;
            transition: transform .12s ease, background .12s ease, border-color .12s ease;
            position: relative;
            user-select: none;
        }
        .consentCard:hover { transform: translateY(-1px); background: rgba(255, 255, 255, .05); border-color: rgba(234, 240, 255, .18); }

        .consentIcon {
            width: 38px; height: 38px; border-radius: 14px;
            border: 1px solid rgba(234, 240, 255, .12);
            background: rgba(8, 12, 24, .55);
            display: grid;
            place-items: center;
            flex: 0 0 auto;
            margin-top: 2px;
        }

        .consentCheck {
            width: 22px; height: 22px; border-radius: 999px;
            border: 1px solid rgba(234, 240, 255, .22);
            background: rgba(8, 12, 24, .55);
            display: grid;
            place-items: center;
            flex: 0 0 auto;
            margin-top: 6px;
        }
        .consentCheck .dotOk { width: 10px; height: 10px; border-radius: 99px; background: var(--accent); box-shadow: 0 0 16px rgba(110, 231, 255, .55); }

        .consentBody { flex: 1 1 auto; min-width: 0 }
        .consentTitle { font-weight: 900; color: var(--text); display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .consentMeta { margin-top: 4px; color: var(--muted); font-size: 12px; line-height: 1.4; }

        .consentHint { margin-top: 8px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }

        .chip {
            display: inline-flex;
            gap: 6px;
            align-items: center;
            padding: 4px 8px;
            border-radius: 999px;
            border: 1px solid rgba(234, 240, 255, .12);
            background: rgba(255, 255, 255, .03);
            color: var(--muted);
            font-size: 12px;
        }
        .chip.ok { color: var(--accent); border-color: rgba(110, 231, 255, .25); }

        .arrow { position: absolute; right: 12px; top: 50%; transform: translateY(-50%); color: rgba(234, 240, 255, .45); font-weight: 900; }

        .alert {
            padding: 12px 14px;
            border-radius: 16px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            color: var(--text);
            font-size: 13px;
        }
        .alert.ok { border-color: rgba(110, 231, 255, .35); }
        .alert.err { border-color: rgba(255, 120, 120, .35); }

        .footer { margin-top: 22px; padding: 18px; color: var(--muted); font-size: 12px; }
        .footer .cols { display: grid; grid-template-columns: 1.2fr .8fr; gap: 14px; }

        .kv { display: grid; gap: 6px; }
        .kv div { display: flex; gap: 10px; align-items: flex-start; }
        .kv b { min-width: 110px; color: rgba(234, 240, 255, .85); }

        .hr { height: 1px; background: var(--line); margin: 14px 0; }

        .tiny { font-size: 11px; color: rgba(157, 176, 208, .9); }

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

        button[disabled] { opacity: .45; cursor: not-allowed; filter: grayscale(20%); }

        .action-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-top: 10px; }
        .action-row>* { margin: 0 !important; }

        /* ✅ 예시 박스 + 주소찾기 버튼 */
        .example-box {
            margin: 8px 0;
            padding: 12px;
            border-radius: 14px;
            border: 1px solid rgba(234, 240, 255, .12);
            background: rgba(255, 255, 255, .03);
            font-size: 12px;
            color: #9DB0D0;
            line-height: 1.5;
        }

        .btnAddr {
            padding: 12px 14px;
            border-radius: 14px;
            border: 1px solid rgba(234, 240, 255, .12);
            background: rgba(255, 255, 255, .04);
            color: #EAF0FF;
            font-weight: 800;
            cursor: pointer;
            white-space: nowrap;
        }
        .btnAddr:hover { background: rgba(255, 255, 255, .06) }

        @media (max-width: 920px) {
            .hero { grid-template-columns: 1fr; }
            .row { grid-template-columns: 1fr; }
            .col4, .col6 { grid-column: span 12; }
            h1 { font-size: 30px; }
            .footer .cols { grid-template-columns: 1fr; }
        }
    </style>
</head>

<body>
<header class="nav" role="banner">
    <div class="navin">
        <a class="brand" href="#top" aria-label="<?= h($brandEn) ?> 홈으로">
            <div class="logo">
                <img src="<?= h($logoImg) ?>" alt="<?= h($brandEn) ?> 로고" />
            </div>
            <div>
                <strong><?= h($brandEn) ?></strong>
                <span><?= h($brandKr) ?></span>
            </div>
        </a>

        <nav class="navlinks" aria-label="상단 메뉴">
            <a href="#services">서비스</a>
            <a href="#process">절차</a>
            <a href="#disclosure">고지</a>
            <a href="#apply">상담신청</a>
            <a class="cta" href="#apply">빠른 상담</a>
            <a class="btnGhost" href="admin_login.php" rel="nofollow">관리자 로그인</a>
        </nav>
    </div>
</header>

<main class="wrap" id="top">
    <section class="hero">
        <div class="card heroL">
            <div class="kicker"><span class="dot"></span> 신속 · 정확 · 친절 상담</div>
            <h1><?= h($brandEn) ?>,<br />필요한 순간에 <span style="color:var(--accent)">빠르게</span> 안내드립니다.</h1>
            <p class="sub">
                이케쉬대부(ECASH)는 상담 신청 접수 후 담당자가 확인하여 연락드립니다.
                (※ 실제 조건은 심사/신용도/상품에 따라 달라질 수 있습니다.)
            </p>

            <div class="bullets" aria-label="핵심 장점">
                <div class="b"><i></i><div><strong>간편 상담 신청</strong><span>기본 정보 입력으로 빠르게 접수</span></div></div>
                <div class="b"><i></i><div><strong>개인정보 최소 수집</strong><span>입력 완료 후 동의 진행(증적 목적)</span></div></div>
                <div class="b"><i></i><div><strong>투명한 고지</strong><span>필수 정보를 명확히 안내</span></div></div>
            </div>

            <div class="heroBtns">
                <a class="cta" href="#apply">상담 신청하기</a>
                <a class="btnGhost" href="#disclosure">필수 고지 확인</a>
            </div>
        </div>

        <aside class="card heroR" aria-label="요약 정보">
            <div class="mini"><h3>운영시간</h3><p><?= h($companyInfo['운영시간']) ?></p></div>
            <div class="mini"><h3>대표전화</h3><p><?= h($companyInfo['대표전화']) ?></p></div>
            <div class="mini"><h3>안내</h3><p>상담은 본인 확인 및 심사 과정이 포함될 수 있으며, 과도한 대출은 금융 부담을 초래할 수 있습니다.</p></div>
        </aside>
    </section>

    <section id="services">
        <h2 class="sectionTitle">서비스</h2>
        <p class="sectionSub">상담부터 안내까지, 핵심 흐름을 간결하게 구성했습니다.</p>

        <div class="grid">
            <div class="card box col4"><div class="pill">01 · 상담 접수</div><h3>기본 정보로 접수</h3><p>연락처/희망금액/용도 등 항목을 입력합니다.</p></div>
            <div class="card box col4"><div class="pill">02 · 동의 진행</div><h3>전문 열람 후 동의</h3><p>입력 완료 후 동의 페이지에서 동의를 완료합니다.</p></div>
            <div class="card box col4"><div class="pill">03 · 접수 완료</div><h3>저장 및 확인 연락</h3><p>접수 완료 후 담당자가 확인하여 연락드립니다.</p></div>
        </div>
    </section>

    <section id="process">
        <h2 class="sectionTitle">진행 절차</h2>
        <p class="sectionSub">입력 → 동의 → 접수 순으로 진행됩니다.</p>

        <div class="grid">
            <div class="card box col6"><h3>입력</h3><p>성함/연락처/희망금액/자금용도 등 항목을 입력합니다.</p></div>
            <div class="card box col6"><h3>동의</h3><p>전문 열람 후 개인정보/마케팅 동의를 완료합니다.</p></div>
            <div class="card box col6"><h3>접수</h3><p>동의 완료 상태에서만 접수 버튼이 동작합니다.</p></div>
            <div class="card box col6"><h3>확인 연락</h3><p>담당자가 확인 후 연락드리며, 필요 시 추가 정보를 요청드릴 수 있습니다.</p></div>
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
        <p class="sectionSub">입력 완료 후 동의 진행이 가능합니다. (요청사항은 선택)</p>

        <div class="grid">
            <div class="card formWrap col12">

                <?php if ($successMsg): ?>
                    <div class="alert ok" role="status" aria-live="polite"><?= h($successMsg) ?></div>
                <?php elseif ($errorMsg): ?>
                    <div class="alert err" role="alert"><?= h($errorMsg) ?></div>
                <?php endif; ?>

                <form id="applyForm" method="post" action="#apply" autocomplete="on" novalidate>
                    <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>" />

                    <input type="text" name="company_website" value="" tabindex="-1" autocomplete="off"
                           style="position:absolute; left:-9999px; width:1px; height:1px;"
                           aria-hidden="true" />

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

                    <!-- ✅ 주소 2개 + 다음 주소 API -->
                    <div class="row">
                        <div>
                            <label for="addr_live">주소 (실거주지) (필수)</label>
                            <div style="display:flex; gap:8px;">
                                <input id="addr_live" name="addr_live" type="text" placeholder="주소찾기를 눌러 입력" required
                                       value="<?= h($old['addr_live']) ?>" />
                                <button type="button" class="btnAddr" onclick="openDaumPostcode('addr_live')">주소찾기</button>
                            </div>
                        </div>
                        <div>
                            <label for="addr_resident">주소 (등본 주소지) (필수)</label>
                            <div style="display:flex; gap:8px;">
                                <input id="addr_resident" name="addr_resident" type="text" placeholder="주소찾기를 눌러 입력" required
                                       value="<?= h($old['addr_resident']) ?>" />
                                <button type="button" class="btnAddr" onclick="openDaumPostcode('addr_resident')">주소찾기</button>
                            </div>
                        </div>
                    </div>

                    <!-- ✅ 희망금액 + 대출기간 -->
                    <div class="row">
                        <div>
                            <label for="amount">희망금액 (필수)</label>
                            <input id="amount" name="amount" type="text" inputmode="numeric" placeholder="예: 500만원"
                                   required value="<?= h($old['amount']) ?>" />
                        </div>
                        <div>
                            <label for="loan_period">예상 대출기간 (필수)</label>
                            <select id="loan_period" name="loan_period" required>
                                <option value="">선택해주세요</option>
                                <?php for ($i = 1; $i <= 24; $i++): ?>
                                    <option value="<?= $i ?>" <?= ((string)$i === (string)$old['loan_period']) ? 'selected' : '' ?>>
                                        <?= $i ?>개월
                                    </option>
                                <?php endfor; ?>
                            </select>
                        </div>
                    </div>

                    <!-- ✅ 자금용도 + 신청유형 -->
                    <div class="row">
                        <div>
                            <label for="purpose">자금용도 (필수)</label>
                            <select id="purpose" name="purpose" required>
                                <?php
                                $options = ['선택 안함', '생활자금', '사업자금', '대환', '기타'];
                                foreach ($options as $opt) {
                                    $sel = ($old['purpose'] === $opt) ? 'selected' : '';
                                    echo '<option value="' . h($opt) . '" ' . $sel . '>' . h($opt) . '</option>';
                                }
                                ?>
                            </select>
                            <div class="tiny" style="margin-top:6px;">※ “선택 안함”은 접수/동의 진행 불가</div>
                        </div>

                        <div>
                            <label for="applicant_type">신청 유형 (필수)</label>
                            <select id="applicant_type" name="applicant_type" required>
                                <option value="">선택해주세요</option>
                                <option value="personal" <?= ($old['applicant_type'] === 'personal') ? 'selected' : '' ?>>개인</option>
                                <option value="company" <?= ($old['applicant_type'] === 'company') ? 'selected' : '' ?>>기업</option>
                            </select>
                        </div>
                    </div>

                    <!-- ✅ 기업일 때만 펼쳐지는 기업 정보 -->
                    <div id="company_block" style="display:none;">
                        <label for="company_info">기업 정보 (기업일 경우 작성)</label>

                        <div class="example-box">
                            <b>작성 예시</b><br>
                            1. 기업명: ○○건설(주)<br>
                            2. 직원수: 12명<br>
                            3. 월매출: 8,000만원<br>
                            4. 월 예상 순이익: 1,200만원
                        </div>

                        <textarea id="company_info" name="company_info"
                                  placeholder="기업일 경우 위 형식에 맞춰 작성해주세요."><?= h($old['company_info']) ?></textarea>
                    </div>

                    <div>
                        <label for="memo">추가정보 (선택)</label>
                        <textarea id="memo" name="memo" placeholder="상담 시 참고할 내용을 적어주세요."><?= h($old['memo']) ?></textarea>
                    </div>

                    <div class="checks" aria-label="동의 항목">
                        <div class="consentCard" id="goConsentPrivacy" role="button" tabindex="0" aria-disabled="false">
                            <div class="consentIcon" aria-hidden="true">📄</div>
                            <div class="consentBody">
                                <div class="consentTitle">
                                    개인정보 처리방침 동의 (필수)
                                    <span class="chip"><?= h(PRIVACY_POLICY_VERSION) ?></span>
                                    <?php if ($consentOk): ?><span class="chip ok">완료</span><?php endif; ?>
                                </div>
                                <div class="consentMeta">
                                    <?= $consentOk ? '동의 완료되었습니다. 접수 버튼을 눌러 접수하세요.' : '입력 완료 후 클릭하면 동의 페이지로 이동합니다.' ?>
                                </div>
                                <div class="consentHint">
                                    <span class="chip">전문 열람</span>
                                    <span class="chip">스크롤 끝까지</span>
                                    <span class="chip">동의하기</span>
                                </div>
                            </div>
                            <div class="consentCheck" aria-hidden="true">
                                <?php if ($consentOk): ?><span class="dotOk"></span><?php endif; ?>
                            </div>
                            <div class="arrow" aria-hidden="true">›</div>
                        </div>

                        <div class="consentCard" id="goConsentMarketing" role="button" tabindex="0" aria-disabled="false">
                            <div class="consentIcon" aria-hidden="true">📢</div>
                            <div class="consentBody">
                                <div class="consentTitle">
                                    마케팅 정보 수신 동의 (필수)
                                    <?php if ($consentOk): ?><span class="chip ok">완료</span><?php endif; ?>
                                </div>
                                <div class="consentMeta">
                                    <?= $consentOk ? '동의 완료되었습니다. 접수 버튼을 눌러 접수하세요.' : '입력 완료 후 클릭하면 동의 페이지로 이동합니다.' ?>
                                </div>
                                <div class="consentHint">
                                    <span class="chip">수신 동의 전문</span>
                                    <span class="chip">스크롤 끝까지</span>
                                    <span class="chip">동의하기</span>
                                </div>
                            </div>
                            <div class="consentCheck" aria-hidden="true">
                                <?php if ($consentOk): ?><span class="dotOk"></span><?php endif; ?>
                            </div>
                            <div class="arrow" aria-hidden="true">›</div>
                        </div>

                        <div class="action-row">
                            <?php if (!$consentOk): ?>
                                <a class="cta" href="#" id="goConsentBtn">동의하러 가기</a>
                            <?php endif; ?>

                            <button class="cta" type="submit" <?= $consentOk ? '' : 'disabled' ?>>
                                상담 신청 접수
                            </button>
                        </div>

                        <div class="tiny">
                            ※ 입력 오류가 있으면 팝업으로 안내됩니다. 동의는 입력 완료 후 진행됩니다.
                        </div>
                    </div>
                </form>

                <!-- ✅ 서류 제출(카메라 촬영만) -->
                <div style="margin-top:14px;">
                    <div class="pill">서류 제출</div>
                    <p class="sectionSub" style="margin:10px 0 12px;">
                        휴대폰 <b>카메라로 촬영한 사진만</b> 등록됩니다. (여러 장 가능)
                    </p>

                    <?php if ($lastInquiryId > 0): ?>
                        <div class="mini" id="cameraBox" style="display:grid; gap:10px;">
                            <div class="row" style="grid-template-columns: 1fr 1fr;">
                                <div>
                                    <label for="docType">서류 유형</label>
                                    <select id="docType">
                                        <option value="id_card">신분증</option>
                                        <option value="resident_record">등본</option>
                                        <option value="bankbook">통장사본</option>
                                        <option value="income_proof">소득증빙</option>
                                        <option value="business_license">사업자등록증</option>
                                        <option value="etc" selected>기타</option>
                                    </select>
                                </div>
                                <div>
                                    <label>안내</label>
                                    <div class="alert" style="margin:0;">카메라 시작 → 촬영(여러장) → 업로드</div>
                                </div>
                            </div>

                            <video id="camVideo" autoplay playsinline
                                style="width:100%; max-height:420px; border-radius:18px; border:1px solid rgba(234,240,255,.12); background:rgba(8,12,24,.55);">
                            </video>

                            <div style="display:flex; gap:10px; flex-wrap:wrap;">
                                <button type="button" class="cta" id="btnStartCam">카메라 시작</button>
                                <button type="button" class="btnGhost" id="btnCapture">촬영</button>
                                <button type="button" class="btnGhost" id="btnStopCam">카메라 종료</button>
                                <button type="button" class="cta" id="btnUploadAll">촬영본 업로드</button>
                            </div>

                            <div class="tiny">
                                ※ 촬영본은 자동으로 <b>최대 1600px / JPEG 품질 최적화</b> 후 업로드됩니다.
                            </div>
                        </div>

                        <div id="docList" style="display:grid; gap:10px; margin-top:12px;"></div>
                    <?php else: ?>
                        <div class="alert err" style="margin-top:10px;">
                            서류 업로드는 <b>상담 신청 접수 완료 후</b> 가능합니다. (접수 완료 메시지 확인 후 사용)
                        </div>
                    <?php endif; ?>
                </div>

            </div>
        </div>
    </section>

    <footer class="card footer" aria-label="사업자 정보">
        <div class="cols">
            <div>
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:8px;">
                    <div class="logo" style="width:34px;height:34px;border-radius:14px;">
                        <img src="<?= h($logoImg) ?>" alt="<?= h($brandEn) ?> 로고" />
                    </div>
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
                <div class="tiny">© <?= date('Y') ?> <?= h($brandEn) ?>. All rights reserved.</div>
            </div>

            <div>
                <div class="pill">개인정보처리방침(요약)</div>
                <p style="margin:10px 0 0; color:var(--muted); font-size:12px;">
                    • 수집항목: 성함, 연락처, 주소(실거주/등본), 희망금액, 예상대출기간, 자금용도, 상담내용(선택), 접속기록(보안 목적)<br />
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
(function() {
    const err = <?= json_encode($errorMsg ?? '', JSON_UNESCAPED_UNICODE) ?>;
    const ok = <?= json_encode($successMsg ?? '', JSON_UNESCAPED_UNICODE) ?>;
    const kerr = <?= json_encode($kakaoErr ?? '', JSON_UNESCAPED_UNICODE) ?>;
    const kok = <?= json_encode($kakaoOkMsg ?? '', JSON_UNESCAPED_UNICODE) ?>;

    if (err) alert(err);
    if (ok) alert(ok);
    if (kerr) alert(kerr);
    if (kok) alert(kok);
})();

// 앵커 부드러운 스크롤
document.querySelectorAll('a[href^="#"]').forEach(a => {
    a.addEventListener('click', (e) => {
        const id = a.getAttribute('href');
        if (!id || id === '#') return;
        const el = document.querySelector(id);
        if (!el) return;
        e.preventDefault();
        el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        history.replaceState(null, '', id);
    });
});

// TOP 버튼
const topBtn = document.getElementById('topbtn');
const onScroll = () => { if (topBtn) topBtn.style.display = (window.scrollY > 600) ? 'block' : 'none'; };
window.addEventListener('scroll', onScroll, { passive: true });
if (topBtn) topBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
onScroll();

// 폰 번호 자동 포맷
(function() {
    const phoneEl = document.getElementById('phone');
    if (!phoneEl) return;

    function formatPhoneKR(value) {
        const digits = (value || '').replace(/\D+/g, '').slice(0, 11);
        if (digits.startsWith('02')) {
            if (digits.length <= 2) return digits;
            if (digits.length <= 5) return digits.replace(/^(\d{2})(\d{1,3})$/, '$1-$2');
            if (digits.length <= 9) return digits.replace(/^(\d{2})(\d{3})(\d{1,4})$/, '$1-$2-$3');
            return digits.replace(/^(\d{2})(\d{4})(\d{1,4})$/, '$1-$2-$3');
        }
        if (digits.length <= 3) return digits;
        if (digits.length <= 7) return digits.replace(/^(\d{3})(\d{1,4})$/, '$1-$2');
        if (digits.length <= 10) return digits.replace(/^(\d{3})(\d{3})(\d{1,4})$/, '$1-$2-$3');
        return digits.replace(/^(\d{3})(\d{4})(\d{1,4})$/, '$1-$2-$3');
    }

    function onInput() {
        const before = phoneEl.value;
        const formatted = formatPhoneKR(before);
        if (before !== formatted) phoneEl.value = formatted;
    }

    phoneEl.addEventListener('input', onInput, { passive: true });
    phoneEl.addEventListener('blur', onInput, { passive: true });
    onInput();
})();

// ✅ 다음(카카오) 주소 API 함수
function openDaumPostcode(targetInputId) {
    if (!window.daum || !daum.Postcode) {
        alert('주소 검색 모듈 로딩에 실패했습니다. 새로고침 후 다시 시도해주세요.');
        return;
    }
    new daum.Postcode({
        oncomplete: function(data) {
            const addr = (data.userSelectedType === 'R') ? data.roadAddress : data.jibunAddress;
            const el = document.getElementById(targetInputId);
            if (el) el.value = addr;
        }
    }).open();
}

// ✅ 기업 선택 시 자동 펼침
(function() {
    const typeSel = document.getElementById('applicant_type');
    const companyBlock = document.getElementById('company_block');

    function toggleCompanyBlock() {
        const isCompany = typeSel && typeSel.value === 'company';
        if (companyBlock) companyBlock.style.display = isCompany ? 'block' : 'none';
    }

    if (typeSel) typeSel.addEventListener('change', toggleCompanyBlock);
    toggleCompanyBlock();
})();

const form = document.getElementById('applyForm');

async function preConsentAndGo() {
    const fd = new FormData(form);
    fd.append('action', 'preconsent');

    try {
        const res = await fetch(location.href, {
            method: 'POST',
            body: fd,
            credentials: 'same-origin'
        });
        const data = await res.json();

        if (!data.ok) {
            alert(data.message || '입력값을 확인해주세요.');
            return;
        }
        location.href = 'consent.php?return=index.php#apply';
    } catch (e) {
        alert('네트워크 오류가 발생했습니다.');
    }
}

function bindConsentClick(el) {
    if (!el) return;
    el.addEventListener('click', preConsentAndGo);
    el.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            preConsentAndGo();
        }
    });
}

bindConsentClick(document.getElementById('goConsentPrivacy'));
bindConsentClick(document.getElementById('goConsentMarketing'));

const goBtn = document.getElementById('goConsentBtn');
if (goBtn) {
    goBtn.addEventListener('click', (e) => {
        e.preventDefault();
        preConsentAndGo();
    });
}

form?.addEventListener('submit', (e) => {
    const consentOk = <?= $consentOk ? 'true' : 'false' ?>;
    if (!consentOk) {
        e.preventDefault();
        alert('동의가 완료되어야 접수할 수 있습니다.');
    }
});

/* =========================================================
   ✅ 서류 제출: 카메라 촬영만 + 업로드
   - HTTPS(또는 localhost)에서만 카메라 동작합니다.
========================================================= */
(function () {
    const inquiryId = <?= json_encode($lastInquiryId) ?>;
    if (!inquiryId) return;

    const video = document.getElementById('camVideo');
    const btnStartCam = document.getElementById('btnStartCam');
    const btnCapture = document.getElementById('btnCapture');
    const btnStopCam = document.getElementById('btnStopCam');
    const btnUploadAll = document.getElementById('btnUploadAll');
    const docTypeSel = document.getElementById('docType');
    const docList = document.getElementById('docList');

    let stream = null;
    const shots = []; // Blob 저장 (삭제 대비 null 가능)

    function setBtnState() {
        const camOn = !!stream;
        if (btnCapture) btnCapture.disabled = !camOn;
        if (btnStopCam) btnStopCam.disabled = !camOn;
    }

    async function startCamera() {
        if (!navigator.mediaDevices?.getUserMedia) {
            alert('이 브라우저는 카메라 사용을 지원하지 않습니다.');
            return;
        }
        try {
            stream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: { ideal: 'environment' } },
                audio: false
            });
            video.srcObject = stream;
            setBtnState();
        } catch (e) {
            alert('카메라 권한을 허용해주세요. (HTTPS 환경 필요)');
        }
    }

    function stopCamera() {
        if (stream) {
            stream.getTracks().forEach(t => t.stop());
            stream = null;
        }
        if (video) video.srcObject = null;
        setBtnState();
    }

    async function capture() {
        if (!video || !video.videoWidth) {
            alert('카메라가 준비되지 않았습니다.');
            return;
        }

        const maxW = 1600;
        const w = video.videoWidth;
        const h = video.videoHeight;
        const scale = Math.min(1, maxW / w);
        const nw = Math.round(w * scale);
        const nh = Math.round(h * scale);

        const canvas = document.createElement('canvas');
        canvas.width = nw;
        canvas.height = nh;

        const ctx = canvas.getContext('2d', { alpha: false });
        ctx.drawImage(video, 0, 0, nw, nh);

        const blob = await new Promise(res => canvas.toBlob(res, 'image/jpeg', 0.82));
        if (!blob) {
            alert('촬영 처리에 실패했습니다.');
            return;
        }

        const idx = shots.length;
        shots.push(blob);
        renderShot(blob, idx);
    }

    function renderShot(blob, idx) {
        const url = URL.createObjectURL(blob);
        const row = document.createElement('div');
        row.className = 'mini';
        row.style.display = 'grid';
        row.style.gridTemplateColumns = '96px 1fr auto';
        row.style.gap = '10px';
        row.style.alignItems = 'center';

        row.innerHTML = `
            <img src="${url}" alt="촬영본"
                style="width:96px;height:96px;object-fit:cover;border-radius:14px;border:1px solid rgba(234,240,255,.12);" />
            <div style="min-width:0;">
                <div style="font-weight:900; font-size:13px;">촬영본 #${idx + 1}</div>
                <div class="tiny">${Math.round(blob.size / 1024)} KB</div>
            </div>
            <button type="button" class="btnGhost" data-del="${idx}" style="padding:10px 12px;">삭제</button>
        `;

        row.querySelector('[data-del]').addEventListener('click', () => {
            shots[idx] = null;
            row.remove();
        });

        docList.appendChild(row);
    }

    async function uploadAll() {
        const valid = shots.filter(Boolean);
        if (valid.length === 0) {
            alert('업로드할 촬영본이 없습니다.');
            return;
        }

        const fd = new FormData();
        fd.append('inquiry_id', String(inquiryId));
        fd.append('doc_type', (docTypeSel?.value || 'etc'));
        valid.forEach((b, i) => {
            fd.append('files[]', b, `camera_${Date.now()}_${i}.jpg`);
        });

        btnUploadAll.disabled = true;
        try {
            const res = await fetch('upload_document.php', {
                method: 'POST',
                body: fd,
                credentials: 'same-origin'
            });
            const data = await res.json();

            if (!data.ok) {
                alert(data.message || '업로드 실패');
                return;
            }

            alert('서류 업로드 완료!');
            shots.length = 0;
            docList.innerHTML = '';
        } catch (e) {
            alert('네트워크 오류가 발생했습니다.');
        } finally {
            btnUploadAll.disabled = false;
        }
    }

    btnStartCam?.addEventListener('click', startCamera);
    btnCapture?.addEventListener('click', capture);
    btnStopCam?.addEventListener('click', stopCamera);
    btnUploadAll?.addEventListener('click', uploadAll);

    setBtnState();
    window.addEventListener('beforeunload', stopCamera);
})();
</script>

</body>
</html>