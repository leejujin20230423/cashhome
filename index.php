<?php
declare(strict_types=1);
session_start();

// // 테스트: 세션이 유지되는지 확인용(새로고침마다 유지되어야 함)
// if (!isset($_SESSION['__test'])) {
//     $_SESSION['__test'] = 'set@' . date('H:i:s');
// }

// echo "Hello, Cashhome! This is the landing page (index.php)\n";

// if (!empty($_GET['debug'])) {
//     echo "<pre style='color:#0f0;background:#000;padding:15px;border-radius:12px;font-size:14px;white-space:pre-wrap;'>";
//     echo "==== 0. PHP SESSION ====\n";
//     var_dump([
//         'session_id' => session_id(),
//         'cookie_name' => session_name(),
//         'cookie_has' => isset($_COOKIE[session_name()]) ? 'YES' : 'NO',
//         'cookie_value' => $_COOKIE[session_name()] ?? null,
//         '__test' => $_SESSION['__test'] ?? null,
//     ]);

//     echo "\n==== 1. kakao_profile ====\n";
//     var_dump($_SESSION['kakao_profile'] ?? null);

//     echo "\n==== 2. draft ====\n";
//     var_dump($_SESSION['cashhome_inquiry_draft'] ?? null);

//     echo "\n==== 3. GET ====\n";
//     var_dump($_GET);

//     echo "\n==== 4. FULL _SESSION ====\n";
//     var_dump($_SESSION);

//     echo "</pre>";
// }
// exit; // ✅ 여기서 멈춰서 테스트만 보이게 함
/**
 * ECASH (이케쉬대부) - index.php
 * - 랜딩페이지 + 상담신청
 * - 동의는 consent.php에서만 완료되며(index.php 체크박스/영역 클릭 시 consent.php로 이동)
 * - 동의 완료(세션) 상태일 때만 접수 가능
 * - 동의 클릭 전 입력값 필수 검증(누가 동의했는지 증적 확보 목적)
 * - 입력 오류는 팝업(alert)으로 안내
 * - 상담신청 저장: cashhome_1000_inquiries + cashhome_1100_consent_logs
 */

session_start();
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self' 'unsafe-inline' https: data:;");

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * ===== DB CONFIG =====
 */
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**'; // <-- 운영 환경에 맞게 관리(권장: env)

/**
 * 개인정보처리방침 버전
 */
const PRIVACY_POLICY_VERSION = 'v1';

/**
 * PDO 연결 함수
 */
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

/**
 * ✅ 동의 완료 여부(세션 기반)
 * consent.php에서 세팅되는 형태(당신이 준 consent.php 기준):
 * $_SESSION['cashhome_consent'] = [
 *   'privacy' => bool,
 *   'marketing' => bool,
 *   'privacy_at' => 'YYYY-mm-dd HH:ii:ss' | null,
 *   'marketing_at' => 'YYYY-mm-dd HH:ii:ss' | null,
 *   'privacy_ver' => 'v1',
 *   'marketing_ver' => 'v1',
 *   // (옵션) 'version','consented_at' 형태도 호환 처리
 * ];
 */
function cashhome_consent_ok(): bool
{
    if (empty($_SESSION['cashhome_consent']) || !is_array($_SESSION['cashhome_consent'])) return false;
    $c = $_SESSION['cashhome_consent'];

    $privacy = !empty($c['privacy']);
    $marketing = !empty($c['marketing']);
    if (!$privacy || !$marketing) return false;

    // consent.php(최신) 키 우선
    $hasPrivacyAt = !empty($c['privacy_at']);
    $hasMarketingAt = !empty($c['marketing_at']);
    $hasPrivacyVer = !empty($c['privacy_ver']);
    $hasMarketingVer = !empty($c['marketing_ver']);

    // (이전 형태) version/consented_at도 허용
    $hasLegacy = (!empty($c['version']) && !empty($c['consented_at']));

    if (($hasPrivacyAt && $hasMarketingAt && $hasPrivacyVer && $hasMarketingVer) || $hasLegacy) {
        return true;
    }
    return false;
}

/**
 * ✅ 입력값 검증 (동의 페이지로 이동 전 / 최종 접수 전 공통 사용)
 * - 메모는 선택
 * - 성함/연락처/희망금액/자금용도는 필수
 */
function validate_inquiry_input(array $in): array
{
    $name = trim((string)($in['name'] ?? ''));
    $phone = trim((string)($in['phone'] ?? ''));
    $amount = trim((string)($in['amount'] ?? ''));
    $purpose = trim((string)($in['purpose'] ?? ''));
    $memo = trim((string)($in['memo'] ?? ''));

    $errors = [];

    if ($name === '' || mb_strlen($name) < 2) {
        $errors[] = '성함을 2자 이상 입력해주세요.';
    }

    $phoneDigits = preg_replace('/\D+/', '', $phone) ?? '';
    if ($phoneDigits === '' || strlen($phoneDigits) < 9 || strlen($phoneDigits) > 12) {
        $errors[] = '연락처를 정확히 입력해주세요.';
    }

    // 희망금액 필수
    if ($amount === '') {
        $errors[] = '희망금액을 입력해주세요.';
    } else {
        $amountDigits = preg_replace('/\D+/', '', $amount);
        if ($amountDigits === null || $amountDigits === '') {
            $errors[] = '희망금액은 숫자로 입력해주세요.';
        }
    }

    // 자금용도 필수 (선택 안함 불가)
    if ($purpose === '' || $purpose === '선택 안함') {
        $errors[] = '자금용도를 선택해주세요.';
    }

    // 요청사항 선택 (길이만 제한)
    if (mb_strlen($memo) > 1000) {
        $errors[] = '요청사항은 1000자 이하로 입력해주세요.';
    }

    return [$errors, [
        'name' => $name,
        'phone' => $phone,
        'amount' => $amount,
        'purpose' => $purpose,
        'memo' => $memo,
    ]];
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$consentOk = cashhome_consent_ok();

$successMsg = '';
$errorMsg = '';

// ✅ 입력값 draft: 동의 페이지 갔다 와도 입력 유지
$draft = $_SESSION['cashhome_inquiry_draft'] ?? null;

$old = [
    'name' => is_array($draft) ? (string)($draft['name'] ?? '') : '',
    'phone' => is_array($draft) ? (string)($draft['phone'] ?? '') : '',
    'amount' => is_array($draft) ? (string)($draft['amount'] ?? '') : '',
    'purpose' => is_array($draft) ? (string)($draft['purpose'] ?? '선택 안함') : '선택 안함',
    'memo' => is_array($draft) ? (string)($draft['memo'] ?? '') : '',
];


// ==========================================================
// ✅🔥 카카오 로그인 → 자동입력 (완전 안정 버전)
// ==========================================================

$kakaoErr = (string)($_GET['kakao_error'] ?? '');
$kakaoOkMsg = !empty($_GET['kakao_ok'])
    ? '카카오 로그인 완료! 성함이 자동 입력되었습니다.'
    : '';

if (!empty($_SESSION['kakao_profile']) && is_array($_SESSION['kakao_profile'])) {

    $kp = $_SESSION['kakao_profile'];

    $kName  = trim((string)($kp['nickname'] ?? ''));
    $kPhone = trim((string)($kp['phone_number'] ?? ''));

    // 👉 카카오 값이 존재하면 무조건 우선 적용
    if ($kName !== '') {
        $old['name'] = $kName;
    }

    if ($kPhone !== '') {
        $old['phone'] = $kPhone;
    }

    // 👉 draft 세션도 동기화 (동의 이동/새로고침 대비)
    $_SESSION['cashhome_inquiry_draft'] = $old;
}

// 2) ✅ 사전검증(preconsent)용 draft에도 반영(동의 누르기 전에 이름/폰 유지)
if (empty($_SESSION['cashhome_inquiry_draft']) || !is_array($_SESSION['cashhome_inquiry_draft'])) {
    $_SESSION['cashhome_inquiry_draft'] = $old;
} else {
    if ($kName !== '' && (empty($_SESSION['cashhome_inquiry_draft']['name']) || mb_strlen((string)$_SESSION['cashhome_inquiry_draft']['name']) < 2)) {
        $_SESSION['cashhome_inquiry_draft']['name'] = $kName;
    }
    if ($kPhone !== '' && empty($_SESSION['cashhome_inquiry_draft']['phone'])) {
        $_SESSION['cashhome_inquiry_draft']['phone'] = $kPhone;
    }
}


/**
 * ✅ 동의페이지 이동 전 사전검증 요청 (AJAX)
 * POST action=preconsent
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

    // ✅ 누가 동의했는지 증적을 위해 입력값을 먼저 확보(세션 저장)
    $_SESSION['cashhome_inquiry_draft'] = $clean;

    echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * --- FORM HANDLER (최종 접수) ---
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') !== 'preconsent') {

    // Honeypot (봇 방지)
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
            ];

            // ✅ 동의 완료 필수
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

                // ✅ 세션 동의 정보(증적)
                $consent = $_SESSION['cashhome_consent'];

                // consent.php(최신) 기반
                $privacyVer = (string)($consent['privacy_ver'] ?? PRIVACY_POLICY_VERSION);
                $marketingVer = (string)($consent['marketing_ver'] ?? 'v1');
                $privacyAt = (string)($consent['privacy_at'] ?? '');
                $marketingAt = (string)($consent['marketing_at'] ?? '');

                // 레거시 호환
                if ($privacyAt === '' && !empty($consent['consented_at'])) $privacyAt = (string)$consent['consented_at'];
                if ($marketingAt === '' && !empty($consent['consented_at'])) $marketingAt = (string)$consent['consented_at'];
                if ($privacyVer === '' && !empty($consent['version'])) $privacyVer = (string)$consent['version'];

                $newId = null;

                try {
                    $pdo = cashhome_pdo();
                    $pdo->beginTransaction();

                    // 1) 상담 신청 저장 (1000)
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

                        ':loan_amount' => $amount,
                        ':loan_purpose' => $purpose,
                        ':request_memo' => $memo !== '' ? $memo : null,

                        // ✅ 동의 완료 후에만 여기까지 오므로 1 저장
                        ':agree_privacy' => 1,
                        ':privacy_policy_version' => $privacyVer,
                        ':privacy_agreed_at' => $privacyAt !== '' ? $privacyAt : $ts,

                        ':agree_marketing' => 1,
                        ':marketing_agreed_at' => $marketingAt !== '' ? $marketingAt : $ts,

                        ':status' => 'new',
                    ]);

                    $newId = (int)$pdo->lastInsertId();

                    // 2) 동의 로그 저장 (1100) - privacy
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

                    // 3) 동의 로그 저장 (1100) - marketing
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
                    if (isset($pdo) && $pdo instanceof PDO && $pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    error_log('[DB/CONSENT INSERT ERROR] ' . $e->getMessage());
                    $errorMsg = '일시적인 오류로 접수가 완료되지 않았습니다. 잠시 후 다시 시도해주세요.';
                }

                if ($errorMsg === '') {
                    // CSRF rotate
                    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

                    // ✅ 접수 완료 후: 동의/입력 draft 정리
                    unset($_SESSION['cashhome_consent'], $_SESSION['cashhome_inquiry_draft']);
                    $consentOk = false;

                    $successMsg = '상담 신청이 접수되었습니다. 담당자가 확인 후 연락드리겠습니다.';
                    $old = ['name' => '', 'phone' => '', 'amount' => '', 'purpose' => '선택 안함', 'memo' => ''];
                } else {
                    // 오류가 나도 입력 draft는 유지
                    $_SESSION['cashhome_inquiry_draft'] = $clean;
                }
            }
        }
    }
}

// --- DISPLAY DATA ---
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
?>
<!doctype html>
<html lang="ko">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="theme-color" content="#0B1220" />
    <title><?= h($brandEn) ?> | <?= h($brandKr) ?> - 빠르고 간편한 상담</title>
    <meta name="description" content="<?= h($brandEn) ?>(<?= h($brandKr) ?>) 대출 상담/상담신청. 빠르고 정확한 안내를 제공합니다." />
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
            /* color: var(--muted); */
            font-size: 13px;
            padding: 8px 10px;
            border-radius: 999px;
            border: 1px solid transparent;
        }

        .navlinks a:hover {
            color: var(--text);
            border-color: var(--line);
            background: rgba(255, 255, 255, .04);
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
            box-shadow: 0 0 18px rgba(110, 231, 255, .7);
        }

        h1 {
            margin: 12px 0 10px;
            font-size: 36px;
            line-height: 1.15;
            letter-spacing: -0.6px;
        }

        .sub {
            color: var(--muted);
            margin: 0 0 18px;
            font-size: 14px;
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
            font-size: 13px;
        }

        .b span {
            display: block;
            font-size: 12px;
            color: var(--muted);
        }

        .heroBtns {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
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
            background: rgba(255, 255, 255, .05);
        }

        .heroR {
            padding: 18px;
            display: grid;
            gap: 12px;
        }

        .mini {
            padding: 14px 14px;
            border-radius: var(--radius2);
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
        }

        .mini h3 {
            margin: 0 0 8px;
            font-size: 14px;
        }

        .mini p {
            margin: 0;
            color: var(--muted);
            font-size: 12px;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 14px;
            margin-top: 14px;
        }

        .col4 {
            grid-column: span 4;
        }

        .col6 {
            grid-column: span 6;
        }

        .col12 {
            grid-column: span 12;
        }

        .sectionTitle {
            margin: 26px 0 10px;
            font-size: 18px;
            letter-spacing: -0.2px;
        }

        .sectionSub {
            margin: 0 0 12px;
            color: var(--muted);
            font-size: 13px;
        }

        .box {
            padding: 18px;
        }

        .box h3 {
            margin: 0 0 8px;
            font-size: 15px;
        }

        .box p {
            margin: 0;
            color: var(--muted);
            font-size: 13px;
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
            padding: 18px;
        }

        form {
            display: grid;
            gap: 10px;
        }

        .row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }

        label {
            font-size: 12px;
            color: var(--muted);
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
            box-shadow: 0 0 0 3px rgba(110, 231, 255, .12);
        }

        textarea {
            min-height: 110px;
            resize: vertical;
        }

        .checks {
            display: grid;
            gap: 10px;
            margin-top: 6px;
        }

        /* ====== ✅ UX 업그레이드: Consent 카드형 ====== */
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

        .consentCard:hover {
            transform: translateY(-1px);
            background: rgba(255, 255, 255, .05);
            border-color: rgba(234, 240, 255, .18);
        }

        .consentCard:active {
            transform: translateY(0px);
        }

        .consentIcon {
            width: 38px;
            height: 38px;
            border-radius: 14px;
            border: 1px solid rgba(234, 240, 255, .12);
            background: rgba(8, 12, 24, .55);
            display: grid;
            place-items: center;
            flex: 0 0 auto;
            margin-top: 2px;
        }

        .consentCheck {
            width: 22px;
            height: 22px;
            border-radius: 999px;
            border: 1px solid rgba(234, 240, 255, .22);
            background: rgba(8, 12, 24, .55);
            display: grid;
            place-items: center;
            flex: 0 0 auto;
            margin-top: 6px;
        }

        .consentCheck .dotOk {
            width: 10px;
            height: 10px;
            border-radius: 99px;
            background: var(--accent);
            box-shadow: 0 0 16px rgba(110, 231, 255, .55);
        }

        .consentBody {
            flex: 1 1 auto;
            min-width: 0
        }

        .consentTitle {
            font-weight: 900;
            color: var(--text);
            display: flex;
            gap: 8px;
            align-items: center;
            flex-wrap: wrap;
        }

        .consentMeta {
            margin-top: 4px;
            color: var(--muted);
            font-size: 12px;
            line-height: 1.4;
        }

        .consentHint {
            margin-top: 8px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

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

        .chip.ok {
            color: var(--accent);
            border-color: rgba(110, 231, 255, .25);
        }

        .arrow {
            position: absolute;
            right: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: rgba(234, 240, 255, .45);
            font-weight: 900;
        }

        .consentCard[aria-disabled="true"] {
            cursor: pointer;
            /* 클릭은 가능(사전검증 후 이동), 단 내부 체크박스는 없음 */
        }

        .consentCard:focus {
            outline: none;
            box-shadow: 0 0 0 3px rgba(110, 231, 255, .12);
            border-color: rgba(110, 231, 255, .35);
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
            border-color: rgba(110, 231, 255, .35);
        }

        .alert.err {
            border-color: rgba(255, 120, 120, .35);
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
            gap: 14px;
        }

        .kv {
            display: grid;
            gap: 6px;
        }

        .kv div {
            display: flex;
            gap: 10px;
            align-items: flex-start;
        }

        .kv b {
            min-width: 110px;
            color: rgba(234, 240, 255, .85);
        }

        .hr {
            height: 1px;
            background: var(--line);
            margin: 14px 0;
        }

        .tiny {
            font-size: 11px;
            color: rgba(157, 176, 208, .9);
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

        button[disabled] {
            opacity: .45;
            cursor: not-allowed;
            filter: grayscale(20%);
        }

        /* ===== 카카오 버튼 커스텀 ===== */
        .kakao-btn {
            padding: 10px 14px;
            border-radius: 999px;
            font-weight: 800;
            font-size: 13px;
            text-decoration: none;
            display: inline-block;
            border: 0;
            cursor: pointer;
            transition: all .18s ease;
            white-space: nowrap;

            /* 카카오 느낌 + 은은한 그라데이션 */
            background: linear-gradient(135deg, #FEE500 0%, #F7D800 100%);
            color: #111;

            box-shadow: 0 8px 20px rgba(0, 0, 0, .25);
        }

        .kakao-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 26px rgba(0, 0, 0, .35);
            background: linear-gradient(135deg, #FFE812 0%, #F5D000 100%);
        }

        .kakao-btn:active {
            transform: translateY(0px);
            box-shadow: 0 6px 16px rgba(0, 0, 0, .25);
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
                font-size: 30px;
            }

            .footer .cols {
                grid-template-columns: 1fr;
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
                <a class="btnGhost" href="admin_login.php" rel="nofollow">관리자 로그인</a>
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
                        <div><strong>개인정보 최소 수집</strong><span>입력 완료 후 동의 진행(증적 목적)</span></div>
                    </div>
                    <div class="b"><i></i>
                        <div><strong>투명한 고지</strong><span>필수 정보를 명확히 안내</span></div>
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
                    <p>연락처/희망금액/용도 등 항목을 입력합니다.</p>
                </div>
                <div class="card box col4">
                    <div class="pill">02 · 동의 진행</div>
                    <h3>전문 열람 후 동의</h3>
                    <p>입력 완료 후 동의 페이지에서 동의를 완료합니다.</p>
                </div>
                <div class="card box col4">
                    <div class="pill">03 · 접수 완료</div>
                    <h3>저장 및 확인 연락</h3>
                    <p>접수 완료 후 담당자가 확인하여 연락드립니다.</p>
                </div>
            </div>
        </section>

        <section id="process">
            <h2 class="sectionTitle">진행 절차</h2>
            <p class="sectionSub">입력 → 동의 → 접수 순으로 진행됩니다.</p>

            <div class="grid">
                <div class="card box col6">
                    <h3>입력</h3>
                    <p>성함/연락처/희망금액/자금용도를 입력합니다. (요청사항은 선택)</p>
                </div>
                <div class="card box col6">
                    <h3>동의</h3>
                    <p>전문 열람 후 개인정보/마케팅 동의를 완료합니다.</p>
                </div>
                <div class="card box col6">
                    <h3>접수</h3>
                    <p>동의 완료 상태에서만 접수 버튼이 동작합니다.</p>
                </div>
                <div class="card box col6">
                    <h3>확인 연락</h3>
                    <p>담당자가 확인 후 연락드리며, 필요 시 추가 정보를 요청드릴 수 있습니다.</p>
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
            <p class="sectionSub">입력 완료 후 동의 진행이 가능합니다. (요청사항은 선택)</p>

            <div class="grid">
                <div class="card formWrap col12">
                    <?php if ($successMsg): ?>
                        <div class="alert ok" role="status" aria-live="polite"><?= h($successMsg) ?></div>
                    <?php elseif ($errorMsg): ?>
                        <div class="alert err" role="alert"><?= h($errorMsg) ?></div>
                    <?php endif; ?>



                    <?php if (!empty($_GET['debug'])): ?>
                        <pre style="color:#fff; background:#000; padding:10px; border-radius:10px;">
kakao_profile:
<?= htmlspecialchars(print_r($_SESSION['kakao_profile'] ?? null, true), ENT_QUOTES, 'UTF-8') ?>
draft:
<?= htmlspecialchars(print_r($_SESSION['cashhome_inquiry_draft'] ?? null, true), ENT_QUOTES, 'UTF-8') ?>
old:
<?= htmlspecialchars(print_r($old ?? null, true), ENT_QUOTES, 'UTF-8') ?>
</pre>
                    <?php endif; ?>



                    <form id="applyForm" method="post" action="#apply" autocomplete="on" novalidate>
                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>" />

                        <!-- Honeypot -->
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

                        <div class="row">
                            <div>
                                <label for="amount">희망금액 (필수)</label>
                                <input id="amount" name="amount" type="text" inputmode="numeric" placeholder="예: 500만원"
                                    required value="<?= h($old['amount']) ?>" />
                            </div>
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
                        </div>

                        <div>
                            <label for="memo">요청사항 (선택)</label>
                            <textarea id="memo" name="memo" placeholder="상담 시 참고할 내용을 적어주세요."><?= h($old['memo']) ?></textarea>
                        </div>

                        <!-- ✅ UX 업그레이드: “체크박스처럼 보이는” 카드 / 실제 checkbox 없음 -->
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

                            <?php if (!$consentOk): ?>
                                <div style="margin-top:6px;">
                                    <a class="cta" href="#" id="goConsentBtn" style="display:inline-block;">동의하러 가기</a>
                                </div>
                            <?php endif; ?>
                        </div>

                        <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">

                            <!-- 카카오 1초접수 -->
                            <a href="kakao_login.php?return=index.php#apply"
                                class="kakao-btn">
                                💬 카카오 1초접수
                            </a>

                            <!-- 상담 신청 접수 -->
                            <button class="cta" type="submit"
                                <?= $consentOk ? '' : 'disabled' ?>>
                                상담 신청 접수
                            </button>

                        </div>
                        <div class="tiny">
                            ※ 입력 오류가 있으면 팝업으로 안내됩니다. 동의는 입력 완료 후 진행됩니다.
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
                        • 수집항목: 성함, 연락처, 희망금액, 자금용도, 상담내용(선택), 접속기록(보안 목적)<br />
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
        // ✅ 서버 에러/성공/카카오 메시지 -> 팝업(alert)
        (function() {
            const err = <?= json_encode($errorMsg, JSON_UNESCAPED_UNICODE) ?>;
            const ok = <?= json_encode($successMsg, JSON_UNESCAPED_UNICODE) ?>;

            const kerr = <?= json_encode($kakaoErr ?? '', JSON_UNESCAPED_UNICODE) ?>;
            const kok = <?= json_encode($kakaoOkMsg ?? '', JSON_UNESCAPED_UNICODE) ?>;

            if (err) alert(err);
            if (ok) alert(ok);

            if (kerr) alert(kerr);
            if (kok) alert(kok);
        })();

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
            topBtn.style.display = (window.scrollY > 600) ? 'block' : 'none';
        };
        window.addEventListener('scroll', onScroll, {
            passive: true
        });
        topBtn.addEventListener('click', () => window.scrollTo({
            top: 0,
            behavior: 'smooth'
        }));
        onScroll();

        // ✅ 전화번호 하이픈 자동 포맷 (010-1234-5678 / 02 예외 포함)
        (function() {
            const phoneEl = document.getElementById('phone');
            if (!phoneEl) return;

            function formatPhoneKR(value) {
                const digits = (value || '').replace(/\D+/g, '').slice(0, 11);

                // 02(서울) 예외 처리
                if (digits.startsWith('02')) {
                    if (digits.length <= 2) return digits;
                    if (digits.length <= 5) return digits.replace(/^(\d{2})(\d{1,3})$/, '$1-$2');
                    if (digits.length <= 9) return digits.replace(/^(\d{2})(\d{3})(\d{1,4})$/, '$1-$2-$3');
                    return digits.replace(/^(\d{2})(\d{4})(\d{1,4})$/, '$1-$2-$3');
                }

                // 일반(휴대폰/지역번호 3자리 가정)
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

            phoneEl.addEventListener('input', onInput, {
                passive: true
            });
            phoneEl.addEventListener('blur', onInput, {
                passive: true
            });

            // 초기값 포맷
            onInput();
        })();

        // ✅ 동의 이동 전 사전검증 + draft 저장(AJAX)
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
                alert('네트워크 오류가 발생했습니다. 잠시 후 다시 시도해주세요.');
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

        // ✅ 동의 없는데 접수 버튼 눌러지는 경우 방지
        form.addEventListener('submit', (e) => {
            const consentOk = <?= $consentOk ? 'true' : 'false' ?>;
            if (!consentOk) {
                e.preventDefault();
                alert('동의가 완료되어야 접수할 수 있습니다. 입력 완료 후 동의 페이지에서 동의를 완료해주세요.');
            }
        });
    </script>
</body>

</html>