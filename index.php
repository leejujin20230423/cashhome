<?php

declare(strict_types=1);

/**
 * index.php (PHP 부분 전체) ✅ 업로드 완료 시점 메일 발송용 + ✅ 랜덤 대출(접수)번호(loan_no) 적용본
 *
 * ✅ 추가 변경 요약
 * - cashhome_1000_inquiries.cashhome_1000_loan_no (UNIQUE) 컬럼을 사용한다고 가정
 * - 접수 INSERT 시 YYMMDD-XXXX 형태 랜덤 대출번호 생성 후 DB 저장
 * - 세션에 cashhome_last_loan_no 저장
 * - 업로드 알림 payload 조회 시 loan_no도 함께 읽어오도록 수정
 * - 메일 발송 시 sendLoanRequestEmail(payload, inquiryId)로 inquiryId 전달(기존 어댑터 버그 수정)
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
if (!isset($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

if (!empty($_GET['reset'])) {
  unset(
    $_SESSION['cashhome_inquiry_draft'],
    $_SESSION['kakao_profile'],
    $_SESSION['kakao_oauth_state'],
    $_SESSION['cashhome_consent'],
    $_SESSION['cashhome_last_inquiry_id'],
    $_SESSION['cashhome_last_loan_no']
  );
  header('Location: index.php#apply');
  exit;
}

header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
// ✅ 다음 주소 API 포함 CSP (index.php에서는 카메라 필요 없음)
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://t1.daumcdn.net https://postcode.map.daum.net; style-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:; connect-src 'self' https:; frame-src https://t1.daumcdn.net https://postcode.map.daum.net;");

function h(string $s): string
{
  return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

const PRIVACY_POLICY_VERSION = 'v1';

// 호환용(수신자는 mail_sender.php 설정이 우선)
const CASHHOME_NOTIFY_EMAIL = 'ecashhome@gmail.com';

// ✅ mail_sender.php 로드 (MailSender 클래스 포함)
require_once __DIR__ . '/mail_sender.php';
if (!class_exists('MailSender')) {
  error_log('[MAIL] MailSender class not found after require_once');
}

/**
 * ✅ PDO
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
 * ✅ 랜덤 대출(접수)번호 생성: YYMMDD-XXXX (Base36)
 * 예) 260224-7K3F
 */
function cashhome_make_loan_no(DateTimeZone $tz = new DateTimeZone('Asia/Seoul')): string
{
  $date = (new DateTime('now', $tz))->format('ymd'); // YYMMDD
  $chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  $suffix = '';
  for ($i = 0; $i < 4; $i++) {
    $suffix .= $chars[random_int(0, 35)];
  }
  return $date . '-' . $suffix;
}

/**
 * ✅ MailSender 어댑터 (기존 호출부 유지 목적)
 * - 상담접수: sendLoanRequestEmail()로 보냄
 * - 서류업로드 완료: sendLoanDocumentSubmissionEmail()로 보냄
 *
 * 사용 방식:
 *  - 상담접수 메일: cashhome_send_mail('inquiry', $payload, $inquiryId)
 *  - 업로드완료 메일: cashhome_send_mail('upload',  $payload, $inquiryId)
 */
function cashhome_send_mail(string $type, array $payload, int $inquiryId = 0): bool
{
  if (!class_exists('MailSender')) {
    error_log('[MAIL] MailSender missing');
    return false;
  }

  try {
    static $mailer = null;
    if (!$mailer) $mailer = new MailSender();

    if ($type === 'upload') {
      return (bool)$mailer->sendLoanDocumentSubmissionEmail($payload, $inquiryId);
    }

    // 기본: 상담 접수 ✅ inquiryId 전달(기존 누락 버그 수정)
    return (bool)$mailer->sendLoanRequestEmail($payload, $inquiryId);
  } catch (Throwable $e) {
    error_log('[MAIL] MailSender error: ' . $e->getMessage());
    return false;
  }
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
  if (!$hasPrivacyAt || !$hasMarketingAt) return false;

  return true;
}

/**
 * ✅ 배달대행 기본 템플릿 (company_info에 자동 주입용)
 */
function delivery_company_info_template(): string
{
  return "1.배달대행소속 지사명: \n"
    . "2.최근 3개월간 월평균소득: \n"
    . "3.평균 근무시간: \n"
    . "4.준비서류: 최근 3개월간 평균 배달대행 건수 사진(아이디보이도록),인감증명서 원본,가족관계증명서 원본,주민등록 초본 원본 전체내역, 주민등록 등본 전체내역,인감도장\n";
}

/**
 * ✅ 입력 검증
 */
function validate_inquiry_input(array $in): array
{
  $name = trim((string)($in['name'] ?? ''));
  $phone = trim((string)($in['phone'] ?? ''));
  $amount = trim((string)($in['amount'] ?? ''));
  $purpose = trim((string)($in['purpose'] ?? ''));
  $memo = trim((string)($in['memo'] ?? ''));

  $applicantType = trim((string)($in['applicant_type'] ?? ''));
  $companyInfo = trim((string)($in['company_info'] ?? ''));

  $addrLive = trim((string)($in['addr_live'] ?? ''));
  $addrLiveDetail = trim((string)($in['addr_live_detail'] ?? ''));
  $addrResident = trim((string)($in['addr_resident'] ?? ''));
  $addrResidentDetail = trim((string)($in['addr_resident_detail'] ?? ''));

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

  if (!in_array($applicantType, ['personal', 'company', 'delivery'], true)) {
    $errors[] = '신청 유형(개인/기업/배달대행)을 선택해주세요.';
  }

  if ($addrLive === '') $errors[] = '주소(실거주지)를 입력해주세요.';
  if ($addrResident === '') $errors[] = '주소(등본 주소지)를 입력해주세요.';

  if ($addrLiveDetail === '') $errors[] = '상세주소(실거주지)를 입력해주세요.';
  if ($addrResidentDetail === '') $errors[] = '상세주소(등본 주소지)를 입력해주세요.';

  if (mb_strlen($addrLiveDetail) > 255) $errors[] = '상세주소(실거주지)는 255자 이하로 입력해주세요.';
  if (mb_strlen($addrResidentDetail) > 255) $errors[] = '상세주소(등본 주소지)는 255자 이하로 입력해주세요.';

  $loanPeriod = 0;
  if ($loanPeriodRaw === '' || !ctype_digit($loanPeriodRaw)) {
    $errors[] = '예상 대출기간을 선택해주세요.';
  } else {
    $loanPeriod = (int)$loanPeriodRaw;
    if ($loanPeriod < 1 || $loanPeriod > 24) {
      $errors[] = '예상 대출기간은 1~24개월 범위로 선택해주세요.';
    }
  }

  if (mb_strlen($companyInfo) > 2000) $errors[] = '추가 정보는 2000자 이하로 입력해주세요.';
  if (mb_strlen($memo) > 1000) $errors[] = '요청사항은 1000자 이하로 입력해주세요.';

  if ($applicantType === 'delivery' && $companyInfo === '') {
    $companyInfo = delivery_company_info_template();
  }

  return [$errors, [
    'name' => $name,
    'phone' => $phone,
    'amount' => $amount,
    'purpose' => $purpose,
    'memo' => $memo,

    'applicant_type' => $applicantType,
    'company_info' => $companyInfo,

    'addr_live' => $addrLive,
    'addr_live_detail' => $addrLiveDetail,
    'addr_resident' => $addrResident,
    'addr_resident_detail' => $addrResidentDetail,

    'loan_period' => (string)$loanPeriod,
  ]];
}

/**
 * ✅ 업로드 완료 메일에 넣을 payload를 DB에서 정확히 읽어오는 함수
 * - ✅ loan_no도 함께 조회해서 payload에 포함
 */
function cashhome_fetch_payload_by_inquiry_id(int $inquiryId): ?array
{
  if ($inquiryId <= 0) return null;

  try {
    $pdo = cashhome_pdo();
    $stmt = $pdo->prepare("
      SELECT
        cashhome_1000_loan_no AS loan_no,
        cashhome_1000_customer_name AS name,
        cashhome_1000_customer_phone AS phone,
        cashhome_1000_loan_amount AS amount,
        cashhome_1000_addr_live AS addr_live,
        cashhome_1000_addr_resident AS addr_resident,
        cashhome_1000_request_memo AS memo
      FROM cashhome_1000_inquiries
      WHERE cashhome_1000_id = :id
      LIMIT 1
    ");
    $stmt->execute([':id' => $inquiryId]);
    $row = $stmt->fetch();

    if (!$row) return null;

    $region = trim((string)($row['addr_live'] ?? ''));
    if ($region === '') $region = trim((string)($row['addr_resident'] ?? ''));

    return [
      'loan_no' => (string)($row['loan_no'] ?? ''),
      'name' => (string)($row['name'] ?? '이름없음'),
      'phone' => (string)($row['phone'] ?? '-'),
      'amount' => (string)($row['amount'] ?? '-'),
      'region' => $region !== '' ? $region : '-',
      'memo' => (string)($row['memo'] ?? '-'),
    ];
  } catch (Throwable $e) {
    error_log('[DB] fetch payload failed: ' . $e->getMessage());
    return null;
  }
}

if (empty($_SESSION['csrf_token'])) {
  $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$consentOk = cashhome_consent_ok();

$successMsg = '';
$errorMsg = '';

$draft = $_SESSION['cashhome_inquiry_draft'] ?? null;

$old = [
  'name' => is_array($draft) ? (string)($draft['name'] ?? '') : '',
  'phone' => is_array($draft) ? (string)($draft['phone'] ?? '') : '',
  'amount' => is_array($draft) ? (string)($draft['amount'] ?? '') : '',
  'purpose' => is_array($draft) ? (string)($draft['purpose'] ?? '선택 안함') : '선택 안함',
  'memo' => is_array($draft) ? (string)($draft['memo'] ?? '') : '',

  'applicant_type' => is_array($draft) ? (string)($draft['applicant_type'] ?? '') : '',
  'company_info' => is_array($draft) ? (string)($draft['company_info'] ?? '') : '',

  'addr_live' => is_array($draft) ? (string)($draft['addr_live'] ?? '') : '',
  'addr_live_detail' => is_array($draft) ? (string)($draft['addr_live_detail'] ?? '') : '',
  'addr_resident' => is_array($draft) ? (string)($draft['addr_resident'] ?? '') : '',
  'addr_resident_detail' => is_array($draft) ? (string)($draft['addr_resident_detail'] ?? '') : '',

  'loan_period' => is_array($draft) ? (string)($draft['loan_period'] ?? '') : '',
];

$kakaoErr = (string)($_GET['kakao_error'] ?? '');
$kakaoOk = !empty($_GET['kakao_ok']);
$kakaoOkMsg = $kakaoOk ? '카카오 로그인 완료! 성함이 자동 입력되었습니다.' : '';

/**
 * ✅ (신규) 실제 업로드 완료 시점 메일 발송 엔드포인트
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'upload_notice') {
  header('Content-Type: application/json; charset=utf-8');

  // ✅ CSRF 검증
  $token = (string)($_POST['csrf_token'] ?? '');
  if (empty($_SESSION['csrf_token']) || !hash_equals((string)$_SESSION['csrf_token'], $token)) {
    echo json_encode(['ok' => false, 'message' => '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.'], JSON_UNESCAPED_UNICODE);
    exit;
  }

  // ✅ inquiry_id 우선 사용 (세션이 끊겨도 발송 가능하도록)
  $inquiryId = (int)($_POST['inquiry_id'] ?? 0);
  if ($inquiryId <= 0) $inquiryId = (int)($_SESSION['cashhome_last_inquiry_id'] ?? 0);

  if ($inquiryId <= 0) {
    echo json_encode(['ok' => false, 'message' => '접수번호가 없습니다. (inquiry_id 누락)'], JSON_UNESCAPED_UNICODE);
    exit;
  }

  // ✅ 업로드 메일 payload는 반드시 DB에서 다시 읽어오기 (loan_no 포함)
  $payload = cashhome_fetch_payload_by_inquiry_id($inquiryId) ?? [
    'loan_no' => '',
    'name' => '이름없음',
    'phone' => '-',
    'amount' => '-',
    'region' => '-',
    'memo' => '-',
  ];

  $sent = cashhome_send_mail('upload', $payload, $inquiryId);

  if (!$sent) {
    error_log('[MAIL] upload_notice failed. inquiry_id=' . $inquiryId);
    echo json_encode(['ok' => false, 'message' => '이메일 발송에 실패했습니다(메일 설정 확인 필요).'], JSON_UNESCAPED_UNICODE);
    exit;
  }

  echo json_encode(['ok' => true], JSON_UNESCAPED_UNICODE);
  exit;
}

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
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') !== 'preconsent' && (string)($_POST['action'] ?? '') !== 'upload_notice') {

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
        'addr_live_detail' => $clean['addr_live_detail'],
        'addr_resident' => $clean['addr_resident'],
        'addr_resident_detail' => $clean['addr_resident_detail'],

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
        $addrLiveDetail = $clean['addr_live_detail'];
        $addrResident = $clean['addr_resident'];
        $addrResidentDetail = $clean['addr_resident_detail'];

        $loanPeriod = (int)$clean['loan_period'];

        $consent = $_SESSION['cashhome_consent'];

        $privacyVer = (string)($consent['privacy_ver'] ?? PRIVACY_POLICY_VERSION);
        $marketingVer = (string)($consent['marketing_ver'] ?? 'v1');
        $privacyAt = (string)($consent['privacy_at'] ?? '');
        $marketingAt = (string)($consent['marketing_at'] ?? '');

        if ($privacyAt === '' && !empty($consent['consented_at'])) $privacyAt = (string)$consent['consented_at'];
        if ($marketingAt === '' && !empty($consent['consented_at'])) $marketingAt = (string)$consent['consented_at'];
        if ($privacyVer === '' && !empty($consent['version'])) $privacyVer = (string)$consent['version'];

        $newId = 0;
        $loanNo = '';

        try {
          $pdo = cashhome_pdo();
          $pdo->beginTransaction();

          $stmt = $pdo->prepare("
            INSERT INTO cashhome_1000_inquiries (
              cashhome_1000_created_at,
              cashhome_1000_loan_no,

              cashhome_1000_user_ip,
              cashhome_1000_user_agent,
              cashhome_1000_customer_name,
              cashhome_1000_customer_phone,

              cashhome_1000_addr_live,
              cashhome_1000_addr_live_detail,
              cashhome_1000_addr_resident,
              cashhome_1000_addr_resident_detail,

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
              :loan_no,

              :user_ip,
              :user_agent,
              :customer_name,
              :customer_phone,

              :addr_live,
              :addr_live_detail,
              :addr_resident,
              :addr_resident_detail,

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

          // ✅ loan_no UNIQUE 중복 시 재시도
          $maxTry = 8;
          for ($try = 0; $try < $maxTry; $try++) {
            $loanNo = cashhome_make_loan_no();

            try {
              $stmt->execute([
                ':created_at' => $ts,
                ':loan_no' => $loanNo,

                ':user_ip' => $ip !== '' ? $ip : null,
                ':user_agent' => $ua !== '' ? mb_substr($ua, 0, 255) : null,
                ':customer_name' => $name,
                ':customer_phone' => $phone,

                ':addr_live' => $addrLive !== '' ? $addrLive : null,
                ':addr_live_detail' => $addrLiveDetail !== '' ? $addrLiveDetail : null,
                ':addr_resident' => $addrResident !== '' ? $addrResident : null,
                ':addr_resident_detail' => $addrResidentDetail !== '' ? $addrResidentDetail : null,

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
              break; // ✅ 성공
            } catch (PDOException $e) {
              // MySQL duplicate key = 1062
              $dup = (int)($e->errorInfo[1] ?? 0) === 1062;
              if ($dup && $try < $maxTry - 1) {
                continue; // 재시도
              }
              throw $e;
            }
          }

          if ($newId <= 0) {
            throw new RuntimeException('insert failed: newId=0');
          }

          // ✅ 업로드 흐름에서 쓰려고 세션에 접수번호/대출번호 저장
          $_SESSION['cashhome_last_inquiry_id'] = $newId;
          $_SESSION['cashhome_last_loan_no'] = $loanNo;

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

        // ✅ DB 저장 성공 후 “상담 접수” 메일 발송 (MailSender)
        if ($errorMsg === '' && $newId > 0) {
          $region = $addrLive !== '' ? $addrLive : ($addrResident !== '' ? $addrResident : '-');
          $payload = [
            'loan_no' => $loanNo, // ✅ 추가(메일에서 쓰면 더 좋음)
            'name' => $name,
            'phone' => $phone,
            'amount' => $amount,
            'region' => $region,
            'memo' => $memo !== '' ? $memo : '-',
          ];

          $sent = cashhome_send_mail('inquiry', $payload, $newId);
          if (!$sent) {
            // 접수는 성공이므로 사용자에게는 성공 유지, 로그만 남김
            error_log('[MAIL] inquiry mail failed. inquiry_id=' . $newId);
          }
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
            'addr_live_detail' => '',
            'addr_resident' => '',
            'addr_resident_detail' => '',

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

// ✅ 업로드 페이지에서 쓸 수 있는 접수번호/대출번호 (세션)
$lastInquiryId = (int)($_SESSION['cashhome_last_inquiry_id'] ?? 0);
$lastLoanNo = (string)($_SESSION['cashhome_last_loan_no'] ?? '');
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

  <link rel="manifest" href="/manifest.webmanifest">
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
      padding-top: var(--navH);
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
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: var(--navH);
      z-index: 30;
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
      flex-wrap: nowrap; 
    }
    

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      text-decoration: none
    }

    .logo {
      width: 50px;
      height: 50px;
      border-radius: 14px;
      overflow: hidden;
      background: none;
      border: 0;
      box-shadow: none;
      padding: 0;
      flex: 0 0 auto;
    }

    .logo img {
      width: 100%;
      height: 100%;
      display: block;
      object-fit: cover;
      padding: 0;
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

    .btnGhost:hover {
      background: rgba(255, 255, 255, .05);
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
      font-size: 20px;
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

    .action-row {
      display: flex;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-top: 10px;
    }

    .action-row>* {
      margin: 0 !important;
    }

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

    .btnAddr:hover {
      background: rgba(255, 255, 255, .06)
    }

    .installBtn {
      height: 38px;
      /* ✅ 원하는 고정 높이 */
      padding: 0 14px;
      /* ✅ 세로 padding 제거 */
      display: inline-flex;
      /* ✅ 내용 정렬 안정 */
      align-items: center;
      justify-content: center;

      line-height: 1;
      /* ✅ 라인높이로 늘어나는 현상 방지 */
      white-space: nowrap;
      /* ✅ 줄바꿈 방지 */
      flex: 0 0 auto;
      /* ✅ flex에서 늘어나지 않게 */

      background: #2c7be5;
      color: #fff;
      border: none;
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
      transition: 0.2s;
    }

    .installBtn:hover {
      background: #1a68d1;
    }

    @keyframes consentGlow {
      0% {
        box-shadow: 0 0 0 rgba(110, 231, 255, 0);
      }

      50% {
        box-shadow: 0 0 20px rgba(110, 231, 255, .9);
      }

      100% {
        box-shadow: 0 0 0 rgba(110, 231, 255, 0);
      }
    }

    .inputAddon {
      position: relative;
      width: 100%;
    }

    .inputAddon input {
      width: 100%;
      padding-right: 70px;
      /* 오른쪽 '만원' 공간 확보 */
    }

    .addonRight {
      position: absolute;
      right: 14px;
      top: 50%;
      transform: translateY(-50%);
      font-size: 13px;
      color: var(--muted);
      pointer-events: none;
      user-select: none;
    }

    .consent-highlight {
      animation: consentGlow 1s ease-in-out 3;
    }

    #apply2 {
      scroll-margin-top: 120px;
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

      .inputAddon {
        position: relative;
        width: 100%;
      }

      .inputAddon input {
        width: 100%;
        padding-right: 70px;
        /* 오른쪽 '만원' 공간 확보 */
      }

      .addonRight {
        position: absolute;
        right: 14px;
        top: 50%;
        transform: translateY(-50%);
        font-size: 13px;
        color: var(--muted);
        pointer-events: none;
        user-select: none;
      }

      .footer .cols {
        grid-template-columns: 1fr;
      }
    }
  

/* ===== Premium left card 3D slider (main_header) ===== */
.main_header{position:relative; overflow:hidden;}
.mhWrap{margin-top:18px;}
.mhViewport{position:relative; border:1px solid var(--line); border-radius:var(--radius2); padding:22px; min-height:192px; overflow:hidden; background:rgba(16,26,51,.45); box-shadow:inset 0 0 0 1px rgba(255,255,255,.04);}
.mhBg{position:absolute; inset:0; z-index:0;}
.mhBgA,.mhBgB{position:absolute; inset:-12%; background-size:cover; background-position:center; filter:blur(0px); transform:scale(1.08); opacity:0; transition:opacity .9s cubic-bezier(.22,1,.36,1), transform 3.8s cubic-bezier(.22,1,.36,1);}
.mhBgOverlay{position:absolute; inset:0; background:linear-gradient(180deg, rgba(11,18,32,.10) 0%, rgba(11,18,32,.55) 55%, rgba(11,18,32,.78) 100%); backdrop-filter: blur(2px);}
.mhDeck{position:relative; z-index:1; perspective:1200px; height:138px;}
.mhSlide{position:absolute; inset:0; display:flex; gap:18px; align-items:flex-start; padding:18px 18px 18px 18px; border-radius:18px; border:1px solid rgba(234,240,255,.10); background:rgba(11,18,32,.35); box-shadow:0 18px 40px rgba(0,0,0,.28); opacity:0; transform:translateX(18%) rotateY(52deg) scale(.98); transform-origin:left center; transition:transform .72s cubic-bezier(.22,1,.36,1), opacity .72s cubic-bezier(.22,1,.36,1), filter .72s cubic-bezier(.22,1,.36,1);}
.mhSlide::after{content:""; position:absolute; inset:0; border-radius:18px; pointer-events:none; background:linear-gradient(90deg, rgba(255,255,255,.10), rgba(255,255,255,0) 42%);}
.mhSlide.isActive{opacity:1; transform:translateX(0) rotateY(0deg) scale(1); }
.mhSlide.isPrev{opacity:0; transform:translateX(-18%) rotateY(-62deg) scale(.98); transform-origin:right center;}
.mhSlide.isNext{opacity:0; transform:translateX(18%) rotateY(62deg) scale(.98); }
.mhNo{width:56px; height:56px; flex:0 0 56px; border-radius:16px; display:flex; align-items:center; justify-content:center; font-weight:800; letter-spacing:.5px; color:rgba(234,240,255,.92); background:linear-gradient(180deg, rgba(110,231,255,.18), rgba(167,139,250,.18)); border:1px solid rgba(234,240,255,.16); box-shadow:0 10px 30px rgba(0,0,0,.25);}
.mhTitle{display:block; font-size:18px; font-weight:800; margin-bottom:6px;}
.mhDesc{margin:0; color:rgba(234,240,255,.76); line-height:1.55;}
.mhBody{padding-top:2px;}
.mhArrow{position:absolute; z-index:2; bottom:18px; width:38px; height:38px; border-radius:14px; border:1px solid rgba(234,240,255,.14); background:rgba(16,26,51,.55); color:rgba(234,240,255,.85); display:flex; align-items:center; justify-content:center; cursor:pointer; transition:transform .18s ease, background .18s ease, border-color .18s ease;}
.mhArrow:hover{transform:translateY(-1px); background:rgba(16,26,51,.75); border-color:rgba(234,240,255,.22);}
.mhPrev{left:18px;}
.mhNext{right:18px;}
.mhDots{position:absolute; z-index:2; left:50%; transform:translateX(-50%); bottom:28px; display:flex; gap:8px; align-items:center;}
.mhDot{width:18px; height:6px; border-radius:999px; border:1px solid rgba(234,240,255,.12); background:rgba(234,240,255,.10); cursor:pointer; transition:width .22s ease, background .22s ease, border-color .22s ease, opacity .22s ease; opacity:.6;}
.mhDot.isOn{width:28px; background:rgba(110,231,255,.55); border-color:rgba(110,231,255,.55); opacity:1;}
@media (max-width: 920px){
  .mhViewport{min-height:210px; padding:18px;}
  .mhDeck{height:160px;}
  .mhSlide{padding:16px; gap:14px;}
  .mhNo{width:52px; height:52px; border-radius:16px;}
  .mhTitle{font-size:17px;}
  .mhDots{bottom:22px;}
  .mhArrow{bottom:14px;}
}
</style>
</head>

<body>
  <header class="nav" role="banner">
    <div class="navin">
      <div style="display:flex; align-items:center; gap:10px;">
        <a class="brand" href="#top" aria-label="<?= h($brandEn) ?> 홈으로">
          <div class="logo">
            <img src="<?= h($logoImg) ?>" alt="<?= h($brandEn) ?> 로고" />
          </div>
          <div>
            <strong><?= h($brandEn) ?></strong>
            <span><?= h($brandKr) ?></span>
          </div>
        </a>

        <button id="installAppBtn" class="installBtn" style="display:none;">
          📲 앱 설치하기
        </button>
      </div>

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
      <div class="card heroL main_header">
        <div class="kicker"><span class="dot"></span> 신속 · 정확 · 친절 상담</div>
        <div class="heroFxArea" aria-hidden="true">
          <div class="heroFxText"><span class="fxEn"><?= h($brandEn) ?></span> <span class="fxKr">필요한 순간</span></div>
        </div>
        <h1><?= h($brandEn) ?>,<br />필요한 순간에 <span style="color:var(--accent)">빠르게</span> 안내드립니다.</h1>
        <p class="sub">
          이케쉬대부(ECASH)는 상담 신청 접수 후 담당자가 확인하여 연락드립니다.
          (※ 실제 조건은 심사/신용도/상품에 따라 달라질 수 있습니다.)
        </p>
        
        <div class="mhWrap" aria-label="핵심 장점 슬라이더">
          <div class="mhBg" aria-hidden="true">
            <div class="mhBgA"></div>
            <div class="mhBgB"></div>
            <div class="mhBgOverlay"></div>
          </div>

          <div class="mhViewport">
            <div class="mhDeck">
          <article class="mhSlide" data-bg="/cashhome_bg/hero-1.webp" aria-label="간편 심사">
            <div class="mhNo">01</div>
            <div class="mhBody">
              <strong class="mhTitle">간편 심사</strong>
              <p class="mhDesc">기본 정보 입력으로 빠르게 접수하고, 담당자가 확인 후 안내드립니다.</p>
            </div>
          </article>
          <article class="mhSlide" data-bg="/cashhome_bg/hero-2.webp" aria-label="안전한 개인정보 수집">
            <div class="mhNo">02</div>
            <div class="mhBody">
              <strong class="mhTitle">안전한 개인정보 수집</strong>
              <p class="mhDesc">필수 항목만 최소 수집하며, 입력 완료 후 동의 절차를 진행합니다.</p>
            </div>
          </article>
          <article class="mhSlide" data-bg="/cashhome_bg/hero-3.webp" aria-label="투명한 고지">
            <div class="mhNo">03</div>
            <div class="mhBody">
              <strong class="mhTitle">투명한 고지</strong>
              <p class="mhDesc">필수 고지 사항을 명확히 안내하고, 절차를 단계별로 확인할 수 있습니다.</p>
            </div>
          </article>
          <article class="mhSlide" data-bg="/cashhome_bg/hero-4.webp" aria-label="맞춤 상담">
            <div class="mhNo">04</div>
            <div class="mhBody">
              <strong class="mhTitle">맞춤 상담</strong>
              <p class="mhDesc">신용도/상품 조건에 따라 가능한 옵션을 정리해 드립니다.</p>
            </div>
          </article>
          <article class="mhSlide" data-bg="/cashhome_bg/hero-5.webp" aria-label="빠른 회신">
            <div class="mhNo">05</div>
            <div class="mhBody">
              <strong class="mhTitle">빠른 회신</strong>
              <p class="mhDesc">접수 후 담당자가 확인하여 빠르게 연락드립니다.</p>
            </div>
          </article>
            </div>

            <button class="mhArrow mhPrev" type="button" aria-label="이전">
              ‹
            </button>
            <button class="mhArrow mhNext" type="button" aria-label="다음">
              ›
            </button>

            <div class="mhDots" role="tablist" aria-label="슬라이드 선택">
              <button class="mhDot" type="button" aria-label="1번" data-idx="0"></button><button class="mhDot" type="button" aria-label="2번" data-idx="1"></button><button class="mhDot" type="button" aria-label="3번" data-idx="2"></button><button class="mhDot" type="button" aria-label="4번" data-idx="3"></button><button class="mhDot" type="button" aria-label="5번" data-idx="4"></button>
            </div>
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
          <p>성함/연락처/희망금액/용도 등 항목을 입력합니다.</p>
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

          <form id="applyForm" method="post" action="#apply" autocomplete="on" novalidate>
            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>" />
            <input type="hidden" id="csrf_token_index" value="<?= h($_SESSION['csrf_token']) ?>" />

            <input type="text" name="company_website" value="" tabindex="-1" autocomplete="off"
              style="position:absolute; left:-9999px; width:1px; height:1px;" aria-hidden="true" />

            <div class="row">
              <div>
                <label for="name">성함 (필수)</label>
                <input id="name" name="name" type="text" inputmode="text" placeholder="예: 홍길동" required minlength="2"
                  value="<?= h($old['name']) ?>" />
              </div>
              <div>
                <label for="phone">연락처 (필수)</label>
                <input id="phone" name="phone" type="tel" inputmode="tel" placeholder="예: 010-1234-5678" required
                  value="<?= h($old['phone']) ?>" />
              </div>
            </div>

            <div class="row">
              <div>
                <label for="addr_live">주소 (실거주지) (필수)</label>
                <div style="display:flex; gap:8px;">
                  <input id="addr_live" name="addr_live" type="text" placeholder="주소찾기를 눌러 입력" required
                    value="<?= h($old['addr_live']) ?>" />
                  <button type="button" class="btnAddr" onclick="openDaumPostcode('addr_live')">주소찾기</button>
                </div>
                <div style="margin-top:8px;">
                  <label for="addr_live_detail">상세주소 (실거주지) (필수)</label>
                  <input id="addr_live_detail" name="addr_live_detail" type="text" placeholder="예: 101동 1203호"
                    required value="<?= h($old['addr_live_detail'] ?? '') ?>" />
                </div>
              </div>

              <div>
                <label for="addr_resident">주소 (등본 주소지) (필수)</label>
                <div style="display:flex; gap:8px;">
                  <input id="addr_resident" name="addr_resident" type="text" placeholder="주소찾기를 눌러 입력" required
                    value="<?= h($old['addr_resident']) ?>" />
                  <button type="button" class="btnAddr" onclick="openDaumPostcode('addr_resident')">주소찾기</button>
                </div>
                <div style="margin-top:8px;">
                  <label for="addr_resident_detail">상세주소 (등본 주소지) (필수)</label>
                  <input id="addr_resident_detail" name="addr_resident_detail" type="text" placeholder="예: 202호"
                    required value="<?= h($old['addr_resident_detail'] ?? '') ?>" />
                </div>
              </div>
            </div>

            <div class="row">
              <div>
                <label for="amount">희망금액 (필수)</label>

                <div class="inputAddon">
                  <input
                    id="amount"
                    name="amount"
                    type="text"
                    inputmode="numeric"
                    placeholder="예: 500"
                    required
                    value="<?= h($old['amount']) ?>"
                    autocomplete="off" />
                  <span class="addonRight" aria-hidden="true">만원</span>
                </div>

                <div class="tiny" style="margin-top:6px;">※ 숫자만 입력해주세요 (예: 500)</div>
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
                  <option value="delivery" <?= ($old['applicant_type'] === 'delivery') ? 'selected' : '' ?>>배달대행</option>
                </select>
              </div>
            </div>

            <div id="company_block" style="display:none;">
              <label for="company_info" id="company_info_label">추가 정보</label>

              <div class="example-box" id="company_example">
                <b>작성 예시(기업)</b><br>
                1. 기업명: ○○건설(주)<br>
                2. 직원수: 12명<br>
                3. 월매출: 8,000만원<br>
                4. 월 예상 순이익: 1,200만원
              </div>

              <textarea id="company_info" name="company_info" placeholder="유형에 맞춰 작성해주세요."><?= h($old['company_info']) ?></textarea>
            </div>

            <div>
              <label for="memo">추가정보 (선택)</label>
              <?php
              $memoPlaceholder = "- 상담 시 참고할 내용을 적어주세요.\n"
                . "- 담보로 제공할 물건/물품이 있을 경우 승인률이 높아 집니다.\n"
                . "- 담보물건/물품: 자동차(할부 종료 필수, 렌트/리스 불가), 노트북, 휴대폰, 금/은, 부동산 등";
              ?>
              <textarea id="memo" name="memo" placeholder="<?= h($memoPlaceholder) ?>"><?= h($old['memo']) ?></textarea>
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

                <div id="apply2"></div>

                <button class="cta" id="applyBtn" type="submit" <?= $consentOk ? '' : 'disabled' ?>>
                  상담 신청 접수
                </button>
              </div>

              <div class="tiny">
                ※ 입력 오류가 있으면 팝업으로 안내됩니다. 동의는 입력 완료 후 진행됩니다.
              </div>
            </div>
          </form>

          <div style="margin-top:14px;">
            <div class="pill">서류 제출</div>
            <p class="sectionSub" style="margin:10px 0 12px;">
              관리자에게 받은 <b>6자리 인증코드</b>를 입력하면 서류 촬영/업로드가 가능합니다.
            </p>

            <div class="mini" style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
              <a class="cta" href="document_token.php" id="goDocumentToken">서류 제출하기(인증코드 입력)</a>
              <span class="tiny">※ 인증코드가 없으면 관리자에게 요청해주세요.</span>
            </div>

            <!-- ✅ (옵션) 최근 접수번호(대출번호) 표시하고 싶으면 아래 주석 해제 -->
            <!--
            <?php if (!empty($lastLoanNo)): ?>
              <div class="tiny" style="margin-top:10px;">
                최근 접수번호: <b><?= h($lastLoanNo) ?></b>
              </div>
            <?php endif; ?>
            -->
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
            • 수집항목: 성함, 연락처, 주소(실거주/등본), 상세주소, 희망금액, 예상대출기간, 자금용도, 상담내용(선택), 접속기록(보안 목적)<br />
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
    /* =========================================================
index.php 스크립트 (전체)
- 알림 / 앵커 스크롤 / TOP 버튼 / 폰 포맷 / 다음주소
- 기업/배달대행 토글 + 템플릿 자동 입력 + sessionStorage 저장/복원
- 동의 preconsent
- ✅ 서류제출 버튼: 메일 발송 제거(이제 업로드 성공 시점에 서버에서 upload_notice 호출)
========================================================= */

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
        el.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
        history.replaceState(null, '', id);
      });
    });

    // TOP 버튼
    const topBtn = document.getElementById('topbtn');
    const onScroll = () => {
      if (topBtn) topBtn.style.display = (window.scrollY > 600) ? 'block' : 'none';
    };
    window.addEventListener('scroll', onScroll, {
      passive: true
    });
    if (topBtn) topBtn.addEventListener('click', () => window.scrollTo({
      top: 0,
      behavior: 'smooth'
    }));
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

      phoneEl.addEventListener('input', onInput, {
        passive: true
      });
      phoneEl.addEventListener('blur', onInput, {
        passive: true
      });
      onInput();
    })();

    // ✅ 다음(카카오) 주소 API 함수 (HTML onclick에서 호출)
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

    // ✅ 기업/배달대행 토글 + 유형별 작성내용 sessionStorage 저장/복원
    (function() {
      const typeSel = document.getElementById('applicant_type');
      const companyBlock = document.getElementById('company_block');
      const companyInfo = document.getElementById('company_info');
      const companyInfoLabel = document.getElementById('company_info_label');
      const companyExample = document.getElementById('company_example');

      if (!typeSel || !companyBlock || !companyInfo) return;

      const KEY = {
        company: 'cashhome_company_info_company',
        delivery: 'cashhome_company_info_delivery',
      };

      const deliveryTemplate =
        `1. 배달대행소속 지사명:
2. 사무실주소:
3. 사무실 전화번호:
4. 지사장 연락처(지사장 동의후 기입) :
5. 최근 3개월간 월평균소득:
6. 평균 근무시간:
7. 준비서류:
- 최근 3개월간 평균 배달대행 건수 사진(아이디 보이도록)
- 인감증명서 원본(대출용)
- 가족관계증명서 원본
- 주민등록 초본 원본 전체내역
- 주민등록 등본 전체내역
- 인감도장
- 그외 요청추가서류
`;

      const companyTemplate =
        `1. 기업명:
2. 직원수:
3. 월매출:
4. 월 예상 순이익:
`;

      function getStored(mode) {
        try {
          const k = KEY[mode];
          if (!k) return '';
          return sessionStorage.getItem(k) || '';
        } catch (e) {
          return '';
        }
      }

      function setStored(mode, value) {
        try {
          const k = KEY[mode];
          if (!k) return;
          sessionStorage.setItem(k, value ?? '');
        } catch (e) {}
      }

      let currentMode = typeSel.value;

      function saveCurrent() {
        if (currentMode === 'company' || currentMode === 'delivery') {
          setStored(currentMode, companyInfo.value);
        }
      }

      function applyMode(mode) {
        if (mode === 'delivery') {
          companyBlock.style.display = 'block';

          if (companyInfoLabel) companyInfoLabel.textContent = '배달대행 필요정보 (배달대행일 경우 작성)';
          if (companyExample) {
            companyExample.innerHTML =
              "<b>작성 예시(배달대행)</b><br>" +
              "1. 배달대행소속 지사명: ○○지사<br>" +
              "2. 사무실주소: 서울특별시 ○○구 ○○동 ○○번지<br>" +
              "3. 사무실 전화번호: 010-1234-5678<br>" +
              "4. 지사장 연락처(지사장 동의후 기입) : 010-1234-5678<br>" +
              "5. 최근 3개월간 월평균소득(관리자 프로그램 화면): 300만원<br>" +
              "6. 평균 근무시간: 주 6일 / 하루 8시간<br>" +
              "7. 준비서류:<br>" +
              "- 최근 3개월간 평균 배달대행 건수 사진(아이디 보이도록)<br>" +
              "- 인감증명서 원본(대출용)<br>" +
              "- 가족관계증명서 원본<br>" +
              "- 주민등록 초본 원본 전체내역<br>" +
              "- 주민등록 등본 전체내역<br>" +
              "- 인감도장<br>" +
              "- 그외 요청추가서류<br>";
          }

          const saved = getStored('delivery');
          companyInfo.value = saved || deliveryTemplate;

          currentMode = 'delivery';
          return;
        }

        if (mode === 'company') {
          companyBlock.style.display = 'block';

          if (companyInfoLabel) companyInfoLabel.textContent = '기업 정보 (기업일 경우 작성)';
          if (companyExample) {
            companyExample.innerHTML =
              "<b>작성 예시(기업)</b><br>" +
              "1. 기업명: ○○건설(주)<br>" +
              "2. 직원수: 12명<br>" +
              "3. 월매출: 8,000만원<br>" +
              "4. 월 예상 순이익: 1,200만원";
          }

          const saved = getStored('company');
          companyInfo.value = saved || companyTemplate;

          currentMode = 'company';
          return;
        }

        companyBlock.style.display = 'none';
        currentMode = 'personal';
      }

      typeSel.addEventListener('change', function() {
        saveCurrent();
        applyMode(this.value);
      });

      companyInfo.addEventListener('input', function() {
        if (currentMode === 'company' || currentMode === 'delivery') {
          setStored(currentMode, companyInfo.value);
        }
      }, {
        passive: true
      });

      (function init() {
        const initial = (companyInfo.value || '').trim();
        const mode = typeSel.value;

        if ((mode === 'company' || mode === 'delivery') && initial !== '') {
          setStored(mode, companyInfo.value);
        }
        applyMode(typeSel.value);
      })();
    })();

    const form = document.getElementById('applyForm');

    async function preConsentAndGo() {
      if (!form) return;

      const fd = new FormData(form);
      fd.append('action', 'preconsent');

      try {
        const res = await fetch(location.href, {
          method: 'POST',
          body: fd,
          credentials: 'same-origin'
        });

        const data = await res.json().catch(() => null);

        if (!data || !data.ok) {
          alert((data && data.message) ? data.message : '입력값을 확인해주세요.');
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

    /**
     * ✅ 서류제출 버튼 클릭 시:
     * - (기존) 여기서 메일 발송(doc_notice) ❌ 제거
     * - (현재) confirm만 띄우고 document_token.php로 이동
     * - 메일은 “업로드 성공 직후” 업로드 처리 페이지에서 index.php?action=upload_notice로 호출해야 함
     */
    (function() {
      const a = document.getElementById('goDocumentToken');
      if (!a) return;

      a.addEventListener('click', (e) => {
        e.preventDefault();

        const msg = '제출된 실물 서류는 대출 승인 시 현재 실물을 제출하여야합니다.';
        if (!confirm(msg + '\n\n계속 진행하시겠습니까?')) return;

        location.href = a.getAttribute('href');
      });
    })();

    /**
     * consent=done 하이라이트
     */
    (function() {
      const params = new URLSearchParams(window.location.search);

      if (params.get('consent') === 'done') {
        const btn = document.getElementById('applyBtn');

        if (btn) {
          btn.classList.add('consent-highlight');
          setTimeout(() => btn.classList.remove('consent-highlight'), 3500);
        }

        const newUrl = window.location.pathname + window.location.hash;
        history.replaceState({}, '', newUrl);
      }
    })();

    /**
     * PWA 설치 버튼
     */
    let deferredPrompt;
    const installBtn = document.getElementById('installAppBtn');

    function isIOS() {
      return /iphone|ipad|ipod/i.test(window.navigator.userAgent);
    }

    function isSafari() {
      return /safari/i.test(navigator.userAgent) && !/chrome|android/i.test(navigator.userAgent);
    }

    // 1) 안드로이드 PWA 설치
    window.addEventListener('beforeinstallprompt', (e) => {
      e.preventDefault();
      deferredPrompt = e;

      if (installBtn) installBtn.style.display = 'inline-block';

      if (installBtn) {
        installBtn.onclick = async () => {
          deferredPrompt.prompt();
          const choice = await deferredPrompt.userChoice;

          if (choice.outcome === 'accepted') {
            console.log('사용자가 설치를 승인했습니다.');
          }

          deferredPrompt = null;
          installBtn.style.display = 'none';
        };
      }
    });

    // 2) iOS Safari 안내
    window.addEventListener('load', () => {
      if (!installBtn) return;

      if (isIOS() && isSafari()) {
        installBtn.style.display = 'inline-block';
        installBtn.onclick = () => {
          alert(
            "📌 아이폰 홈화면 추가 방법\n\n" +
            "1️⃣ 하단 공유 버튼 클릭\n" +
            "2️⃣ '홈 화면에 추가' 선택\n" +
            "3️⃣ 추가 버튼 클릭"
          );
        };
      }
    });

    // Service Worker 등록
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/service-worker.js')
          .then(reg => console.log('SW 등록 성공'))
          .catch(err => console.log('SW 등록 실패', err));
      });
    }
  </script>
<script>
  (function(){
    const root = document.querySelector('.main_header');
    if(!root) return;

    const slides = Array.from(root.querySelectorAll('.mhSlide'));
    const dots = Array.from(root.querySelectorAll('.mhDot'));
    const prevBtn = root.querySelector('.mhPrev');
    const nextBtn = root.querySelector('.mhNext');
    const bgA = root.querySelector('.mhBgA');
    const bgB = root.querySelector('.mhBgB');
    let bgToggle = false;

    let idx = 0;
    let timer = null;
    const AUTOPLAY_MS = 3800;

    function setBg(url){
      const next = bgToggle ? bgA : bgB;
      const cur  = bgToggle ? bgB : bgA;
      bgToggle = !bgToggle;

      next.style.backgroundImage = `url('${url}')`;
      next.style.opacity = '1';
      next.style.transform = 'scale(1.03)';

      cur.style.opacity = '0';
      cur.style.transform = 'scale(1.08)';
    }

    function render(nextIdx, dir){
      const n = slides.length;
      idx = (nextIdx + n) % n;

      slides.forEach((el,i)=>{
        el.classList.remove('isActive','isPrev','isNext');
        if(i === idx) el.classList.add('isActive');
        else if(i === (idx-1+n)%n) el.classList.add('isPrev');
        else if(i === (idx+1)%n) el.classList.add('isNext');
      });

      dots.forEach((d,i)=> d.classList.toggle('isOn', i===idx));

      const bg = slides[idx].getAttribute('data-bg');
      if(bg) setBg(bg);
    }

    function go(step){
      render(idx + step, step);
      restart();
    }

    function restart(){
      if(timer) clearInterval(timer);
      timer = setInterval(()=> render(idx+1, 1), AUTOPLAY_MS);
    }

    // init
    render(0, 1);
    restart();

    prevBtn && prevBtn.addEventListener('click', ()=>go(-1));
    nextBtn && nextBtn.addEventListener('click', ()=>go(1));
    dots.forEach(d=>{
      d.addEventListener('click', ()=>{
        const target = parseInt(d.getAttribute('data-idx')||'0',10);
        render(target, target>idx ? 1 : -1);
        restart();
      });
    });

    // pause on hover (premium feel)
    root.addEventListener('mouseenter', ()=> timer && clearInterval(timer));
    root.addEventListener('mouseleave', ()=> restart());
  })();
</script>
</body>

</html>