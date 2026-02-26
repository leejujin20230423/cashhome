<?php

declare(strict_types=1);

session_start();
require_once __DIR__ . '/mail_sender.php';
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * =========================
 * DB 설정 (본인 환경 값으로)
 * =========================
 */
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

const PRIVACY_POLICY_VERSION = 'v1';

// 로그인 유지 시간(초) - admin_login.php와 동일하게
const ADMIN_SESSION_TTL = 7200;

// 토큰 만료 임박 기준(초): 5시간
const TOKEN_SOON_SECONDS = 5 * 3600;

/**
 * =========================
 * 역할/상태/결과 정의
 * =========================
 * status: 문자열 코드로 저장
 * outcome: 문자열 숫자 '1'~'5' 로 저장
 */

// status codes
const ST_NEW         = 'new';
const ST_CONTACTED   = 'contacted';
const ST_PROGRESSING = 'progressing';
const ST_CLOSED_OK   = 'closed_ok';     // master만
const ST_CLOSED_ISSUE = 'closed_issue';  // master만

// closed 상태 판별용
const CLOSED_STATUSES = [ST_CLOSED_OK, ST_CLOSED_ISSUE];

// outcome codes (문자열 숫자)
const OC_PENDING  = '1'; // 대기
const OC_REVIEWING = '2';
// const OC_REVIEW   = '2'; // 검토
const OC_APPROVED = '3'; // 승인 (master만)
const OC_PAID     = '4'; // 출금완료
const OC_REJECTED = '5'; // 부결

// 메일 수신자
const REPORT_MAIL_TO = 'ecashhome@gmail.com';

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

function is_admin_authed(): bool
{
    if (empty($_SESSION['cashhome_admin_authed']) || empty($_SESSION['cashhome_admin_authed_at'])) return false;
    if ((time() - (int)$_SESSION['cashhome_admin_authed_at']) > ADMIN_SESSION_TTL) {
        unset($_SESSION['cashhome_admin_authed'], $_SESSION['cashhome_admin_authed_at']);
        return false;
    }
    return true;
}

/**
 * admin_login.php 세션 구조
 * $_SESSION['cashhome_admin_role'] = 'master' 또는 'admin'
 * $_SESSION['cashhome_admin_id']   = 1 또는 2
 */
function admin_role_from_session(): ?string
{
    $u = (string)($_SESSION['cashhome_admin_role'] ?? '');
    $u = strtolower(trim($u));
    if ($u === 'master' || $u === 'admin') return $u;
    return null;
}

function admin_id_from_session(): int
{
    $id = (int)($_SESSION['cashhome_admin_id'] ?? 0);
    return $id > 0 ? $id : 0;
}

function admin_badge_text(?string $u): string
{
    if ($u === 'master') return 'master';
    if ($u === 'admin') return 'admin';
    return '—';
}

/**
 * DB에 저장된 관리자 ID(1/2)를 라벨(master/admin)로 변환
 */
function admin_label_from_db_id(int $id): string
{
    return match ($id) {
        1 => 'master',
        2 => 'admin',
        default => ($id > 0 ? (string)$id : '—'),
    };
}

/**
 * 역할별 허용 처리상태 목록
 */
function allowed_statuses_for_role(?string $role): array
{
    if ($role === 'master') {
        return [ST_NEW, ST_CONTACTED, ST_PROGRESSING, ST_CLOSED_OK, ST_CLOSED_ISSUE];
    }
    // admin
    return [ST_NEW, ST_CONTACTED, ST_PROGRESSING];
}

/**
 * 역할별 허용 대출결과 목록
 * - admin: 1/2/4/5
 * - master: 1/2/3/4/5
 */
function allowed_outcomes_for_role(?string $role): array
{
    if ($role === 'master') {
        return [OC_PENDING, OC_REVIEWING, OC_APPROVED, OC_PAID, OC_REJECTED];
    }
    return [OC_PENDING, OC_REVIEWING, OC_PAID, OC_REJECTED];
}

function is_closed_status(string $status): bool
{
    return in_array($status, CLOSED_STATUSES, true);
}

function status_label(string $s): string
{
    return match ($s) {
        ST_NEW => '신규',
        ST_CONTACTED => '연락완료',
        ST_PROGRESSING => '대출진행중',
        ST_CLOSED_OK => '정상종결',
        ST_CLOSED_ISSUE => '문제종결',
        // 레거시 호환
        'closed' => '종결',
        default => $s,
    };
}

function normalize_outcome_legacy(string $s): string
{
    $s = trim($s);
    if ($s === '') return OC_PENDING;

    // 이미 '1'~'5'라면 그대로
    if (preg_match('/^[1-5]$/', $s)) return $s;

    // 기존 문자열(레거시) 호환
    return match ($s) {
        'pending'  => OC_PENDING,
        'reviewing' => OC_REVIEWING,
        'approved' => OC_APPROVED,
        'paid' => OC_PAID,
        'rejected' => OC_REJECTED,
        default => OC_PENDING,
    };
}

function outcome_label(string $s): string
{
    $n = normalize_outcome_legacy($s);
    return match ($n) {
        OC_PENDING => '대기',
        OC_REVIEWING => '검토',
        OC_APPROVED => '승인',
        OC_PAID => '출금완료',
        OC_REJECTED => '부결',
        default => $n,
    };
}

function phone_digits(string $phone): string
{
    return preg_replace('/\D+/', '', $phone) ?? '';
}


function consent_label(?string $v): string
{
    // DB에 1/0 또는 '1'/'0' 등으로 저장되는 값 대응
    $vv = trim((string)$v);
    return ($vv === '1' || strtolower($vv) === 'y' || strtolower($vv) === 'yes') ? '동의' : '미동의';
}

/**
 * 대출(접수)번호 생성: YYMMDD-XXXX (Base36)
 * 예) 260224-7K3F
 */
function cashhome_make_loan_no_from_ymd(string $ymd): string
{
    $ymd = preg_replace('/\D+/', '', $ymd) ?? '';
    $ymd = substr($ymd, 2, 6); // YYYYMMDD -> YYMMDD
    if (strlen($ymd) !== 6) {
        $ymd = (new DateTime('now', new DateTimeZone('Asia/Seoul')))->format('ymd');
    }

    $chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $suffix = '';
    for ($i = 0; $i < 4; $i++) {
        $suffix .= $chars[random_int(0, 35)];
    }
    return $ymd . '-' . $suffix;
}

function ensure_loan_no(PDO $pdo, array &$row): void
{
    // cashhome_1000_loan_no가 비어있거나 '00'이면 생성해서 DB 저장 후 row에 반영
    $loanNo = trim((string)($row['cashhome_1000_loan_no'] ?? ''));
    if ($loanNo !== '' && $loanNo !== '00') return;

    $createdAt = (string)($row['cashhome_1000_created_at'] ?? '');
    $ymd = '';
    if ($createdAt !== '') {
        // 'YYYY-MM-DD ...' 형태
        $ymd = substr(str_replace('-', '', substr($createdAt, 0, 10)), 0, 8);
    }
    $newNo = cashhome_make_loan_no_from_ymd($ymd);

    $id = (int)($row['cashhome_1000_id'] ?? 0);
    if ($id <= 0) return;

    // UNIQUE 충돌 가능성 대비: 5회 재시도
    for ($i = 0; $i < 5; $i++) {
        try {
            $st = $pdo->prepare("UPDATE cashhome_1000_inquiries SET cashhome_1000_loan_no = :no WHERE cashhome_1000_id = :id AND (cashhome_1000_loan_no IS NULL OR cashhome_1000_loan_no='' OR cashhome_1000_loan_no='00') LIMIT 1");
            $st->execute([':no' => $newNo, ':id' => $id]);
            $row['cashhome_1000_loan_no'] = $newNo;
            return;
        } catch (Throwable $e) {
            // 중복이면 새로 생성
            $newNo = cashhome_make_loan_no_from_ymd($ymd);
            continue;
        }
    }
}

function doc_type_label(string $t): string
{
    return match ($t) {
        'id_card' => '신분증',
        'resident_record' => '등본',
        'bankbook' => '통장',
        'income_proof' => '소득증빙',
        'business_license' => '사업자등록증',
        'admin_extra' => '관리자 추가 서류',
        default => '기타',
    };
}

function fetch_docs_grouped(PDO $pdo, int $inquiryId): array
{
    if ($inquiryId <= 0) return [];

    $st = $pdo->prepare("
        SELECT
          cashhome_1200_id,
          cashhome_1200_inquiry_id,
          cashhome_1200_doc_type,
          cashhome_1200_file_path,
          cashhome_1200_original_name,
          cashhome_1200_mime,
          cashhome_1200_size_bytes,
          cashhome_1200_width,
          cashhome_1200_height,
          cashhome_1200_created_at
        FROM cashhome_1200_documents
        WHERE cashhome_1200_inquiry_id = :iid
        ORDER BY cashhome_1200_doc_type ASC, cashhome_1200_id DESC
    ");
    $st->execute([':iid' => $inquiryId]);
    $rows = $st->fetchAll();

    $grouped = [];
    foreach ($rows as $r) {
        $type = (string)($r['cashhome_1200_doc_type'] ?? 'etc');
        if (!isset($grouped[$type])) $grouped[$type] = [];
        $grouped[$type][] = $r;
    }
    return $grouped;
}

function safe_realpath_for_doc(?string $path): ?string
{
    if (!$path) return null;

    if (str_starts_with($path, '/') || preg_match('#^[A-Za-z]:[\\\\/]#', $path)) {
        $rp = realpath($path);
        return $rp ?: null;
    }

    $full = __DIR__ . '/' . ltrim($path, '/');
    $rp = realpath($full);
    return $rp ?: null;
}

/**
 * 종결 상태면 삭제도 막기(요구사항: 종결이면 버튼 막기 + 서버에서도 차단)
 */
function inquiry_status_by_doc_id(PDO $pdo, int $docId): ?string
{
    $st = $pdo->prepare("
        SELECT i.cashhome_1000_status
        FROM cashhome_1200_documents d
        JOIN cashhome_1000_inquiries i ON i.cashhome_1000_id = d.cashhome_1200_inquiry_id
        WHERE d.cashhome_1200_id = :id
        LIMIT 1
    ");
    $st->execute([':id' => $docId]);
    $s = $st->fetchColumn();
    return $s !== false ? (string)$s : null;
}

function delete_doc(PDO $pdo, int $docId, ?string $role = null): bool
{
    if ($docId <= 0) return false;

    // ✅ 종결 잠금 규칙
    // - admin: 종결이면 삭제 금지
    // - master: 종결이어도 삭제 허용
    $stt = inquiry_status_by_doc_id($pdo, $docId);
    if ($stt !== null && is_closed_status((string)$stt) && ($role === 'admin')) {
        return false;
    }

    $pdo->beginTransaction();
    try {
        $st = $pdo->prepare("
            SELECT cashhome_1200_id, cashhome_1200_file_path
            FROM cashhome_1200_documents
            WHERE cashhome_1200_id = :id
            LIMIT 1
        ");
        $st->execute([':id' => $docId]);
        $row = $st->fetch();
        if (!$row) {
            $pdo->rollBack();
            return false;
        }

        $filePath = safe_realpath_for_doc((string)($row['cashhome_1200_file_path'] ?? ''));

        $del = $pdo->prepare("DELETE FROM cashhome_1200_documents WHERE cashhome_1200_id = :id LIMIT 1");
        $del->execute([':id' => $docId]);

        $pdo->commit();

        if ($filePath && is_file($filePath)) {
            @unlink($filePath);
        }
        return true;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        error_log('[DOC DELETE ERROR] ' . $e->getMessage());
        return false;
    }
}

function build_filters_from_request(array $src, ?string $role): array
{
    $today = date('Y-m-d');
    $defaultStart = date('Y-m-d', strtotime('-7 days'));

    $start = (string)($src['start'] ?? $defaultStart);
    $end   = (string)($src['end'] ?? $today);

    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $start)) $start = $defaultStart;
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $end))   $end   = $today;

    $status  = (string)($src['status'] ?? 'all');
    $outcome = (string)($src['outcome'] ?? 'all');

    $name = trim((string)($src['name'] ?? ''));
    $memo = trim((string)($src['memo'] ?? ''));
    $note = trim((string)($src['note'] ?? ''));

    // ✅ 역할별 status/outcome 목록
    $allowedStatus = array_merge(['all'], allowed_statuses_for_role($role));
    $allowedOutcome = array_merge(['all'], allowed_outcomes_for_role($role));

    // 레거시 호환(필터에서 pending/approved/rejected가 넘어오면 숫자로 normalize)
    if ($outcome !== 'all') $outcome = normalize_outcome_legacy($outcome);

    if (!in_array($status, $allowedStatus, true)) $status = 'all';
    if (!in_array($outcome, $allowedOutcome, true)) $outcome = 'all';

    return [
        'start' => $start,
        'end' => $end,
        'startDT' => $start . ' 00:00:00',
        'endDT' => $end . ' 23:59:59',
        'status' => $status,
        'outcome' => $outcome,
        'name' => $name,
        'memo' => $memo,
        'note' => $note,
        'today' => $today,
        'defaultStart' => $defaultStart,
    ];
}

function build_where_and_params(array $f): array
{
    $where = " WHERE i.cashhome_1000_created_at BETWEEN :startDT AND :endDT ";
    $params = [
        ':startDT' => $f['startDT'],
        ':endDT' => $f['endDT'],
    ];

    if ($f['status'] !== 'all') {
        $where .= " AND i.cashhome_1000_status = :st ";
        $params[':st'] = $f['status'];
    }
    if ($f['outcome'] !== 'all') {
        $where .= " AND i.cashhome_1000_outcome = :oc ";
        $params[':oc'] = $f['outcome'];
    }
    if ($f['name'] !== '') {
        $where .= " AND i.cashhome_1000_customer_name LIKE :nm ";
        $params[':nm'] = '%' . $f['name'] . '%';
    }
    if ($f['memo'] !== '') {
        $where .= " AND i.cashhome_1000_request_memo LIKE :mm ";
        $params[':mm'] = '%' . $f['memo'] . '%';
    }
    if ($f['note'] !== '') {
        $where .= " AND i.cashhome_1000_admin_note LIKE :nt ";
        $params[':nt'] = '%' . $f['note'] . '%';
    }

    return [$where, $params];
}

function generate_doc_token6(): string
{
    $n = random_int(0, 999999);
    return str_pad((string)$n, 6, '0', STR_PAD_LEFT);
}

function is_token_in_use(PDO $pdo, string $token): bool
{
    $st = $pdo->prepare("
        SELECT 1
        FROM cashhome_1000_inquiries
        WHERE cashhome_1000_doc_token = :tk
          AND cashhome_1000_doc_token_status = 1
          AND cashhome_1000_doc_token_expires_at > NOW()
        LIMIT 1
    ");
    $st->execute([':tk' => $token]);
    return (bool)$st->fetchColumn();
}

function build_sms_body(string $token): string
{
    $token = trim($token);
    if ($token === '') $token = '000000';
    return "[인증번호]:{$token}복사되었습니다. 서류제출하기 버튼을 누르신후 인증번호를 입력후 서류를 등록해주세요.";
}

function build_copy_alert_text(string $token): string
{
    $token = trim($token);
    if ($token === '') $token = '000000';
    return "[인증번호]:{$token} 이 복사되었습니다.";
}

function fetch_rows(PDO $pdo, array $f): array
{
    [$where, $params] = build_where_and_params($f);

    $sql = "
      SELECT
        i.cashhome_1000_id,
        i.cashhome_1000_loan_no,
        i.cashhome_1000_created_at,
        i.cashhome_1000_updated_at,
        i.cashhome_1000_customer_name,
        i.cashhome_1000_customer_phone,
        i.cashhome_1000_loan_amount,
        i.cashhome_1000_loan_purpose,
        i.cashhome_1000_request_memo,
        i.cashhome_1000_user_ip,
        i.cashhome_1000_user_agent,
        i.cashhome_1000_status,
        i.cashhome_1000_outcome,
        i.cashhome_1000_processed_at,
        i.cashhome_1000_admin_note,

        i.cashhome_1000_doc_token,
        i.cashhome_1000_doc_token_status,
        i.cashhome_1000_doc_token_issued_at,
        i.cashhome_1000_doc_token_expires_at,
        i.cashhome_1000_doc_token_used_at,
        i.cashhome_1000_doc_token_issued_by,
        i.cashhome_1000_doc_token_attempt_count,

        i.cashhome_1000_last_modified_by,
        i.cashhome_1000_last_modified_at,

        COALESCE(dc.docs_count, 0) AS docs_count,

        MAX(CASE WHEN c.cashhome_1100_consent_type='privacy' THEN c.cashhome_1100_consented_at END) AS privacy_at,
        MAX(CASE WHEN c.cashhome_1100_consent_type='privacy' THEN c.cashhome_1100_consent_version END) AS privacy_ver,
        MAX(CASE WHEN c.cashhome_1100_consent_type='marketing' THEN c.cashhome_1100_consented_at END) AS marketing_at

      FROM cashhome_1000_inquiries i
      LEFT JOIN cashhome_1100_consent_logs c
        ON c.cashhome_1100_inquiry_id = i.cashhome_1000_id
      LEFT JOIN (
        SELECT cashhome_1200_inquiry_id AS inquiry_id, COUNT(*) AS docs_count
        FROM cashhome_1200_documents
        GROUP BY cashhome_1200_inquiry_id
      ) dc ON dc.inquiry_id = i.cashhome_1000_id
      $where
      GROUP BY
        i.cashhome_1000_id,
        i.cashhome_1000_loan_no,
        i.cashhome_1000_created_at,
        i.cashhome_1000_updated_at,
        i.cashhome_1000_customer_name,
        i.cashhome_1000_customer_phone,
        i.cashhome_1000_loan_amount,
        i.cashhome_1000_loan_purpose,
        i.cashhome_1000_request_memo,
        i.cashhome_1000_user_ip,
        i.cashhome_1000_user_agent,
        i.cashhome_1000_status,
        i.cashhome_1000_outcome,
        i.cashhome_1000_processed_at,
        i.cashhome_1000_admin_note,
        i.cashhome_1000_doc_token,
        i.cashhome_1000_doc_token_status,
        i.cashhome_1000_doc_token_issued_at,
        i.cashhome_1000_doc_token_expires_at,
        i.cashhome_1000_doc_token_used_at,
        i.cashhome_1000_doc_token_issued_by,
        i.cashhome_1000_doc_token_attempt_count,
        i.cashhome_1000_last_modified_by,
        i.cashhome_1000_last_modified_at,
        dc.docs_count
      ORDER BY i.cashhome_1000_id DESC
      LIMIT 5000
    ";



    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    // ✅ outcome 레거시 normalize(화면/통계 일관성)
    foreach ($rows as &$r) {
        $r['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($r['cashhome_1000_outcome'] ?? ''));
        $r['cashhome_1000_status'] = (string)($r['cashhome_1000_status'] ?? ST_NEW);
    }
    unset($r);

    return $rows;
}

function compute_stats(array $rows): array
{
    $total = count($rows);

    $byOutcome = [
        OC_PENDING => 0,
        OC_REVIEWING => 0,
        OC_APPROVED => 0,
        OC_PAID => 0,
        OC_REJECTED => 0,
    ];

    $dailyAll = [];
    $dailyApproved = [];

    $tokenSoon = 0;
    $now = time();

    // ✅ 처리상태 카운트
    $byStatus = [
        ST_NEW => 0,
        ST_CONTACTED => 0,
        ST_PROGRESSING => 0,
        ST_CLOSED_OK => 0,
        ST_CLOSED_ISSUE => 0,
    ];

    foreach ($rows as $r) {
        $oc = normalize_outcome_legacy((string)($r['cashhome_1000_outcome'] ?? OC_PENDING));
        if (!isset($byOutcome[$oc])) $byOutcome[$oc] = 0;
        $byOutcome[$oc]++;

        // ✅ 처리상태 집계
        $st = (string)($r['cashhome_1000_status'] ?? ST_NEW);
        if (!isset($byStatus[$st])) $byStatus[$st] = 0;
        $byStatus[$st]++;

        $d = substr((string)$r['cashhome_1000_created_at'], 0, 10);
        $dailyAll[$d] = ($dailyAll[$d] ?? 0) + 1;
        if ($oc === OC_APPROVED) $dailyApproved[$d] = ($dailyApproved[$d] ?? 0) + 1;

        $tkStatus = (int)($r['cashhome_1000_doc_token_status'] ?? 0);
        $expiresAt = (string)($r['cashhome_1000_doc_token_expires_at'] ?? '');
        if ($tkStatus === 1 && $expiresAt !== '') {
            $expTs = strtotime($expiresAt);
            if ($expTs !== false) {
                $diff = $expTs - $now;
                if ($diff > 0 && $diff < TOKEN_SOON_SECONDS) $tokenSoon++;
            }
        }
    }

    ksort($dailyAll);
    ksort($dailyApproved);

    $approved = (int)($byOutcome[OC_APPROVED] ?? 0);
    $rate = $total > 0 ? round(($approved / $total) * 100, 1) : 0.0;

    $labels = array_keys($dailyAll);
    $allSeries = [];
    $apprSeries = [];
    foreach ($labels as $d) {
        $allSeries[] = $dailyAll[$d] ?? 0;
        $apprSeries[] = $dailyApproved[$d] ?? 0;
    }

    return [
        'total' => $total,
        'by_outcome' => $byOutcome,
        'approved' => $approved,
        // 기존 UI에서 쓰던 필드(호환)
        'pending' => (int)($byOutcome[OC_PENDING] ?? 0),
        'reviewing' => (int)($byOutcome[OC_REVIEWING] ?? 0),
        'paid' => (int)($byOutcome[OC_PAID] ?? 0),
        'rejected' => (int)($byOutcome[OC_REJECTED] ?? 0),
        'rate' => $rate,
        'by_status' => $byStatus,
        'labels' => $labels,
        'series_all' => $allSeries,
        'series_approved' => $apprSeries,
        'token_soon' => $tokenSoon,
    ];
}

/**
 * ✅ 토큰 표시 라벨(리스트에서 "미발급" / "사용완료" / "만료" 등을 유지하기 위해)
 */
function token_display_label(array $r): string
{
    $status = (int)($r['cashhome_1000_doc_token_status'] ?? 0);
    $token = trim((string)($r['cashhome_1000_doc_token'] ?? ''));

    return match ($status) {
        1 => ($token !== '' ? "token:{$token}" : 'token: 발급'),
        2 => 'Token: 사용완료',
        3 => 'Token: 만료',
        4 => 'Token: 폐기',
        default => 'token: 미발급',
    };
}

function compact_rows_for_json(array $rows): array
{
    $out = [];
    $seq = 0;
    foreach ($rows as $r) {
        $seq++;

        $token = (string)($r['cashhome_1000_doc_token'] ?? '');
        $tokenStatus = (int)($r['cashhome_1000_doc_token_status'] ?? 0);

        // ✅ 발급(1)인 경우만 복사/문자 템플릿 제공
        $showToken = (trim($token) !== '' && $tokenStatus === 1);
        $smsBody = $showToken ? build_sms_body($token) : '';
        $copyAlert = $showToken ? build_copy_alert_text($token) : '';

        $status = (string)($r['cashhome_1000_status'] ?? ST_NEW);
        $outcome = normalize_outcome_legacy((string)($r['cashhome_1000_outcome'] ?? OC_PENDING));

        $out[] = [
            'seq' => $seq,
            'loan_no' => (string)($r['cashhome_1000_loan_no'] ?? ''),
            'id' => (int)$r['cashhome_1000_id'],
            'created_at' => (string)$r['cashhome_1000_created_at'],
            'name' => (string)$r['cashhome_1000_customer_name'],
            'phone' => (string)$r['cashhome_1000_customer_phone'],
            'status' => $status,
            'outcome' => $outcome,
            'privacy_ok' => !empty($r['privacy_at']),
            'marketing_ok' => !empty($r['marketing_at']),
            'loan_amount' => (int)($r['cashhome_1000_loan_amount'] ?? 0),
            'doc_token' => $token,
            'doc_token_status' => $tokenStatus,
            'doc_token_expires_at' => (string)($r['cashhome_1000_doc_token_expires_at'] ?? ''),
            'docs_count' => (int)($r['docs_count'] ?? 0),

            // ✅ 프론트에서 토큰 표기 분기하기 쉽게
            'token_display_label' => token_display_label($r),

            // ✅ 복사/문자 템플릿
            'copy_alert' => $copyAlert,
            'sms_body' => $smsBody,

            // ✅ 종결 여부(버튼 막기용)
            'is_closed' => is_closed_status($status),
        ];
    }
    return $out;
}

/**
 * =========================
 * CSRF
 * =========================
 */
if (empty($_SESSION['csrf_token_admin'])) {
    $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));
}

/**
 * =========================
 * 로그아웃
 * =========================
 */
if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    unset(
        $_SESSION['cashhome_admin_authed'],
        $_SESSION['cashhome_admin_authed_at'],
        $_SESSION['cashhome_admin_role'],
        $_SESSION['cashhome_admin_id']
    );
    header('Location: admin_login.php');
    exit;
}

/**
 * =========================
 * 인증
 * =========================
 */

// =========================
// CLI 크론: 3시간마다 리포트 메일 발송
// 사용 예: php admin_inquiries.php report
// =========================
if (PHP_SAPI === 'cli') {
    $cmd = $argv[1] ?? '';
    if ($cmd === 'report') {
        $pdo = cashhome_pdo();
        $ok = send_report_mail($pdo);
        echo $ok ? "OK
" : "FAIL
";
        exit;
    }
}

if (!is_admin_authed()) {
    header('Location: admin_login.php');
    exit;
}

$currentAdminRole = admin_role_from_session();
$currentAdminDbId = admin_id_from_session();
$currentAdminBadgeText = admin_badge_text($currentAdminRole);

$pdo = cashhome_pdo();
$f = build_filters_from_request($_GET, $currentAdminRole);

/**
 * 관리자 세션 체크(저장/발급 시)
 */
function require_admin_for_write(): array
{
    $role = admin_role_from_session();
    $dbId = admin_id_from_session();
    if (!$role || $dbId <= 0) {
        return [false, '관리자 아이디(세션)가 없습니다. 다시 로그인 후 시도해주세요.', null, 0];
    }
    return [true, '', $role, $dbId];
}

/**
 * 현재 문의 상태 조회
 */
function get_inquiry_status(PDO $pdo, int $id): ?string
{
    $st = $pdo->prepare("SELECT cashhome_1000_status FROM cashhome_1000_inquiries WHERE cashhome_1000_id = :id LIMIT 1");
    $st->execute([':id' => $id]);
    $s = $st->fetchColumn();
    return $s !== false ? (string)$s : null;
}

/**
 * 현재 문의의 처리상태/대출결과(및 기본 정보) 조회
 * - 저장 시 변경사항 메일 발송용
 */
function get_inquiry_snapshot(PDO $pdo, int $id): ?array
{
    $st = $pdo->prepare("
      SELECT
        cashhome_1000_id,
        cashhome_1000_loan_no,
        cashhome_1000_created_at,
        cashhome_1000_customer_name,
        cashhome_1000_customer_phone,
        cashhome_1000_loan_amount,
        cashhome_1000_status,
        cashhome_1000_outcome,
        cashhome_1000_admin_note,
        cashhome_1000_processed_at
      FROM cashhome_1000_inquiries
      WHERE cashhome_1000_id = :id
      LIMIT 1
    ");
    $st->execute([':id' => $id]);
    $row = $st->fetch(PDO::FETCH_ASSOC);
    if (!$row) return null;

    $row['cashhome_1000_status'] = (string)($row['cashhome_1000_status'] ?? ST_NEW);
    $row['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($row['cashhome_1000_outcome'] ?? OC_PENDING));
    return $row;
}

/**
 * 저장 시 '처리상태/대출결과' 변경사항 메일 발송
 * - 기존 3개월 통계 메일(리포트)과 별개
 */
function send_inquiry_change_mail(PDO $pdo, array $before, array $after, string $adminRole, int $adminDbId): bool
{
    $beforeSt = (string)($before['cashhome_1000_status'] ?? ST_NEW);
    $beforeOc = normalize_outcome_legacy((string)($before['cashhome_1000_outcome'] ?? OC_PENDING));
    $afterSt  = (string)($after['cashhome_1000_status'] ?? ST_NEW);
    $afterOc  = normalize_outcome_legacy((string)($after['cashhome_1000_outcome'] ?? OC_PENDING));

    // 변경 없음이면 메일 미발송
    if ($beforeSt === $afterSt && $beforeOc === $afterOc) return false;

    $id = (int)($after['cashhome_1000_id'] ?? ($before['cashhome_1000_id'] ?? 0));
    if ($id <= 0) return false;

    $name  = (string)($after['cashhome_1000_customer_name'] ?? $before['cashhome_1000_customer_name'] ?? '');
    $phone = (string)($after['cashhome_1000_customer_phone'] ?? $before['cashhome_1000_customer_phone'] ?? '');
    $amt   = (string)($after['cashhome_1000_loan_amount'] ?? $before['cashhome_1000_loan_amount'] ?? '');
    $loanNo = (string)($after['cashhome_1000_loan_no'] ?? $before['cashhome_1000_loan_no'] ?? '');
    $loanNo4 = '';
    $loanNoTrim = trim($loanNo);
    if ($loanNoTrim !== '' && $loanNoTrim !== '00') {
        $loanNo4 = mb_substr($loanNoTrim, -4);
    }

    $adminLabel = admin_label_from_db_id($adminDbId);
    $adminText = trim($adminLabel) !== '' ? $adminLabel : (string)$adminDbId;

    $h = static function (string $s): string {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    };

    $fmtAmt = static function ($v): string {
        $n = (string)$v;
        $n = preg_replace('/[^\d]/', '', $n);
        if ($n === '') return '';
        return number_format((int)$n);
    };

        // 제목: ID 제외, NO(접수번호) + 변경내용 포함
    $noDisplay = $loanNo4 !== '' ? $loanNo4 : $loanNoTrim;

    $changeParts = [];
    if ($beforeSt !== $afterSt) {
        $changeParts[] = '처리상태 ' . status_label($beforeSt) . '→' . status_label($afterSt);
    }
    if ($beforeOc !== $afterOc) {
        $changeParts[] = '대출결과 ' . outcome_label($beforeOc) . '→' . outcome_label($afterOc);
    }
    $changeText = implode(' / ', $changeParts);

    if ($noDisplay !== '') {
        $subject = '[CASHHOME] NO:' . $noDisplay . ' | 변경자:' . $adminText . ' | ' . $changeText;
    } else {
        $subject = '[CASHHOME] 변경자:' . $adminText . ' | ' . $changeText;
    }

    $html = '';
    $html .= '<div style="font-family:Apple SD Gothic Neo,Malgun Gothic,Arial,sans-serif;">';
    $html .= '<h2 style="margin:0 0 12px 0;">대출 처리 변경 알림</h2>';
    $html .= '<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:13px;">';
    $html .= '<tbody>';
    $html .= '<tr><th align="left" style="background:#f5f5f5;">신청자</th><td>' . $h($name) . '</td></tr>';
    $html .= '<tr><th align="left" style="background:#f5f5f5;">연락처</th><td>' . $h($phone) . '</td></tr>';
    $html .= '<tr><th align="left" style="background:#f5f5f5;">희망금액</th><td>' . $h($fmtAmt($amt)) . '</td></tr>';
    $html .= '<tr><th align="left" style="background:#f5f5f5;">접수번호</th><td>' . $h($loanNo4 !== '' ? $loanNo4 : $loanNoTrim) . '</td></tr>';
    $html .= '<tr><th align="left" style="background:#f5f5f5;">처리상태</th><td>' . $h(status_label($beforeSt)) . ' → <b>' . $h(status_label($afterSt)) . '</b></td></tr>';
    $html .= '<tr><th align="left" style="background:#f5f5f5;">대출결과</th><td>' . $h(outcome_label($beforeOc)) . ' → <b>' . $h(outcome_label($afterOc)) . '</b></td></tr>';
    $html .= '<tr><th align="left" style="background:#f5f5f5;">변경자</th><td>' . $h($adminText) . ' (' . $h($adminRole) . ')</td></tr>';
    $html .= '<tr><th align="left" style="background:#f5f5f5;">변경시각</th><td>' . $h(date('Y-m-d H:i:s')) . '</td></tr>';
    $html .= '</tbody>';
    $html .= '</table>';

    $note = (string)($after['cashhome_1000_admin_note'] ?? '');
    if (trim($note) !== '') {
        $html .= '<div style="margin-top:12px;">';
        $html .= '<div style="font-weight:700;margin:0 0 6px 0;">관리자 메모</div>';
        $html .= '<div style="white-space:pre-wrap;border:1px solid #eee;padding:10px;border-radius:8px;">' . $h($note) . '</div>';
        $html .= '</div>';
    }

    $html .= '<div style="margin-top:14px;color:#888;font-size:12px;">※ 본 메일은 관리자 저장 시 처리상태/대출결과 변경이 있을 때만 발송됩니다.</div>';
    $html .= '</div>';

    $plain = "대출 처리 변경 알림\n"
        . "- 신청자: {$name}\n"
        . "- 연락처: {$phone}\n"
        . "- 희망금액: {$amt}\n"
        . "- 접수번호: " . ($loanNo4 !== '' ? $loanNo4 : $loanNoTrim) . "\n"
        . "- 처리상태: " . status_label($beforeSt) . " -> " . status_label($afterSt) . "\n"
        . "- 대출결과: " . outcome_label($beforeOc) . " -> " . outcome_label($afterOc) . "\n"
        . "- 변경자: {$adminText} ({$adminRole})\n"
        . "- 변경시각: " . date('Y-m-d H:i:s') . "\n";
    if (trim($note) !== '') {
        $plain .= "- 메모:\n{$note}\n";
    }

    try {
        $ms = new MailSender();
        return $ms->sendHtmlTo(REPORT_MAIL_TO, $subject, $html, $plain);
    } catch (Throwable $e) {
        error_log('[change_mail] ' . $e->getMessage());
        return false;
    }
}

/**
 * =========================
 * 저장(POST) - 종결이면 막기 + 역할별 옵션
 * =========================
 */

// =========================
// 최근 3개월 통계 리포트 메일(수동 발송)
// =========================
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'send_report') {
    header('Content-Type: application/json; charset=utf-8');

    $token = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token_admin'], $token)) {
        echo json_encode(['ok' => false, 'message' => '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    [$okAdmin, $adminErr] = require_admin_for_write();
    if (!$okAdmin) {
        echo json_encode(['ok' => false, 'message' => $adminErr], JSON_UNESCAPED_UNICODE);
        exit;
    }

    try {
        $ok = send_report_mail($pdo);
        // CSRF 토큰 회전
        $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));

        echo json_encode([
            'ok' => (bool)$ok,
            'message' => $ok ? '최근 3개월 통계 리포트 메일을 발송했습니다.' : '메일 발송에 실패했습니다.',
            'csrf_token' => $_SESSION['csrf_token_admin'],
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (Throwable $e) {
        $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));
        echo json_encode([
            'ok' => false,
            'message' => '메일 발송 중 오류가 발생했습니다.',
            'csrf_token' => $_SESSION['csrf_token_admin'],
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'save') {
    header('Content-Type: application/json; charset=utf-8');

    $token = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token_admin'], $token)) {
        echo json_encode(['ok' => false, 'message' => '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    [$okAdmin, $adminErr, $adminRole, $adminDbId] = require_admin_for_write();
    if (!$okAdmin) {
        echo json_encode(['ok' => false, 'message' => $adminErr], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $id = (int)($_POST['id'] ?? 0);
    $status = (string)($_POST['status'] ?? ST_NEW);
    $outcome = (string)($_POST['outcome'] ?? OC_PENDING);
    $note = trim((string)($_POST['admin_note'] ?? ''));

    $outcome = normalize_outcome_legacy($outcome);

    if ($id <= 0) {
        echo json_encode(['ok' => false, 'message' => '잘못된 요청입니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // ✅ 종결이면 서버에서 저장 자체를 막기
    $currentStatus = get_inquiry_status($pdo, $id);
    $isClosedNow = ($currentStatus !== null && is_closed_status($currentStatus));

    // ✅ 변경사항 메일용: 저장 전 스냅샷(처리상태/대출결과)
    $beforeSnap = get_inquiry_snapshot($pdo, $id);

    $allowedStatus = allowed_statuses_for_role($adminRole);
    $allowedOutcome = allowed_outcomes_for_role($adminRole);

    // ✅ 종결 상태인 경우
    // - admin: 처리상태/대출결과 변경은 잠금(메모만 저장 가능)
    // - master: 정상 저장(전체 수정 허용)
    if ($isClosedNow && $adminRole === 'admin') {
        try {
            $stmt = $pdo->prepare("
              UPDATE cashhome_1000_inquiries
              SET
                cashhome_1000_admin_note = :nt,
                cashhome_1000_last_modified_by = :mb,
                cashhome_1000_last_modified_at = NOW()
              WHERE cashhome_1000_id = :id
              LIMIT 1
            ");
            $stmt->execute([
                ':nt' => $note !== '' ? $note : null,
                ':mb' => $adminDbId,
                ':id' => $id,
            ]);

            $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));

            $q = $pdo->prepare("
              SELECT cashhome_1000_last_modified_by, cashhome_1000_last_modified_at
              FROM cashhome_1000_inquiries
              WHERE cashhome_1000_id = :id
              LIMIT 1
            ");
            $q->execute([':id' => $id]);
            $lm = $q->fetch() ?: [];
            $lmBy = (int)($lm['cashhome_1000_last_modified_by'] ?? 0);

            // 종결건(admin)은 메모만 저장 -> 처리상태/대출결과 변경 불가(메일 미발송)
            $mailSent = false;

            echo json_encode([
                'ok' => true,
                'message' => '저장되었습니다. (종결건: 메모만 저장)',
                'csrf_token' => $_SESSION['csrf_token_admin'],
                'processed_at' => null,
                'last_modified_by' => $lmBy,
                'last_modified_at' => (string)($lm['cashhome_1000_last_modified_at'] ?? ''),
                'last_modified_by_label' => admin_label_from_db_id($lmBy),
                'mail_sent' => $mailSent,
                // 하위 호환: 기존 프론트에서 report_sent 사용 중이면 그대로 동작
                'report_sent' => $mailSent,
            ], JSON_UNESCAPED_UNICODE);
            exit;
        } catch (Throwable $e) {
            error_log('[ADMIN SAVE CLOSED NOTE ERROR] ' . $e->getMessage());
            echo json_encode(['ok' => false, 'message' => '저장 중 오류가 발생했습니다.'], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // ✅ 일반 저장(또는 master 종결 저장)
    if (!in_array($status, $allowedStatus, true) || !in_array($outcome, $allowedOutcome, true)) {
        echo json_encode(['ok' => false, 'message' => '권한에 없는 항목입니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // ✅ 처리일시: (대기=1)은 null, 나머지는 NOW
    $processedAt = null;
    if ($outcome !== OC_PENDING) $processedAt = date('Y-m-d H:i:s');

    try {
        $stmt = $pdo->prepare("
          UPDATE cashhome_1000_inquiries
          SET
            cashhome_1000_status = :st,
            cashhome_1000_outcome = :oc,
            cashhome_1000_processed_at = :pa,
            cashhome_1000_admin_note = :nt,
            cashhome_1000_last_modified_by = :mb,
            cashhome_1000_last_modified_at = NOW()
          WHERE cashhome_1000_id = :id
          LIMIT 1
        ");
        $stmt->execute([
            ':st' => $status,
            ':oc' => $outcome,
            ':pa' => $processedAt,
            ':nt' => $note !== '' ? $note : null,
            ':mb' => $adminDbId,
            ':id' => $id,
        ]);

        $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));

        $q = $pdo->prepare("
          SELECT cashhome_1000_last_modified_by, cashhome_1000_last_modified_at
          FROM cashhome_1000_inquiries
          WHERE cashhome_1000_id = :id
          LIMIT 1
        ");
        $q->execute([':id' => $id]);
        $lm = $q->fetch() ?: [];

        $lmBy = (int)($lm['cashhome_1000_last_modified_by'] ?? 0);

        // ✅ 저장 시 변경사항 메일(처리상태/대출결과가 실제로 바뀐 경우에만)
        $mailSent = false;
        try {
            $afterSnap = $beforeSnap ?: [];
            $afterSnap['cashhome_1000_id'] = $id;
            $afterSnap['cashhome_1000_status'] = $status;
            $afterSnap['cashhome_1000_outcome'] = $outcome;
            $afterSnap['cashhome_1000_admin_note'] = $note;
            $afterSnap['cashhome_1000_processed_at'] = $processedAt;
            $mailSent = ($beforeSnap !== null) ? send_inquiry_change_mail($pdo, $beforeSnap, $afterSnap, (string)$adminRole, (int)$adminDbId) : false;
        } catch (Throwable $e) {
            $mailSent = false;
        }

        echo json_encode([
            'ok' => true,
            'message' => '저장되었습니다.',
            'csrf_token' => $_SESSION['csrf_token_admin'],
            'processed_at' => $processedAt,
            'last_modified_by' => $lmBy,
            'last_modified_at' => (string)($lm['cashhome_1000_last_modified_at'] ?? ''),
            // ✅ 숫자 대신 라벨
            'last_modified_by_label' => admin_label_from_db_id($lmBy),
            'mail_sent' => $mailSent,
            // 하위 호환
            'report_sent' => $mailSent,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (Throwable $e) {
        error_log('[ADMIN SAVE ERROR] ' . $e->getMessage());
        echo json_encode(['ok' => false, 'message' => $e->getMessage() . '처리상태 변경 중 오류가 발생했습니다[967].'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

/**
 * =========================
 * 토큰 발급(POST) - 종결이면 막기
 * =========================
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'issue_token') {
    header('Content-Type: application/json; charset=utf-8');

    $csrf = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token_admin'], $csrf)) {
        echo json_encode(['ok' => false, 'message' => '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    [$okAdmin, $adminErr, $adminRole, $adminDbId] = require_admin_for_write();
    if (!$okAdmin) {
        echo json_encode(['ok' => false, 'message' => $adminErr], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $id = (int)($_POST['id'] ?? 0);
    $expiresHours = (int)($_POST['expires_hours'] ?? 0);

    $allowedHours = [24, 48, 72];
    if ($id <= 0 || !in_array($expiresHours, $allowedHours, true)) {
        echo json_encode(['ok' => false, 'message' => '잘못된 요청입니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // ✅ 종결 잠금 규칙
    // - admin: 종결이면 발급 금지
    // - master: 종결이어도 발급 허용
    $currentStatus = get_inquiry_status($pdo, $id);
    if ($currentStatus !== null && is_closed_status($currentStatus) && $adminRole === 'admin') {
        echo json_encode(['ok' => false, 'message' => '종결된 건(admin)은 토큰을 발급할 수 없습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    try {
        $newToken = '';
        for ($i = 0; $i < 30; $i++) {
            $candidate = generate_doc_token6();
            if (!is_token_in_use($pdo, $candidate)) {
                $newToken = $candidate;
                break;
            }
        }
        if ($newToken === '') $newToken = generate_doc_token6();

        $st = $pdo->prepare("
            UPDATE cashhome_1000_inquiries
            SET
              cashhome_1000_doc_token = :tk,
              cashhome_1000_doc_token_status = 1,
              cashhome_1000_doc_token_issued_at = NOW(),
              cashhome_1000_doc_token_expires_at = DATE_ADD(NOW(), INTERVAL :hh HOUR),
              cashhome_1000_doc_token_used_at = NULL,
              cashhome_1000_doc_token_attempt_count = 0,
              cashhome_1000_doc_token_issued_by = :ab
            WHERE cashhome_1000_id = :id
            LIMIT 1
        ");
        $st->execute([
            ':tk' => $newToken,
            ':hh' => $expiresHours,
            ':ab' => $adminDbId,
            ':id' => $id,
        ]);

        if ($st->rowCount() < 1) {
            echo json_encode(['ok' => false, 'message' => '발급할 대상이 없습니다.'], JSON_UNESCAPED_UNICODE);
            exit;
        }

        $q = $pdo->prepare("
            SELECT cashhome_1000_doc_token_expires_at, cashhome_1000_doc_token_issued_by
            FROM cashhome_1000_inquiries
            WHERE cashhome_1000_id = :id
            LIMIT 1
        ");
        $q->execute([':id' => $id]);
        $row = $q->fetch() ?: [];
        $expiresAt = (string)($row['cashhome_1000_doc_token_expires_at'] ?? '');
        $issuedBy = (int)($row['cashhome_1000_doc_token_issued_by'] ?? 0);

        $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));

        echo json_encode([
            'ok' => true,
            'message' => '토큰이 발급되었습니다.',
            'doc_token' => $newToken,
            'expires_at' => $expiresAt,
            'issued_by' => $issuedBy,
            'issued_by_label' => admin_label_from_db_id($issuedBy),
            'copy_alert' => build_copy_alert_text($newToken),
            'sms_body' => build_sms_body($newToken),
            'csrf_token' => $_SESSION['csrf_token_admin'],
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (Throwable $e) {
        error_log('[ISSUE TOKEN ERROR] ' . $e->getMessage());
        echo json_encode(['ok' => false, 'message' => '토큰 발급 중 오류가 발생했습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

/**
 * =========================
 * 서류 삭제(POST) - 종결이면 막기(위 delete_doc에서 2차 방어)
 * =========================
 */
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'delete_doc') {
    header('Content-Type: application/json; charset=utf-8');

    $token = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token_admin'], $token)) {
        echo json_encode(['ok' => false, 'message' => '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $docId = (int)($_POST['doc_id'] ?? 0);
    if ($docId <= 0) {
        echo json_encode(['ok' => false, 'message' => '잘못된 요청입니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    [$okAdmin, $adminErr, $adminRole, $adminDbId] = require_admin_for_write();
    if (!$okAdmin) {
        echo json_encode(['ok' => false, 'message' => $adminErr], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $ok = delete_doc($pdo, $docId, $adminRole);
    if (!$ok) {
        echo json_encode(['ok' => false, 'message' => '삭제에 실패했습니다. (종결건이거나 존재하지 않습니다)'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));

    echo json_encode([
        'ok' => true,
        'message' => '서류가 삭제되었습니다.',
        'csrf_token' => $_SESSION['csrf_token_admin'],
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * =========================
 * AJAX
 * =========================
 */
if (isset($_GET['ajax']) && $_GET['ajax'] === '1') {
    header('Content-Type: application/json; charset=utf-8');

    try {
        $rows = fetch_rows($pdo, $f);

        $stats = compute_stats($rows);

        // ✅ 헤더는 기간 고정(필터 영향 제거)
        $fHeader = $f;
        $fHeader['outcome'] = 'all';
        $fHeader['status'] = 'all';
        $fHeader['name'] = '';
        $fHeader['memo'] = '';
        $fHeader['note'] = '';

        $rowsHeader = fetch_rows($pdo, $fHeader);
        $headerStats = compute_stats($rowsHeader);

        $selectedId = (int)($_GET['id'] ?? 0);
        if ($selectedId <= 0 && !empty($rows)) $selectedId = (int)$rows[0]['cashhome_1000_id'];

        $selected = null;
        foreach ($rows as $r) {
            if ((int)$r['cashhome_1000_id'] === $selectedId) {
                $selected = $r;
                break;
            }
        }
        if (!$selected && !empty($rows)) $selected = $rows[0];

        $docs = $selected ? fetch_docs_grouped($pdo, (int)$selected['cashhome_1000_id']) : [];

        if ($selected) {
            $issuedBy = (int)($selected['cashhome_1000_doc_token_issued_by'] ?? 0);
            $lastBy   = (int)($selected['cashhome_1000_last_modified_by'] ?? 0);

            $selected['issued_by_label'] = ($issuedBy > 0) ? admin_label_from_db_id($issuedBy) : '—';
            $selected['last_modified_by_label'] = ($lastBy > 0) ? admin_label_from_db_id($lastBy) : '—';

            // ✅ outcome normalize + 종결 여부
            $selected['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($selected['cashhome_1000_outcome'] ?? OC_PENDING));
            $selected['is_closed'] = is_closed_status((string)($selected['cashhome_1000_status'] ?? ''));
        }

        echo json_encode([
            'ok' => true,
            'filters' => [
                'start' => $f['start'],
                'end' => $f['end'],
                'status' => $f['status'],
                'outcome' => $f['outcome'],
                'name' => $f['name'],
                'memo' => $f['memo'],
                'note' => $f['note'],
            ],
            'rows' => compact_rows_for_json($rows),
            'stats' => $stats,
            'header_stats' => $headerStats,
            'selected' => $selected,
            'docs' => $docs,
            'csrf_token' => $_SESSION['csrf_token_admin'],
            'admin' => [
                'role' => $currentAdminRole,
                'label' => $currentAdminBadgeText,
                'db_id' => $currentAdminDbId,
                // ✅ 프론트에서 셀렉트 옵션 렌더링/잠금에 쓰기 좋게 내려줌
                'allowed_statuses' => allowed_statuses_for_role($currentAdminRole),
                'allowed_outcomes' => allowed_outcomes_for_role($currentAdminRole),
            ],
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (Throwable $e) {
        error_log('[ADMIN AJAX ERROR] ' . $e->getMessage());
        echo json_encode(['ok' => false, 'message' => '데이터를 불러오지 못했습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

/**
 * =========================
 * 엑셀 다운로드(CSV)
 * =========================
 * ※ outcome/status는 저장값(코드)이 나가므로,
 *   원하면 HTML/JS 쪽에서 라벨 CSV로 바꾸는 옵션도 추가 가능.
 */
if (isset($_GET['excel']) && $_GET['excel'] === '1') {
    ini_set('display_errors', '0');
    ini_set('html_errors', '0');
    error_reporting(E_ALL & ~E_DEPRECATED);

    while (ob_get_level() > 0) ob_end_clean();

    [$where, $params] = build_where_and_params($f);

    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="inquiries_' . $f['start'] . '_to_' . $f['end'] . '.csv"');
    header('Pragma: no-cache');
    header('Expires: 0');

    echo "\xEF\xBB\xBF";

    $columns = [
        'cashhome_1000_loan_no' => '접수번호',
        'cashhome_1000_created_at' => '접수일시',
        'cashhome_1000_updated_at' => '수정일시',
        'cashhome_1000_customer_name' => '신청자명',
        'cashhome_1000_customer_phone' => '연락처',
        'cashhome_1000_loan_amount' => '희망금액',
        'cashhome_1000_loan_purpose' => '자금용도',
        'cashhome_1000_request_memo' => '요청사항',
        'cashhome_1000_user_ip' => 'IP',
        'cashhome_1000_user_agent' => '브라우저정보',
        'cashhome_1000_agree_privacy' => '개인정보동의',
        'cashhome_1000_privacy_policy_version' => '개인정보동의버전',
        'cashhome_1000_privacy_agreed_at' => '개인정보동의일시',
        'cashhome_1000_agree_marketing' => '마케팅동의',
        'cashhome_1000_marketing_agreed_at' => '마케팅동의일시',
        'cashhome_1000_status' => '처리상태',
        'cashhome_1000_outcome' => '대출결과',
        'cashhome_1000_processed_at' => '처리일시',
        'cashhome_1000_admin_note' => '관리자메모',
    ];

    $sql = "
      SELECT
        i.cashhome_1000_loan_no,
        i.cashhome_1000_created_at,
        i.cashhome_1000_updated_at,
        i.cashhome_1000_customer_name,
        i.cashhome_1000_customer_phone,
        i.cashhome_1000_loan_amount,
        i.cashhome_1000_loan_purpose,
        i.cashhome_1000_request_memo,
        i.cashhome_1000_user_ip,
        i.cashhome_1000_user_agent,
        i.cashhome_1000_agree_privacy,
        i.cashhome_1000_privacy_policy_version,
        i.cashhome_1000_privacy_agreed_at,
        i.cashhome_1000_agree_marketing,
        i.cashhome_1000_marketing_agreed_at,
        i.cashhome_1000_status,
        i.cashhome_1000_outcome,
        i.cashhome_1000_processed_at,
        i.cashhome_1000_admin_note
      FROM cashhome_1000_inquiries i
      $where
      ORDER BY i.cashhome_1000_id DESC
      LIMIT 50000
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);

    $out = fopen('php://output', 'w');
    fputcsv($out, array_values($columns), ',', '"', '\\');

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        // outcome normalize
        $row['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($row['cashhome_1000_outcome'] ?? ''));

        $line = [];
        foreach (array_keys($columns) as $k) {
            $v = $row[$k] ?? '';
            // ✅ 한글 변환
            if ($k === 'cashhome_1000_loan_no') {
                $vv = trim((string)$v);
                $v = ($vv !== '' && $vv !== '00') ? substr($vv, -4) : '';
            } elseif ($k === 'cashhome_1000_agree_privacy' || $k === 'cashhome_1000_agree_marketing') {
                $v = consent_label((string)$v);
            } elseif ($k === 'cashhome_1000_status') {
                $v = status_label((string)$v);
            } elseif ($k === 'cashhome_1000_outcome') {
                $v = outcome_label((string)$v);
            }
            $line[] = $v;
        }
        fputcsv($out, $line, ',', '"', '\\');
    }

    fclose($out);
    exit;
}

/**
 * =========================
 * 3시간마다 최근 3개월 메일 리포트
 * =========================
 * 실행 예시(크론):
 *   0 */
// 3 * * * /usr/bin/php /path/to/admin_inquiries.php --send-report >/dev/null 2>&1
//  *
//  * ※ 서버 mail() 환경이 불안정하면 PHPMailer/SMTP로 바꾸는 걸 권장.
//  */

function fmt_kr_date(string $ymd): string
{
    // YYYY-MM-DD -> YY년 MM월 DD일
    if (!preg_match('/^(\d{4})-(\d{2})-(\d{2})$/', $ymd, $m)) return $ymd;
    $yy = substr($m[1], 2, 2);
    return sprintf('%s년 %s월 %s일', $yy, $m[2], $m[3]);
}

function fetch_rows_for_period(PDO $pdo, string $startDT, string $endDT): array
{
    // 리포트는 필터/권한과 무관하게 전체를 기준으로 잡는 게 일반적이어서 별도 조회
    $stmt = $pdo->prepare("
      SELECT
        cashhome_1000_id,
        cashhome_1000_loan_no,
        cashhome_1000_created_at,
        cashhome_1000_customer_name,
        cashhome_1000_customer_phone,
        cashhome_1000_loan_amount,
        cashhome_1000_status,
        cashhome_1000_outcome,
        cashhome_1000_doc_token_status,
        cashhome_1000_doc_token_expires_at
      FROM cashhome_1000_inquiries
      WHERE cashhome_1000_created_at BETWEEN :s AND :e
      ORDER BY cashhome_1000_id DESC
      LIMIT 20000
    ");
    $stmt->execute([':s' => $startDT, ':e' => $endDT]);
    $rows = $stmt->fetchAll();
    foreach ($rows as &$r) {
        $r['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($r['cashhome_1000_outcome'] ?? OC_PENDING));
        $r['cashhome_1000_status'] = (string)($r['cashhome_1000_status'] ?? ST_NEW);
    }
    unset($r);
    return $rows;
}

function group_rows_by_outcome(array $rows): array
{
    $g = [
        OC_PENDING => [],
        OC_REVIEWING => [],
        OC_APPROVED => [],
        OC_PAID => [],
        OC_REJECTED => [],
    ];
    foreach ($rows as $r) {
        $oc = normalize_outcome_legacy((string)($r['cashhome_1000_outcome'] ?? OC_PENDING));
        $g[$oc][] = $r;
    }
    return $g;
}

function group_rows_by_status_master(array $rows): array
{
    $g = [
        ST_NEW => [],
        ST_CONTACTED => [],
        ST_PROGRESSING => [],
        ST_CLOSED_OK => [],
        ST_CLOSED_ISSUE => [],
    ];
    foreach ($rows as $r) {
        $st = (string)($r['cashhome_1000_status'] ?? ST_NEW);
        if (!isset($g[$st])) $g[$st] = [];
        $g[$st][] = $r;
    }
    return $g;
}

function token_soon_rows(array $rows): array
{
    $out = [];
    $now = time();
    foreach ($rows as $r) {
        $tkStatus = (int)($r['cashhome_1000_doc_token_status'] ?? 0);
        $expiresAt = (string)($r['cashhome_1000_doc_token_expires_at'] ?? '');
        if ($tkStatus !== 1 || $expiresAt === '') continue;
        $exp = strtotime($expiresAt);
        if ($exp === false) continue;
        $diff = $exp - $now;
        if ($diff > 0 && $diff < TOKEN_SOON_SECONDS) $out[] = $r;
    }
    return $out;
}

function row_line(array $r): string
{
    $name = (string)($r['cashhome_1000_customer_name'] ?? '');
    $amt  = (string)($r['cashhome_1000_loan_amount'] ?? '');
    $phone = (string)($r['cashhome_1000_customer_phone'] ?? '');
    $loanNo = (string)($r['cashhome_1000_loan_no'] ?? '');
    $displayNo = ($loanNo !== '' && $loanNo !== '00') ? substr($loanNo, -4) : (string)($r['cashhome_1000_id'] ?? '');

    return "-신청자: {$name}\n-금액: {$amt}\n-연락처: {$phone}\n-대출렌덤번호: {$displayNo}\n";
}

function build_report_mail_body(PDO $pdo): array
{
    // 최근 3개월
    $end = new DateTimeImmutable('now');
    $start = $end->sub(new DateInterval('P3M'));

    $startYmd = $start->format('Y-m-d');
    $endYmd   = $end->format('Y-m-d');

    $startDT = $startYmd . ' 00:00:00';
    $endDT   = $endYmd . ' 23:59:59';

    $rows = fetch_rows_for_period($pdo, $startDT, $endDT);

    // ✅ 3개월 리포트용 그룹핑(대출결과/처리상태)
    $groupOutcome = [];
    $groupStatusM = [];
    foreach ($rows as &$rr) {
        $rr['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($rr['cashhome_1000_outcome'] ?? OC_PENDING));
        $rr['cashhome_1000_status'] = (string)($rr['cashhome_1000_status'] ?? ST_NEW);

        $oc = (string)$rr['cashhome_1000_outcome'];
        $st = (string)$rr['cashhome_1000_status'];

        if (!isset($groupOutcome[$oc])) $groupOutcome[$oc] = [];
        $groupOutcome[$oc][] = $rr;

        if (!isset($groupStatusM[$st])) $groupStatusM[$st] = [];
        $groupStatusM[$st][] = $rr;
    }
    unset($rr);

    $total = count($rows);

    // outcome 집계
    $cntPending  = count($groupOutcome[OC_PENDING] ?? []);
    $cntRejected = count($groupOutcome[OC_REJECTED] ?? []);
    $cntApproved = count($groupOutcome[OC_APPROVED] ?? []);

    // token 만료(5시간 미만)
    $expiring = [];
    $nowTs = time();
    foreach ($rows as $r) {
        $status = (int)($r['cashhome_1000_doc_token_status'] ?? 0); // 1=발급, 2=사용
        $expiresAt = (string)($r['cashhome_1000_doc_token_expires_at'] ?? '');
        if ($status !== 1 || $expiresAt === '') continue;

        $expTs = strtotime($expiresAt);
        if ($expTs === false) continue;

        $remainSec = $expTs - $nowTs;
        if ($remainSec <= 0) continue;
        if ($remainSec < 5 * 3600) {
            $r['_remain_hours'] = round($remainSec / 3600, 2);
            $expiring[] = $r;
        }
    }

    // status(master 기준) 집계 (위에서 그룹핑)

    $subject = '[CASHHOME] 3시간 통계 리포트 (' . fmt_kr_date($startYmd) . ' ~ ' . fmt_kr_date($endYmd) . ')';

    $h = static function (string $s): string {
        return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    };

    $loanNo4 = static function (array $r): string {
        $raw = (string)($r['cashhome_1000_loan_no'] ?? '');
        $raw = trim($raw);
        if ($raw === '') return '';
        return mb_substr($raw, -4);
    };

    $fmtAmt = static function ($v): string {
        $n = (string)$v;
        $n = preg_replace('/[^\d]/', '', $n);
        if ($n === '') return '';
        return number_format((int)$n);
    };

    $renderTable = static function (array $rows) use ($h, $loanNo4, $fmtAmt): string {
        if (!$rows) {
            return '<div style="color:#666;font-size:12px;">(없음)</div>';
        }

        $tableStyle = 'border-collapse:collapse;width:100%;font-size:12px;';
        $thStyle = 'background:#f2f2f2;border:1px solid #ddd;padding:7px;white-space:nowrap;';
        $tdStyle = 'border:1px solid #ddd;padding:7px;vertical-align:top;';

        $html = '<table cellpadding="0" cellspacing="0" style="' . $tableStyle . '">';
        $html .= '<thead><tr>'
            . '<th align="left" style="' . $thStyle . '">NO</th>'
            . '<th align="left" style="' . $thStyle . '">신청일시</th>'
            . '<th align="left" style="' . $thStyle . '">신청자</th>'
            . '<th align="left" style="' . $thStyle . '">연락처</th>'
            . '<th align="right" style="' . $thStyle . '">금액</th>'
            . '<th align="left" style="' . $thStyle . '">처리상태</th>'
            . '<th align="left" style="' . $thStyle . '">대출결과</th>'
            . '<th align="left" style="' . $thStyle . '">대출번호</th>'
            . '</tr></thead><tbody>';

        $i = 0;
        foreach ($rows as $r) {
            $i++;
            $bg = ($i % 2 === 0) ? 'background:#fafafa;' : '';
            $id = $h((string)($r['cashhome_1000_id'] ?? ''));
            $created = $h((string)($r['cashhome_1000_created_at'] ?? ''));
            $name = $h((string)($r['cashhome_1000_customer_name'] ?? ''));
            $phone = $h((string)($r['cashhome_1000_customer_phone'] ?? ''));
            $amt  = $h($fmtAmt($r['cashhome_1000_loan_amount'] ?? ''));
            $st = $h(status_label((string)($r['cashhome_1000_status'] ?? ST_NEW)));
            $oc = $h(outcome_label((string)normalize_outcome_legacy((string)($r['cashhome_1000_outcome'] ?? OC_PENDING))));
            $no4 = $h($loanNo4($r));

            $html .= '<tr style="' . $bg . '">'
                . '<td style="' . $tdStyle . '">' . $id . '</td>'
                . '<td style="' . $tdStyle . '">' . $created . '</td>'
                . '<td style="' . $tdStyle . '">' . $name . '</td>'
                . '<td style="' . $tdStyle . '">' . $phone . '</td>'
                . '<td align="right" style="' . $tdStyle . '">' . $amt . '</td>'
                . '<td style="' . $tdStyle . '">' . $st . '</td>'
                . '<td style="' . $tdStyle . '">' . $oc . '</td>'
                . '<td style="' . $tdStyle . '">' . $no4 . '</td>'
                . '</tr>';
        }

        $html .= '</tbody></table>';
        return $html;
    };


    $html = '';
    $html .= '<div style="font-family:Apple SD Gothic Neo,Malgun Gothic,Arial,sans-serif;">';
    $html .= '<h2 style="margin:0 0 10px 0;">CASHHOME 통계 리포트</h2>';
    $html .= '<div style="margin:0 0 14px 0;color:#333;">(조회기간 표시 ' . $h(fmt_kr_date($startYmd)) . ' ~ ' . $h(fmt_kr_date($endYmd)) . ' 까지)</div>';

    // 요약
    $html .= '<h3 style="margin:18px 0 8px 0;">%대출정보</h3>';
    $html .= '<ul style="margin:0 0 12px 18px;padding:0;">'
        . '<li>대출 총건수: <b>' . $total . '</b></li>'
        . '<li>대기 총건수: <b>' . $cntPending . '</b></li>'
        . '<li>부결 총건수: <b>' . $cntRejected . '</b></li>'
        . '<li>승인 총건수: <b>' . $cntApproved . '</b></li>'
        . '</ul>';

    // 토큰 만료
    $html .= '<h3 style="margin:18px 0 8px 0;">토큰 만료 요약</h3>';
    $html .= '<div style="margin:0 0 8px 0;">1. 토큰이 5시간 미만으로 남은 건수가 <b>' . count($expiring) . '</b>건(서류등록 독촉)</div>';
    $html .= $renderTable($expiring);

    // outcome 섹션
    $html .= '<h3 style="margin:22px 0 8px 0;">대출결과 요약</h3>';

    $mapOutcomeOrder = [
        OC_PENDING => '1. 대출 대기건',
        OC_REVIEWING => '2. 대출 검토건',
        OC_APPROVED => '3. 대출 승인',
        OC_PAID => '4. 대출 출금완료',
        OC_REJECTED => '5. 대출 부결',
    ];

    foreach ($mapOutcomeOrder as $k => $title) {
        $rows2 = $groupOutcome[$k] ?? [];
        $html .= '<h4 style="margin:14px 0 6px 0;">' . $h($title) . ' : <b>' . count($rows2) . '</b>건</h4>';
        $html .= $renderTable($rows2);
    }

    // status 섹션(master 기준)
    $html .= '<h3 style="margin:22px 0 8px 0;">처리상태 요약</h3>';
    $html .= '<div style="margin:0 0 10px 0;color:#333;">master=신규 / 연락완료 /대출진행중/ 정상종결 / 문제종결</div>';

    $mapStatusOrder = [
        ST_NEW => '1.대출 신규',
        ST_CONTACTED => '2.대출 연락완료',
        ST_PROGRESSING => '3.대출 진행',
        ST_CLOSED_OK => '4.대출 정상종결',
        ST_CLOSED_ISSUE => '5.대출 문제종결',
    ];
    foreach ($mapStatusOrder as $k => $title) {
        $rows3 = $groupStatusM[$k] ?? [];
        $html .= '<h4 style="margin:14px 0 6px 0;">' . $h($title) . ' : <b>' . count($rows3) . '</b>건</h4>';
        $html .= $renderTable($rows3);
    }

    $html .= '<div style="margin-top:18px;color:#888;font-size:12px;">※ 본 메일은 3시간마다 자동 발송됩니다.</div>';
    $html .= '</div>';


    $columns = [
        'cashhome_1000_loan_no' => '접수번호',
        'cashhome_1000_created_at' => '접수일시',
        'cashhome_1000_customer_name' => '신청자명',
        'cashhome_1000_customer_phone' => '연락처',
        'cashhome_1000_loan_amount' => '희망금액',
        'cashhome_1000_loan_purpose' => '자금용도',
        'cashhome_1000_status' => '처리상태',
        'cashhome_1000_outcome' => '대출결과',
        'cashhome_1000_processed_at' => '처리일시'
    ];

    $sql = "
      SELECT
        i.cashhome_1000_loan_no,
        i.cashhome_1000_created_at,
        i.cashhome_1000_updated_at,
        i.cashhome_1000_customer_name,
        i.cashhome_1000_customer_phone,
        i.cashhome_1000_loan_amount,
        i.cashhome_1000_loan_purpose,
        i.cashhome_1000_request_memo,
        i.cashhome_1000_user_ip,
        i.cashhome_1000_user_agent,
        i.cashhome_1000_agree_privacy,
        i.cashhome_1000_privacy_policy_version,
        i.cashhome_1000_privacy_agreed_at,
        i.cashhome_1000_agree_marketing,
        i.cashhome_1000_marketing_agreed_at,
        i.cashhome_1000_status,
        i.cashhome_1000_outcome,
        i.cashhome_1000_processed_at,
        i.cashhome_1000_admin_note
      FROM cashhome_1000_inquiries i
      WHERE 1
      ORDER BY i.cashhome_1000_id DESC
      LIMIT 50000
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute();

    // ===============================
    // 대출 신청 리스트 테이블 시작
    // ===============================

    $html .= '<div style="margin-top:30px;">';
    $html .= '<h3 style="margin-bottom:10px;">📋 신규 대출 신청 목록</h3>';

    $html .= '<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:12px;">';

    // ✅ 테이블 헤더
    $html .= '<thead style="background:#f5f5f5;">';
    $html .= '<tr>';
    foreach ($columns as $label) {
        $html .= '<th style="border:1px solid #ddd;">' . htmlspecialchars($label) . '</th>';
    }
    $html .= '</tr>';
    $html .= '</thead>';

    $html .= '<tbody>';

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {

        $row['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($row['cashhome_1000_outcome'] ?? ''));

        $html .= '<tr>';

        foreach (array_keys($columns) as $k) {

            $v = $row[$k] ?? '';

            // ===== 값 변환 로직 =====
            if ($k === 'cashhome_1000_loan_no') {
                $vv = trim((string)$v);
                $v = ($vv !== '' && $vv !== '00') ? substr($vv, -4) : '';
            } elseif ($k === 'cashhome_1000_agree_privacy' || $k === 'cashhome_1000_agree_marketing') {
                $v = consent_label((string)$v);
            } elseif ($k === 'cashhome_1000_status') {
                $v = status_label((string)$v);
            } elseif ($k === 'cashhome_1000_outcome') {
                $v = outcome_label((string)$v);
            }

            $html .= '<td style="border:1px solid #ddd;">' . nl2br(htmlspecialchars((string)$v)) . '</td>';
        }

        $html .= '</tr>';
    }

    $html .= '</tbody>';
    $html .= '</table>';
    $html .= '</div>';


    // plain fallback(간단 요약)
    $plain = "(조회기간 표시 {$startYmd} ~ {$endYmd})\n"
        . "%대출정보\n"
        . "1.대출 총건수: {$total}\n"
        . "2.대기 총건수 : {$cntPending}\n"
        . "3.부결 총건수: {$cntRejected}\n"
        . "4.승인 총건수: {$cntApproved}\n";

    return [$subject, $html, $plain];

}


function send_report_mail(PDO $pdo): bool
{
    [$subject, $html, $plain] = build_report_mail_body($pdo);

    try {
        $ms = new MailSender();
        // HTML 우선, 실패 시 MailSender 내부에서 mail()/SMTP fallback 처리
        return $ms->sendHtmlTo(REPORT_MAIL_TO, $subject, $html, $plain);
    } catch (Throwable $e) {
        error_log('[report_mail] ' . $e->getMessage());
        return false;
    }
}

/**
 * ✅ CLI 모드로 리포트 전송
 * (웹 접근으로 보내지 않도록 안전장치)
 */
if (PHP_SAPI === 'cli') {
    global $argv;
    if (isset($argv[1]) && $argv[1] === '--send-report') {
        $pdoCli = cashhome_pdo();
        $ok = send_report_mail($pdoCli);
        echo $ok ? "OK\n" : "FAIL\n";
        exit;
    }
}

/**
 * =========================
 * SSR 준비
 * =========================
 */
$rows = [];
$stats = [
    'total' => 0,
    'approved' => 0,
    'pending' => 0,
    'rejected' => 0,
    'rate' => 0,
    'labels' => [],
    'series_all' => [],
    'series_approved' => [],
    'token_soon' => 0
];
$error = '';
$selectedId = 0;
$selected = null;
$docsSelected = [];

$pendingHeaderCount = 0;
$reviewingHeaderCount = 0;
$approvedBadgeCount = 0;
$paidHeaderCount = 0;
$rejectedHeaderCount = 0;
$rateHeader = '0.0';
$tokenSoonHeaderCount = 0;

// 처리상태 헤더(기간 고정)
$stNewHeader = 0;
$stContactedHeader = 0;
$stProgressingHeader = 0;
$stClosedOkHeader = 0;
$stClosedIssueHeader = 0;

$headerStats = $stats; // 기본값

try {
    $rows = fetch_rows($pdo, $f);
    $stats = compute_stats($rows);

    // ✅ 헤더는 기간 고정(필터 영향 제거)
    $fHeader = $f;
    $fHeader['outcome'] = 'all';
    $fHeader['status'] = 'all';
    $fHeader['name'] = '';
    $fHeader['memo'] = '';
    $fHeader['note'] = '';

    $rowsHeader = fetch_rows($pdo, $fHeader);
    $headerStats = compute_stats($rowsHeader);

    $pendingHeaderCount = (int)($headerStats['pending'] ?? 0);
    $reviewingHeaderCount = (int)($headerStats['reviewing'] ?? 0);
    $approvedBadgeCount = (int)($headerStats['approved'] ?? 0);
    $paidHeaderCount = (int)($headerStats['paid'] ?? 0);
    $rejectedHeaderCount = (int)($headerStats['rejected'] ?? 0);
    $rateHeader = (string)($headerStats['rate'] ?? 0);
    $tokenSoonHeaderCount = (int)($headerStats['token_soon'] ?? 0);

    $bs = $headerStats['by_status'] ?? [];
    $stNewHeader = (int)($bs[ST_NEW] ?? 0);
    $stContactedHeader = (int)($bs[ST_CONTACTED] ?? 0);
    $stProgressingHeader = (int)($bs[ST_PROGRESSING] ?? 0);
    $stClosedOkHeader = (int)($bs[ST_CLOSED_OK] ?? 0);
    $stClosedIssueHeader = (int)($bs[ST_CLOSED_ISSUE] ?? 0);

    $selectedId = (int)($_GET['id'] ?? 0);
    if ($selectedId <= 0 && !empty($rows)) $selectedId = (int)$rows[0]['cashhome_1000_id'];

    foreach ($rows as $r) {
        if ((int)$r['cashhome_1000_id'] === $selectedId) {
            $selected = $r;
            break;
        }
    }
    if (!$selected && !empty($rows)) $selected = $rows[0];

    if ($selected) {
        $docsSelected = fetch_docs_grouped($pdo, (int)$selected['cashhome_1000_id']);

        // ✅ 라벨 필드 SSR에서도 제공
        $issuedBy = (int)($selected['cashhome_1000_doc_token_issued_by'] ?? 0);
        $lastBy   = (int)($selected['cashhome_1000_last_modified_by'] ?? 0);
        $selected['issued_by_label'] = ($issuedBy > 0) ? admin_label_from_db_id($issuedBy) : '—';
        $selected['last_modified_by_label'] = ($lastBy > 0) ? admin_label_from_db_id($lastBy) : '—';

        $selected['cashhome_1000_outcome'] = normalize_outcome_legacy((string)($selected['cashhome_1000_outcome'] ?? OC_PENDING));
        $selected['is_closed'] = is_closed_status((string)($selected['cashhome_1000_status'] ?? ''));
    }
} catch (Throwable $e) {
    error_log('[ADMIN SSR ERROR] ' . $e->getMessage());
    $error = '데이터를 불러오지 못했습니다.';
}

function admin_name_by_id(int $id): string
{
    return admin_label_from_db_id($id);
}

// ===== 여기 아래부터는 SSR(HTML 렌더) 영역 =====
?>


<!doctype html>
<html lang="ko">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex,nofollow" />
    <title>접수이력</title>

    <!-- Chart.js (그래프는 script 파트에서 초기화) -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        :root {
            --bg: #0B1220;
            --card: rgba(16, 26, 51, .80);
            --card2: rgba(16, 26, 51, .62);
            --line: rgba(234, 240, 255, .12);
            --line2: rgba(234, 240, 255, .08);
            --text: #EAF0FF;
            --muted: #9DB0D0;
            --shadow: 0 14px 40px rgba(0, 0, 0, .38);
            --r1: 18px;
            --r2: 22px;

            --pending: #FBBF24;
            --approved: #22C55E;
            --rejected: #EF4444;
            --accent: #6EE7FF;
            --accent2: #A78BFA;

            --chipH: 26px;
            --chipPadX: 10px;
            --chipFont: 12px;
        }

        * {
            box-sizing: border-box
        }

        body {
            margin: 0;
            font-family: system-ui, "Noto Sans KR";
            background:
                radial-gradient(1200px 600px at 20% -10%, rgba(110, 231, 255, .18), transparent 60%),
                radial-gradient(900px 520px at 90% 10%, rgba(167, 139, 250, .16), transparent 55%),
                var(--bg);
            color: var(--text);
        }

        a {
            color: inherit
        }

        .wrap {
            max-width: 1500px;
            margin: 0 auto;
            padding: 18px 16px 26px
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
            padding: 14px 14px;
            border: 1px solid var(--line);
            border-radius: var(--r2);
            background: linear-gradient(180deg, rgba(255, 255, 255, .05), rgba(255, 255, 255, .02));
            box-shadow: var(--shadow);
        }

        .title h2 {
            margin: 0 0 4px;
            font-size: 18px;
            letter-spacing: -.2px
        }

        .title .muted {
            color: var(--muted);
            font-size: 12px
        }

        .actions {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center
        }

        .btn {
            padding: 10px 12px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(16, 26, 51, .55);
            color: var(--text);
            text-decoration: none;
            font-size: 12px;
            font-weight: 900;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            height: 38px;
            line-height: 38px;
        }

        .btn:hover {
            background: rgba(255, 255, 255, .05)
        }

        .btn.primary {
            border: 0;
            background: linear-gradient(135deg, rgba(110, 231, 255, .95), rgba(167, 139, 250, .95));
            color: #061025;
        }

        .btn[disabled],
        .btn:disabled {
            opacity: .55;
            cursor: not-allowed;
        }

        .btn.danger {
            border: 1px solid rgba(239, 68, 68, .35);
            background: rgba(255, 255, 255, .03);
        }

        .err {
            margin-top: 10px;
            padding: 10px 12px;
            border-radius: 14px;
            border: 1px solid rgba(255, 120, 120, .35);
            background: rgba(255, 255, 255, .03);
            font-size: 12px;
        }

        .topPills {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .topPill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: var(--chipFont);
            font-weight: 1000;
            line-height: var(--chipH);
            white-space: nowrap;
        }

        .topPill.pending {
            border-color: rgba(251, 191, 36, .25);
            color: #FFE6A8;
        }

        .topPill.approved {
            border-color: rgba(34, 197, 94, .25);
            color: #BFF7D3;
        }


        .topPill.reviewing {
            border-color: rgba(167, 139, 250, .25);
            color: #E7DEFF;
        }

        .topPill.paid {
            border-color: rgba(110, 231, 255, .25);
            color: #D0FBFF;
        }

        .statusPills {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
            margin-top: 8px;
        }

        .statusPill {
            display: inline-flex;
            align-items: center;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: var(--chipFont);
            font-weight: 900;
            line-height: var(--chipH);
            white-space: nowrap;
            color: var(--muted);
        }

        .statusPill.st-new {
            border-color: rgba(251, 191, 36, .18);
            color: #FFE6A8;
        }

        .statusPill.st-contacted {
            border-color: rgba(110, 231, 255, .18);
            color: #D0FBFF;
        }

        .statusPill.st-progressing {
            border-color: rgba(167, 139, 250, .18);
            color: #E7DEFF;
        }

        .statusPill.st-ok {
            border-color: rgba(34, 197, 94, .18);
            color: #BFF7D3;
        }

        .statusPill.st-issue {
            border-color: rgba(239, 68, 68, .18);
            color: #FFD3D3;
        }


        .topPill.rejected {
            border-color: rgba(239, 68, 68, .25);
            color: #FFD3D3;
        }

        .topPill.rate {
            border-color: rgba(110, 231, 255, .25);
            color: #D0FBFF;
        }

        .topPill.soon {
            border-color: rgba(239, 68, 68, .35);
            background: rgba(239, 68, 68, .12);
            color: #FFD3D3;
        }

        .badgeDot {
            width: 10px;
            height: 10px;
            border-radius: 99px;
            background: var(--rejected);
            box-shadow: 0 0 18px rgba(239, 68, 68, .55);
        }

        .adminChip {
            display: inline-flex;
            align-items: center;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid rgba(110, 231, 255, .25);
            background: rgba(110, 231, 255, .06);
            color: #D0FBFF;
            font-size: var(--chipFont);
            font-weight: 1000;
            line-height: var(--chipH);
            white-space: nowrap;
        }

        .filters {
            margin-top: 12px;
            padding: 14px;
            border: 1px solid var(--line);
            border-radius: var(--r2);
            background: var(--card);
            box-shadow: var(--shadow);
            display: grid;
            grid-template-columns: 1fr 1fr 1fr 1fr 1.2fr 1.2fr 1.2fr auto;
            gap: 10px;
            align-items: end;
        }

        .field {
            display: grid;
            gap: 6px
        }

        .field label {
            font-size: 12px;
            color: var(--muted);
            font-weight: 800
        }

        input[type="date"],
        select,
        input[type="text"] {
            width: 100%;
            padding: 12px 12px;
            border-radius: 14px;
            border: 1px solid var(--line);
            background: rgba(8, 12, 24, .55);
            color: var(--text);
            outline: none;
        }

        input[type="date"]:focus,
        select:focus,
        input[type="text"]:focus {
            border-color: rgba(110, 231, 255, .55);
            box-shadow: 0 0 0 3px rgba(110, 231, 255, .12);
        }

        input:disabled,
        select:disabled {
            opacity: .55;
            cursor: not-allowed;
        }

        .meta {
            grid-column: 1 / -1;
            color: var(--muted);
            font-size: 12px;
            display: flex;
            justify-content: space-between;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 2px;
        }

        .hint {
            color: var(--muted);
            font-size: 12px
        }

        @media (max-width: 1200px) {
            .filters {
                grid-template-columns: 1fr 1fr 1fr 1fr;
            }
        }

        @media (max-width: 720px) {
            .filters {
                grid-template-columns: 1fr 1fr;
            }
        }

        .statsGrid {
            margin-top: 12px;
            display: grid;
            grid-template-columns: 1fr 1fr 1.5fr;
            gap: 12px;
        }

        @media (max-width:1100px) {
            .statsGrid {
                grid-template-columns: 1fr;
            }
        }

        .statCard {
            border: 1px solid var(--line);
            border-radius: var(--r2);
            background: var(--card2);
            box-shadow: var(--shadow);
            padding: 14px;
            overflow: hidden;
        }

        .statTitle {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px
        }

        .statTitle b {
            font-size: 13px
        }

        .statNums {
            margin-top: 10px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap
        }

        .pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: var(--chipFont);
            font-weight: 1000;
            line-height: var(--chipH);
            white-space: nowrap;
        }

        .pill.pending {
            border-color: rgba(251, 191, 36, .25);
            color: #FFE6A8
        }

        .pill.approved {
            border-color: rgba(34, 197, 94, .25);
            color: #BFF7D3
        }

        .pill.rejected {
            border-color: rgba(239, 68, 68, .25);
            color: #FFD3D3
        }

        .pill.rate {
            border-color: rgba(110, 231, 255, .25);
            color: #D0FBFF
        }

        .chartWrap {
            margin-top: 12px
        }

        canvas {
            width: 100% !important;
            height: 260px !important
        }

        .layout {
            margin-top: 12px;
            display: grid;
            grid-template-columns: 430px 1fr;
            gap: 12px;
            align-items: start;
        }

        @media (max-width:1100px) {
            .layout {
                grid-template-columns: 1fr;
            }
        }

        .panel {
            border: 1px solid var(--line);
            border-radius: var(--r2);
            background: var(--card);
            box-shadow: var(--shadow);
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .panelHead {
            padding: 12px 14px;
            border-bottom: 1px solid var(--line2);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            background: rgba(11, 18, 32, .35);
        }

        .panelHead b {
            font-size: 13px
        }

        .count {
            color: var(--muted);
            font-size: 12px
        }

        .list {
            overflow: auto;
        }

        .item {
            padding: 12px 14px;
            border-bottom: 1px solid var(--line2);
            text-decoration: none;
            display: block;
            transition: background .15s ease;
            cursor: pointer;
        }

        .item:hover {
            background: rgba(255, 255, 255, .04)
        }

        .item.on {
            background: rgba(255, 255, 255, .06)
        }

        .row1 {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px
        }

        .name {
            font-weight: 1000;
            letter-spacing: -.2px;
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .idchip {
            color: var(--muted);
            font-size: 12px
        }

        .row2 {
            margin-top: 6px;
            color: var(--muted);
            font-size: 12px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }

        .chips {
            margin-top: 8px;
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center
        }

        .badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: var(--chipFont);
            font-weight: 1000;
            line-height: var(--chipH);
            white-space: nowrap;
        }

        .badge .dot {
            width: 10px;
            height: 10px;
            border-radius: 99px
        }

        .badge.pending {
            border-color: rgba(251, 191, 36, .28);
            color: #FFE6A8
        }

        .badge.pending .dot {
            background: var(--pending);
            box-shadow: 0 0 16px rgba(251, 191, 36, .35)
        }

        .badge.approved {
            border-color: rgba(34, 197, 94, .28);
            color: #BFF7D3
        }

        .badge.approved .dot {
            background: var(--approved);
            box-shadow: 0 0 16px rgba(34, 197, 94, .35)
        }

        .badge.rejected {
            border-color: rgba(239, 68, 68, .28);
            color: #FFD3D3
        }

        .badge.rejected .dot {
            background: var(--rejected);
            box-shadow: 0 0 16px rgba(239, 68, 68, .35)
        }

        .badge.status {
            border-color: rgba(110, 231, 255, .18);
            color: #D0FBFF
        }

        .badge.consent {
            border-color: rgba(234, 240, 255, .12);
            color: rgba(234, 240, 255, .92)
        }

        .badge.consent.ok {
            border-color: rgba(34, 197, 94, .20);
            color: #BFF7D3
        }

        .seqChip {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            height: var(--chipH);
            min-width: var(--chipH);
            padding: 0 10px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: var(--chipFont);
            line-height: var(--chipH);
            font-weight: 1000;
            color: rgba(234, 240, 255, .92);
        }

        .tokenInfo,
        .callMiniWrap {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .tokenInfo .ttl,
        .tokenInfo .noToken,
        .tokenInfo .docs,
        .callMini,
        .tokenInfo .usedToken {
            display: inline-flex;
            align-items: center;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: var(--chipFont);
            font-weight: 1000;
            line-height: var(--chipH);
            white-space: nowrap;
            text-decoration: none;
        }

        .copyMiniBtn {
            display: inline-flex;
            align-items: center;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid rgba(110, 231, 255, .25);
            background: rgba(110, 231, 255, .06);
            color: #D0FBFF;
            font-size: var(--chipFont);
            font-weight: 1000;
            line-height: var(--chipH);
            cursor: pointer;
            user-select: none;
            white-space: nowrap;
        }

        .copyMiniBtn:hover {
            background: rgba(110, 231, 255, .10);
        }

        .copyMiniBtn:disabled {
            opacity: .55;
            cursor: not-allowed;
        }

        .tokenInfo .noToken {
            color: #FFD3D3;
            background: rgba(239, 68, 68, .10);
            border: 1px solid rgba(239, 68, 68, .35);
        }

        .tokenInfo .usedToken {
            color: #BFF7D3;
            border: 1px solid rgba(34, 197, 94, .25);
            background: rgba(34, 197, 94, .08);
        }

        .tokenInfo .ttl.soon {
            color: #FFD3D3;
            background: rgba(239, 68, 68, .10);
            border: 1px solid rgba(239, 68, 68, .35);
        }

        .tokenInfo .docs.none {
            color: #FFD3D3;
            background: rgba(239, 68, 68, .10);
            border: 1px solid rgba(239, 68, 68, .35);
        }

        .tokenInfo .docs.count {
            color: #D0FBFF;
            border: 1px solid rgba(110, 231, 255, .25);
            background: rgba(110, 231, 255, .06);
        }

        .tokenInfo .docs .n,
        .tokenInfo .docs .u {
            color: #6EE7FF;
            font-weight: 1000;
        }

        .callMini {
            border-color: rgba(110, 231, 255, .25);
            color: #D0FBFF;
            background: rgba(255, 255, 255, .03);
        }

        .callMini:hover {
            background: rgba(255, 255, 255, .06)
        }

        .detailBody {
            padding: 14px;
            overflow: visible;
            max-height: none;
        }

        .detailTitle {
            font-size: 18px;
            margin: 0 0 10px;
            letter-spacing: -.2px
        }

        .kv {
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 8px 12px;
            font-size: 13px
        }

        .k {
            color: var(--muted);
            font-weight: 900
        }

        .v {
            color: var(--text)
        }

        .memoBox {
            margin-top: 10px;
            padding: 12px;
            border-radius: 16px;
            border: 1px solid var(--line);
            background: rgba(8, 12, 24, .45);
            white-space: pre-wrap;
            color: var(--text);
            font-size: 13px;
            min-height: 84px;
        }

        .subhr {
            margin: 14px 0;
            height: 1px;
            background: var(--line2)
        }

        .formRow {
            margin-top: 10px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            align-items: end;
        }

        @media (max-width:720px) {
            .formRow {
                grid-template-columns: 1fr;
            }
        }

        .saveBar {
            margin-top: 12px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
            justify-content: flex-start;
        }

        .sideMeta {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: var(--chipFont);
            font-weight: 1000;
            line-height: var(--chipH);
            color: rgba(234, 240, 255, .92);
            white-space: nowrap;
        }

        .callBtn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            height: 34px;
            padding: 0 14px;
            border-radius: 999px;
            border: 1px solid rgba(110, 231, 255, .25);
            background: rgba(255, 255, 255, .03);
            text-decoration: none;
            font-weight: 1000;
            font-size: 12px;
            color: #D0FBFF;
            line-height: 34px;
        }

        .callBtn:hover {
            background: rgba(255, 255, 255, .05)
        }

        /* docs */
        .docsWrap {
            display: grid;
            gap: 12px;
        }

        .docGroup {
            border: 1px solid var(--line);
            border-radius: 16px;
            background: rgba(8, 12, 24, .35);
            padding: 12px;
        }

        .docGroupHead {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 10px;
        }

        .docGroupHead b {
            font-size: 13px;
        }

        .docGrid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 10px;
        }

        @media (max-width: 900px) {
            .docGrid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }
        }

        .docItem {
            border: 1px solid var(--line2);
            border-radius: 14px;
            background: rgba(255, 255, 255, .03);
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .thumbBtn {
            border: 0;
            padding: 0;
            margin: 0;
            background: transparent;
            cursor: pointer;
        }

        .thumb {
            width: 100%;
            aspect-ratio: 4 / 3;
            background: rgba(0, 0, 0, .25);
            display: block;
            object-fit: cover;
        }

        .docMeta {
            padding: 10px;
            display: grid;
            gap: 8px;
            font-size: 12px;
            color: var(--muted);
        }

        .docMeta .fn {
            color: rgba(234, 240, 255, .92);
            font-weight: 900;
            font-size: 12px;
            word-break: break-word;
        }

        .docBtns {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .miniBtn {
            display: inline-flex;
            align-items: center;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            color: var(--text);
            font-size: var(--chipFont);
            font-weight: 900;
            cursor: pointer;
            text-decoration: none;
            gap: 6px;
            line-height: var(--chipH);
            white-space: nowrap;
        }

        .miniBtn:hover {
            background: rgba(255, 255, 255, .05);
        }

        .miniBtn:disabled {
            opacity: .55;
            cursor: not-allowed;
        }

        /* 탭 */
        .tabBar {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin-top: 10px;
        }

        .tabBtn {
            height: 36px;
            padding: 0 14px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            color: var(--text);
            font-size: 12px;
            font-weight: 1000;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            line-height: 36px;
        }

        .tabBtn.on {
            border: 0;
            background: linear-gradient(135deg, rgba(110, 231, 255, .95), rgba(167, 139, 250, .95));
            color: #061025;
        }

        .tabBtn:disabled {
            opacity: .55;
            cursor: not-allowed;
        }

        .tabPane {
            margin-top: 12px;
            padding: 12px;
            border-radius: 16px;
            border: 1px solid var(--line);
            background: rgba(8, 12, 24, .35);
        }

        .tabPane[hidden] {
            display: none !important;
        }

        .tokenBox {
            display: grid;
            gap: 10px;
        }

        .tokenRow {
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 8px 12px;
            font-size: 13px;
        }

        .tokenCode {
            font-size: 18px;
            letter-spacing: 2px;
            font-weight: 1000;
        }

        .radioRow {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
            margin-top: 4px;
        }


        .radioChip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            height: var(--chipH);
            padding: 0 var(--chipPadX);
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: var(--chipFont);
            font-weight: 900;
            cursor: pointer;
            user-select: none;
            line-height: var(--chipH);
            white-space: nowrap;
        }

        .radioChip input {
            accent-color: #6EE7FF;
        }

        .tokenActions {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
            margin-top: 2px;
        }

        .smallHint {
            color: var(--muted);
            font-size: 12px;
        }

        @media (min-width: 1101px) {
            #backToListBtn {
                display: none !important;
            }
        }

        /* ✅ Docs Modal (다음/이전/닫기) */
        .modal {
            position: fixed;
            inset: 0;
            z-index: 9999;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 18px;
            background: rgba(0, 0, 0, .65);
            backdrop-filter: blur(8px);
        }

        .modal.on {
            display: flex;
        }

        .modalBox {
            width: min(1100px, 96vw);
            max-height: 92vh;
            border: 1px solid var(--line);
            border-radius: 18px;
            background: rgba(8, 12, 24, .92);
            box-shadow: var(--shadow);
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .modalHead {
            padding: 12px 14px;
            border-bottom: 1px solid var(--line2);
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 10px;
        }

        .modalHead b {
            font-size: 13px;
        }

        .modalBody {
            padding: 14px;
            overflow: auto;
            display: grid;
            gap: 10px;
        }

        .modalImg {
            width: 100%;
            height: auto;
            border-radius: 14px;
            border: 1px solid var(--line2);
            background: rgba(0, 0, 0, .25);
        }

        .modalFoot {
            padding: 12px 14px;
            border-top: 1px solid var(--line2);
            display: flex;
            justify-content: space-between;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }

        .modalBtns {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            align-items: center;
        }

        .modalMeta {
            color: var(--muted);
            font-size: 12px;
            word-break: break-word;
        }
    </style>
</head>

<body>
    <div class="wrap">

        <div class="topbar">
            <div class="title">
                <h2>접수이력</h2>
                <div class="muted">조건 변경은 자동 반영 · 키워드 입력은 실시간 검색 · 저장은 버튼 클릭 필수</div>
            </div>

            <div class="actions headerActions">
                <!-- 왼쪽: 2줄(대출결과/처리결과) + 관리자칩 -->
                <div class="headerLeft">
                    <div class="topPillsRow" id="topPills">
                        <span class="rowLabel">대출결과 =</span>
                        <span class="topPill all">전체 <?= h((string)($headerStats['total'] ?? 0)) ?>건</span>
                        <span class="topPill pending">대기 <?= h((string)$pendingHeaderCount) ?>건</span>
                        <span class="topPill reviewing">검토 <?= h((string)$reviewingHeaderCount) ?>건</span>
                        <span class="topPill approved">승인 <?= h((string)$approvedBadgeCount) ?>건</span>
                        <span class="topPill paid">출금완료 <?= h((string)$paidHeaderCount) ?>건</span>
                        <span class="topPill rejected">부결 <?= h((string)$rejectedHeaderCount) ?>건</span>
                    </div>

                    <div class="statusPillsRow" id="statusPills">
                        <span class="rowLabel">처리결과 =</span>
                        <span class="statusPill all">전체 <?= h((string)($headerStats['total'] ?? 0)) ?>건</span>
                        <span class="statusPill st-contacted">연락완료 <?= h((string)$stContactedHeader) ?>건</span>
                        <span class="statusPill st-progressing">대출진행중 <?= h((string)$stProgressingHeader) ?>건</span>
                        <span class="statusPill st-ok">정상종결 <?= h((string)$stClosedOkHeader) ?>건</span>
                        <span class="statusPill st-issue">문제종결 <?= h((string)$stClosedIssueHeader) ?>건</span>
                    </div>


                </div>

                <!-- 오른쪽: 버튼만 -->
                <div class="headerRight">
                    <div class="adminRow">
                        <span class="btn adminChip">
                            관리자:
                            <b id="adminBadgeText"><?= h($currentAdminBadgeText ?? '—') ?></b>
                            <?php if (!empty($_SESSION['cashhome_admin_id'])): ?>
                                <span style="opacity:.85; font-weight:900; margin-left:6px;">
                                    (#<?= h((string)$_SESSION['cashhome_admin_id']) ?>)
                                </span>
                            <?php endif; ?>
                        </span>
                    </div>
                    <a class="btn" href="./">GO TO HOME</a>
                    <a class="btn" href="admin_inquiries.php?logout=1">LOG OUT</a>
                </div>
            </div>
        </div>

        <?php if (!empty($error)): ?>
            <div class="err"><?= h($error) ?></div>
        <?php endif; ?>

        <!-- 필터 -->
        <form class="filters" id="filtersForm" method="get" action="admin_inquiries.php" autocomplete="off">
            <div class="field">
                <label for="start">시작일</label>
                <input id="start" name="start" type="date" value="<?= h($f['start']) ?>">
            </div>
            <div class="field">
                <label for="end">종료일</label>
                <input id="end" name="end" type="date" value="<?= h($f['end']) ?>">
            </div>

            <?php
            // ✅ 필터 outcome/status 옵션도 역할에 맞게
            $role = $currentAdminRole;

            $allowedOutcomes = allowed_outcomes_for_role($role);
            $allowedStatuses = allowed_statuses_for_role($role);

            // outcome 라벨 맵
            $outcomeOpts = [
                OC_PENDING => '대기',
                OC_REVIEWING => '검토',
                OC_APPROVED => '승인',
                OC_PAID => '출금완료',
                OC_REJECTED => '부결',
            ];

            // status 라벨 맵
            $statusOpts = [
                ST_NEW => '신규',
                ST_CONTACTED => '연락완료',
                ST_PROGRESSING => '대출진행중',
                ST_CLOSED_OK => '정상종결',
                ST_CLOSED_ISSUE => '문제종결',
            ];
            ?>

            <div class="field">
                <label for="outcome">대출결과</label>
                <select id="outcome" name="outcome">
                    <option value="all" <?= $f['outcome'] === 'all' ? 'selected' : '' ?>>전체</option>
                    <?php foreach ($allowedOutcomes as $oc): ?>
                        <option value="<?= h($oc) ?>" <?= $f['outcome'] === $oc ? 'selected' : '' ?>>
                            <?= h($outcomeOpts[$oc] ?? $oc) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="field">
                <label for="status">처리상태</label>
                <select id="status" name="status">
                    <option value="all" <?= $f['status'] === 'all' ? 'selected' : '' ?>>전체</option>
                    <?php foreach ($allowedStatuses as $stt): ?>
                        <option value="<?= h($stt) ?>" <?= $f['status'] === $stt ? 'selected' : '' ?>>
                            <?= h(status_label($stt)) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </div>

            <div class="field">
                <label for="name">이름 검색</label>
                <input id="name" name="name" type="text" value="<?= h($f['name']) ?>" placeholder="예: 홍길동">
            </div>
            <div class="field">
                <label for="memo">요청사항 키워드</label>
                <input id="memo" name="memo" type="text" value="<?= h($f['memo']) ?>" placeholder="요청사항에서 검색">
            </div>
            <div class="field">
                <label for="note">관리자메모 키워드</label>
                <input id="note" name="note" type="text" value="<?= h($f['note']) ?>" placeholder="관리자 메모에서 검색">
            </div>

            <a class="btn primary" id="excelBtn"
                href="admin_inquiries.php?<?= h(http_build_query([
                                                'start' => $f['start'],
                                                'end' => $f['end'],
                                                'status' => $f['status'],
                                                'outcome' => $f['outcome'],
                                                'name' => $f['name'],
                                                'memo' => $f['memo'],
                                                'note' => $f['note'],
                                                'excel' => '1'
                                            ])) ?>">엑셀 다운로드</a>

            <div class="meta">
                <span>표시 건수: <b id="countText"><?= h((string)count($rows)) ?></b> (최대 5000)</span>
                <span class="hint">※ 키워드 입력은 즉시 검색됩니다(페이지 리로드 없음)</span>
            </div>
        </form>

        <!-- 리스트 + 상세 -->
        <div class="layout" id="layoutBox">

            <!-- 좌측 리스트 -->
            <div class="panel">
                <div class="panelHead">
                    <b>리스트</b>
                    <span class="count">최신순</span>
                </div>

                <div class="list" id="listBox">
                    <?php if (!$rows): ?>
                        <div style="padding:14px;color:var(--muted);font-size:12px;">해당 조건에 접수 내역이 없습니다.</div>
                    <?php endif; ?>

                    <?php $seq = 0; ?>
                    <?php foreach ($rows as $r): ?>
                        <?php
                        $seq++;
                        $id = (int)$r['cashhome_1000_id'];
                        $loanNo = trim((string)($r['cashhome_1000_loan_no'] ?? ''));
                        if ($loanNo === '' || $loanNo === '00') {
                            $loanNo = (string)$id;
                        } else {
                            // ✅ 랜덤 접수번호 뒤 4자리만 표시
                            $loanNo = substr($loanNo, -4);
                        }
                        $loanAmt = trim((string)($r['cashhome_1000_loan_amount'] ?? ''));
                        $on = ($id === $selectedId);
                        $pOk = !empty($r['privacy_at']);
                        $mOk = !empty($r['marketing_at']);

                        $st = (string)($r['cashhome_1000_status'] ?? ST_NEW);
                        $oc = normalize_outcome_legacy((string)($r['cashhome_1000_outcome'] ?? OC_PENDING));

                        // ✅ 리스트 outcome 점 색(approved/rejected/pending 스타일만 재사용)
                        $ocClass = ($oc === OC_APPROVED) ? 'approved' : (($oc === OC_REJECTED) ? 'rejected' : 'pending');

                        // ✅ 토큰
                        $docToken = (string)($r['cashhome_1000_doc_token'] ?? '');
                        $docTokenStatus = (int)($r['cashhome_1000_doc_token_status'] ?? 0);
                        $docExpiresAt = (string)($r['cashhome_1000_doc_token_expires_at'] ?? '');

                        // 발급(1)인 경우에만 토큰/TTL/복사 제공
                        $showToken = (trim($docToken) !== '' && $docTokenStatus === 1);

                        // 사용완료(2) 표시
                        $isUsedToken = ($docTokenStatus === 2);

                        $smsBody = $showToken ? build_sms_body($docToken) : '';
                        $copyAlert = $showToken ? build_copy_alert_text($docToken) : '';

                        $docsCount = (int)($r['docs_count'] ?? 0);

                        $phone = (string)($r['cashhome_1000_customer_phone'] ?? '');
                        $tel = phone_digits($phone);
                        ?>
                        <div class="item <?= $on ? 'on' : '' ?>" data-id="<?= h((string)$id) ?>">
                            <div class="row1">
                                <div class="name">
                                    <span class="seqChip"><?= h((string)$seq) ?></span>
                                    <?= h((string)$r['cashhome_1000_customer_name']) ?>

                                    <span class="tokenInfo"
                                        data-token="<?= h($docToken) ?>"
                                        data-token-status="<?= h((string)$docTokenStatus) ?>"
                                        data-expires-at="<?= h($docExpiresAt) ?>"
                                        data-docs-count="<?= h((string)$docsCount) ?>"
                                        data-sms-body="<?= h($smsBody) ?>"
                                        data-copy-alert="<?= h($copyAlert) ?>"
                                        data-loan-amt="<?= h($loanAmt) ?>">

                                        <?php if ($showToken): ?>
                                            <span class="ttl" data-ttl data-token="<?= h($docToken) ?>" data-expires-at="<?= h($docExpiresAt) ?>">token:<?= h($docToken) ?></span>
                                            <span class="ttl" data-ttl></span>

                                            <button
                                                type="button"
                                                class="copyMiniBtn"
                                                data-copy-btn
                                                onclick="event.stopPropagation();"
                                                title="문자에 붙여넣을 문구를 복사">📋 복사</button>

                                        <?php elseif ($isUsedToken): ?>
                                            <span class="usedToken">Token: 사용완료</span>
                                        <?php else: ?>
                                            <span class="noToken">token: 미발급</span>
                                        <?php endif; ?>

                                        <?php if ($docsCount > 0): ?>
                                            <span class="docs count">서류 <span class="n"><?= h((string)$docsCount) ?></span><span class="u">개</span></span>
                                        <?php else: ?>
                                            <span class="docs none">서류없음</span>
                                        <?php endif; ?>
                                        <?php if ($loanAmt !== ''): ?>
                                            <span class="docs" style="border-color:rgba(96,165,250,.22);background:rgba(96,165,250,.08);"><?= h($loanAmt) ?></span>
                                        <?php endif; ?>
                                    </span>
                                </div>
                                <div class="idchip">#<?= h((string)$loanNo) ?></div>
                                <?php if ($loanAmt !== ''): ?>
                                    <div class="loanAmt"><?= h($loanAmt) ?></div>
                                <?php endif; ?>
                            </div>

                            <div class="row2">
                                <span><?= h((string)$r['cashhome_1000_created_at']) ?></span>
                                <span>·</span>
                                <span><?= h($phone) ?></span>
                                <?php if ($tel !== ''): ?>
                                    <a class="callMini" href="tel:<?= h($tel) ?>" onclick="event.stopPropagation();">📞 전화</a>
                                <?php endif; ?>
                            </div>

                            <div class="chips">
                                <span class="badge <?= h($ocClass) ?>"><span class="dot"></span> <?= h(outcome_label($oc)) ?></span>
                                <span class="badge status">상태: <?= h(status_label($st)) ?></span>
                                <span class="badge consent <?= $pOk ? 'ok' : '' ?>">개인정보: <?= $pOk ? '동의함' : '미동의' ?></span>
                                <span class="badge consent <?= $mOk ? 'ok' : '' ?>">마케팅: <?= $mOk ? '동의함' : '미동의' ?></span>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- 우측 상세 -->
            <div class="panel">
                <div class="panelHead">
                    <?php
                    $selectedLoanNoRaw = $selected ? trim((string)($selected['cashhome_1000_loan_no'] ?? '')) : '';
                    $selectedLoanNoDisplay = ($selectedLoanNoRaw !== '' && $selectedLoanNoRaw !== '00') ? substr($selectedLoanNoRaw, -4) : (string)$selectedId;
                    ?>
                    <b>상세 처리 · <span id="detailId">#<?= h((string)$selectedLoanNoDisplay) ?></span></b>
                    <span class="count" id="detailHint"><?= $selected ? '선택된 항목' : '' ?></span>
                </div>

                <div class="detailBody" id="detailBox">
                    <?php if (!$selected): ?>
                        <div style="color:var(--muted);font-size:12px;">선택된 항목이 없습니다.</div>
                    <?php else: ?>
                        <?php
                        $pOk = !empty($selected['privacy_at']);
                        $mOk = !empty($selected['marketing_at']);
                        $phone = (string)$selected['cashhome_1000_customer_phone'];
                        $tel = phone_digits($phone);

                        $oc = normalize_outcome_legacy((string)($selected['cashhome_1000_outcome'] ?? OC_PENDING));
                        $st = (string)($selected['cashhome_1000_status'] ?? ST_NEW);

                        // ✅ 종결 여부(서버에서 내려준 is_closed도 있지만, SSR에선 다시 계산)
                        $isClosed = is_closed_status($st);
                        // ✅ 종결 잠금 규칙
                        // - admin: 종결 시 처리상태/대출결과/토큰발급(및 서류삭제) 잠금
                        // - master: 종결이어도 정상 작동
                        $lockClosedForRole = ($isClosed && ($currentAdminRole === 'admin'));

                        // ✅ 토큰 정보
                        $docToken = (string)($selected['cashhome_1000_doc_token'] ?? '');
                        $docTokenStatus = (int)($selected['cashhome_1000_doc_token_status'] ?? 0);
                        $docIssuedAt = (string)($selected['cashhome_1000_doc_token_issued_at'] ?? '');
                        $docExpiresAt = (string)($selected['cashhome_1000_doc_token_expires_at'] ?? '');
                        $docUsedAt = (string)($selected['cashhome_1000_doc_token_used_at'] ?? '');
                        $docIssuedBy = (int)($selected['cashhome_1000_doc_token_issued_by'] ?? 0);

                        $smsBodyDetail = ($docToken !== '' && $docTokenStatus === 1) ? build_sms_body($docToken) : '';
                        $copyAlertDetail = ($docToken !== '' && $docTokenStatus === 1) ? build_copy_alert_text($docToken) : '';

                        $lastBy = (int)($selected['cashhome_1000_last_modified_by'] ?? 0);
                        $lastAt = (string)($selected['cashhome_1000_last_modified_at'] ?? '');

                        $tokenStatusLabel = match ($docTokenStatus) {
                            1 => '발급',
                            2 => '사용완료',
                            3 => '만료',
                            4 => '폐기',
                            default => '미발급',
                        };

                        // ✅ 상세에서 마지막 저장자 라벨
                        $lastByLabel = $selected['last_modified_by_label'] ?? admin_label_from_db_id($lastBy);
                        ?>
                        <h3 class="detailTitle">접수 정보</h3>

                        <?php if ($isClosed): ?>
                            <div class="err" style="margin-top:0;">
                                <?php if ($lockClosedForRole): ?>
                                    ✅ 종결된 건입니다. (admin) 처리상태/대출결과/토큰발급/서류삭제가 잠금 처리됩니다. 메모 저장은 가능합니다.
                                <?php else: ?>
                                    ✅ 종결된 건입니다. (master) 정상적으로 수정/발급이 가능합니다.
                                <?php endif; ?>
                            </div>
                        <?php endif; ?>

                        <div class="kv">
                            <div class="k">접수일시</div>
                            <div class="v" id="d_created"><?= h((string)$selected['cashhome_1000_created_at']) ?></div>

                            <div class="k">이름</div>
                            <div class="v" id="d_name"><?= h((string)$selected['cashhome_1000_customer_name']) ?></div>

                            <div class="k">연락처</div>
                            <div class="v" id="d_phone">
                                <?= h($phone) ?>
                                <?php if ($tel !== ''): ?>
                                    <div style="margin-top:8px;">
                                        <a class="callBtn" href="tel:<?= h($tel) ?>">📞 전화걸기</a>
                                    </div>
                                <?php endif; ?>
                            </div>

                            <div class="k">희망금액</div>
                            <div class="v" id="d_amount"><?= h((string)($selected['cashhome_1000_loan_amount'] ?? '')) ?></div>

                            <div class="k">자금용도</div>
                            <div class="v" id="d_purpose"><?= h((string)($selected['cashhome_1000_loan_purpose'] ?? '')) ?></div>

                            <div class="k">IP</div>
                            <div class="v" id="d_ip"><?= h((string)($selected['cashhome_1000_user_ip'] ?? '')) ?></div>

                            <div class="k">User-Agent</div>
                            <div class="v" id="d_ua" style="word-break:break-word;"><?= h((string)($selected['cashhome_1000_user_agent'] ?? '')) ?></div>

                            <div class="k">개인정보 동의</div>
                            <div class="v" id="d_privacy">
                                <?= $pOk ? '동의함' : '미동의' ?>
                                <?php if ($pOk): ?>
                                    <span style="color:var(--muted)"> (<?= h((string)($selected['privacy_ver'] ?? '')) ?>)</span>
                                <?php endif; ?>
                            </div>

                            <div class="k">마케팅 동의</div>
                            <div class="v" id="d_marketing"><?= $mOk ? '동의함' : '미동의' ?></div>

                            <div class="k">처리일시</div>
                            <div class="v" id="d_processed"><?= h((string)($selected['cashhome_1000_processed_at'] ?? '')) ?></div>

                            <div class="k">수정일시</div>
                            <div class="v" id="d_updated"><?= h((string)($selected['cashhome_1000_updated_at'] ?? '')) ?></div>
                        </div>

                        <div class="subhr"></div>

                        <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">요청사항</h3>
                        <div class="memoBox" id="d_memo"><?= h((string)($selected['cashhome_1000_request_memo'] ?? '')) ?></div>

                        <div class="subhr"></div>

                        <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">처리 / 메모 / 토큰발급</h3>

                        <div class="tabBar" id="detailTabs" data-closed="<?= $isClosed ? '1' : '0' ?>" data-locked="<?= $lockClosedForRole ? '1' : '0' ?>" data-role="<?= h($currentAdminRole ?? '') ?>">
                            <button type="button" class="tabBtn on" data-tab="tab_process">처리/메모</button>
                            <button type="button" class="tabBtn" data-tab="tab_token">토큰발급</button>
                        </div>

                        <!-- 탭: 처리/메모 -->
                        <div class="tabPane" id="tab_process" data-closed="<?= $isClosed ? '1' : '0' ?>" data-locked="<?= $lockClosedForRole ? '1' : '0' ?>">
                            <div class="formRow">
                                <div class="field">
                                    <label for="edit_status">처리상태</label>
                                    <select id="edit_status" <?= $lockClosedForRole ? 'disabled' : '' ?> data-role="<?= h($currentAdminRole ?? '') ?>">
                                        <?php foreach (allowed_statuses_for_role($currentAdminRole) as $stOpt): ?>
                                            <option value="<?= h($stOpt) ?>" <?= $st === $stOpt ? 'selected' : '' ?>><?= h(status_label($stOpt)) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>

                                <div class="field">
                                    <label for="edit_outcome">대출결과</label>
                                    <select id="edit_outcome" <?= $lockClosedForRole ? 'disabled' : '' ?> data-role="<?= h($currentAdminRole ?? '') ?>">
                                        <?php foreach (allowed_outcomes_for_role($currentAdminRole) as $ocOpt): ?>
                                            <option value="<?= h($ocOpt) ?>" <?= $oc === $ocOpt ? 'selected' : '' ?>><?= h(outcome_label($ocOpt)) ?> (<?= h($ocOpt) ?>)</option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                            </div>
                            <div class="field" style="margin-top:10px; flex: 1 1 320px;">
                                <label for="edit_note">관리자 메모</label>
                                <input id="edit_note" type="text" value="<?= h((string)($selected['cashhome_1000_admin_note'] ?? '')) ?>" placeholder="처리 내용/메모를 입력하세요">
                            </div>

                            <div class="saveBar">
                                    <button class="btn primary" id="saveBtn" type="button">저장</button>
                                    <button class="btn primary" id="reportBtn" type="button">최근 3개월간 통계보기</button>
                                    <button class="btn" id="backToListBtn" type="button">목록</button>

                                    <span class="sideMeta" id="lastSaveMeta">
                                        마지막 저장: <b id="lastSaveBy" data-by="<?= h((string)$lastBy) ?>"><?= h((string)$lastByLabel) ?></b>
                                        · <b id="lastSaveAt"><?= $lastAt !== '' ? h($lastAt) : '—' ?></b>
                                    </span>

                                    <span class="hint" id="saveHint">
                                        <?= $lockClosedForRole ? '※ 종결된 건(admin)은 처리상태/대출결과 변경이 불가합니다. 메모 저장은 가능합니다.' : '※ 변경 후 저장 버튼을 눌러야 DB에 반영됩니다.' ?>
                                    </span>
                                </div>
                        </div>

                        <!-- 탭: 토큰발급 -->
                        <div class="tabPane" id="tab_token" hidden data-closed="<?= $isClosed ? '1' : '0' ?>" data-locked="<?= $lockClosedForRole ? '1' : '0' ?>">
                            <div class="tokenBox">

                                <div class="tokenRow">
                                    <div class="k">현재 상태</div>
                                    <div class="v">
                                        <span class="badge status" id="tokenStatusBadge">토큰: <?= h($tokenStatusLabel) ?></span>
                                        <span class="smallHint" id="tokenStatusHint" style="margin-left:8px;">
                                            <?php if ($docTokenStatus === 1 && $docExpiresAt): ?>
                                                만료: <?= h($docExpiresAt) ?>
                                            <?php elseif ($docTokenStatus === 2 && $docUsedAt): ?>
                                                사용완료: <?= h($docUsedAt) ?>
                                            <?php elseif ($docTokenStatus === 0): ?>
                                                아직 발급되지 않았습니다.
                                            <?php endif; ?>
                                        </span>
                                    </div>
                                </div>

                                <div class="tokenRow">
                                    <div class="k">발급코드</div>
                                    <div class="v">
                                        <span class="tokenCode" id="tokenCodeText"
                                            data-sms-body="<?= h($smsBodyDetail) ?>"
                                            data-copy-alert="<?= h($copyAlertDetail) ?>"><?= $docToken !== '' ? h($docToken) : '—' ?></span>

                                        <button type="button" class="miniBtn" id="copyTokenBtn" <?= ($docToken === '' || $docTokenStatus !== 1 || $lockClosedForRole) ? 'disabled' : '' ?>>
                                            📋 코드 복사
                                        </button>

                                        <div class="smallHint">※ “코드 복사”는 문자에 바로 붙여넣을 문구로 복사됩니다.</div>
                                    </div>
                                </div>

                                <div class="tokenRow">
                                    <div class="k">발급일시</div>
                                    <div class="v" id="tokenIssuedAt"><?= $docIssuedAt !== '' ? h($docIssuedAt) : '—' ?></div>
                                </div>

                                <div class="tokenRow">
                                    <div class="k">만료일시</div>
                                    <div class="v" id="tokenExpiresAt"><?= $docExpiresAt !== '' ? h($docExpiresAt) : '—' ?></div>
                                </div>

                                <div class="tokenRow">
                                    <div class="k">유효시간</div>
                                    <div class="v">
                                        <div class="radioRow" id="expiresHoursRow">
                                            <label class="radioChip"><input type="radio" name="expires_hours" value="24" checked <?= $lockClosedForRole ? 'disabled' : '' ?>> 24시간</label>
                                            <label class="radioChip"><input type="radio" name="expires_hours" value="48" <?= $lockClosedForRole ? 'disabled' : '' ?>> 48시간</label>
                                            <label class="radioChip"><input type="radio" name="expires_hours" value="72" <?= $lockClosedForRole ? 'disabled' : '' ?>> 72시간</label>
                                        </div>
                                        <div class="smallHint">※ 재발급 시 기존 코드는 무효 처리(현재 코드가 새 코드로 덮어써짐)</div>
                                    </div>
                                </div>

                                <div class="tokenActions">
                                    <button class="btn primary" type="button" id="issueTokenBtn" data-inquiry-id="<?= h((string)$selectedId) ?>" <?= $lockClosedForRole ? 'disabled' : '' ?>>토큰 발급하기</button>

                                    <!-- ✅ (신규) 관리자 서류추가 버튼 (토큰 발급 버튼 오른쪽) -->
                                    <a class="btn" id="adminAddDocBtn" href="admin_document_upload.php?inquiry_id=<?= h((string)$selectedId) ?>" <?= $lockClosedForRole ? 'aria-disabled="true" style="pointer-events:none;opacity:.5"' : '' ?>>서류추가</a>

                                    <span class="sideMeta" id="issuedByMeta">
                                        발급자: <b id="issuedByText"><?= $docIssuedBy > 0 ? h(admin_name_by_id($docIssuedBy)) : '—' ?></b>
                                    </span>

                                    <button class="btn" type="button" id="smsTokenBtn"
                                        data-phone="<?= h($phone) ?>"
                                        data-sms-body="<?= h($smsBodyDetail) ?>" <?= $lockClosedForRole ? 'disabled' : '' ?>>문자 전송</button>

                                    <span class="hint" id="issueTokenHint">
                                        <?= $lockClosedForRole ? '※ 종결된 건(admin)은 토큰 발급/문자 전송이 불가합니다.' : '※ 모바일에서 누르면 메시지 앱이 열리며 본문이 자동 입력됩니다.' ?>
                                    </span>
                                </div>

                            </div>
                        </div>

                        <input type="hidden" id="csrf_token" value="<?= h($_SESSION['csrf_token_admin']) ?>">

                        <div class="subhr"></div>
                        <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">서류</h3>

                        <div class="docsWrap" id="docsWrap" data-closed="<?= $isClosed ? '1' : '0' ?>">
                            <?php if (empty($docsSelected)): ?>
                                <div style="color:var(--muted);font-size:12px;">등록된 서류가 없습니다.</div>
                            <?php else: ?>
                                <?php foreach ($docsSelected as $dtype => $items): ?>
                                    <div class="docGroup">
                                        <div class="docGroupHead">
                                            <b><?= h(doc_type_label((string)$dtype)) ?></b>
                                            <span class="hint">총 <?= h((string)count($items)) ?>개</span>
                                        </div>

                                        <div class="docGrid">
                                            <?php foreach ($items as $d): ?>
                                                <?php
                                                $docId = (int)$d['cashhome_1200_id'];
                                                $fn = (string)($d['cashhome_1200_original_name'] ?? '');
                                                if ($fn === '') $fn = 'image_' . $docId;
                                                $imgUrl = 'document_view.php?id=' . $docId;
                                                ?>
                                                <div class="docItem" data-doc-id="<?= h((string)$docId) ?>" data-doc-url="<?= h($imgUrl) ?>" data-doc-name="<?= h($fn) ?>">
                                                    <!-- ✅ 이미지 클릭해도 크게보기(모달은 script에서) -->
                                                    <button type="button" class="thumbBtn" data-doc-open>
                                                        <img class="thumb" src="<?= h($imgUrl) ?>" alt="<?= h($fn) ?>" loading="lazy" />
                                                    </button>

                                                    <div class="docMeta">
                                                        <div class="fn"><?= h($fn) ?></div>
                                                        <div><?= h((string)($d['cashhome_1200_created_at'] ?? '')) ?></div>

                                                        <div class="docBtns">
                                                            <!-- ✅ 크게보기 버튼 -->
                                                            <button type="button" class="miniBtn" data-doc-open>🔍 크게보기</button>

                                                            <!-- (선택) 원본 새창 -->
                                                            <a class="miniBtn" href="<?= h($imgUrl) ?>" target="_blank" rel="noopener">↗ 새창</a>

                                                            <!-- ✅ 종결이면 삭제 버튼을 HTML에서 숨기고, 서버에서도 막음(PHP파트에서) -->
                                                            <button type="button" class="miniBtn" data-doc-delete <?= $lockClosedForRole ? 'disabled' : '' ?> data-doc-id="<?= h((string)$docId) ?>">🗑 삭제</button>
                                                        </div>
                                                    </div>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>

                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- 통계(그래프/요약) -->
        <div class="statsGrid" id="statsGrid">
            <div class="statCard">
                <div class="statTitle">
                    <b>요약</b>
                    <span class="hint">조회기간: <span id="rangeText"><?= h($f['start']) ?> ~ <?= h($f['end']) ?></span></span>
                </div>
                <div class="statNums" id="statNums">
                    <span class="pill pending">대기 <span id="statPending"><?= h((string)($stats['pending'] ?? 0)) ?></span></span>
                    <span class="pill approved">승인 <span id="statApproved"><?= h((string)($stats['approved'] ?? 0)) ?></span></span>
                    <span class="pill rejected">부결 <span id="statRejected"><?= h((string)($stats['rejected'] ?? 0)) ?></span></span>
                    <span class="pill rate">승인율 <span id="statRate"><?= h((string)($stats['rate'] ?? 0)) ?>%</span></span>
                </div>
            </div>

            <div class="statCard">
                <div class="statTitle">
                    <b>기간별 접수</b><span class="hint">일자 기준</span>
                </div>
                <div class="chartWrap">
                    <canvas id="chartAll"></canvas>
                </div>
            </div>

            <div class="statCard">
                <div class="statTitle">
                    <b>기간별 승인</b><span class="hint">일자 기준</span>
                </div>
                <div class="chartWrap">
                    <canvas id="chartApproved"></canvas>
                </div>
            </div>
        </div>
    </div>

    <!-- ✅ 서류 크게보기 모달(다음/이전/닫기) -->
    <div class="modal" id="docModal" aria-hidden="true">
        <div class="modalBox" role="dialog" aria-modal="true" aria-label="서류 크게보기">
            <div class="modalHead">
                <b id="docModalTitle">서류 크게보기</b>
                <div class="modalBtns">
                    <button type="button" class="btn" id="docModalClose">닫기 ✕</button>
                </div>
            </div>

            <div class="modalBody">
                <img id="docModalImg" class="modalImg" src="" alt="">
                <div class="modalMeta" id="docModalMeta"></div>
            </div>

            <div class="modalFoot">
                <div class="modalBtns">
                    <button type="button" class="btn" id="docModalPrev">◀ 이전</button>
                    <button type="button" class="btn" id="docModalNext">다음 ▶</button>
                </div>
                <div class="modalMeta" id="docModalIndex">0 / 0</div>
            </div>
        </div>
    </div>

    <script>
        (function() {
            const $ = (sel) => document.querySelector(sel);

            const elStart = $("#start");
            const elEnd = $("#end");
            const elStatus = $("#status");
            const elOutcome = $("#outcome");
            const elName = $("#name");
            const elMemo = $("#memo");
            const elNote = $("#note");

            const listBox = $("#listBox");
            const countText = $("#countText");

            const topPills = $("#topPills");
            const statusPills = $("#statusPills");

            const statPending = $("#statPending");
            const statApproved = $("#statApproved");
            const statRejected = $("#statRejected");
            const statRate = $("#statRate");
            const rangeText = $("#rangeText");

            const excelBtn = $("#excelBtn");

            let selectedId = Number(<?php echo (int)$selectedId ?> || 0);

            let chartAll = null;
            let chartApproved = null;

            // 상세 탭
            let currentDetailTab = "tab_process";

            // 5시간 미만 기준(초)
            const SOON_SECONDS = 5 * 3600;

            // 모바일 모드
            const layoutBox = document.getElementById("layoutBox");
            const statsGrid = document.getElementById("statsGrid");
            const filtersForm = document.getElementById("filtersForm");

            function isMobile() {
                return window.matchMedia && window.matchMedia("(max-width: 1100px)").matches;
            }

            function setMobileMode(mode) {
                // mode: 'list' | 'detail'
                if (!isMobile()) return;

                const panels = layoutBox ? layoutBox.querySelectorAll(".panel") : [];
                const listPanel = panels[0] || null;
                const detailPanel = panels[1] || null;
                if (!listPanel || !detailPanel) return;

                if (mode === "detail") {
                    if (filtersForm) filtersForm.style.display = "none";
                    if (statsGrid) statsGrid.style.display = "none";
                    if (listPanel) listPanel.style.display = "none";
                    detailPanel.style.display = "flex";

                    const hint = document.getElementById("detailHint");
                    if (hint) hint.textContent = "목록으로 돌아가려면 상단 “상세 처리”를 누르세요";
                } else {
                    if (filtersForm) filtersForm.style.display = "";
                    if (statsGrid) statsGrid.style.display = "";
                    if (listPanel) listPanel.style.display = "flex";
                    if (detailPanel) detailPanel.style.display = "none";

                    const hint = document.getElementById("detailHint");
                    if (hint) hint.textContent = "";
                }
            }

            function autoListHeight() {
                const list = document.querySelector("#listBox");
                if (!list) return;
                const rect = list.getBoundingClientRect();
                const bottomGap = 18;
                const available = window.innerHeight - rect.top - bottomGap;
                const minH = 260;
                list.style.maxHeight = Math.max(minH, Math.floor(available)) + "px";
            }

            window.addEventListener("load", autoListHeight);
            window.addEventListener("resize", () => {
                autoListHeight();
                if (isMobile()) {
                    const panels = layoutBox ? layoutBox.querySelectorAll(".panel") : [];
                    const detailPanel = panels[1] || null;
                    if (detailPanel && detailPanel.style.display !== "none" && detailPanel.style.display !== "") {
                        setMobileMode("detail");
                    } else {
                        setMobileMode("list");
                    }
                }
            });

            // ====== Role 기반 옵션/라벨 ======

            // 처리상태 값(서버 PHP와 동일하게 맞추는 것이 베스트)
            const ST = {
                NEW: "new",
                CONTACTED: "contacted",
                PROGRESSING: "progressing", // 대출진행중
                CLOSED_OK: "closed_ok", // 정상종결
                CLOSED_ISSUE: "closed_issue" // 문제종결
            };

            // 대출결과 값(요구사항: 1~5)
            const OC = {
                PENDING: "1", // 대기
                REVIEW: "2", // 검토
                APPROVED: "3", // 승인 (master만)
                PAID: "4", // 출금완료
                REJECTED: "5" // 부결
            };

            function allowedOutcomesForRole(role) {
                const r = String(role || "").toLowerCase().trim();
                if (r === "master") return [OC.PENDING, OC.REVIEW, OC.APPROVED, OC.PAID, OC.REJECTED];
                // admin
                return [OC.PENDING, OC.REVIEW, OC.PAID, OC.REJECTED];
            }

            function allowedStatusesForRole(role) {
                const r = String(role || "").toLowerCase().trim();
                if (r === "master") return [ST.NEW, ST.CONTACTED, ST.PROGRESSING, ST.CLOSED_OK, ST.CLOSED_ISSUE];
                // admin
                return [ST.NEW, ST.CONTACTED, ST.PROGRESSING];
            }

            function isClosedStatus(st) {
                const v = String(st || "").toLowerCase().trim();
                // 혹시 레거시 값이 들어올 수 있어 넓게 허용
                return v === ST.CLOSED_OK || v === ST.CLOSED_ISSUE || v === "closed" || v === "closedok" || v === "closedissue";
            }

            function statusLabel(st) {
                const v = String(st || "").toLowerCase().trim();
                if (v === ST.NEW) return "신규";
                if (v === ST.CONTACTED) return "연락완료";
                if (v === ST.PROGRESSING) return "대출진행중";
                if (v === ST.CLOSED_OK) return "정상종결";
                if (v === ST.CLOSED_ISSUE) return "문제종결";
                // fallback
                return st || "";
            }

            function outcomeLabel(oc) {
                const v = String(oc || "").trim();
                if (v === OC.PENDING) return "대기";
                if (v === OC.REVIEW) return "검토";
                if (v === OC.APPROVED) return "승인";
                if (v === OC.PAID) return "출금완료";
                if (v === OC.REJECTED) return "부결";
                // 레거시 호환
                if (v === "pending") return "대기";
                if (v === "approved") return "승인";
                if (v === "rejected") return "부결";
                return oc || "";
            }

            // 리스트 dot 색 클래스(기존 스타일 재사용: approved/rejected/pending)
            function outcomeClass(oc) {
                const v = String(oc || "").trim();
                if (v === OC.APPROVED || v === "approved") return "approved";
                if (v === OC.REJECTED || v === "rejected") return "rejected";
                return "pending";
            }

            // ====== 공통 유틸 ======

            function escapeHtml(s) {
                return String(s ?? "")
                    .replaceAll("&", "&amp;")
                    .replaceAll("<", "&lt;")
                    .replaceAll(">", "&gt;")
                    .replaceAll('"', "&quot;")
                    .replaceAll("'", "&#039;");
            }

            function parseMysqlDatetime(s) {
                const str = String(s || "").trim();
                if (!str) return null;
                const iso = str.replace(" ", "T");
                const d = new Date(iso);
                if (isNaN(d.getTime())) return null;
                return d;
            }

            function formatRemain(seconds) {
                const s = Math.max(0, Math.floor(seconds));
                const h = Math.floor(s / 3600);
                const m = Math.floor((s % 3600) / 60);
                if (h <= 0) return `${m}분`;
                return `${h}시간 ${m}분`;
            }

            async function copyTextToClipboard(text) {
                try {
                    if (navigator.clipboard && window.isSecureContext) {
                        await navigator.clipboard.writeText(text);
                        return true;
                    }
                } catch (e) {}

                try {
                    const ta = document.createElement("textarea");
                    ta.value = text;
                    ta.style.position = "fixed";
                    ta.style.left = "-9999px";
                    ta.style.top = "-9999px";
                    document.body.appendChild(ta);
                    ta.focus();
                    ta.select();
                    const ok = document.execCommand("copy");
                    document.body.removeChild(ta);
                    return !!ok;
                } catch (e) {
                    return false;
                }
            }

            function getSmsBodyFromEl(el) {
                if (!el) return "";
                const v = el.dataset && el.dataset.smsBody ? String(el.dataset.smsBody) : "";
                return v.trim();
            }

            function getCopyAlertFromEl(el) {
                if (!el) return "";
                const v = el.dataset && el.dataset.copyAlert ? String(el.dataset.copyAlert) : "";
                return v.trim();
            }

            function openSmsApp(phone, body) {
                const p = String(phone || "").trim();
                const b = String(body || "").trim();
                if (!b) return false;

                const ua = navigator.userAgent || "";
                const isIOS = /iP(hone|ad|od)/.test(ua);

                const encoded = encodeURIComponent(b);
                const to = p ? p.replace(/[^\d+]/g, "") : "";
                const base = to ? `sms:${to}` : `sms:`;
                const link = isIOS ? `${base}&body=${encoded}` : `${base}?body=${encoded}`;

                try {
                    window.location.href = link;
                    return true;
                } catch (e) {
                    return false;
                }
            }

            function buildQuery(extra = {}) {
                const q = new URLSearchParams();

                q.set("start", elStart.value);
                q.set("end", elEnd.value);
                q.set("status", elStatus.value);
                q.set("outcome", elOutcome.value);
                q.set("name", elName.value.trim());
                q.set("memo", elMemo.value.trim());
                q.set("note", elNote.value.trim());
                if (selectedId > 0) q.set("id", String(selectedId));
                Object.entries(extra).forEach(([k, v]) => q.set(k, String(v)));
                return q.toString();
            }

            function updateExcelLink() {
                if (!excelBtn) return;
                const q = buildQuery({
                    excel: 1
                });
                excelBtn.setAttribute("href", "admin_inquiries.php?" + q);
            }

            // ====== 토큰 TTL 표시(발급 상태만) ======

            function applyTokenTTLToList() {
                const now = Date.now();

                document.querySelectorAll(".tokenInfo").forEach((wrap) => {
                    const status = Number(wrap.dataset.tokenStatus || 0);
                    const expiresAt = (wrap.dataset.expiresAt || "").trim();

                    // 발급(1)만 TTL 표시
                    if (status !== 1 || !expiresAt) return;

                    const d = parseMysqlDatetime(expiresAt);
                    if (!d) return;

                    const diffSec = Math.floor((d.getTime() - now) / 1000);
                    const ttlEls = wrap.querySelectorAll("[data-ttl]");
                    if (!ttlEls || ttlEls.length === 0) return;

                    // 두 번째 ttl에 남은시간
                    const ttlEl = ttlEls.length > 1 ? ttlEls[1] : ttlEls[0];

                    if (diffSec <= 0) {
                        ttlEl.textContent = "만료";
                        ttlEl.classList.add("soon");
                        return;
                    }

                    ttlEl.textContent = formatRemain(diffSec);
                    if (diffSec < SOON_SECONDS) ttlEl.classList.add("soon");
                    else ttlEl.classList.remove("soon");
                });
            }

            // ====== 헤더 pills ======

            function renderTopPills(stats) {
                const p = Number(stats.pending ?? 0);
                const rv = Number(stats.reviewing ?? 0);
                const a = Number(stats.approved ?? 0);
                const paid = Number(stats.paid ?? 0);
                const r = Number(stats.rejected ?? 0);
                const rate = String(stats.rate ?? 0);
                const soon = Number(stats.token_soon ?? 0);

                if (!topPills) return;
                topPills.innerHTML = `
            <span class="topPill pending">대기 ${p}건</span>
            <span class="topPill reviewing">검토 ${rv}건</span>
            <span class="topPill approved">승인 ${a}건</span>
            <span class="topPill paid">출금완료 ${paid}건</span>
            <span class="topPill rejected">부결 ${r}건</span>
            <span class="topPill rate">승인율 ${escapeHtml(rate)}%</span>
            <span class="topPill soon"><span class="badgeDot"></span> 토큰임박 ${soon}건</span>
        `;
            }

            function renderStatusPills(stats) {
                const bs = stats.by_status || {};
                const n = Number(bs.new ?? 0);
                const c = Number(bs.contacted ?? 0);
                const pr = Number(bs.progressing ?? 0);
                const ok = Number(bs.closed_ok ?? 0);
                const issue = Number(bs.closed_issue ?? 0);

                const el = statusPills || document.getElementById("statusPills");
                if (!el) return;

                el.innerHTML = `
            <span class="statusPill st-new">신규 ${n}</span>
            <span class="statusPill st-contacted">연락완료 ${c}</span>
            <span class="statusPill st-progressing">대출진행중 ${pr}</span>
            <span class="statusPill st-ok">정상종결 ${ok}</span>
            <span class="statusPill st-issue">문제종결 ${issue}</span>
        `;
            }

            // ====== 리스트 토큰 복사 버튼 ======

            function bindListCopyButtons(scope) {
                const root = scope || document;
                root.querySelectorAll("[data-copy-btn]").forEach((btn) => {
                    if (btn.dataset.bound === "1") return;
                    btn.dataset.bound = "1";

                    btn.addEventListener("click", async (e) => {
                        e.preventDefault();
                        e.stopPropagation();

                        const tokenInfo = btn.closest(".tokenInfo");
                        if (!tokenInfo) return;

                        const smsBody = getSmsBodyFromEl(tokenInfo);
                        const alertMsg = getCopyAlertFromEl(tokenInfo);

                        if (!smsBody) {
                            alert("토큰이 없습니다.");
                            return;
                        }

                        const ok = await copyTextToClipboard(smsBody);
                        alert(ok ? (alertMsg || "복사되었습니다.") : "복사에 실패했습니다.");
                    });
                });
            }

            // ====== 리스트 렌더 ======

            function renderList(rows) {
                listBox.innerHTML = "";

                if (!rows || rows.length === 0) {
                    const div = document.createElement("div");
                    div.style.padding = "14px";
                    div.style.color = "var(--muted)";
                    div.style.fontSize = "12px";
                    div.textContent = "해당 조건에 접수 내역이 없습니다.";
                    listBox.appendChild(div);
                    autoListHeight();
                    return;
                }

                rows.forEach((r, idx) => {
                    const on = r.id === selectedId;

                    const st = String(r.status || ST.NEW);
                    const oc = String(r.outcome || OC.PENDING);

                    const token = String(r.doc_token || "").trim();
                    const tokenStatus = Number(r.doc_token_status || 0);
                    const expiresAt = String(r.doc_token_expires_at || "").trim();

                    const showToken = token && tokenStatus === 1;
                    const usedToken = tokenStatus === 2;

                    const docsCount = Number(r.docs_count || 0);

                    // ✅✅✅ (추가) 희망금액 문자열 확보
                    const loanAmt = String(r.loan_amount ?? "").trim();

                    // ✅✅✅ 희망금액 뱃지(loanAmt)는 서류 유무와 상관없이 표시
                    const loanAmtHtml =
                        (loanAmt !== "") ?
                        `<span class="docs" style="border-color:rgba(96,165,250,.22);background:rgba(96,165,250,.08);">${escapeHtml(loanAmt)}</span>` :
                        "";

                    const docsHtml =
                        (docsCount > 0 ?
                        `<span class="docs count">서류 <span class="n">${docsCount}</span><span class="u">개</span></span>` :
                        `<span class="docs none">서류없음</span>`) + loanAmtHtml;

                    const seq = Number(r.seq || idx + 1);
                    const phone = String(r.phone || "");
                    const tel = (phone.match(/\d+/g) || []).join("");

                    const smsBody = showToken ?
                        (r.sms_body || `[인증번호]:${token}복사되었습니다. 서류제출하기 버튼을 누르신후 인증번호를 입력후 서류를 등록해주세요.`) :
                        "";
                    const copyAlert = showToken ? (r.copy_alert || `[인증번호]:${token} 이 복사되었습니다.`) : "";

                    const item = document.createElement("div");
                    item.className = "item" + (on ? " on" : "");
                    item.dataset.id = String(r.id);

                    // 주의: r.loan_no 가 undefined일 수 있으니 안전 처리
                    if (typeof r.loan_no === "string" && r.loan_no.includes("-")) {
                        r.loan_no = r.loan_no.split("-")[1];
                    }

                    item.innerHTML = `
                <div class="row1">
                    <div class="name">
                        <span class="seqChip">${seq}</span>
                        ${escapeHtml(r.name || "")}

                        <span class="tokenInfo"
                            data-token="${escapeHtml(token)}"
                            data-token-status="${tokenStatus}"
                            data-expires-at="${escapeHtml(expiresAt)}"
                            data-docs-count="${docsCount}"
                            data-loan-amt="${escapeHtml(loanAmt)}"
                            data-sms-body="${escapeHtml(smsBody)}"
                            data-copy-alert="${escapeHtml(copyAlert)}"
                        >
                            ${
                                showToken
                                    ? `<span class="ttl" data-ttl>token:${escapeHtml(token)}</span>
                                       <span class="ttl" data-ttl></span>
                                       <button type="button" class="copyMiniBtn" data-copy-btn onclick="event.stopPropagation();" title="문자에 붙여넣을 문구를 복사">📋 복사</button>`
                                    : usedToken
                                    ? `<span class="usedToken">Token: 사용완료</span>`
                                    : `<span class="noToken">token: 미발급</span>`
                            }
                            ${docsHtml}
                        </span>
                    </div>
                    <div class="idchip">#${escapeHtml(r.loan_no || "")}</div>
                    <div class="loanAmt">${escapeHtml(loanAmt)}</div>
                </div>

                <div class="row2">
                    <span>${escapeHtml(r.created_at || "")}</span>
                    <span>·</span>
                    <span>${escapeHtml(phone || "")}</span>
                    ${tel ? `<a class="callMini" href="tel:${escapeHtml(tel)}" onclick="event.stopPropagation();">📞 전화</a>` : ``}
                </div>

                <div class="chips">
                    <span class="badge ${outcomeClass(oc)}"><span class="dot"></span> ${escapeHtml(outcomeLabel(oc))}</span>
                    <span class="badge status">상태: ${escapeHtml(statusLabel(st))}</span>
                    <span class="badge consent ${r.privacy_ok ? "ok" : ""}">개인정보: ${r.privacy_ok ? "동의함" : "미동의"}</span>
                    <span class="badge consent ${r.marketing_ok ? "ok" : ""}">마케팅: ${r.marketing_ok ? "동의함" : "미동의"}</span>
                </div>
            `;

                    item.addEventListener("click", () => {
                        selectedId = r.id;
                        document.querySelectorAll(".item").forEach((x) => x.classList.remove("on"));
                        item.classList.add("on");

                        const q = buildQuery({
                            ajax: 0
                        });
                        history.replaceState(null, "", "admin_inquiries.php?" + q);

                        if (isMobile()) setMobileMode("detail");
                        refresh(true);
                    });

                    listBox.appendChild(item);
                });

                applyTokenTTLToList();
                bindListCopyButtons(listBox);
                autoListHeight();
            }

            // ====== 차트/통계 ======

            function renderStats(stats) {
                if (statPending) statPending.textContent = String(stats.pending ?? 0);
                if (statApproved) statApproved.textContent = String(stats.approved ?? 0);
                if (statRejected) statRejected.textContent = String(stats.rejected ?? 0);
                if (statRate) statRate.textContent = String(stats.rate ?? 0) + "%";

                const labels = stats.labels || [];
                const allSeries = stats.series_all || [];
                const apprSeries = stats.series_approved || [];

                if (chartAll) chartAll.destroy();
                if (chartApproved) chartApproved.destroy();

                const c1 = document.getElementById("chartAll");
                const c2 = document.getElementById("chartApproved");
                if (!c1 || !c2) return;

                chartAll = new Chart(c1, {
                    type: "line",
                    data: {
                        labels,
                        datasets: [{
                            label: "접수건수",
                            data: allSeries,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false
                    },
                });

                chartApproved = new Chart(c2, {
                    type: "line",
                    data: {
                        labels,
                        datasets: [{
                            label: "승인건수",
                            data: apprSeries,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false
                    },
                });
            }

            // ====== Docs Modal (다음/이전/닫기) ======

            const docModal = document.getElementById("docModal");
            const docModalImg = document.getElementById("docModalImg");
            const docModalTitle = document.getElementById("docModalTitle");
            const docModalMeta = document.getElementById("docModalMeta");
            const docModalIndex = document.getElementById("docModalIndex");
            const docModalPrev = document.getElementById("docModalPrev");
            const docModalNext = document.getElementById("docModalNext");
            const docModalClose = document.getElementById("docModalClose");

            let docItemsFlat = [];
            let docIndex = 0;

            function collectDocItems(root) {
                const items = [];
                (root || document).querySelectorAll(".docItem").forEach((it) => {
                    const url = it.dataset.docUrl || "";
                    const name = it.dataset.docName || "";
                    const id = Number(it.dataset.docId || 0);
                    if (!url || !id) return;
                    items.push({
                        id,
                        url,
                        name
                    });
                });
                return items;
            }

            function openDocModalAt(index) {
                if (!docModal || !docModalImg) return;
                if (!docItemsFlat || docItemsFlat.length === 0) return;

                docIndex = Math.max(0, Math.min(index, docItemsFlat.length - 1));
                const cur = docItemsFlat[docIndex];

                docModalImg.src = cur.url;
                docModalImg.alt = cur.name || "document";
                if (docModalTitle) docModalTitle.textContent = "서류 크게보기";
                if (docModalMeta) docModalMeta.textContent = `${cur.name || ""} (doc_id: ${cur.id})`;
                if (docModalIndex) docModalIndex.textContent = `${docIndex + 1} / ${docItemsFlat.length}`;

                docModal.classList.add("on");
                docModal.setAttribute("aria-hidden", "false");
            }

            function closeDocModal() {
                if (!docModal) return;
                docModal.classList.remove("on");
                docModal.setAttribute("aria-hidden", "true");
                if (docModalImg) docModalImg.src = "";
            }

            function bindDocModal(root) {
                const r = root || document;
                docItemsFlat = collectDocItems(r);

                r.querySelectorAll("[data-doc-open]").forEach((btn) => {
                    if (btn.dataset.bound === "1") return;
                    btn.dataset.bound = "1";
                    btn.addEventListener("click", (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        const item = btn.closest(".docItem");
                        if (!item) return;
                        const id = Number(item.dataset.docId || 0);
                        const idx = docItemsFlat.findIndex((x) => x.id === id);
                        if (idx >= 0) openDocModalAt(idx);
                    });
                });

                if (docModalClose && docModalClose.dataset.bound !== "1") {
                    docModalClose.dataset.bound = "1";
                    docModalClose.addEventListener("click", (e) => {
                        e.preventDefault();
                        closeDocModal();
                    });
                }
                if (docModal && docModal.dataset.bound !== "1") {
                    docModal.dataset.bound = "1";

                    // 배경 클릭 닫기
                    docModal.addEventListener("click", (e) => {
                        if (e.target === docModal) closeDocModal();
                    });

                    // ESC 닫기 / 좌우 이동
                    window.addEventListener("keydown", (e) => {
                        if (!docModal.classList.contains("on")) return;
                        if (e.key === "Escape") closeDocModal();
                        if (e.key === "ArrowLeft") openDocModalAt(docIndex - 1);
                        if (e.key === "ArrowRight") openDocModalAt(docIndex + 1);
                    });
                }

                if (docModalPrev && docModalPrev.dataset.bound !== "1") {
                    docModalPrev.dataset.bound = "1";
                    docModalPrev.addEventListener("click", (e) => {
                        e.preventDefault();
                        openDocModalAt(docIndex - 1);
                    });
                }
                if (docModalNext && docModalNext.dataset.bound !== "1") {
                    docModalNext.dataset.bound = "1";
                    docModalNext.addEventListener("click", (e) => {
                        e.preventDefault();
                        openDocModalAt(docIndex + 1);
                    });
                }
            }

            // ====== 탭/잠금 처리 ======

            function setDetailLock(root, isClosed, role) {
                const r = root || document;
                const disabled = (!!isClosed && String(role || "").toLowerCase() === "admin");

                // 처리/메모
                const s1 = r.querySelector("#edit_status");
                const s2 = r.querySelector("#edit_outcome");
                if (s1) s1.disabled = disabled;
                if (s2) s2.disabled = disabled;

                // 토큰탭 버튼/영역
                // 토큰탭은 조회는 가능(버튼 비활성화 하지 않음)

                const issueBtn = r.querySelector("#issueTokenBtn");
                const copyBtn = r.querySelector("#copyTokenBtn");
                const smsBtn = r.querySelector("#smsTokenBtn");
                r.querySelectorAll('input[name="expires_hours"]').forEach((x) => (x.disabled = disabled));

                if (issueBtn) issueBtn.disabled = disabled;
                if (copyBtn) copyBtn.disabled = disabled || copyBtn.disabled;
                if (smsBtn) smsBtn.disabled = disabled;

                // 서류 삭제 버튼
                r.querySelectorAll("[data-doc-delete]").forEach((x) => {
                    x.disabled = disabled;
                });

                const hint = r.querySelector("#saveHint");
                if (hint) hint.textContent = disabled ? "※ 종결된 건(admin)은 처리상태/대출결과 변경이 불가합니다. 메모 저장은 가능합니다." : "※ 변경 후 저장 버튼을 눌러야 DB에 반영됩니다.";
            }

            function bindDetailTabs(scopeEl) {
                const root = scopeEl || document;
                const tabBar = root.querySelector("#detailTabs");
                if (!tabBar) return;

                const btns = tabBar.querySelectorAll(".tabBtn");
                const paneProcess = root.querySelector("#tab_process");
                const paneToken = root.querySelector("#tab_token");

                function apply(tabId) {
                    currentDetailTab = tabId;

                    btns.forEach((b) => b.classList.remove("on"));
                    const onBtn = Array.from(btns).find((b) => (b.dataset.tab || "") === tabId);
                    if (onBtn) onBtn.classList.add("on");

                    if (paneProcess && paneToken) {
                        if (tabId === "tab_token") {
                            paneProcess.hidden = true;
                            paneToken.hidden = false;
                        } else {
                            paneProcess.hidden = false;
                            paneToken.hidden = true;
                        }
                    }
                }

                btns.forEach((btn) => {
                    if (btn.dataset.bound === "1") return;
                    btn.dataset.bound = "1";
                    btn.addEventListener("click", (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        if (btn.disabled) return;
                        apply(btn.dataset.tab || "tab_process");
                    });
                });

                apply(currentDetailTab || "tab_process");
            }

            // 상태를 종결로 바꾸면 즉시 잠금
            function bindCloseChangeLock(root) {
                const r = root || document;
                const stSel = r.querySelector("#edit_status");
                if (!stSel) return;
                if (stSel.dataset.boundCloseLock === "1") return;
                stSel.dataset.boundCloseLock = "1";

                stSel.addEventListener("change", () => {
                    const closed = isClosedStatus(stSel.value);
                    setDetailLock(r, closed, adminRole);

                    // 종결이면 토큰탭 열려있으면 처리/메모로 강제
                    if (closed && String(adminRole).toLowerCase() === "admin" && currentDetailTab === "tab_token") {
                        currentDetailTab = "tab_process";
                        bindDetailTabs(r);
                    }
                });
            }

            // ====== API ======

            async function issueToken(inquiryId, expiresHours) {
                const csrf = document.getElementById("csrf_token")?.value || "";
                const fd = new FormData();
                fd.append("action", "issue_token");
                fd.append("csrf_token", csrf);
                fd.append("id", String(inquiryId));
                fd.append("expires_hours", String(expiresHours));

                const res = await fetch("admin_inquiries.php", {
                    method: "POST",
                    body: fd,
                    credentials: "same-origin",
                });
                return await res.json();
            }

            async function saveInquiry(payload) {
                const res = await fetch("admin_inquiries.php", {
                    method: "POST",
                    body: payload,
                    credentials: "same-origin",
                });
                return await res.json();
            }

            async function deleteDoc(docId) {
                const csrf = document.getElementById("csrf_token")?.value || "";
                const fd = new FormData();
                fd.append("action", "delete_doc");
                fd.append("csrf_token", csrf);
                fd.append("doc_id", String(docId));

                const res = await fetch("admin_inquiries.php", {
                    method: "POST",
                    body: fd,
                    credentials: "same-origin",
                });
                return await res.json();
            }

            // ====== 토큰 영역 바인딩 ======

            function bindTokenActions(scopeEl, sel) {
                const root = scopeEl || document;

                const isClosed = isClosedStatus(root.querySelector("#edit_status")?.value || "");

                const copyBtn = root.querySelector("#copyTokenBtn");
                const tokenTextEl = root.querySelector("#tokenCodeText");

                if (copyBtn && tokenTextEl) {
                    if (copyBtn.dataset.bound !== "1") {
                        copyBtn.dataset.bound = "1";
                        copyBtn.addEventListener("click", async (e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            if (copyBtn.disabled) return;

                            const code = (tokenTextEl.textContent || "").trim();
                            if (!code || code === "—") return;

                            const smsBody =
                                getSmsBodyFromEl(tokenTextEl) ||
                                `[인증번호]:${code}복사되었습니다. 서류제출하기 버튼을 누르신후 인증번호를 입력후 서류를 등록해주세요.`;
                            const alertMsg = getCopyAlertFromEl(tokenTextEl) || `[인증번호]:${code} 이 복사되었습니다.`;

                            const ok = await copyTextToClipboard(smsBody);
                            alert(ok ? alertMsg : "복사에 실패했습니다.");
                        });
                    }
                }

                const smsBtn = root.querySelector("#smsTokenBtn");
                if (smsBtn) {
                    if (smsBtn.dataset.bound !== "1") {
                        smsBtn.dataset.bound = "1";
                        smsBtn.addEventListener("click", async (e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            if (smsBtn.disabled) return;

                            const phone = (smsBtn.dataset.phone || "").trim();
                            const body = (smsBtn.dataset.smsBody || "").trim();

                            if (!body) {
                                const code = (root.querySelector("#tokenCodeText")?.textContent || "").trim();
                                if (!code || code === "—") {
                                    alert("먼저 토큰을 발급해주세요.");
                                    return;
                                }
                                const body2 = `[인증번호]:${code}복사되었습니다. 서류제출하기 버튼을 누르신후 인증번호를 입력후 서류를 등록해주세요.`;
                                openSmsApp(phone, body2);
                                return;
                            }

                            const opened = openSmsApp(phone, body);
                            if (!opened) {
                                const ok = await copyTextToClipboard(body);
                                alert(ok ? "문자 내용이 복사되었습니다. 문자에 붙여넣어 전송하세요." : "문자 내용 복사에 실패했습니다.");
                            }
                        });
                    }
                }

                const issueBtn = root.querySelector("#issueTokenBtn");
                if (issueBtn) {
                    if (issueBtn.dataset.bound !== "1") {
                        issueBtn.dataset.bound = "1";
                        issueBtn.addEventListener("click", async (e) => {
                            e.preventDefault();
                            e.stopPropagation();

                            if (issueBtn.disabled) return;
                            if (isClosed && role === "admin") {
                                alert("종결된 건(admin)은 토큰 발급이 불가합니다.");
                                return;
                            }

                            const inquiryId = Number(issueBtn.dataset.inquiryId || (sel?.cashhome_1000_id || 0));
                            if (!inquiryId) {
                                alert("선택된 항목이 없습니다.");
                                return;
                            }

                            const checked = root.querySelector('input[name="expires_hours"]:checked');
                            const expiresHours = Number(checked?.value || 24);

                            if (!confirm(`토큰을 발급할까요? (유효시간 ${expiresHours}시간)\n재발급 시 기존 코드는 무효화됩니다.`)) return;

                            try {
                                currentDetailTab = "tab_token";

                                issueBtn.disabled = true;
                                issueBtn.textContent = "발급중...";

                                const data = await issueToken(inquiryId, expiresHours);
                                if (!data.ok) {
                                    alert(data.message || "토큰 발급 실패");
                                    return;
                                }

                                if (data.csrf_token) {
                                    const t = document.getElementById("csrf_token");
                                    if (t) t.value = data.csrf_token;
                                }

                                alert(data.message || "토큰이 발급되었습니다.");

                                // 발급자 라벨
                                const issuedByText = root.querySelector("#issuedByText");
                                if (issuedByText) {
                                    const label = String(data.issued_by_label ?? "").trim();
                                    issuedByText.textContent = label || "—";
                                }

                                // 코드/본문 갱신
                                if (data.doc_token) {
                                    const codeEl = root.querySelector("#tokenCodeText");
                                    if (codeEl) {
                                        codeEl.textContent = String(data.doc_token);
                                        codeEl.dataset.smsBody = data.sms_body || `[인증번호]:${data.doc_token}복사되었습니다. 서류제출하기 버튼을 누르신후 인증번호를 입력후 서류를 등록해주세요.`;
                                        codeEl.dataset.copyAlert = data.copy_alert || `[인증번호]:${data.doc_token} 이 복사되었습니다.`;
                                    }

                                    const copyBtn2 = root.querySelector("#copyTokenBtn");
                                    if (copyBtn2) copyBtn2.disabled = false;

                                    const smsBtn2 = root.querySelector("#smsTokenBtn");
                                    if (smsBtn2) smsBtn2.dataset.smsBody = data.sms_body || `[인증번호]:${data.doc_token}복사되었습니다. 서류제출하기 버튼을 누르신후 인증번호를 입력후 서류를 등록해주세요.`;
                                }

                                refresh(true);
                            } catch (e2) {
                                alert("네트워크 오류가 발생했습니다.");
                            } finally {
                                issueBtn.disabled = false;
                                issueBtn.textContent = "토큰 발급하기";
                            }
                        });
                    }
                }
            }

            // ====== 서류 삭제 바인딩 ======

            function bindDocDelete(root) {
                const r = root || document;
                r.querySelectorAll("[data-doc-delete]").forEach((btn) => {
                    if (btn.dataset.bound === "1") return;
                    btn.dataset.bound = "1";

                    btn.addEventListener("click", async (e) => {
                        e.preventDefault();
                        e.stopPropagation();

                        if (btn.disabled) return;

                        const docId = Number(btn.dataset.docId || 0);
                        if (!docId) return;

                        if (!confirm("서류를 삭제할까요?")) return;

                        try {
                            btn.disabled = true;
                            btn.textContent = "삭제중...";

                            const data = await deleteDoc(docId);
                            if (!data.ok) {
                                alert(data.message || "삭제 실패");
                                return;
                            }

                            if (data.csrf_token) {
                                const t = document.getElementById("csrf_token");
                                if (t) t.value = data.csrf_token;
                            }

                            alert(data.message || "서류가 삭제되었습니다.");
                            refresh(true);
                        } catch (err) {
                            alert("네트워크 오류가 발생했습니다.");
                        } finally {
                            btn.disabled = false;
                            btn.textContent = "🗑 삭제";
                        }
                    });
                });
            }

            // ====== 상세 렌더 ======

            function buildStatusOptions(role, current) {
                const opts = allowedStatusesForRole(role);
                return opts
                    .map((v) => `<option value="${escapeHtml(v)}" ${String(current) === String(v) ? "selected" : ""}>${escapeHtml(statusLabel(v))}</option>`)
                    .join("");
            }

            function buildOutcomeOptions(role, current) {
                const opts = allowedOutcomesForRole(role);
                return opts
                    .map((v) => `<option value="${escapeHtml(v)}" ${String(current) === String(v) ? "selected" : ""}>${escapeHtml(outcomeLabel(v))}</option>`)
                    .join("");
            }

            function renderDetail(sel, docs, adminRole) {
                const box = document.getElementById("detailBox");
                if (!sel) {
                    box.innerHTML = `<div style="color:var(--muted);font-size:12px;">선택된 항목이 없습니다.</div>`;
                    return;
                }

                selectedId = Number(sel.cashhome_1000_id || 0);
                const detailIdEl = document.getElementById("detailId");
                const loanNoRaw = String(sel.cashhome_1000_loan_no || "").trim();
                const loanNoDisplay = (loanNoRaw && loanNoRaw !== "00") ? loanNoRaw.slice(-4) : String(selectedId);
                if (detailIdEl) detailIdEl.textContent = "#" + loanNoDisplay;

                const role = String(adminRole || sel.admin_role || "").toLowerCase().trim() || "admin";

                const phone = sel.cashhome_1000_customer_phone || "";
                const tel = (phone.match(/\d+/g) || []).join("");

                const pOk = !!sel.privacy_at;
                const mOk = !!sel.marketing_at;

                const st = String(sel.cashhome_1000_status || ST.NEW);
                const oc = String(sel.cashhome_1000_outcome || OC.PENDING);
                const note = sel.cashhome_1000_admin_note || "";

                const isClosed = isClosedStatus(st);
                const locked = (isClosed && role === "admin");

                const docToken = sel.cashhome_1000_doc_token || "";
                const docTokenStatus = Number(sel.cashhome_1000_doc_token_status || 0);
                const docIssuedAt = sel.cashhome_1000_doc_token_issued_at || "";
                const docExpiresAt = sel.cashhome_1000_doc_token_expires_at || "";
                const docUsedAt = sel.cashhome_1000_doc_token_used_at || "";

                const issuedByLabel = String(sel.issued_by_label ?? "").trim();

                const smsBody = docToken && docTokenStatus === 1 ?
                    `[인증번호]:${docToken}복사되었습니다. 서류제출하기 버튼을 누르신후 인증번호를 입력후 서류를 등록해주세요.` :
                    "";
                const copyAlert = docToken && docTokenStatus === 1 ? `[인증번호]:${docToken} 이 복사되었습니다.` : "";

                let tokenHint = "";
                if (docTokenStatus === 1 && docExpiresAt) tokenHint = `만료: ${escapeHtml(docExpiresAt)}`;
                else if (docTokenStatus === 2 && docUsedAt) tokenHint = `사용완료: ${escapeHtml(docUsedAt)}`;
                else if (docTokenStatus === 0) tokenHint = "아직 발급되지 않았습니다.";

                const lastByLabel = String(sel.last_modified_by_label ?? "—");
                const lastAt = String(sel.cashhome_1000_last_modified_at || "");

                const docsHtml = buildDocsHtml(docs || {});

                box.innerHTML = `
        <h3 class="detailTitle">접수 정보</h3>

        ${isClosed ? `
          <div class="err" style="margin-top:0;">
            ${locked ? "✅ 종결된 건입니다. (admin) 처리상태/대출결과/토큰발급/서류삭제가 잠금 처리됩니다. 메모 저장은 가능합니다." : "✅ 종결된 건입니다. (master) 정상적으로 수정/발급이 가능합니다."}
          </div>` : ``}

        <div class="kv">
          <div class="k">접수일시</div><div class="v">${escapeHtml(sel.cashhome_1000_created_at||'')}</div>
          <div class="k">이름</div><div class="v">${escapeHtml(sel.cashhome_1000_customer_name||'')}</div>

          <div class="k">연락처</div>
          <div class="v">
            ${escapeHtml(phone)}
            ${tel ? `<div style="margin-top:8px;"><a class="callBtn" href="tel:${escapeHtml(tel)}">📞 전화걸기</a></div>` : ``}
          </div>

          <div class="k">희망금액</div><div class="v">${escapeHtml(sel.cashhome_1000_loan_amount||'')}</div>
          <div class="k">자금용도</div><div class="v">${escapeHtml(sel.cashhome_1000_loan_purpose||'')}</div>

          <div class="k">IP</div><div class="v">${escapeHtml(sel.cashhome_1000_user_ip||'')}</div>
          <div class="k">User-Agent</div><div class="v" style="word-break:break-word;">${escapeHtml(sel.cashhome_1000_user_agent||'')}</div>

          <div class="k">개인정보 동의</div>
          <div class="v">
            ${pOk?'동의함':'미동의'} ${pOk ? `<span style="color:var(--muted)">(${escapeHtml(sel.privacy_ver||'')})</span>` : ''}
          </div>

          <div class="k">마케팅 동의</div><div class="v">${mOk?'동의함':'미동의'}</div>

          <div class="k">처리일시</div><div class="v" id="d_processed">${escapeHtml(sel.cashhome_1000_processed_at||'')}</div>
          <div class="k">수정일시</div><div class="v">${escapeHtml(sel.cashhome_1000_updated_at||'')}</div>
        </div>

        <div class="subhr"></div>
        <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">요청사항</h3>
        <div class="memoBox">${escapeHtml(sel.cashhome_1000_request_memo||'')}</div>

        <div class="subhr"></div>
        <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">처리 / 메모 / 토큰발급</h3>

        <div class="tabBar" id="detailTabs" data-closed="${isClosed?1:0}" data-locked="${locked?1:0}" data-role="${escapeHtml(role)}">
          <button type="button" class="tabBtn on" data-tab="tab_process">처리/메모</button>
          <button type="button" class="tabBtn" data-tab="tab_token">토큰발급</button>
        </div>

        <div class="tabPane" id="tab_process">
          <div class="formRow">
            <div class="field">
              <label for="edit_status">처리상태</label>
              <select id="edit_status" data-role="${escapeHtml(role)}" ${locked ? "disabled" : ""}>
                ${buildStatusOptions(role, st)}
              </select>
            </div>
            <div class="field">
              <label for="edit_outcome">대출결과</label>
              <select id="edit_outcome" data-role="${escapeHtml(role)}" ${locked ? "disabled" : ""}>
                ${buildOutcomeOptions(role, oc)}
              </select>
            </div>
          </div>

          <div class="field" style="margin-top:10px;">
            <label for="edit_note">관리자 메모</label>
            <input id="edit_note" type="text" value="${escapeHtml(note)}" placeholder="처리 내용/메모를 입력하세요">
          </div>

          <div class="saveBar">
            <button class="btn primary" id="saveBtn" type="button">저장</button>
            <button class="btn primary" id="reportBtn" type="button">최근 3개월간 통계보기</button>
            <button class="btn" id="backToListBtn" type="button">목록</button>

            <span class="sideMeta" id="lastSaveMeta">
              마지막 저장: <b id="lastSaveBy">${escapeHtml(lastByLabel || '—')}</b>
              · <b id="lastSaveAt">${lastAt ? escapeHtml(lastAt) : '—'}</b>
            </span>

            <span class="hint" id="saveHint">${locked ? "※ 종결된 건(admin)은 처리상태/대출결과 변경이 불가합니다. 메모 저장은 가능합니다." : "※ 변경 후 저장 버튼을 눌러야 DB에 반영됩니다."}</span>
          </div>
        </div>

        <div class="tabPane" id="tab_token" hidden>
          <div class="tokenBox">

            <div class="tokenRow">
              <div class="k">현재 상태</div>
              <div class="v">
                <span class="badge status" id="tokenStatusBadge">토큰: ${escapeHtml(docTokenStatus===1?'발급':docTokenStatus===2?'사용완료':docTokenStatus===3?'만료':docTokenStatus===4?'폐기':'미발급')}</span>
                <span class="smallHint" id="tokenStatusHint" style="margin-left:8px;">${tokenHint}</span>
              </div>
            </div>

            <div class="tokenRow">
              <div class="k">발급코드</div>
              <div class="v">
                <span class="tokenCode" id="tokenCodeText"
                  data-sms-body="${escapeHtml(smsBody)}"
                  data-copy-alert="${escapeHtml(copyAlert)}"
                >${docToken ? escapeHtml(docToken) : '—'}</span>

                <button type="button" class="miniBtn" id="copyTokenBtn" ${docToken && docTokenStatus===1 && !locked ? "" : "disabled"}>📋 코드 복사</button>
                <div class="smallHint">※ “코드 복사”는 문자에 바로 붙여넣을 문구로 복사됩니다.</div>
              </div>
            </div>

            <div class="tokenRow">
              <div class="k">발급일시</div>
              <div class="v" id="tokenIssuedAt">${docIssuedAt ? escapeHtml(docIssuedAt) : '—'}</div>
            </div>

            <div class="tokenRow">
              <div class="k">만료일시</div>
              <div class="v" id="tokenExpiresAt">${docExpiresAt ? escapeHtml(docExpiresAt) : '—'}</div>
            </div>

            <div class="tokenRow">
              <div class="k">유효시간</div>
              <div class="v">
                <div class="radioRow" id="expiresHoursRow">
                  <label class="radioChip"><input type="radio" name="expires_hours" value="24" checked ${locked?"disabled":""}> 24시간</label>
                  <label class="radioChip"><input type="radio" name="expires_hours" value="48" ${locked?"disabled":""}> 48시간</label>
                  <label class="radioChip"><input type="radio" name="expires_hours" value="72" ${locked?"disabled":""}> 72시간</label>
                </div>
                <div class="smallHint">※ 재발급 시 기존 코드는 무효 처리(현재 코드가 새 코드로 덮어써짐)</div>
              </div>
            </div>

            <div class="tokenActions">
              <button class="btn primary" type="button" id="issueTokenBtn" data-inquiry-id="${selectedId}" ${locked ? "disabled" : ""}>토큰 발급하기</button>
              <a class="btn" id="adminAddDocBtn" href="admin_document_upload.php?inquiry_id=${selectedId}" ${locked ? "aria-disabled=\"true\" style=\"pointer-events:none;opacity:.5\"" : ""}>서류추가</a>
              <span class="sideMeta" id="issuedByMeta">발급자: <b id="issuedByText">${issuedByLabel ? escapeHtml(issuedByLabel) : '—'}</b></span>

              <button class="btn" type="button" id="smsTokenBtn"
                data-phone="${escapeHtml(phone)}"
                data-sms-body="${escapeHtml(smsBody)}"
                ${locked ? "disabled" : ""}
              >문자 전송</button>

              <span class="hint" id="issueTokenHint">${locked ? "※ 종결된 건(admin)은 토큰 발급/문자 전송이 불가합니다." : "※ 모바일에서 누르면 메시지 앱이 열리며 본문이 자동 입력됩니다."}</span>
            </div>

          </div>
        </div>

        <input type="hidden" id="csrf_token" value="${escapeHtml(sel.csrf_token || document.getElementById("csrf_token")?.value || "")}">

        <div class="subhr"></div>
        <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">서류</h3>
        <div class="docsWrap" id="docsWrap">${docsHtml}</div>
      `;

                // 바인딩
                const saveBtn = document.getElementById("saveBtn");
                if (saveBtn && saveBtn.dataset.bound !== "1") {
                    saveBtn.dataset.bound = "1";
                    saveBtn.addEventListener("click", saveCurrent);
                }

                const reportBtn = document.getElementById("reportBtn");
                if (reportBtn && reportBtn.dataset.bound !== "1") {
                    reportBtn.dataset.bound = "1";
                    reportBtn.addEventListener("click", sendThreeMonthReport);
                }

                const backBtn = document.getElementById("backToListBtn");
                if (backBtn && backBtn.dataset.bound !== "1") {
                    backBtn.dataset.bound = "1";
                    backBtn.addEventListener("click", (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        if (isMobile()) {
                            setMobileMode("list");
                            window.scrollTo({
                                top: 0,
                                behavior: "smooth"
                            });
                        }
                    });
                }

                bindDetailTabs(box);
                bindCloseChangeLock(box);
                setDetailLock(box, isClosed, role);

                bindTokenActions(box, sel);
                bindDocModal(box);
                bindDocDelete(box);

                if (isMobile()) setMobileMode("detail");
                autoListHeight();

                const panelHead = box.closest(".panel")?.querySelector(".panelHead");
                if (panelHead) {
                    panelHead.style.cursor = "pointer";
                    panelHead.onclick = () => {
                        if (isMobile()) {
                            setMobileMode("list");
                            window.scrollTo({
                                top: 0,
                                behavior: "smooth"
                            });
                        }
                    };
                }
            }

            // ====== docs html 빌드(AJAX용) ======

            function docTypeLabel(t) {
                const v = String(t || "").trim();
                if (v === "id_card") return "신분증";
                if (v === "resident_record") return "등본";
                if (v === "bankbook") return "통장";
                if (v === "income_proof") return "소득증빙";
                if (v === "business_license") return "사업자등록증";
                return "기타";
            }

            function buildDocsHtml(docs) {
                if (!docs || Object.keys(docs).length === 0) {
                    return `<div style="color:var(--muted);font-size:12px;">등록된 서류가 없습니다.</div>`;
                }

                let html = "";
                for (const [dtype, items] of Object.entries(docs)) {
                    const title = docTypeLabel(dtype);
                    html += `
          <div class="docGroup">
            <div class="docGroupHead">
              <b>${escapeHtml(title)}</b>
              <span class="hint">총 ${items.length}개</span>
            </div>
            <div class="docGrid">
        `;

                    for (const d of items) {
                        const docId = Number(d.cashhome_1200_id || 0);
                        const fn = (d.cashhome_1200_original_name || "") ? d.cashhome_1200_original_name : ("image_" + docId);
                        const created = d.cashhome_1200_created_at || "";
                        const url = `document_view.php?id=${docId}`;

                        html += `
            <div class="docItem" data-doc-id="${docId}" data-doc-url="${escapeHtml(url)}" data-doc-name="${escapeHtml(fn)}">
              <button type="button" class="thumbBtn" data-doc-open>
                <img class="thumb" src="${escapeHtml(url)}" alt="${escapeHtml(fn)}" loading="lazy" />
              </button>
              <div class="docMeta">
                <div class="fn">${escapeHtml(fn)}</div>
                <div>${escapeHtml(created)}</div>
                <div class="docBtns">
                  <button type="button" class="miniBtn" data-doc-open>🔍 크게보기</button>
                  <a class="miniBtn" href="${escapeHtml(url)}" target="_blank" rel="noopener">↗ 새창</a>
                  <button type="button" class="miniBtn" data-doc-delete data-doc-id="${docId}">🗑 삭제</button>
                </div>
              </div>
            </div>
          `;
                    }

                    html += `</div></div>`;
                }
                return html;
            }

            // ====== 저장 ======

            async function saveCurrent() {
                const id = selectedId;
                if (!id) {
                    alert("선택된 항목이 없습니다.");
                    return;
                }

                const st = document.getElementById("edit_status")?.value;
                const oc = document.getElementById("edit_outcome")?.value;
                const note = document.getElementById("edit_note")?.value || "";
                const csrf = document.getElementById("csrf_token")?.value || "";

                // ✅ 종결 저장 정책
                // - admin: 처리상태/대출결과/토큰은 잠금이지만 '메모 저장'은 가능
                // - master: 종결이어도 전체 저장 가능
                // (서버단에서도 동일 정책으로 한번 더 검증함)

                const fd = new FormData();
                fd.append("action", "save");
                fd.append("csrf_token", csrf);
                fd.append("id", String(id));
                fd.append("status", st);
                fd.append("outcome", oc);
                fd.append("admin_note", note);

                try {
                    const data = await saveInquiry(fd);
                    if (!data.ok) {
                        alert(data.message || "저장 실패");
                        return;
                    }
                    alert(data.message || "저장되었습니다.");

                    if (data.csrf_token) {
                        const t = document.getElementById("csrf_token");
                        if (t) t.value = data.csrf_token;
                    }

                    const byEl = document.getElementById("lastSaveBy");
                    const atEl = document.getElementById("lastSaveAt");

                    // ✅ 숫자 대신 라벨 표시
                    if (byEl) {
                        const label = String(data.last_modified_by_label ?? "").trim();
                        if (label) byEl.textContent = label;
                        else if (typeof data.last_modified_by !== "undefined") {
                            const v = Number(data.last_modified_by || 0);
                            byEl.textContent = v > 0 ? String(v) : "—";
                        } else byEl.textContent = "—";
                    }
                    if (atEl && data.last_modified_at) {
                        atEl.textContent = String(data.last_modified_at || "—");
                    }

                    if (isMobile()) setMobileMode("list");
                    refresh(true);
                } catch (e) {
                    alert("네트워크 오류가 발생했습니다.");
                }
            }

            
            async function sendThreeMonthReport() {
                const csrf = document.getElementById("csrf_token")?.value || "";
                if (!csrf) {
                    alert("보안 토큰이 없습니다. 새로고침 후 다시 시도해주세요.");
                    return;
                }

                if (!confirm("최근 3개월 대출 통계 리포트를 이메일로 발송할까요?")) return;

                try {
                    const fd = new FormData();
                    fd.append("action", "send_report");
                    fd.append("csrf_token", csrf);

                    const res = await fetch(location.pathname, {
                        method: "POST",
                        body: fd,
                        credentials: "same-origin",
                    });

                    const data = await res.json().catch(() => null);
                    if (!data) {
                        alert("응답을 처리할 수 없습니다.");
                        return;
                    }

                    // 서버에서 토큰이 갱신되면 반영
                    if (data.csrf_token) {
                        const el = document.getElementById("csrf_token");
                        if (el) el.value = data.csrf_token;
                    }

                    if (data.ok) {
                        alert(data.message || "리포트 메일을 발송했습니다.");
                    } else {
                        alert(data.message || "리포트 메일 발송에 실패했습니다.");
                    }
                } catch (e) {
                    alert("네트워크 오류가 발생했습니다.");
                }
            }

// ====== refresh ======

            let debounceTimer = null;

            function debounce(fn, ms) {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(fn, ms);
            }

            async function refresh(keepSelection) {
                updateExcelLink();

                const q = buildQuery({
                    ajax: 1
                });


                try {
                    const res = await fetch("admin_inquiries.php?" + q, {
                        credentials: "same-origin"
                    });

                    const data = await res.json();

                    console.log(data);

                    if (!data.ok) {
                        alert(data.message || "데이터를 불러오지 못했습니다.");
                        return;
                    }

                    if (!keepSelection) {
                        selectedId = data.selected?.cashhome_1000_id ? Number(data.selected.cashhome_1000_id) : 0;
                    }

                    if (countText) countText.textContent = String((data.rows || []).length);
                    if (rangeText) rangeText.textContent = `${data.filters.start} ~ ${data.filters.end}`;

                    elStart.value = data.filters.start;
                    elEnd.value = data.filters.end;
                    elStatus.value = data.filters.status;
                    elOutcome.value = data.filters.outcome;

                    renderList(data.rows || []);
                    renderStats(data.stats || {});

                    const hs = data.header_stats || {};
                    renderTopPills(hs);
                    renderStatusPills(hs);

                    applyTokenTTLToList();

                    if (data.selected) data.selected.csrf_token = data.csrf_token || "";

                    const role = data.admin?.role || "";
                    renderDetail(data.selected || null, data.docs || {}, role);

                    const q2 = buildQuery({
                        ajax: 0
                    });
                    history.replaceState(null, "", "admin_inquiries.php?" + q2);

                    autoListHeight();
                } catch (e) {
                    alert("네트워크 오류가 발생했습니다.");
                }
            }

            // ====== 이벤트 바인딩 ======
            // (원본 코드 그대로)
            [elStart, elEnd, elStatus, elOutcome].forEach((el) => {
                el.addEventListener("change", () => debounce(() => refresh(false), 80));
            });
            [elName, elMemo, elNote].forEach((el) => {
                el.addEventListener("input", () => debounce(() => refresh(false), 180));
            });

            const initStats = <?= json_encode($stats, JSON_UNESCAPED_UNICODE) ?>;
            renderStats(initStats);

            const initHeaderStats = <?= json_encode($headerStats ?? $stats, JSON_UNESCAPED_UNICODE) ?>;
            renderTopPills(initHeaderStats);
            renderStatusPills(initHeaderStats);

            function handleSelectItem(item) {
                selectedId = Number(item?.dataset?.id || 0);
                if (!selectedId) return;

                document.querySelectorAll(".item").forEach((x) => x.classList.remove("on"));
                item.classList.add("on");

                if (isMobile()) setMobileMode("detail");
                refresh(true);
            }

            listBox.addEventListener("click", (e) => {
                const item = e.target?.closest?.(".item");
                if (!item) return;
                handleSelectItem(item);
            });

            const initialOn = document.querySelector(".item.on");
            if (initialOn) {
                selectedId = Number(initialOn.dataset.id || 0);
            }

            bindDetailTabs(document);
            bindCloseChangeLock(document);

            let adminRole = '<?php echo $_SESSION['cashhome_admin_role'] ?>';

            setDetailLock(document, isClosedStatus(document.querySelector("#edit_status")?.value || ""), adminRole);

            bindTokenActions(document, null);

            const initSaveBtn = document.getElementById("saveBtn");
            if (initSaveBtn && initSaveBtn.dataset.bound !== "1") {
                initSaveBtn.dataset.bound = "1";
                initSaveBtn.addEventListener("click", saveCurrent);
            }

            const initReportBtn = document.getElementById("reportBtn");
            if (initReportBtn && initReportBtn.dataset.bound !== "1") {
                initReportBtn.dataset.bound = "1";
                initReportBtn.addEventListener("click", sendThreeMonthReport);
            }

            const initBackBtn = document.getElementById("backToListBtn");
            if (initBackBtn && initBackBtn.dataset.bound !== "1") {
                initBackBtn.dataset.bound = "1";
                initBackBtn.addEventListener("click", (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    if (isMobile()) {
                        setMobileMode("list");
                        window.scrollTo({
                            top: 0,
                            behavior: "smooth"
                        });
                    }
                });
            }

            bindListCopyButtons(document);
            applyTokenTTLToList();

            bindDocModal(document);
            bindDocDelete(document);

            updateExcelLink();
            autoListHeight();

            if (isMobile()) setMobileMode("list");
        })();
    </script>
</body>

</html>