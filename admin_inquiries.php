<?php

declare(strict_types=1);

session_start();
header('X-Frame-Options: SAMEORIGIN');
header('X-Content-Type-Options: nosniff');

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// ===== DB 설정 =====
const DB_HOST = '49.247.29.76';
const DB_NAME = 'cashhome';
const DB_USER = 'lokia';
const DB_PASS = 'lokia0528**';

// 로그인 유지 시간(초) - admin_login.php와 동일
const ADMIN_SESSION_TTL = 7200;

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

function status_label(string $s): string
{
    return match ($s) {
        'new' => '신규',
        'contacted' => '연락완료',
        'closed' => '종결',
        default => $s,
    };
}

function outcome_label(string $s): string
{
    return match ($s) {
        'pending' => '대기',
        'approved' => '승인',
        'rejected' => '부결',
        default => $s,
    };
}

function phone_digits(string $phone): string
{
    return preg_replace('/\D+/', '', $phone) ?? '';
}

function build_filters_from_request(array $src): array
{
    $today = date('Y-m-d');
    $defaultStart = date('Y-m-d', strtotime('-7 days'));

    $start = (string)($src['start'] ?? $defaultStart);
    $end   = (string)($src['end'] ?? $today);

    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $start)) $start = $defaultStart;
    if (!preg_match('/^\d{4}-\d{2}-\d{2}$/', $end))   $end   = $today;

    $status  = (string)($src['status'] ?? 'all');     // all|new|contacted|closed
    $outcome = (string)($src['outcome'] ?? 'all');    // all|pending|approved|rejected

    $name = trim((string)($src['name'] ?? ''));
    $memo = trim((string)($src['memo'] ?? ''));
    $note = trim((string)($src['note'] ?? ''));

    $allowedStatus  = ['all', 'new', 'contacted', 'closed'];
    $allowedOutcome = ['all', 'pending', 'approved', 'rejected'];
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

function fetch_rows(PDO $pdo, array $f): array
{
    [$where, $params] = build_where_and_params($f);

    $sql = "
      SELECT
        i.cashhome_1000_id,
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

        MAX(CASE WHEN c.cashhome_1100_consent_type='privacy' THEN c.cashhome_1100_consented_at END) AS privacy_at,
        MAX(CASE WHEN c.cashhome_1100_consent_type='privacy' THEN c.cashhome_1100_consent_version END) AS privacy_ver,
        MAX(CASE WHEN c.cashhome_1100_consent_type='marketing' THEN c.cashhome_1100_consented_at END) AS marketing_at

      FROM cashhome_1000_inquiries i
      LEFT JOIN cashhome_1100_consent_logs c
        ON c.cashhome_1100_inquiry_id = i.cashhome_1000_id

      $where

      GROUP BY
        i.cashhome_1000_id,
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
        i.cashhome_1000_admin_note

      ORDER BY i.cashhome_1000_id DESC
      LIMIT 5000
    ";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function compute_stats(array $rows): array
{
    $total = count($rows);
    $approved = 0;
    $pending = 0;
    $rejected = 0;

    $dailyAll = [];
    $dailyApproved = [];

    foreach ($rows as $r) {
        $oc = (string)($r['cashhome_1000_outcome'] ?? 'pending');
        if ($oc === 'approved') $approved++;
        elseif ($oc === 'rejected') $rejected++;
        else $pending++;

        $d = substr((string)$r['cashhome_1000_created_at'], 0, 10);
        $dailyAll[$d] = ($dailyAll[$d] ?? 0) + 1;
        if ($oc === 'approved') $dailyApproved[$d] = ($dailyApproved[$d] ?? 0) + 1;
    }

    ksort($dailyAll);
    ksort($dailyApproved);

    $rate = $total > 0 ? round(($approved / $total) * 100, 1) : 0.0;

    // 그래프 레이블 통합(빈날 0 보정)
    $labels = array_keys($dailyAll);
    $allSeries = [];
    $apprSeries = [];
    foreach ($labels as $d) {
        $allSeries[] = $dailyAll[$d] ?? 0;
        $apprSeries[] = $dailyApproved[$d] ?? 0;
    }

    return [
        'total' => $total,
        'approved' => $approved,
        'pending' => $pending,
        'rejected' => $rejected,
        'rate' => $rate,
        'labels' => $labels,
        'series_all' => $allSeries,
        'series_approved' => $apprSeries,
    ];
}

function compact_rows_for_json(array $rows): array
{
    $out = [];
    foreach ($rows as $r) {
        $out[] = [
            'id' => (int)$r['cashhome_1000_id'],
            'created_at' => (string)$r['cashhome_1000_created_at'],
            'name' => (string)$r['cashhome_1000_customer_name'],
            'phone' => (string)$r['cashhome_1000_customer_phone'],
            'status' => (string)$r['cashhome_1000_status'],
            'outcome' => (string)$r['cashhome_1000_outcome'],
            'privacy_ok' => !empty($r['privacy_at']),
            'marketing_ok' => !empty($r['marketing_at']),
        ];
    }
    return $out;
}

// ===== CSRF =====
if (empty($_SESSION['csrf_token_admin'])) {
    $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));
}

// ===== 로그아웃 =====
if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    unset($_SESSION['cashhome_admin_authed'], $_SESSION['cashhome_admin_authed_at']);
    header('Location: admin_login.php');
    exit;
}

// ===== 인증 =====
if (!is_admin_authed()) {
    header('Location: admin_login.php');
    exit;
}

$pdo = cashhome_pdo();
$f = build_filters_from_request($_GET);

// ===== 저장(POST) =====
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (string)($_POST['action'] ?? '') === 'save') {
    header('Content-Type: application/json; charset=utf-8');

    $token = (string)($_POST['csrf_token'] ?? '');
    if (!hash_equals($_SESSION['csrf_token_admin'], $token)) {
        echo json_encode(['ok' => false, 'message' => '요청이 만료되었습니다. 새로고침 후 다시 시도해주세요.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $id = (int)($_POST['id'] ?? 0);
    $status = (string)($_POST['status'] ?? 'new');
    $outcome = (string)($_POST['outcome'] ?? 'pending');
    $note = trim((string)($_POST['admin_note'] ?? ''));

    $allowedStatus = ['new', 'contacted', 'closed'];
    $allowedOutcome = ['pending', 'approved', 'rejected'];
    if ($id <= 0 || !in_array($status, $allowedStatus, true) || !in_array($outcome, $allowedOutcome, true)) {
        echo json_encode(['ok' => false, 'message' => '잘못된 요청입니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // processed_at: 승인/부결이면 NOW, 대기면 NULL (원하면 유지로 바꿀 수 있음)
    $processedAt = null;
    if ($outcome !== 'pending') $processedAt = date('Y-m-d H:i:s');

    try {
        $stmt = $pdo->prepare("
          UPDATE cashhome_1000_inquiries
          SET
            cashhome_1000_status = :st,
            cashhome_1000_outcome = :oc,
            cashhome_1000_processed_at = :pa,
            cashhome_1000_admin_note = :nt
          WHERE cashhome_1000_id = :id
          LIMIT 1
        ");
        $stmt->execute([
            ':st' => $status,
            ':oc' => $outcome,
            ':pa' => $processedAt,
            ':nt' => $note !== '' ? $note : null,
            ':id' => $id,
        ]);

        // CSRF rotate
        $_SESSION['csrf_token_admin'] = bin2hex(random_bytes(32));

        echo json_encode([
            'ok' => true,
            'message' => '저장되었습니다.',
            'csrf_token' => $_SESSION['csrf_token_admin'],
            'processed_at' => $processedAt,
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (Throwable $e) {
        error_log('[ADMIN SAVE ERROR] ' . $e->getMessage());
        echo json_encode(['ok' => false, 'message' => '저장 중 오류가 발생했습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// ===== AJAX: 리스트/통계 갱신(리로드 없이) =====
if (isset($_GET['ajax']) && $_GET['ajax'] === '1') {
    header('Content-Type: application/json; charset=utf-8');
    try {
        $rows = fetch_rows($pdo, $f);
        $stats = compute_stats($rows);

        // 선택 id: 요청이 있으면 유지, 없으면 첫 항목
        $selectedId = (int)($_GET['id'] ?? 0);
        if ($selectedId <= 0 && !empty($rows)) $selectedId = (int)$rows[0]['cashhome_1000_id'];

        // 선택 상세(같은 rows에서 찾기)
        $selected = null;
        foreach ($rows as $r) {
            if ((int)$r['cashhome_1000_id'] === $selectedId) {
                $selected = $r;
                break;
            }
        }
        if (!$selected && !empty($rows)) $selected = $rows[0];

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
            'selected' => $selected,
            'csrf_token' => $_SESSION['csrf_token_admin'],
        ], JSON_UNESCAPED_UNICODE);
        exit;
    } catch (Throwable $e) {
        error_log('[ADMIN AJAX ERROR] ' . $e->getMessage());
        echo json_encode(['ok' => false, 'message' => '데이터를 불러오지 못했습니다.'], JSON_UNESCAPED_UNICODE);
        exit;
    }
}

// ===== 엑셀 다운로드(CSV) =====
if (isset($_GET['excel']) && $_GET['excel'] === '1') {
    [$where, $params] = build_where_and_params($f);

    header("Content-Type: text/csv; charset=UTF-8");
    header("Content-Disposition: attachment; filename=inquiries_" . $f['start'] . "_to_" . $f['end'] . ".csv");
    // UTF-8 BOM (엑셀 한글 깨짐 방지)
    echo "\xEF\xBB\xBF";

    $sql = "
      SELECT
        i.cashhome_1000_id,
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
    $headerWritten = false;

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        if (!$headerWritten) {
            fputcsv($out, array_keys($row));
            $headerWritten = true;
        }
        fputcsv($out, $row);
    }
    fclose($out);
    exit;
}

// ===== 초기 화면 렌더(SSR) =====
$error = '';
$rows = [];
$selected = null;
$selectedId = (int)($_GET['id'] ?? 0);

try {
    $rows = fetch_rows($pdo, $f);
    $stats = compute_stats($rows);

    if ($selectedId <= 0 && !empty($rows)) $selectedId = (int)$rows[0]['cashhome_1000_id'];
    foreach ($rows as $r) {
        if ((int)$r['cashhome_1000_id'] === $selectedId) {
            $selected = $r;
            break;
        }
    }
    if (!$selected && !empty($rows)) $selected = $rows[0];
} catch (Throwable $e) {
    error_log('[ADMIN INIT ERROR] ' . $e->getMessage());
    $error = '데이터를 불러오지 못했습니다. (서버 로그 확인)';
    $stats = ['total' => 0, 'approved' => 0, 'pending' => 0, 'rejected' => 0, 'rate' => 0, 'labels' => [], 'series_all' => [], 'series_approved' => []];
}

$approvedBadgeCount = (int)($stats['approved'] ?? 0);
?>
<!doctype html>
<html lang="ko">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="robots" content="noindex,nofollow" />
    <title>접수이력</title>
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
            /* amber */
            --approved: #22C55E;
            /* green */
            --rejected: #EF4444;
            /* red */
            --accent: #6EE7FF;
            --accent2: #A78BFA;
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
        }

        .btn:hover {
            background: rgba(255, 255, 255, .05)
        }

        .btn.primary {
            border: 0;
            background: linear-gradient(135deg, rgba(110, 231, 255, .95), rgba(167, 139, 250, .95));
            color: #061025;
        }

        .btn.danger {
            border: 1px solid rgba(239, 68, 68, .35);
            background: rgba(255, 255, 255, .03);
        }

        .badgeTop {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 999px;
            border: 1px solid rgba(239, 68, 68, .35);
            background: rgba(239, 68, 68, .12);
            color: #FFD3D3;
            font-weight: 900;
            font-size: 12px;
        }

        .badgeDot {
            width: 10px;
            height: 10px;
            border-radius: 99px;
            background: var(--rejected);
            box-shadow: 0 0 18px rgba(239, 68, 68, .55);
        }

        .err {
            margin-top: 10px;
            padding: 10px 12px;
            border-radius: 14px;
            border: 1px solid rgba(255, 120, 120, .35);
            background: rgba(255, 255, 255, .03);
            font-size: 12px
        }

        /* 검색 */
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
            box-shadow: 0 0 0 3px rgba(110, 231, 255, .12)
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

        @media (max-width: 1200px) {
            .filters {
                grid-template-columns: 1fr 1fr 1fr 1fr;
            }

            .meta {
                grid-column: 1 / -1;
            }
        }

        @media (max-width: 720px) {
            .filters {
                grid-template-columns: 1fr 1fr;
            }
        }

        /* 통계 카드 */
        .statsGrid {
            margin-top: 12px;
            display: grid;
            grid-template-columns: 1fr 1fr 1.5fr;
            gap: 12px;
        }

        @media (max-width: 1100px) {
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
            padding: 8px 10px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: 12px;
            font-weight: 900;
        }

        .pill span {
            font-weight: 900
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

        /* 본문 2열 */
        .layout {
            margin-top: 12px;
            display: grid;
            grid-template-columns: 430px 1fr;
            gap: 12px;
            min-height: calc(100vh - 420px);
        }

        @media (max-width: 1100px) {
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
            min-height: 420px;
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

        /* 리스트 */
        .list {
            overflow: auto;
            max-height: calc(100vh - 440px);
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
            letter-spacing: -.2px
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
            flex-wrap: wrap
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
            padding: 6px 10px;
            border-radius: 999px;
            border: 1px solid var(--line);
            background: rgba(255, 255, 255, .03);
            font-size: 12px;
            font-weight: 1000;
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

        /* 상세 */
        .detailBody {
            padding: 14px;
            overflow: auto;
            max-height: calc(100vh - 440px);
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

        @media (max-width: 720px) {
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

        .hint {
            color: var(--muted);
            font-size: 12px
        }

        .callBtn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 12px;
            border-radius: 999px;
            border: 1px solid rgba(110, 231, 255, .25);
            background: rgba(255, 255, 255, .03);
            text-decoration: none;
            font-weight: 1000;
            font-size: 12px;
            color: #D0FBFF;
        }

        .callBtn:hover {
            background: rgba(255, 255, 255, .05)
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
            <div class="actions">
                <?php if ($approvedBadgeCount > 0): ?>
                    <span class="badgeTop" id="approvedTopBadge"><span class="badgeDot"></span> 승인 <?= h((string)$approvedBadgeCount) ?>건 발생</span>
                <?php else: ?>
                    <span class="badgeTop" id="approvedTopBadge" style="display:none;"><span class="badgeDot"></span> 승인 0건 발생</span>
                <?php endif; ?>
                <a class="btn" href="./">홈</a>
                <a class="btn danger" href="admin_inquiries.php?logout=1">로그아웃</a>
            </div>
        </div>

        <?php if ($error): ?>
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
            <div class="field">
                <label for="outcome">결과(대기/승인/부결)</label>
                <select id="outcome" name="outcome">
                    <option value="all" <?= $f['outcome'] === 'all' ? 'selected' : '' ?>>전체</option>
                    <option value="pending" <?= $f['outcome'] === 'pending' ? 'selected' : '' ?>>대기</option>
                    <option value="approved" <?= $f['outcome'] === 'approved' ? 'selected' : '' ?>>승인</option>
                    <option value="rejected" <?= $f['outcome'] === 'rejected' ? 'selected' : '' ?>>부결</option>
                </select>
            </div>
            <div class="field">
                <label for="status">처리상태(신규/연락/종결)</label>
                <select id="status" name="status">
                    <option value="all" <?= $f['status'] === 'all' ? 'selected' : '' ?>>전체</option>
                    <option value="new" <?= $f['status'] === 'new' ? 'selected' : '' ?>>신규</option>
                    <option value="contacted" <?= $f['status'] === 'contacted' ? 'selected' : '' ?>>연락완료</option>
                    <option value="closed" <?= $f['status'] === 'closed' ? 'selected' : '' ?>>종결</option>
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

        <!-- 통계 -->
        <div class="statsGrid">
            <div class="statCard">
                <div class="statTitle">
                    <b>요약</b>
                    <span class="hint">조회기간: <span id="rangeText"><?= h($f['start']) ?> ~ <?= h($f['end']) ?></span></span>
                </div>
                <div class="statNums" id="statNums">
                    <span class="pill pending">대기 <span id="statPending"><?= h((string)$stats['pending']) ?></span></span>
                    <span class="pill approved">승인 <span id="statApproved"><?= h((string)$stats['approved']) ?></span></span>
                    <span class="pill rejected">부결 <span id="statRejected"><?= h((string)$stats['rejected']) ?></span></span>
                    <span class="pill rate">승인율 <span id="statRate"><?= h((string)$stats['rate']) ?>%</span></span>
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

        <div class="layout">
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

                    <?php foreach ($rows as $r): ?>
                        <?php
                        $id = (int)$r['cashhome_1000_id'];
                        $on = ($id === $selectedId);
                        $pOk = !empty($r['privacy_at']);
                        $mOk = !empty($r['marketing_at']);
                        $st = (string)$r['cashhome_1000_status'];
                        $oc = (string)($r['cashhome_1000_outcome'] ?? 'pending');

                        $ocClass = $oc === 'approved' ? 'approved' : ($oc === 'rejected' ? 'rejected' : 'pending');
                        $qs = http_build_query([
                            'start' => $f['start'],
                            'end' => $f['end'],
                            'status' => $f['status'],
                            'outcome' => $f['outcome'],
                            'name' => $f['name'],
                            'memo' => $f['memo'],
                            'note' => $f['note'],
                            'id' => $id,
                        ]);
                        ?>
                        <div class="item <?= $on ? 'on' : '' ?>" data-id="<?= h((string)$id) ?>">
                            <div class="row1">
                                <div class="name"><?= h((string)$r['cashhome_1000_customer_name']) ?></div>
                                <div class="idchip">#<?= h((string)$id) ?></div>
                            </div>
                            <div class="row2">
                                <span><?= h((string)$r['cashhome_1000_created_at']) ?></span>
                                <span>·</span>
                                <span><?= h((string)$r['cashhome_1000_customer_phone']) ?></span>
                            </div>
                            <div class="chips">
                                <span class="badge <?= h($ocClass) ?>">
                                    <span class="dot"></span> <?= h(outcome_label($oc)) ?>
                                </span>
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
                    <b>상세 처리 · <span id="detailId">#<?= h((string)$selectedId) ?></span></b>
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
                        $oc = (string)($selected['cashhome_1000_outcome'] ?? 'pending');
                        $st = (string)$selected['cashhome_1000_status'];
                        ?>
                        <h3 class="detailTitle">접수 정보</h3>

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

                        <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">처리 / 메모 저장</h3>

                        <div class="formRow">
                            <div class="field">
                                <label for="edit_status">처리상태</label>
                                <select id="edit_status">
                                    <option value="new" <?= $st === 'new' ? 'selected' : '' ?>>신규</option>
                                    <option value="contacted" <?= $st === 'contacted' ? 'selected' : '' ?>>연락완료</option>
                                    <option value="closed" <?= $st === 'closed' ? 'selected' : '' ?>>종결</option>
                                </select>
                            </div>
                            <div class="field">
                                <label for="edit_outcome">대출결과</label>
                                <select id="edit_outcome">
                                    <option value="pending" <?= $oc === 'pending' ? 'selected' : '' ?>>대기</option>
                                    <option value="approved" <?= $oc === 'approved' ? 'selected' : '' ?>>승인</option>
                                    <option value="rejected" <?= $oc === 'rejected' ? 'selected' : '' ?>>부결</option>
                                </select>
                            </div>
                        </div>

                        <div class="field" style="margin-top:10px;">
                            <label for="edit_note">관리자 메모</label>
                            <input id="edit_note" type="text" value="<?= h((string)($selected['cashhome_1000_admin_note'] ?? '')) ?>" placeholder="처리 내용/메모를 입력하세요">
                        </div>

                        <div class="saveBar">
                            <button class="btn primary" id="saveBtn" type="button">저장</button>
                            <span class="hint" id="saveHint">※ 변경 후 저장 버튼을 눌러야 DB에 반영됩니다.</span>
                        </div>

                        <input type="hidden" id="csrf_token" value="<?= h($_SESSION['csrf_token_admin']) ?>">
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script>
        /**
         * ✅ 핵심: 한글 1글자 입력 후 멈춤 문제 해결
         * - 키워드 검색을 "리로드"로 처리하면 포커스가 튕겨서 발생
         * - 그래서 키워드 입력은 fetch(ajax) + DOM 업데이트로 처리한다.
         */

        (function() {
            const $ = (sel) => document.querySelector(sel);

            const filtersForm = $('#filtersForm');
            const elStart = $('#start');
            const elEnd = $('#end');
            const elStatus = $('#status');
            const elOutcome = $('#outcome');
            const elName = $('#name');
            const elMemo = $('#memo');
            const elNote = $('#note');

            const listBox = $('#listBox');
            const countText = $('#countText');

            const approvedTopBadge = $('#approvedTopBadge');
            const statPending = $('#statPending');
            const statApproved = $('#statApproved');
            const statRejected = $('#statRejected');
            const statRate = $('#statRate');
            const rangeText = $('#rangeText');

            const excelBtn = $('#excelBtn');

            let selectedId = <?= (int)$selectedId ?>;

            // Charts
            let chartAll = null;
            let chartApproved = null;

            function outcomeClass(oc) {
                if (oc === 'approved') return 'approved';
                if (oc === 'rejected') return 'rejected';
                return 'pending';
            }

            function statusLabel(st) {
                if (st === 'new') return '신규';
                if (st === 'contacted') return '연락완료';
                if (st === 'closed') return '종결';
                return st;
            }

            function outcomeLabel(oc) {
                if (oc === 'pending') return '대기';
                if (oc === 'approved') return '승인';
                if (oc === 'rejected') return '부결';
                return oc;
            }

            function buildQuery(extra = {}) {
                const q = new URLSearchParams();
                q.set('start', elStart.value);
                q.set('end', elEnd.value);
                q.set('status', elStatus.value);
                q.set('outcome', elOutcome.value);
                q.set('name', elName.value.trim());
                q.set('memo', elMemo.value.trim());
                q.set('note', elNote.value.trim());
                if (selectedId > 0) q.set('id', String(selectedId));
                Object.entries(extra).forEach(([k, v]) => q.set(k, String(v)));
                return q.toString();
            }

            function updateExcelLink() {
                const q = buildQuery({
                    excel: 1
                });
                excelBtn.setAttribute('href', 'admin_inquiries.php?' + q);
            }

            function renderList(rows) {
                listBox.innerHTML = '';
                if (!rows || rows.length === 0) {
                    const div = document.createElement('div');
                    div.style.padding = '14px';
                    div.style.color = 'var(--muted)';
                    div.style.fontSize = '12px';
                    div.textContent = '해당 조건에 접수 내역이 없습니다.';
                    listBox.appendChild(div);
                    return;
                }

                rows.forEach(r => {
                    const on = (r.id === selectedId);
                    const pOk = !!r.privacy_ok;
                    const mOk = !!r.marketing_ok;
                    const oc = r.outcome || 'pending';
                    const st = r.status || 'new';

                    const item = document.createElement('div');
                    item.className = 'item' + (on ? ' on' : '');
                    item.dataset.id = String(r.id);

                    item.innerHTML = `
        <div class="row1">
          <div class="name">${escapeHtml(r.name||'')}</div>
          <div class="idchip">#${r.id}</div>
        </div>
        <div class="row2">
          <span>${escapeHtml(r.created_at||'')}</span>
          <span>·</span>
          <span>${escapeHtml(r.phone||'')}</span>
        </div>
        <div class="chips">
          <span class="badge ${outcomeClass(oc)}"><span class="dot"></span> ${outcomeLabel(oc)}</span>
          <span class="badge status">상태: ${statusLabel(st)}</span>
          <span class="badge consent ${pOk?'ok':''}">개인정보: ${pOk?'동의함':'미동의'}</span>
          <span class="badge consent ${mOk?'ok':''}">마케팅: ${mOk?'동의함':'미동의'}</span>
        </div>
      `;

                    item.addEventListener('click', () => {
                        selectedId = r.id;
                        // 리스트 하이라이트
                        document.querySelectorAll('.item').forEach(x => x.classList.remove('on'));
                        item.classList.add('on');
                        // url state
                        const q = buildQuery({
                            ajax: 0
                        });
                        history.replaceState(null, '', 'admin_inquiries.php?' + q);
                        // 상세 갱신(전체 ajax 한번 더)
                        refresh(true);
                    });

                    listBox.appendChild(item);
                });
            }

            function renderStats(stats) {
                statPending.textContent = String(stats.pending ?? 0);
                statApproved.textContent = String(stats.approved ?? 0);
                statRejected.textContent = String(stats.rejected ?? 0);
                statRate.textContent = String(stats.rate ?? 0) + '%';

                // 상단 승인 배지
                const appr = Number(stats.approved ?? 0);
                if (appr > 0) {
                    approvedTopBadge.style.display = 'inline-flex';
                    approvedTopBadge.innerHTML = `<span class="badgeDot"></span> 승인 ${appr}건 발생`;
                } else {
                    approvedTopBadge.style.display = 'none';
                }

                // 차트 갱신
                const labels = stats.labels || [];
                const allSeries = stats.series_all || [];
                const apprSeries = stats.series_approved || [];

                if (chartAll) chartAll.destroy();
                if (chartApproved) chartApproved.destroy();

                chartAll = new Chart(document.getElementById('chartAll'), {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [{
                            label: '접수건수',
                            data: allSeries,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false
                    }
                });

                chartApproved = new Chart(document.getElementById('chartApproved'), {
                    type: 'line',
                    data: {
                        labels,
                        datasets: [{
                            label: '승인건수',
                            data: apprSeries,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false
                    }
                });
            }

            function escapeHtml(s) {
                return String(s)
                    .replaceAll('&', '&amp;')
                    .replaceAll('<', '&lt;')
                    .replaceAll('>', '&gt;')
                    .replaceAll('"', '&quot;')
                    .replaceAll("'", "&#039;");
            }

            function renderDetail(sel) {
                const box = document.getElementById('detailBox');
                if (!sel) {
                    box.innerHTML = `<div style="color:var(--muted);font-size:12px;">선택된 항목이 없습니다.</div>`;
                    return;
                }

                selectedId = Number(sel.cashhome_1000_id || 0);
                document.getElementById('detailId').textContent = '#' + selectedId;

                const phone = sel.cashhome_1000_customer_phone || '';
                const tel = (phone.match(/\d+/g) || []).join('');
                const pOk = !!sel.privacy_at;
                const mOk = !!sel.marketing_at;

                const st = sel.cashhome_1000_status || 'new';
                const oc = sel.cashhome_1000_outcome || 'pending';
                const note = sel.cashhome_1000_admin_note || '';

                box.innerHTML = `
      <h3 class="detailTitle">접수 정보</h3>
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
        <div class="v">${pOk?'동의함':'미동의'} ${pOk ? `<span style="color:var(--muted)">(${escapeHtml(sel.privacy_ver||'')})</span>` : ''}</div>

        <div class="k">마케팅 동의</div><div class="v">${mOk?'동의함':'미동의'}</div>

        <div class="k">처리일시</div><div class="v" id="d_processed">${escapeHtml(sel.cashhome_1000_processed_at||'')}</div>
        <div class="k">수정일시</div><div class="v">${escapeHtml(sel.cashhome_1000_updated_at||'')}</div>
      </div>

      <div class="subhr"></div>
      <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">요청사항</h3>
      <div class="memoBox">${escapeHtml(sel.cashhome_1000_request_memo||'')}</div>

      <div class="subhr"></div>
      <h3 class="detailTitle" style="font-size:15px;margin:0 0 8px;">처리 / 메모 저장</h3>

      <div class="formRow">
        <div class="field">
          <label for="edit_status">처리상태</label>
          <select id="edit_status">
            <option value="new" ${st==='new'?'selected':''}>신규</option>
            <option value="contacted" ${st==='contacted'?'selected':''}>연락완료</option>
            <option value="closed" ${st==='closed'?'selected':''}>종결</option>
          </select>
        </div>
        <div class="field">
          <label for="edit_outcome">대출결과</label>
          <select id="edit_outcome">
            <option value="pending" ${oc==='pending'?'selected':''}>대기</option>
            <option value="approved" ${oc==='approved'?'selected':''}>승인</option>
            <option value="rejected" ${oc==='rejected'?'selected':''}>부결</option>
          </select>
        </div>
      </div>

      <div class="field" style="margin-top:10px;">
        <label for="edit_note">관리자 메모</label>
        <input id="edit_note" type="text" value="${escapeHtml(note)}" placeholder="처리 내용/메모를 입력하세요">
      </div>

      <div class="saveBar">
        <button class="btn primary" id="saveBtn" type="button">저장</button>
        <span class="hint" id="saveHint">※ 변경 후 저장 버튼을 눌러야 DB에 반영됩니다.</span>
      </div>

      <input type="hidden" id="csrf_token" value="${escapeHtml(sel.csrf_token || document.getElementById('csrf_token')?.value || '')}">
    `;

                // 저장 버튼 바인딩
                const saveBtn = document.getElementById('saveBtn');
                saveBtn.addEventListener('click', saveCurrent);
            }

            async function saveCurrent() {
                const id = selectedId;
                if (!id) {
                    alert('선택된 항목이 없습니다.');
                    return;
                }

                const st = document.getElementById('edit_status').value;
                const oc = document.getElementById('edit_outcome').value;
                const note = document.getElementById('edit_note').value || '';
                const csrf = document.getElementById('csrf_token').value || '';

                const fd = new FormData();
                fd.append('action', 'save');
                fd.append('csrf_token', csrf);
                fd.append('id', String(id));
                fd.append('status', st);
                fd.append('outcome', oc);
                fd.append('admin_note', note);

                try {
                    const res = await fetch('admin_inquiries.php', {
                        method: 'POST',
                        body: fd,
                        credentials: 'same-origin'
                    });
                    const data = await res.json();
                    if (!data.ok) {
                        alert(data.message || '저장 실패');
                        return;
                    }
                    alert(data.message || '저장되었습니다.');

                    // csrf 갱신
                    if (data.csrf_token) {
                        const t = document.getElementById('csrf_token');
                        if (t) t.value = data.csrf_token;
                    }

                    // 저장 후: 목록/통계 즉시 갱신 (승인 배지/그래프 반영)
                    refresh(true);

                } catch (e) {
                    alert('네트워크 오류가 발생했습니다.');
                }
            }

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
                    const res = await fetch('admin_inquiries.php?' + q, {
                        credentials: 'same-origin'
                    });
                    const data = await res.json();
                    if (!data.ok) {
                        alert(data.message || '데이터를 불러오지 못했습니다.');
                        return;
                    }

                    // 선택 유지
                    if (!keepSelection) {
                        selectedId = data.selected?.cashhome_1000_id ? Number(data.selected.cashhome_1000_id) : 0;
                    }

                    // UI 반영
                    countText.textContent = String((data.rows || []).length);
                    rangeText.textContent = `${data.filters.start} ~ ${data.filters.end}`;

                    // excel 링크 업데이트
                    // (필터 값이 서버 기준으로 정규화 될 수 있으니 다시 세팅)
                    elStart.value = data.filters.start;
                    elEnd.value = data.filters.end;
                    elStatus.value = data.filters.status;
                    elOutcome.value = data.filters.outcome;

                    // 키워드는 입력 중인 값 유지(여기서 덮어쓰면 타이핑 중 커서 튐)
                    // 단, 서버에서 트림된 값이 필요하면 저장 후에만 반영해도 됨.

                    renderList(data.rows || []);
                    renderStats(data.stats || {});

                    // 상세 렌더
                    // csrf 토큰을 selected에 실어 보냄
                    if (data.selected) {
                        data.selected.csrf_token = data.csrf_token || '';
                    }
                    renderDetail(data.selected || null);

                    // url state(검색조건 즉시 반영)
                    const q2 = buildQuery({
                        ajax: 0
                    });
                    history.replaceState(null, '', 'admin_inquiries.php?' + q2);

                } catch (e) {
                    alert('네트워크 오류가 발생했습니다.');
                }
            }

            // === 이벤트: 선택형 필터는 변경 즉시 반영(자동 소팅/필터) ===
            [elStart, elEnd, elStatus, elOutcome].forEach(el => {
                el.addEventListener('change', () => {
                    debounce(() => refresh(false), 80);
                });
            });

            // === 이벤트: 키워드 입력은 타이핑마다 검색(리로드 없음) ===
            // ✅ 한글 1글자 멈춤 문제 해결: input 이벤트 + debounce + ajax
            [elName, elMemo, elNote].forEach(el => {
                el.addEventListener('input', () => {
                    debounce(() => refresh(false), 180);
                });
            });

            // 초기 차트 렌더(SSR 값 기반)
            const initStats = <?= json_encode($stats, JSON_UNESCAPED_UNICODE) ?>;
            renderStats(initStats);

            // 리스트 클릭(SSR 렌더된 항목에도 바인딩)
            document.querySelectorAll('.item').forEach(item => {
                item.addEventListener('click', () => {
                    selectedId = Number(item.dataset.id || 0);
                    document.querySelectorAll('.item').forEach(x => x.classList.remove('on'));
                    item.classList.add('on');
                    refresh(true);
                });
            });

            // 초기 엑셀 링크 맞춤
            updateExcelLink();

        })();
    </script>
</body>

</html>